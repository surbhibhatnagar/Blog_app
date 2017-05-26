import os
import re
import hashlib
import hmac
from string import letters
import webapp2
import jinja2
import random
import string
from google.appengine.ext import db
import time
import json
import logging

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# Create randomly generated salt
def generate_salt():
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase)
                   for _ in range(8))


secret = 'test'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


def make_salt(length=8):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


##### user related  stuff
def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog post related stuff

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author = db.StringProperty(required=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    like = db.IntegerProperty(default=0)
    like_status = db.IntegerProperty(default=0)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        return self.render('front.html', posts=posts)


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        return self.render("permalink.html", post=post)


# Post new post
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            return self.render("newpost.html")
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content,
                     author=self.user.name, like=0, like_status=0)
            p.put()
            return self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            return self.render("newpost.html", subject=subject,
                               content=content, error=error)


class EditPost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            return self.redirect('/blog')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post is not None and post.author == self.user.name:
            return self.render("editpost.html", post=post)
        else:
            return self.redirect('/login')

    def post(self, post_id):
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post is not None and post.author == self.user.name:
                # post exists
                post.subject = subject
                post.content = content
                post.put()
                return self.redirect('/blog/%s' % str(post.key().id()))
            else:
                return self.redirect('/login')
        else:
            error = "Please enter subject and content"
            return self.render("editpost.html", post="", error=error)


class DeletePost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            return self.redirect('/blog')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post is not None and post.author == self.user.name:
            return self.render("deletepost.html", post=post)
        else:
            return self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            return self.redirect('/blog')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post is not None and post.author == self.user.name:
            db.delete(key)
            time.sleep(2)
            return self.redirect("/")
        else:
            return self.redirect("/login")


# Comment class
def comment_key(name='default'):
    return db.Key.from_path('comments', name)


class Comment(db.Model):
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author = db.StringProperty(required=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    post_id = db.StringProperty(required=True)

    # to do: add likes
    # likes
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class CommentPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            # Show all comments
            comments = Comment.all().order('-created')
            comments.filter("author =", self.user.name)
            return self.render("commentpost.html", post=post, comments=comments)
        else:
            return self.redirect("/login")

    def post(self, post_id):
        # Save comments
        if not self.user:
            return self.redirect('/blog')
        content = self.request.get('content')

        if content:
            p = Comment(parent=comment_key(), content=content,
                        author=self.user.name, post_id=post_id)
            if p is not None and p.author == self.user.name:
                p.put()
                comments = Comment.all().order('-created')
                comments.filter("author =", self.user.name)
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                time.sleep(2)
                return self.render("commentpost.html", post=post, comments=comments)
            else:
                return self.redirect("/")


class EditComment(BlogHandler):
    def get(self, comment_id, post_id):
        if not self.user:
            return self.redirect('/blog')
        key = db.Key.from_path('Comment', int(comment_id), parent=comment_key())
        comment = db.get(key)
        if comment.author == self.user.name:
            return self.render("editcomment.html", comment=comment)
        else:
            return self.redirect("/login")

    def post(self, comment_id, post_id):
        if not self.user:
            return self.redirect('/blog')

        content = self.request.get('content')

        if content:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=comment_key())
            comment = db.get(key)
            if comment is not None and comment.author == self.user.name:
                comment.content = content
                comment.put()
                time.sleep(2)
                return self.redirect('/blog/commentpost/%s' % str(post_id))
            else:
                return self.redirect("/login")
        else:
            error = "Please enter content"
            return self.render("editcomment.html", comment="", error=error)


class DeleteComment(BlogHandler):
    def get(self, comment_id, post_id):
        if not self.user:
            return self.redirect('/blog')
        key = db.Key.from_path('Comment', int(comment_id), parent=comment_key())
        comment = db.get(key)
        if comment is not None and comment.author == self.user.name:
            return self.render("deletecomment.html", comment=comment)
        else:
            return self.redirect("/login")

    def post(self, comment_id, post_id):
        if not self.user:
            return self.redirect('/blog')
        key = db.Key.from_path('Comment', int(comment_id), parent=comment_key())
        comment = db.get(key)
        if comment is not None and comment.author == self.user.name:
            db.delete(key)
            time.sleep(2)
            return self.redirect('/blog/commentpost/%s' % str(post_id))
        else:
            return self.redirect("/login")


# Like and unlike handlers
class VoteHandlerUp(BlogHandler):
    def post(self):
        logging.info(self.request.body)
        data = json.loads(self.request.body)
        key = db.Key.from_path('Post', int(data['blogKey']), parent=blog_key())
        post = db.get(key)
        if post is not None and post.author != self.user.name:
            post.like += 1
            post.put()
            logging.info(post.like)
            self.response.out.write(json.dumps(({'post_like': post.like})))
        else:
            self.redirect("/")


class VoteHandlerDown(BlogHandler):
    def post(self):
        logging.info(self.request.body)
        data = json.loads(self.request.body)
        key = db.Key.from_path('Post', int(data['blogKey']), parent=blog_key())
        post = db.get(key)
        if post is not None and post.author == self.user.name:
            post.like -= 1
            if post.like < 0:
                post.like = 0
            post.put()
            logging.info(post.like)
            self.response.out.write(json.dumps(({'post_unlike': post.like})))
        else:
            return self.redirect("/")


# Home Page : Any visitor of the blog will be able to see the blog posts so
# far on the home page.
# There will be a signup and login button on the top right.
class MainPage(BlogHandler):
    def get(self):
        # self.write('Welcome, User!')
        posts = Post.all().order('-created')
        return self.render("base.html", posts=posts)


# Signup related validity functions
# Check if username is valid
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


# Check if password is valid
PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


# Check if email is valid
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# Signup/ Register new user :
class Signup(BlogHandler):
    def get(self):
        return self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            return self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            return self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            return self.redirect('/')


# Login Page: Show login page, on submission show welcome page with all the
#  blogs and appropiate user priviliges for posts,
# Show error if user is not found
class Login(BlogHandler):
    def get(self):
        return self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            return self.redirect('/blog')
        else:
            msg = 'Invalid login'
            return self.render('login-form.html', error=msg)


# Logout Page: Logout user from current session. Reset all cookies
class Logout(BlogHandler):
    def get(self):
        self.logout()
        return self.redirect('/')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/commentpost/([0-9]+)', CommentPost),
                               ('/blog/editcomment/([0-9]+)/([0-9]+)',
                                EditComment),
                               ('/blog/deletecomment/([0-9]+)/([0-9]+)',
                                DeleteComment),
                               ('/blog/up', VoteHandlerUp),
                               ('/blog/down', VoteHandlerDown),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)
