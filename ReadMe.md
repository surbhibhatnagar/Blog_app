This is a basic blog application written in Python using Jinja template engine.
To run the application on localhost, run the following command from the project folder in which app.yaml resides :
 dev_appserver.py app.yaml
Live demo: https://blogproject-168105.appspot.com

Note: In order to make things simple, only appropiate logged in users are shown like/unlike and edit/delete options.
Also, time delay of 2s is added to give server enough time to update the datastore.