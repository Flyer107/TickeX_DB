# -*- coding: utf-8 -*-
"""
Created on Sun Aug  5 14:58:57 2018

@author: jake
"""
import string
import os
import os.path
from flask import (Flask, flash, redirect, render_template, request,
                   session, url_for, jsonify, send_from_directory, send_file )
import requests
from passlib.apps import custom_app_context as pwd_context
from flask_session import Session
from flask_jsglue import JSGlue
from tempfile import mkdtemp

from helpers import (json)
from config import getKeys
#from threading import Thread
from pymongo import MongoClient

app = Flask(__name__)
jsglue = JSGlue(app)

app.jinja_env.add_extension('jinja2.ext.loopcontrols')
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['TEMPLATES_AUTO_RELOAD'] = True

settings = getKeys()

secret_Key = settings.get("SECRET_KEY")
#app.config.update({
#    'SECRET_KEY': os.environ['SECRET_KEY']
#})
app.secret_key = secret_Key

if app.config["DEBUG"]:
    @app.after_request
    def after_request(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Expires"] = 0

        response.headers["Pragma"] = "no-cache"
        return response

sess = Session()
sess.init_app(app)
"""
############# HELPER METHODS ##############
"""
# expects an integer and returns a random string of the parameter size
def get_salt(N):
    return ''.join(random.SystemRandom().choice(string.ascii_lowercase +
                   string.ascii_uppercase + string.digits) for _ in range(N))


"""
############### END HELPERS ###################
"""
@app.route('/', methods=["GET", "POST"])
def index():

    return render_template('index.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        print(request.form)
        username = request.form.get('username')
        return redirect( url_for('index') )
    return render_template('forgot_password.html')

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        # get the username or email and password form the form
        username = request.form.get('username')
        print(username)

#        session['user_id'] = user_id

    return render_template('login.html')

@app.route('/register', methods=["GET", "POST"])
def register():

    if request.method == 'POST':
        print(request.form)
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('passwpord')
        confirm_password = request.form.get('confirm-password')

        if not username:
            return render_template("register.html", error="must provide username")
        if not email:
            return render_template("register.html", error="must provide email")
        if not password:
            return render_template("register.html", error="must provide password")
        if not confirm_password:
            return render_template("register.html", error="could not confirm password")
        if password != confirm_password:
            return render_template("register.html", error="could not confirm password")

        password = request.form.get("password")
        # validate password meets conditions
        if not len(password) >= 8 or not any([x.isdigit() for x in password]) \
                or not any([x.isupper() for x in password]) or not any([x.islower() for x in password]):
            return render_template('register.html', error='could not validate password')
        already_exists = []
        if len(already_exists) >= 1:
            error_var = "username" if (username == already_exists[0]["username"]) else "email"

            return render_template("register.html", error="{} unavailable".format(error_var))

        hash_salt = get_salt(12)

        pass_hash = pwd_context.hash(password + hash_salt)

        client = None
        try:
            client = connect_db()
            database = db_name()
            mydb = client[database]
            mycollection = mydb[settings.get('USER_DB')]
            mycollection.insert_one({'hello_world': True})
            does_user_exits = mycollection.find_one({'_id': user_ud})

        except Exception as err:
            # with open('loggedErrors.txt' 'a+') as file:
            #    file.write(err)
            print(err)
        finally:
            if client:
                client.close()

        # results = push user to database
        # print(confirm_user_added)

        #user_id_num = confirm_user_added[0]["id"]

        #session["user_id"] = user_id_num
        #session["user_name"] = confirm_user_added[0]["username"]

        if username == 'admin':
            session['admin'] = True
            return redirect(url_for("managedates"))
        return redirect(url_for("index"))

    return render_template('register.html')

@app.route('/terms_and_conditions', methods=["GET", "POST"])
def terms_and_conditions():
    return render_template('terms_and_conditions.html')

@app.route('/privacy_policy', methods=["GET", "POST"])
def privacy_policy():
    return render_template('privacy_policy.html')

def get_next_Value(collection, sequence_name, value):
    sequence = collection.find_one_and_update(
            {'_id': sequence_name},
            {'$inc' :{'sequence_value' : value} })
    return sequence.get('sequence_value')
   
def connect_db():
    clientString = settings.get('MONGO_STRING').format(settings.get('MONGO_USER'), settings.get('MONGO_USER_PW'), 'retryWrites=true')
    return MongoClient(clientString)

def db_name():
    return settings.get('DB_NAME')


@app.context_processor
def override_url_for():
    return dict(url_for=dated_url_for)

def dated_url_for(endpoint, **values):
    if endpoint == 'static':
        filename = values.get('filename', None)
        if filename:
            file_path = os.path.join(app.root_path,
                                     endpoint, filename)
            values['q'] = int(os.stat(file_path).st_mtime)
    return url_for(endpoint, **values)

def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()
       
@app.route('/shutdown', methods=['GET', 'POST'])
def shutdown():
    shutdown_server()
    return 'Server shutting down...'

def update_queries(collection, query, new_values):
    # query must be dict( {'search property' : 'search value'})
    # new_values is dict {'propert to change' : 'value to set to'}
    set_values = {'$set' : new_values}
    num_changed = collection.update_many(query, set_values)
    return num_changed

if __name__ == "__main__":
#        results = mycol.find_all({'source' : 'Unkown'})
#        for result in results:
#            result 
    app.run(debug=True)
    
"""
    client = None
    try:
        client = connect_db()
        database = db_name()
        mydb = client[database]
        mycollection = mydb['testing']
        mycollection.insert_one({'hello_world' : True })
        does_user_exits = mycollection.find_one({'_id' : user_ud })
        
    except Exception as err:
       # with open('loggedErrors.txt' 'a+') as file:
        #    file.write(err)
        print(err)   
    finally:
        if client:
            client.close()
"""
"""
    client = None
    try:
        client = connect_db()
        database = db_name()
        mydb = client[database]
        mycol = mydb['quotes']
        reset_id = 674        

    finally:
        if client:
            client.close()
"""