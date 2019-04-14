# -*- coding: utf-8 -*-
"""
Created on Sun Aug  5 14:58:57 2018

@author: jake
"""
import string
import os
import os.path
from flask import (Flask, flash, redirect, render_template, request,
                   session, url_for, jsonify, send_from_directory, send_file)
import requests
from passlib.apps import custom_app_context as pwd_context
from flask_session import Session
from flask_jsglue import JSGlue
from tempfile import mkdtemp
import random
from smtplib import SMTP, SMTP_SSL
from helpers import (json, requests)
import datetime
from config import getKeys
#from threading import Thread
from pymongo import MongoClient
from werkzeug.utils import secure_filename

app = Flask(__name__)
jsglue = JSGlue(app)

# app.jinja_env.add_extension('jinja2.ext.loopcontrols')
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
app.config['TEMPLATES_AUTO_RELOAD'] = True

settings = getKeys()

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
print(ROOT_DIR)
#UPLOAD_FOLDER = os.path.join(ROOT_DIR, settings.get("FOLDER_NAME"))
UPLOAD_FOLDER = ROOT_DIR + settings.get("FOLDER_NAME")
print(UPLOAD_FOLDER)
ALLOWED_EXTENSIONS = set(['pdf', 'png', 'jpg', 'jpeg'])

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
secret_Key = settings.get("SECRET_KEY")
# app.config.update({
#    'SECRET_KEY': os.environ['SECRET_KEY']
# })
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


CONFIRM_EMAIL = ('Thanks for joining UMD Ticket Exchange!\n\n' +
                 'Please click the link below to confirm your email:\n' +
                 '{}')


def send_email(recipient, subject, msg):
    try:
        print(settings.get('EMAIL_ADDRESS'), "<-address, ",
              settings.get("EMAIL_PASSWORD"))
        #server = SMTP('smtp.gmail.com', 587)
        server = SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        # server.ehlo()
        # server.starttls()
        # server.ehlo()
        server.login(settings.get('EMAIL_ADDRESS'),
                     settings.get('EMAIL_PASSWORD'))
        message = 'Subject: {}\n\n{}'.format(subject, msg)
        print(message)
        server.sendmail(settings.get('EMAIL_ADDRESS'), recipient, message)
        server.quit()
        print('Success: Email sent!')
        return True
#            print(settings.get('PASSWORD'))
#            print(settings.get('EMAIL_ADDRESS'))
    except Exception as error:
        print('error sending message', error)
        return False


def get_date_time():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_date_obj(date_time_str):
    return datetime.datetime.strptime(date_time_str, '%b %d %Y %I:%M')


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


"""
############### END HELPERS ###################
"""


@app.route('/', methods=["GET", "POST"])
def index():
    gameList = []
    client = None
    try:
        client = connect_db()
        database = db_name()
        mydb = client[database]
        mycollection = mydb[settings.get('GAMES_DB')]
        value = get_next_Value(mycollection, 'id_values', 0)
        for x in range(value):
            item = mycollection.find_one({'_id': x})
            if len(list(item)) > 0:
                gameList.append(item)
    finally:
        if client:
            client.close()        
    return render_template('index.html', game_list = gameList)


@app.route('/addTicket', methods=["GET", "POST"])
def addTicket():
    if 'username' not in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        if 'inputFile' not in request.files:
            return render_template('addTicket.html', error='No file uploaded.')
        gameName = request.form.get('gameName')
        file = request.files['inputFile']

        if file.filename == '':
            return render_template('addTicket.html', error='No file found.')

        if file and allowed_file(file.filename):
            print(file.filename)
            username = session['username']
            client = None
            try:
                client = connect_db()
                database = db_name()
                mydb = client[database]

                mycollection = mydb[settings.get('USER_DB')]
                results = mycollection.find_one({'username': username})

                if not results.get('uploads'):
                    if results.get('_id'):
                        filename = username + '0' + file.filename
                        mycollection.update_one({'username': username}, {
                                                '$set': {'uploads': json.dumps([{'filename': filename, 'game_name': gameName, 'requested': 'False', 'id': get_salt(5)}])}})
                        #file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        gamescollection = mydb[settings.get('GAMES_DB')]
                        game_result = gamescollection.find_one({'gameName' : gameName})

                        if 'tickets' not in game_result:
                            gamescollection.update_one({'gameName' : gameName}, {'$set' : { 'tickets' : [] }})

                        gamescollection.update_one({'gameName' : gameName}, {"$push" : {'tickets': username }} )

                        file.save(
                            app.config['UPLOAD_FOLDER'] + "\\" + filename)
                else:
                    uploads = json.loads(results.get('uploads'))
                    number_of_files_uploaded = len(uploads)
                    filename = secure_filename(file.filename)
                    uploads.append(
                        {'filename': filename, 'game_name': gameName, 'requested': 'False', 'id': get_salt(5)})

                    mycollection.update_one({'username': username}, {
                                            '$set': {'uploads': json.dumps(uploads)}})

                    gamescollection = mydb[settings.get('GAMES_DB')]
                    game_result = gamescollection.find_one({'gameName' : gameName})

                    if 'tickets' not in game_result:

                        gamescollection.update_one({'gameName' : gameName}, {'$set' : { 'tickets' : [] }})

                    gamescollection.update_one({'gameName' : gameName}, {"$push" : {'tickets': username }} )
                
                    file.save(app.config['UPLOAD_FOLDER'] + "\\" + filename)
                #file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            finally:
                if client:
                    client.close()
    gameList = []
    client = None
    try:
        client = connect_db()
        database = db_name()
        mydb = client[database]
        mycollection = mydb[settings.get('GAMES_DB')]
        value = get_next_Value(mycollection, 'id_values', 0)
        for x in range(value):
            item = mycollection.find_one({'_id': x})
            if len(list(item)) > 0:
                gameList.append(item)
    finally:
        if client:
            client.close()

    return render_template('addTicket.html', game_list=gameList)


@app.route('/account', methods=["GET", "POST"])
def account():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    user_id = session.get('user_id')

    my_listed = []
    my_requests = []
    my_bought = []

    client = None
    try:
        client = connect_db()
        database = db_name()
        mydb = client[database]
        mycollection = mydb[settings.get('USER_DB')]
        find_user = mycollection.find_one({'_id' : user_id })
        uploads = json.loads(find_user.get('uploads'))
        for upload in uploads:
            my_listed.append(upload)
    finally:
        if client:
            client.close()
    list_of_tickets = [{'first_event': 'UMD vs Duke', 'ticket_name': 'jake',
                        'ticket_date': '11/20/2019', 'ticket_price': '$10'}]
    return render_template('account.html', posted_tickets=list_of_tickets, my_listed = my_listed)


@app.route('/tickets', methods=["GET", "POST"])
def tickets():
    return render_template('tickets.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        print(request.form)
        username = request.form.get('username')
        return redirect(url_for('index'))
    return render_template('forgot_password.html')


@app.route('/logout', methods=["GET", "POST"])
def logout():
    session.clear()
    return render_template('index.html')


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        # get the username or email and password form the form
        username = request.form.get('username_email')
        password = request.form.get('password')

        if not username or not password:
            return render_template('index.html')
        print(username, password)
        client = None
        try:
            client = connect_db()
            database = db_name()
            mydb = client[database]

            mycollection = mydb[settings.get('USER_DB')]
            result_username = mycollection.find_one({'username': username})

            if len(list(result_username)) < 1:

                result_email = mycollection.find_one({'email': username})
                if len(list(result_email)) < 1:

                    return render_template('index.html')

                if not pwd_context.verify(password + result_username.get('salt'), result_username.get('password')):
                    return render_template("index.html")

                username = result_email.get('username')
                user_id = result_email.get('_id')

                session['user_id'] = user_id
                session['username'] = username
                return render_template('index.html')

            else:

                if not pwd_context.verify(password + result_username.get('salt'), result_username.get('password')):
                    return render_template("index.html")

                session['username'] = username
                user_id = result_username.get('_id')

                session['user_id'] = user_id
                return redirect(url_for('index'))
        except Exception as err:
            error_collection = mydb[settings.get('ERROR_DB')]
            error_collection.insert_one(
                {'error': str(err), 'date/time': get_date_time()})
        finally:
            if client:
                client.close()
    return render_template('index.html')


@app.route('/confirm_email', methods=["GET", "POST"])
def confirm_email():
    email = request.args.get('email')
    pw = request.args.get('pw')
    if not email or not pw:
        return render_template('error_page.html', error='Email or confirmation code not valid')

    client = None
    try:
        client = connect_db()
        database = db_name()
        mydb = client[database]
        mycollection = mydb[settings.get('VERIFY_EMAIL_DB')]

        results = mycollection.find_one({'email': email})

        if not len(list(results)) > 0:
            return render_template('error_page.html', error="Could not confirm email")

        if results.get('pw') != pw:

            return render_template('error_page.html', error="Email or confirmation code not valid")
        else:

            collection2 = mydb[settings.get('USER_DB')]
            resulted = collection2.find_one_and_update(
                {'email': email}, {'$set': {'activated': 'True'}})
            find_user = collection2.find_one({'email': email})
            username = find_user.get('username')
            user_id = find_user.get('_id')

            if not username or not user_id:
                return render_template('error_page.html', error='user not found')

            session['username'] = find_user.get('username')
            session['user_id'] = find_user.get('_id')

            return render_template('index.html')

    except Exception as err:
        error_collection = mydb[settings.get('ERROR_DB')]
        error_collection.insert_one(
            {'error': str(err), 'date/time': get_date_time()})
    finally:
        if client:
            client.close()
    return render_template('confirm_email.html')


@app.route('/register', methods=["GET", "POST"])
def register():

    if request.method == 'POST':
        print(request.form)
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')

        if not username:
            return render_template("register.html", error="must provide username")
        if not email or '.umd.edu' not in email:
            return render_template("register.html", error="No email found or invalid email provided.")
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

        client = None
        try:
            client = connect_db()
            database = db_name()
            mydb = client[database]

            mycollection = mydb[settings.get('USER_DB')]

            results = mycollection.find({'username': username})
            results_email = mycollection.find({'email': email})
            if len(list(results)) > 0 or len(list(results_email)) > 0:
                return render_template('register.html', error='Username or email already in use')

            hash_salt = get_salt(12)

            pass_hash = pwd_context.hash(password + hash_salt)

            user_info = {'_id': get_next_Value(mycollection, 'id_values', 1),
                         'username': username,
                         'email': email,
                         'password': pass_hash,
                         'salt': hash_salt,
                         'activated': 'False',
                         'tickets': []}

            random_string = get_salt(45)

            link_with_url = request.url_root + \
                'confirm_email?email={}&pw={}'.format(email, random_string)

            message = CONFIRM_EMAIL.format(link_with_url)

            email_sent = send_email(
                email, 'Confirm Email', message)

            if not email_sent:
                return render_template('register.html', error='Could not verify email.')

            confirm_email_obj = {'username': username, '_id': user_info.get('_id'),
                                 'email': email, 'pw': random_string, 'data': get_date_time()}

            email_collections = mydb[settings.get('VERIFY_EMAIL_DB')]
            email_collections.insert_one(confirm_email_obj)
            mycollection.insert_one(user_info)

            if username == 'admin':
                session['admin'] = True

            return render_template('confirm_email.html')

        except Exception as err:
            error_collection = mydb[settings.get('ERROR_DB')]
            error_collection.insert_one(
                {'error': str(err), 'date/time': get_date_time()})
        finally:
            if client:
                client.close()

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
        {'$inc': {'sequence_value': value}})
    return sequence.get('sequence_value')


def connect_db():
    clientString = settings.get('MONGO_STRING').format(settings.get(
        'MONGO_USER'), settings.get('MONGO_USER_PW'), 'retryWrites=true')
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
    set_values = {'$set': new_values}
    num_changed = collection.update_many(query, set_values)
    return num_changed


if __name__ == "__main__":
    #        results = mycol.find_all({'source' : 'Unkown'})
    #        for result in results:
    #            result
    #
    app.run(debug=True, port=8000)

    client = None
    try:
        client = connect_db()
        database = db_name()
        mydb = client[database]

        mycollection = mydb[settings.get('USER_DB')]
        results = mycollection.find_one({'username': username})
        resulted = mycollection.find_one_and_update(
            {'email': email}, {'$set': {'activated': 'True'}})
        print(resulted)

    finally:
        if client:
            client.close()
