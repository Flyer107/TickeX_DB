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
import json
#import requests
from passlib.apps import custom_app_context as pwd_context
from flask_session import Session
import traceback
from flask_jsglue import JSGlue
from tempfile import mkdtemp
import random
from smtplib import SMTP, SMTP_SSL
from helpers import (requests, all_ids, csv, get_list_from_sport_id, build_objects,
                    edit_category_and_sport, parse_schedule, insert_list_into_collection, get_next_Value)
import datetime
#from config import getKeys
#from threading import Thread
from pymongo import MongoClient
from werkzeug.utils import secure_filename

def getKeys():
    if 'MONGO_STRING' not in os.environ:
        dotenv = '.env.ini'
        with open(dotenv, 'r') as file:
            content = file.readlines()

        content = [line.strip().split('=') for line in content if '=' in line]
        env_vars = dict(content)
        if file:
            file.close()
        return env_vars
    else:
        return_dict = {}
        to_return = ['MONGO_STRING', 'MONGO_USER', 'MONGO_USER_PW', 'USER_DB', 'VERIFY_EMAIL_DB',
        'GAMES_DB', 'ERROR_DB', 'DB_NAME', 'FOLDER_NAME', 'EMAIL_ADDRESS', 'EMAIL_PASSWORD']
        for item in to_return:
            return_dict[item] = os.environ.get(item)

        return return_dict

app = Flask(__name__)
jsglue = JSGlue(app)

# app.jinja_env.add_extension('jinja2.ext.loopcontrols')
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
app.config['TEMPLATES_AUTO_RELOAD'] = True

settings = getKeys()
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
#UPLOAD_FOLDER = os.path.join(ROOT_DIR, settings.get("FOLDER_NAME"))
slash = "/"
UPLOAD_FOLDER = ROOT_DIR + slash + settings.get("FOLDER_NAME")
# print(UPLOAD_FOLDER)
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

        #server = SMTP('smtp.gmail.com', 587)
        server = SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()

        server.login(settings.get('EMAIL_ADDRESS'),
                     settings.get('EMAIL_PASSWORD'))
        message = 'Subject: {}\n\n{}'.format(subject, msg)
        # print(message)
        server.sendmail(settings.get('EMAIL_ADDRESS'), recipient, message)
        server.quit()
        # print('Success: Email sent!')
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

def connect_db():
    clientString = settings.get('MONGO_STRING_2').format(settings.get(
        'MONGO_USER_2'), settings.get('MONGO_USER_PW_2'), 'retryWrites=true')
    return MongoClient(clientString)
# 'USER_DB', 'VERIFY_EMAIL_DB', 'GAMES_DB', 'ERROR_DB', 'DB_NAME', 'FOLDER_NAME'
def db_name():
    return settings.get('DB_NAME')
def games_db():
    return settings.get("GAMES_DB")
def user_db():
    return settings.get("USER_DB")
def verify_email_db():
    return settings.get("VERIFY_EMAIL_DB")
def error_db():
    return settings.get("ERROR_DB")
def folder_name():
    return settings.get("FOLDER_NAME")

def connect_to_db( method, args):
    client = None
    return_value = None
    try:
        client = connect_db()
        database = db_name()
        mydb = client[database]

        return_value = method( mydb, args )

    except Exception as err:
        print(traceback.print_exc())
        error_collection = mydb[ error_db() ]
        error_collection.insert_one(
            {'error': str(err), 'date/time': get_date_time()})
        return_value = False
    finally:
        if client:
            client.close()
        return return_value

def index_manager( mydb, args ):
    collection = mydb[ games_db() ]
    gameList = collection.find(  { '_id': { '$gt': -1 } }  )
    return render_template('index.html', game_list = gameList)


"""
############### END HELPERS ###################
"""


@app.route('/', methods=["GET", "POST"])
def index():
    print(session.get("user_id"))
    if request.method=="POST":
        ticket_id = request.form.get('ticket_id')
        session['current_ticket'] = ticket_id
        return redirect( url_for('request_ticket') )

    gameList = connect_to_db( index_manager, None )
    if gameList:
        return gameList
    else:
        return render_template('error_page.html', error="Something went wrong.")

def add_ticket_manager(mydb, args):
    file = args.get('file')
    username = args.get('username')
    gameName = args.get('gameName')
    collection = mydb[user_db()]
    results = collection.find_one({'username': username})
    # as a double check to proceed, but this should always be true.
    if results.get('uploads'):
        if results.get('_id'):
            filename = secure_filename(file.filename)
            ticket_object = {'filename': filename, 'Event': gameName, 'requested': 'False', 'id': get_salt(15)}
            collection.update_one({'username': username},
                                    { '$push': {
                                     'uploads': ticket_object } })
            collection = mydb[games_db()]
            game_result = gamescollection.find_one({'Event' : gameName})
            ticket_object['username'] = username
            gamescollection.update_one({'gameName' : gameName}, {"$push" : {'tickets': ticket_object }} )
            slash = "/"
            print(slash)
            file.save( app.config['UPLOAD_FOLDER'] + slash + filename)
            return True

def get_all_games(mydb, args):
    collection = mydb[games_db()]
    return collection.find({'_id': {'$gt' : -1 }})
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
            args = {'file' : file, 'username' : username, 'gameName' : gameName }
            connect_to_db( add_ticket_manager, args)

    gameList = connect_to_db( get_all_games, None)

    return render_template('addTicket.html', game_list=gameList)

@app.route('/accept_request', methods=["POST"])
def accept_request():

    username = session['username']
    other_user = request.form.get('other_user')
    gameName = request.form.get('gameName')
    user_id = session['user_id']

    client = None
    try:
        client = connect_db()
        database = db_name()
        mydb = client[database]
        mycollection = mydb[user_db()]
        # remove from own requests
        mycollection.update_one({'_id' : user_id}, {'$pull' : {'requests' : { 'gameName' : gameName}} })
        ## remove the ticket from own uploads
        find_self = mycollection.find_one({'_id' : user_id})
        after_parsing = []
        filename = ''
        if 'uploads' in find_self:
            uploads = find_self.get('uploads')
            print(uploads)
            for upload in uploads:
                if upload.get('game_name') == gameName:
                    filename = upload.get('filename')
                else:
                    after_parsing.append( upload )
        print(after_parsing)

        mycollection.update_one({'_id' : user_id }, {'$set' : {'uploads' : after_parsing }})

        ## update the other uses ticket to approved
        find_user = mycollection.find_one( { 'username' : other_user } )
        other_users_requests = find_user.get('my_requests')

        after_parsing = []
        if other_users_requests:
            for users_requests in other_users_requests:
                #print(users_requests)
                if users_requests.get('other_user') and users_requests.get('gameName'):
                    print(users_requests)
                    if users_requests.get('other_user') == username and users_requests.get('gameName') == gameName:
                        print('found ticket')
                        users_requests['approved'] = '1'
                        users_requests['filename'] = filename
                    after_parsing.append(users_requests)

        mycollection.update_one({'username' : other_user}, {'$set' : {'my_requests' : after_parsing } })

        #remove the ticket from game tickets
        game_collection = mydb[settings.get('GAMES_DB')]
        game_collection.update_many({'gameName' : gameName}, {'$pull' : {'tickets' : username} })

    finally:
        if client:
            client.close()

    return jsonify({'error' : 'something went wrong'})

@app.route('/account', methods=["GET", "POST"])
def account():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user_id = session.get('user_id')

    my_listed = []
    requests = []
    my_recieved = []

    client = None
    try:
        client = connect_db()
        database = db_name()
        mydb = client[database]
        mycollection = mydb[settings.get('USER_DB')]
        find_user = mycollection.find_one({'_id' : user_id })

        my_listed = find_user.get('uploads', [])
        requests = find_user.get('requests_from', [])

        myrequests = find_user.get('requests_to')
        if myrequests:
            for this_request in myrequests:
                print(this_request)
                if this_request.get('approved') == '1':
                    my_recieved.append(this_request)

    finally:
        if client:
            client.close()

    list_of_tickets = [{'first_event': 'UMD vs Duke', 'ticket_name': 'jake',
                        'ticket_date': '11/20/2019', 'ticket_price': '$10'}]

    return render_template('account.html', my_recieved = my_recieved, my_listed = my_listed, requests = requests)


@app.route('/tickets', methods=["GET", "POST"])
def tickets():
    return render_template('tickets.html')

@app.route('/download_file/')
def download_file():
    filename = request.args.get('file')
    # return render_template('account.html')
    try:
        return send_file(app.config['UPLOAD_FOLDER'] + "/" + filename)
    except Exception as error:
        print(error)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        print(request.form)
        username = request.form.get('username')
        return redirect(url_for('index'))
    return render_template('forgot_password.html')

@app.route('/request_ticket', methods=["GET", "POST"])
def request_ticket():
    if request.method == "POST":
        if 'user_id' not in session or "username" not in session:
            session['request_error'] ='You must be logged in to request a Ticket'
            return redirect( url_for('request_ticket') )

        username = session.get('username')
        user_id = session.get('user_id')

        username_for_ticket = request.form.get('username')
        gameName = request.form.get('gameName')

        if username == username_for_ticket:
            session['request_error'] = 'You cannot make a request for your own ticket.'
            return redirect( url_for('request_ticket') )
        client = None
        try:
            client = connect_db()
            database = db_name()
            mydb = client[database]
            mycollection = mydb[settings.get('USER_DB')]
            find_user = mycollection.find_one({'username' : username_for_ticket })

            if 'requests' not in find_user:
                mycollection.update_one({ 'username' : username_for_ticket }, {'$set' : { 'requests' : [] }})
            else:
                if len(find_user.get('requests')) > 0:
                    for each_request in find_user.get('requests'):
                        if each_request.get('username') == username and each_request.get('gameName') == gameName:
                            session['request_error'] = "You have already requested this ticket."
                            return redirect( url_for('request_ticket') )

            mycollection.update_one({ 'username' : username_for_ticket },
                    {"$push" : {'requests': {'username' :username, 'gameName' : gameName} }
                                })
            # find self in database
            update_self = mycollection.find_one({'_id' : user_id})

            if not update_self:
                session['request_error'] = "Something went wrong."
                return redirect( url_for('request_ticket'))

            if 'my_requests' not in update_self:
                mycollection.update_one({ '_id' : user_id },
                        {'$set' : { 'my_requests' : [] }
                    })

            mycollection.update_one({'_id' : user_id},
                        {'$push' : {'my_requests' : {'gameName': gameName, 'other_user' : username_for_ticket, 'approved' : '0' } }
                    })
           # mycollection.update_one({ 'username' : username_for_ticket },
            #                {"$push" : {'requests': { 'username' : username,  } } } )

        finally:
            if client:
                client.close()
        return redirect( url_for('account') )

    error = session.pop('request_error', '')
    ticket_id = session.get('current_ticket')

    if not ticket_id:
        return redirect( url_for('index') )
    client = None
    try:
        client = connect_db()
        database = db_name()
        mydb = client[database]
        mycollection = mydb[ settings.get('GAMES_DB') ]
        result = mycollection.find_one({'_id': int(ticket_id) })
        uploaded_tickets = []
        if 'tickets' in result:
            gameName = result.get('gameName')
            for username in result.get('tickets'):
                rating = random.randint(1, 5)
                number = random.randint(1, 20)
                uploaded_tickets.append({ "username" : username, 'rating' : rating, 'number_of_ratings' : number})
                # print(uploaded_tickets)
            return render_template('request_ticket.html', uploaded_tickets = uploaded_tickets, gameName = gameName, error=error)
        else:
            return render_template('index.html', error='No Tickets found for this Game.')
    finally:
        if client:
            client.close()
    return render_template('request_ticket.html')

@app.route('/logout', methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect( url_for('index') )

def login_manager( mydb, args ):

    mycollection = mydb[user_db()]

    result_username_or_email = mycollection.find_one({'username': args.get('username')})
    if not result_username_or_email:
        result_username_or_email = mycollection.find_one({'email': args.get('username') })

    if not result_username_or_email:
        return redirect( url_for('index') )

    if not pwd_context.verify(args.get('password') + result_username_or_email.get('salt'), result_username_or_email.get('password')):
        return redirect( url_for('index') )

    admin = False
    if result_username_or_email.get('username') == 'admin':
        admin = True

    return ( result_username_or_email.get('_id'), result_username_or_email.get('username'), admin )

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        # get the username or email and password form the form
        username = request.form.get('username_email')
        password = request.form.get('password')
        if not username or not password:
            return render_template('index.html')

        result = connect_to_db( login_manager, {"username" : username, 'password' : password } )
        if result:
            session['user_id'] = result[0]
            session['username'] = result[1]
            session['admin'] = result[2]
            return redirect( url_for('index'))

    return redirect( url_for('index') )

def handle_confirmation( mydb, args ):
    email = args.get('email')
    pw = args.get('pw')

    mycollection = mydb[settings.get('VERIFY_EMAIL_DB')]

    results = mycollection.find_one({'email': email})
    if not results:
        return render_template('error_page.html', error="Could not confirm email")
    if results.get('pw') != pw:
        return render_template('error_page.html', error="Email or confirmation code not valid")

    mycollection.delete_one({'email' : email})

    collection2 = mydb[settings.get('USER_DB')]
    resulted = collection2.find_one_and_update(
        {'email': email}, {'$set': {'activated': 'True'}})

    find_user = collection2.find_one({'email': email})
    username = find_user.get('username')
    user_id = find_user.get('_id')

    if not username or not user_id:
        return render_template('error_page.html', error='user not found')

    if username == 'admin':
        session['admin'] = True

    session['username'] = find_user.get('username')
    session['user_id'] = find_user.get('_id')

    return redirect( url_for('index') )

@app.route('/confirm_email', methods=["GET", "POST"])
def confirm_email():
    email = request.args.get('email')
    pw = request.args.get('pw')
    if not email or not pw:
        return render_template('error_page.html', error='Email or confirmation code not valid')

    args = {'email' : email, 'pw' : pw }
    results = connect_to_db( handle_confirmation, args )
    if results:
        return results
    else:
        return render_template('error_page.html', error='Something went wrong.')


@app.route('/register', methods=["GET", "POST"])
def register():

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')

        if not username:
            return render_template("register.html", error="must provide username")
        if not email or 'umd.edu' not in email:
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

            user_info = {
                 '_id': get_next_Value(mycollection, 'id_values', 1),
                 'username': username,
                 'email': email,
                 'password': pass_hash,
                 'salt': hash_salt,
                 'activated': 'False',
                 'uploads': [],
                 'requests_to': [],
                 'requests_from': []
            }

            random_string = get_salt(45)

            link_with_url = request.url_root + \
                'confirm_email?email={}&pw={}'.format(email, random_string)

            message = CONFIRM_EMAIL.format(link_with_url)

            email_sent = send_email(
                email, 'Confirm Email', message)
            print(email_sent)
            if not email_sent:
                return render_template('register.html', error='Could not verify email.')

            confirm_email_obj = {'username': username, '_id': user_info.get('_id'),
                                 'email': email, 'pw': random_string, 'data': get_date_time()}

            email_collections = mydb[settings.get('VERIFY_EMAIL_DB')]
            email_collections.insert_one(confirm_email_obj)
            mycollection.insert_one(user_info)

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

def update_queries(collection, query, new_values):
    # query must be dict( {'search property' : 'search value'})
    # new_values is dict {'propert to change' : 'value to set to'}
    set_values = {'$set': new_values}
    num_changed = collection.update_many(query, set_values)
    return num_changed

# FOR EMERGENCY ONLY, will drop all items in a collection.
def drop_documents(mydb, args):
    collection = mydb[args.get('collection_name')]
    collection.remove({'_id' : {'$gt' : -1} })

def decrement_id(mydb, args):
    collection = mydb[args.get('collection_name')]
    value = get_next_Value(collection, 'id_values', args.get('val'))

def init_collection(mydb, args):
    # initialize a collection and add the id values object for keeping serial id's
    collection = mydb[args.get('collection_name')]
    collection.insert_one({'_id' : 'id_values', 'sequence_value' : 0})

if __name__ == "__main__":

    app.debug = True
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

    #sport = all_ids.get("baseball")
    #final_list = parse_schedule( sport )
    #args = {'collection_name' : games_db(), 'list_of_items' : final_list}
    #connect_to_db( insert_list_into_collection, args )

    #connect_to_db( init_collection, {'collection_name': verify_email_db()} )
    #connect_to_db( decrement_id, {'collection_name' : games_db()})

