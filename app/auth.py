from flask import Flask, Blueprint, render_template, request, redirect, url_for, session, make_response
from dotenv import load_dotenv
from .db import connect_to_database
from flask_mail import Mail, Message
import re, uuid, hashlib, datetime, os, math, urllib, json

auth = Blueprint('auth', __name__)

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")

roles_list = ['Admin', 'Member']


@auth.route('/login', methods=['POST', 'GET'])
def login():
    if logged_in():
        return redirect(url_for('auth.home'))

    msg = ''
    settings = get_settings()

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'token' in request.form:
        login_attempts_res = login_attempts(False)

        if settings['brute_force_protection']['value'] == 'true' and login_attempts_res and login_attempts_res['attempts_left'] <= 1:
            return 'You cannot login right now! Please try again later!'

        username = request.form['username']
        password = request.form['password']
        token = request.form['token']

        hash_password = password + SECRET_KEY
        hashed_password = hashlib.sha256(hash_password.encode()).hexdigest()

        connection = connect_to_database()
        cursor = connection.cursor()
        cursor.execute('SELECT * FROM accounts WHERE username = ? AND password = ?', (username, password,))

        account = cursor.fetchone()

        if account:
            if settings['account_activation']['value'] == 'true' and account['activation_code'] != 'activated' and account['activation_code'] != '':
                return 'Please activate your account!'

            if settings['csrf_protection']['value'] == 'true' and str(token) != str(session['token']):
                return 'Invalid token!'

            if settings['twofactor_protection']['value'] == 'true' and account['ip'] != request.environ['REMOTE_ADDR']:
                session['tfa_id'] = account['id']
                session['tfa_email'] = account['email']

                return 'tfa: twofactor'

            session['logged_in'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            session['role'] = account['role']

            cursor.execute('DELETE FROM login_attempts WHERE ip_address = ?', (request.environ['REMOTE_ADDR'],))
            connection.commit()

            if 'rememberme' in request.form:
                rememberme_code = account['rememberme']

                if not rememberme_code:
                    rememberme_code_hash = account['username'] + request.form['password'] + SECRET_KEY
                    rememberme_code = hashlib.sha256(rememberme_code_hash.encode()).hexdigest()

                expires = datetime.datetime.now() + datetime.timedelta(days=90)
                resp = make_response('Success', 200)
                resp.set_cookie('rememberme', rememberme_code, expires=expires)

                cursor.execute('UPDATE accounts SET rememberme = ? WHERE id = ?', (rememberme_code, account['id'],))
                connection.commit()

                return resp
            return 'Success'
        else:
            if settings['brute_force_protection']['value'] == 'true':
                login_attempts_res = login_attempts()
                return 'Incorrect username or password! You have ' + str(login_attempts_res['attempts_left']) + ' attempts remaining!'
            else:
                return 'Incorrect username or password!'

    token = uuid.uuid4()
    session['token'] = token

    return render_template('auth/login.html', msg=msg, token=token, settings=settings)


def logged_in():
    connection = connect_to_database()
    cursor = connection.cursor()

    if 'logged_in' in session:
        cursor.execute('UPDATE accounts SET last_seen = ? WHERE id = ?', (datetime.datetime.utcnow(), session['id'],))
        connection.commit()

        return True
    elif 'rememberme' in request.cookies:
        cursor.execute('SELECT * FROM accounts WHERE rememberme = ?', (request.cookies['rememberme'],))
        account = cursor.fetchone()

        if account:
            session['logged_in'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            session['role'] = account['role']

            return True
    return False


def get_settings():
    connection = connect_to_database()
    cursor = connection.cursor()

    cursor.execute('SELECT * FROM settings ORDER BY id')
    settings = cursor.fetchall()
    settingsTwo = {}

    for setting in settings:
        settingsTwo[setting['setting_key']] = \
            {
                'key': setting['setting_key'],
                'value': setting['setting_value'],
                'category': setting['category']
            }

    return settingsTwo


def login_attempts(update = True):
    connection = connect_to_database()
    cursor = connection.cursor()

    ip = request.environ['REMOTE_ADDR']
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if update:
        cursor.execute('INSERT INTO login_attempts (ip_address, `date`) VALUES (?, ?) ON DUPLICATE KEY UPDATE attempts_left = attempts_left - 1, `date` = VALUES(`date`)', (ip, str(now)))
        connection.commit()

    cursor.execute('SELECT * FROM login_attempts WHERE ip_address = ?', (ip,))
    login_attempts = cursor.fetchone()

    if login_attempts:
        expire = datetime.datetime.strptime(now, '%Y-%m-%d %H:%M:%S') + datetime.timedelta(days=1)

        if datetime.datetime.strptime(now, '%Y-%m-%d %H:%M:%S') > expire:
            cursor.execute('DELETE FROM login_attempts WHERE ip_address = ?', (ip,))
            connection.commit()
            login_attempts = []

    return login_attempts

@auth.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('id', None)
    session.pop('username', None)
    session.pop('role', None)

    resp = make_response(redirect(url_for('auth.login')))
    resp.set_cookie('rememberme', expires=0)

    return resp


@auth.route('/home')
def home():
    if logged_in():
        return render_template('dashboards/admin.html', username=session['username'], role=session['role'])
    return redirect(url_for('auth.login'))


