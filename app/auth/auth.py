import datetime
import hashlib
import os
import re
import uuid

from dotenv import load_dotenv
from flask import Blueprint, render_template, request, redirect, url_for, session, make_response

from app.db import connect_to_database

auth = Blueprint('auth', __name__)

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")

roles_list = ['Admin', 'Member']


@auth.route('/login', methods=['POST', 'GET'])
def login():
    if admin_loggedin():
        return redirect(url_for('admin.admin'))

    if logged_in():
        return redirect(url_for('member.member'))

    msg = ''
    settings = get_settings()

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'token' in request.form:
        login_attempts_res = login_attempts(False)

        if settings['brute_force_protection']['value'] == 'true' and login_attempts_res and login_attempts_res[
            'attempts_left'] < 1:
            return 'You cannot login right now! Please try again later!'

        username = request.form['username']
        password = request.form['password']
        token = request.form['token']

        hash_password = password + SECRET_KEY
        hashed_password = hashlib.sha256(hash_password.encode()).hexdigest()

        connection = connect_to_database()
        cursor = connection.cursor()
        cursor.execute('SELECT * FROM accounts WHERE username = ? AND password = ?', (username, hashed_password,))

        account = cursor.fetchone()

        if account:
            if settings['csrf_protection']['value'] == 'true' and str(token) != str(session['token']):
                return 'Invalid token!'

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
                return 'Incorrect username or password! You have ' + str(
                    login_attempts_res['attempts_left']) + ' attempts remaining!'
            else:
                return 'Incorrect username or password!'

    token = uuid.uuid4()
    session['token'] = token

    return render_template('auth/login.html', msg=msg, token=token, settings=settings)


@auth.route('/register', methods=['GET', 'POST'])
def register():
    if logged_in():
        return redirect(url_for('member.member'))

    msg = ''
    settings = get_settings()

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'confirm_password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']
        role = 'Member'

        hash_password = password + SECRET_KEY
        hashed_password = hashlib.sha256(hash_password.encode()).hexdigest()

        connection = connect_to_database()
        cursor = connection.cursor()
        cursor.execute('SELECT * FROM accounts WHERE username = ?', (username,))
        account = cursor.fetchone()

        if account:
            return 'Already registered!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            return 'Invalid email!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            return 'Username must contain only characters and numbers!'
        elif not username or not password or not confirm_password or not email:
            return 'Please fill out the necessary information!'
        elif password != confirm_password:
            return 'Passwords do not match!'
        elif len('username') < 5 or len('username') > 20:
            return 'Username must contain at least 5 to 20 characters!'
        elif len('password') < 5 or len('password') > 50:
            return 'Password must contain at least 5 to 50 characters!'
        else:
            now = datetime.datetime.now()
            now_format = now.strftime('%Y-%m-%d %H:%M:%S')

            cursor.execute('INSERT INTO accounts (username, password, email, role, rememberme, registered, last_seen, ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                           (username, hashed_password, email, role, '', now_format, now_format, request.environ['REMOTE_ADDR']))
            connection.commit()

            if settings['auto_login_after_register']['value'] == 'true':
                session['logged_in'] = True

                cursor.execute("SELECT @@IDENTITY AS last_id")
                last_row = cursor.fetchone()
                session['id'] = last_row['last_id']
                session['username'] = username
                session['role'] = role

                return 'autologin'
            return 'Registration successful!'
    elif request.method == 'POST':
        return 'Please fill out the necessary information2!'
    return render_template('auth/register.html', msg=msg, settings=settings)


@auth.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('id', None)
    session.pop('username', None)
    session.pop('role', None)

    resp = make_response(redirect(url_for('auth.login')))
    resp.set_cookie('rememberme', expires=0)

    return resp


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


def login_attempts(update=True):
    connection = connect_to_database()
    cursor = connection.cursor()

    ip = request.environ['REMOTE_ADDR']
    now = datetime.datetime.now()
    now_format = now.strftime('%Y-%m-%d %H:%M:%S')

    if update:
        from app.db import update_login_attempts
        update_login_attempts(cursor, ip, now_format)
        connection.commit()

    cursor.execute('SELECT * FROM login_attempts WHERE ip_address = ?', (ip,))
    login_attempts = cursor.fetchone()

    if login_attempts:
        expire = now + datetime.timedelta(days=1)

        if now > expire:
            cursor.execute('DELETE FROM login_attempts WHERE ip_address = ?', (ip,))
            connection.commit()
            login_attempts = []

    return login_attempts


def admin_loggedin():
    if logged_in() and session['role'] == 'Admin':
        return True
    return False