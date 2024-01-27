from flask import Flask, Blueprint, render_template, request, redirect, url_for, session, make_response
from flask_mysqldb import MySQL
from flask_mail import Mail, Message
import MySQLdb.cursors, re, uuid, hashlib, datetime, os, math, urllib, json

app = Flask(__name__)
auth = Blueprint('auth', __name__)

mysql = MySQL(app)
mail = Mail(app)

roles_list = ['Admin', 'Member']


@auth.route('/login', methods=['POST', 'GET'])
def login():
    return render_template('auth/login.html')
