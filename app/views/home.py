from flask import Blueprint, render_template, session, redirect, url_for
from app.auth.auth import logged_in

home_bp = Blueprint('home', __name__)


@home_bp.route('/home')
def home():
    if logged_in():
        return render_template('dashboards/admin.html', username=session['username'], role=session['role'])
    return redirect(url_for('auth.login'))
