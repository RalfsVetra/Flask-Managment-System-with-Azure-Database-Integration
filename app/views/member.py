from flask import Blueprint, render_template, session, redirect, url_for
from app.auth.auth import logged_in

member_bp = Blueprint('member', __name__)


@member_bp.route('/member')
def member():
    if logged_in():
        return render_template('dashboards/member.html', username=session['username'], role=session['role'])
    return redirect(url_for('auth.login'))
