from flask import Blueprint, render_template, session, redirect, url_for
from app.auth.auth import logged_in
from app.auth.auth import admin_loggedin

employee_bp = Blueprint('employee', __name__)


@employee_bp.route('/employee')
def member():
    if logged_in() and session['role'] == 'Employee' or admin_loggedin():
        return render_template('dashboards/employee.html', username=session['username'], role=session['role'])
    return redirect(url_for('auth.login'))