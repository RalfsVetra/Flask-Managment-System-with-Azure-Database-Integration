import datetime

from flask import Blueprint, render_template, redirect, url_for
from app.auth.auth import admin_loggedin
from app.db import connect_to_database

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/admin', methods=['GET', 'POST'])
def admin():
    if not admin_loggedin():
        return redirect(url_for('auth.login'))

    connection = connect_to_database()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT * FROM accounts WHERE cast(registered as DATE) = cast(GETDATE() as DATE) ORDER BY registered DESC"
    )
    accounts = cursor.fetchall()

    cursor.execute(
        'SELECT COUNT(*) AS total FROM accounts'
    )
    accounts_total = cursor.fetchone()

    cursor.execute(
        "SELECT COUNT(*) AS total FROM accounts WHERE last_seen < dateadd(month, -1, GETDATE())"
    )
    inactive_accounts_less_than_one_month = cursor.fetchone()

    cursor.execute(
        "SELECT * FROM accounts WHERE last_seen > dateadd(day, -1, GETDATE()) ORDER BY last_seen DESC"
    )
    active_accounts = cursor.fetchall()

    cursor.execute(
        "SELECT COUNT(*) AS total FROM accounts WHERE last_seen > dateadd(month, -1, GETDATE())"
    )
    inactive_accounts = cursor.fetchone()

    return render_template('dashboards/admin.html',
                           accounts=accounts,
                           selected='dashboard',
                           selected_child='view',
                           accounts_total=accounts_total['total'],
                           inactive_accounts_less_than_one_month=inactive_accounts_less_than_one_month['total'],
                           active_accounts=active_accounts, inactive_accounts=inactive_accounts['total'],
                           time_elapsed_string=time_elapsed_string)


def time_elapsed_string(time):
    now = datetime.datetime.now()
    delta = now - time

    if delta.days > 0:
        if delta.days == 1:
            return '1 day ago'
        else:
            return '{} days ago'.format(delta.days)
    elif delta.seconds >= 3600:
        hours = delta.seconds // 3600
        if hours == 1:
            return '1 hour ago'
        else:
            return '{} hours ago'.format(hours)
    elif delta.seconds >= 60:
        minutes = delta.seconds // 60
        if minutes == 1:
            return '1 minute ago'
        else:
            return '{} minutes ago'.format(minutes)
    else:
        return 'Just now'
