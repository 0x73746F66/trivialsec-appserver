from flask import render_template, Blueprint, redirect, url_for
from flask_login import current_user, login_required
from trivialsec.models.account_config import AccountConfig
from trivialsec.models.activity_log import ActivityLog, ActivityLogs
from trivialsec.models.domain import Domains
from trivialsec.models.member import Member, Members
from trivialsec.models.role import Role, Roles
from trivialsec.models.invitation import Invitations
from trivialsec.models.plan import Plan
from trivialsec.models.plan_invoice import PlanInvoices
from trivialsec.helpers.config import config
from templates import public_params


blueprint = Blueprint('user', __name__)

@blueprint.route('/', methods=['GET'])
@login_required
def user():
    return redirect(url_for('user.user_preferences'))

@blueprint.route('/preferences', methods=['GET'])
@login_required
def user_preferences():
    params = public_params()
    params['page_title'] = 'Preferences'
    params['page'] = 'preferences'
    params['js_includes'] = [
        "utils.min.js",
        "api.min.js",
        "user/preferences.min.js"
    ]
    params['css_includes'] = [
        "user/scaffolding.css",
        "user/main.css",
        "user/preferences.css"
    ]
    params['account'] = current_user
    account_config = AccountConfig(account_id=current_user.account_id)
    if account_config.hydrate():
        params['account_config'] = account_config

    params['activity_logs'] = ActivityLogs().find_by([('member_id', current_user.member_id)], limit=20)

    return render_template('user/preferences.html', **params)

@blueprint.route('/security', methods=['GET'])
@login_required
def user_security():
    params = public_params()
    params['page_title'] = 'Security'
    params['page'] = 'security'
    params['js_includes'] = [
        "vendor/timeago.min.js",
        "utils.min.js",
        "api.min.js",
        "user/security.min.js"
    ]
    params['css_includes'] = [
        "user/scaffolding.css",
        "user/main.css",
        "user/security.css"
    ]
    params['account'] = current_user
    account_config = AccountConfig(account_id=current_user.account_id)
    if account_config.hydrate():
        params['account_config'] = account_config

    return render_template('user/security.html', **params)

@blueprint.route('/add-mfa', methods=['GET'])
@login_required
def user_add_mfa():
    params = public_params()
    params['page'] = 'security'
    params['page_title'] = 'Add MFA'
    params['js_includes'] = [
        "utils.min.js",
        "api.min.js",
        "user/add-mfa.min.js"
    ]
    params['css_includes'] = [
        "public/main.css",
        "public/confirmation.css",
        "user/add-mfa.css"
    ]
    params['account'] = current_user

    return render_template('user/add-mfa.html', **params)

@blueprint.route('/notifications', methods=['GET'])
@login_required
def user_notifications():
    params = public_params()
    params['page_title'] = 'Notifications'
    params['page'] = 'notifications'
    params['js_includes'] = [
        "utils.min.js",
        "api.min.js",
        "user/notifications.min.js"
    ]
    params['css_includes'] = [
        "vendor/choices.9.0.1.min.css",
        "user/scaffolding.css",
        "user/main.css",
        "user/notifications.css"
    ]
    params['account'] = current_user
    account_config = AccountConfig(account_id=current_user.account_id)
    if account_config.hydrate():
        params['account_config'] = account_config

    return render_template('user/notifications.html', **params)
