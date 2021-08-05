from flask import render_template, Blueprint, redirect, url_for
from flask_login import current_user, login_required
from trivialsec.models.account_config import AccountConfig
from trivialsec.models.activity_log import ActivityLogs
from trivialsec.models.finding import Findings
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
    params['activity_logs'] = ActivityLogs().find_by([('member_id', current_user.member_id)], limit=20)
    params['assigned_issues'] = Findings().count([('assignee_id', current_user.member_id), ('state', 'ACTIVE'), ('verification_state', 'UNKNOWN')])
    params['watched_issues'] = len(Findings().get_watched_findings(member_id=current_user.member_id))
    params['triage_issues'] = Findings().count([('assignee_id', current_user.member_id), ('state', 'ACTIVE'), ('verification_state', ['BENIGN_POSITIVE', 'FALSE_POSITIVE', 'TRUE_POSITIVE'])])
    params['resolved_issues'] = Findings().count([('assignee_id', current_user.member_id), ('state', 'RESOLVED'), ('verification_state', ['BENIGN_POSITIVE', 'FALSE_POSITIVE', 'TRUE_POSITIVE'])])

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

    return render_template('user/notifications.html', **params)

@blueprint.route('/apikeys', methods=['GET'])
@login_required
def user_apikeys():
    params = public_params()
    params['page_title'] = 'Api Keys'
    params['page'] = 'apikeys'
    params['js_includes'] = [
        "utils.min.js",
        "api.min.js",
        "user/apikeys.min.js"
    ]
    params['css_includes'] = [
        "vendor/choices.9.0.1.min.css",
        "user/scaffolding.css",
        "user/main.css",
        "user/apikeys.css"
    ]
    params['account'] = current_user

    return render_template('user/apikeys.html', **params)

@blueprint.route('/asssigned-issues', methods=['GET'])
@login_required
def page_asssigned_issues():
    params = public_params()
    params['page_title'] = 'My Issues'
    params['page'] = 'triage'
    params['account'] = current_user
    params['js_includes'] = [
        "utils.min.js",
        "api.min.js",
        "app/triage-unknown.min.js"
    ]
    params['css_includes'] = [
        "app/main.css",
        "app/triage-unknown.css"
    ]
    findings = Findings().find_by([('assignee_id', current_user.member_id), ('state', 'ACTIVE'), ('verification_state', 'UNKNOWN')], limit=10).load_details()
    params['triage_issues'] = sorted(findings, key=lambda k: k.severity_normalized, reverse=True) 

    return render_template('user/asssigned-issues.html', **params)

@blueprint.route('/watched-issues', methods=['GET'])
@login_required
def page_watched_issues():
    params = public_params()
    params['page_title'] = 'Watching'
    params['page'] = 'triage'
    params['account'] = current_user
    params['js_includes'] = [
        "utils.min.js",
        "api.min.js",
        "app/triage-unknown.min.js"
    ]
    params['css_includes'] = [
        "app/main.css",
        "app/triage-unknown.css"
    ]
    findings = Findings().get_watched_findings(member_id=current_user.member_id, limit=10).load_details()
    params['watched_issues'] = sorted(findings, key=lambda k: k.severity_normalized, reverse=True) 

    return render_template('user/watched-issues.html', **params)
