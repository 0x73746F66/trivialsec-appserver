import json
from os import path
from flask import jsonify, send_from_directory, current_app as app
from flask_login import LoginManager
from trivialsec import models
from trivialsec.helpers.config import config


@app.teardown_request
def teardown_request_func(error: Exception = None):
    if error:
        print(error)

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(filename='favicon.ico', directory='/srv/app/static', mimetype='image/vnd.microsoft.icon')

@app.template_filter('autoversion')
def autoversion_filter(filename: str) -> str:
    return f"{filename}?v={config.app_version}"

@app.template_filter('from_json')
def reverse_filter(s):
    return json.loads(s)

@app.template_filter('http_code_group')
def http_code_group(s):
    if str(s).startswith('1'):
        return 'info'
    if str(s).startswith('2'):
        return 'success'
    if str(s).startswith('3'):
        return 'redirect'
    if str(s).startswith('4'):
        return 'error'
    if str(s).startswith('5'):
        return 'critical'
    return ''

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'public.login'

@login_manager.user_loader
def load_user(user_id: int) -> models.Member:
    member = models.Member(member_id=user_id)
    member.hydrate()
    member.get_roles()
    account = models.Account(account_id=member.account_id)
    account.hydrate()
    plan = models.Plan(plan_id=account.plan_id)
    plan.hydrate()
    setattr(account, 'plan', plan)
    setattr(member, 'account', account)

    return member
