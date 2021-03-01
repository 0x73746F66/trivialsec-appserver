import json
from datetime import date
from flask import send_from_directory, request, abort, current_app as app
from flask_login import LoginManager, current_user
from trivialsec.models.member import Member
from trivialsec.models.account import Account
from trivialsec.models.plan import Plan
from trivialsec.models.apikey import ApiKey
from trivialsec.helpers.config import config
from trivialsec.services.roles import is_internal_member, is_audit_member, is_billing_member, is_owner_member, is_support_member, is_readonly_member


def get_frontend_conf() -> dict:
    conf = {
        'app_version': config.app_version,
        'recaptcha_site_key': config.recaptcha_site_key,
        'public_bucket': config.aws.get('public_bucket'),
        'public_object_prefix': config.aws.get('public_object_prefix'),
        'stripe_publishable_key': config.stripe_publishable_key,
        'year': date.today().year,
        'roles': {
            'is_internal_member': is_internal_member(current_user),
            'is_support_member': is_support_member(current_user),
            'is_billing_member': is_billing_member(current_user),
            'is_audit_member': is_audit_member(current_user),
            'is_owner_member': is_owner_member(current_user),
            'is_readonly_member': is_readonly_member(current_user),
        }
    }
    return {**conf, **config.get_app()}
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
login_manager.login_view = 'root.login'

@login_manager.user_loader
def load_user(user_id: int) -> Member:
    if request.path in ['/faq', '/login', '/logout', '/register']:
        return None
    member = Member(member_id=user_id)
    member.hydrate(ttl_seconds=30)
    if not isinstance(member, Member):
        return abort(401)
    member.get_roles()
    apikey = ApiKey(member_id=member.member_id, comment='public-api')
    apikey.hydrate(['member_id', 'comment'], ttl_seconds=10)
    if apikey.api_key_secret is None or apikey.active is not True:
        return abort(401)
    account = Account(account_id=member.account_id)
    account.hydrate(ttl_seconds=30)
    if not isinstance(account, Account):
        return abort(401)
    plan = Plan(account_id=account.account_id)
    plan.hydrate('account_id', ttl_seconds=30)
    if not isinstance(plan, Plan):
        return abort(401)
    setattr(account, 'plan', plan)
    setattr(member, 'account', account)
    setattr(member, 'apikey', apikey)

    return member
