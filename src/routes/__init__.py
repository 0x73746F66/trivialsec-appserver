from gunicorn.glogging import logging
from flask import make_response, request, abort, redirect, current_app as app
from flask_login import LoginManager, current_user
from trivialsec.models.member import Member
from trivialsec.models.account import Account
from trivialsec.models.plan import Plan
from trivialsec.models.apikey import ApiKey
from trivialsec.helpers.config import config


logger = logging.getLogger(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
unauthenticated_paths = [
    '/confirmation',
    '/verify',
    '/login',
    '/logout',
    '/recovery',
]

@app.teardown_request
def teardown_request_func(error: Exception = None):
    if error:
        logger.error(error)

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(config.get_app().get("site_url"), code=401)

@login_manager.user_loader
def load_user(user_id: int) -> Member:
    for unauthenticated_path in unauthenticated_paths:
        if request.path.startswith(unauthenticated_path):
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

@app.before_request
def before_request():
    if request.path in ['/', '/healthcheck']:
        return make_response(), 204

    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        response.headers.add("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        response.headers.add('Access-Control-Allow-Origin', config.get_app().get("app_url"))
        return response
    return None

@app.after_request
def after_request(response):
    if request.method in ["GET", "POST"]:
        allowed_origin_assets = config.get_app().get("asset_url")
        allowed_origin_api = config.get_app().get("api_url")
        allowed_origin_site = config.get_app().get("app_url")
        if hasattr(current_user, 'apikey'):
            allowed_origin_site = current_user.apikey.allowed_origin

        response.headers.add('Access-Control-Allow-Origin', allowed_origin_site)
        if request.method == "GET":
            response.headers.add('Content-Security-Policy', '; '.join([
                f"default-src 'self' {allowed_origin_assets}",
                "frame-src https://www.google.com https://recaptcha.google.com",
                "form-action 'none'",
                "frame-ancestors 'none'",
                f"connect-src 'self' {allowed_origin_api}",
                f"img-src 'self' data: {allowed_origin_assets}",
                f"script-src https://www.gstatic.com https://www.google.com {allowed_origin_assets}",
                f"font-src https://fonts.gstatic.com {allowed_origin_assets} {allowed_origin_site}",
                f"style-src https://fonts.googleapis.com {allowed_origin_assets} {allowed_origin_site}"
            ]))

    return response
