from flask import send_from_directory, make_response, request, abort, redirect, current_app as app
from flask_login import LoginManager, current_user
from trivialsec.models.member import Member
from trivialsec.models.account import Account
from trivialsec.models.plan import Plan
from trivialsec.models.apikey import ApiKey
from trivialsec.helpers.config import config


login_manager = LoginManager()
login_manager.init_app(app)

@app.teardown_request
def teardown_request_func(error: Exception = None):
    if error:
        print(error)

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(filename='favicon.ico', directory='/srv/app', path='/static', mimetype='image/vnd.microsoft.icon')

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(f'{config.get_app().get("site_url")}', code=401)

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

@app.before_request
def before_request():
    if request.path in ['/', '/healthcheck']:
        return make_response(), 204

    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        response.headers.add("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        if request.environ.get('HTTP_ORIGIN') == config.get_app().get("app_url"):
            response.headers.add('Access-Control-Allow-Origin', config.get_app().get("app_url"))
        if request.environ.get('HTTP_ORIGIN') == config.get_app().get("site_url"):
            response.headers.add('Access-Control-Allow-Origin', config.get_app().get("site_url"))
        return response
    return None

@app.after_request
def after_request(response):
    if request.method in ["GET", "POST"]:
        allowed_origin_assets = config.get_app().get("asset_url")
        allowed_origin_site = config.get_app().get("site_url")
        if request.environ.get('HTTP_ORIGIN') == config.get_app().get("app_url"):
            allowed_origin_site = config.get_app().get("app_url")
        elif request.environ.get('HTTP_ORIGIN') == config.get_app().get("site_url"):
            allowed_origin_site = config.get_app().get("site_url")
        if hasattr(current_user, 'apikey'):
            allowed_origin_site = current_user.apikey.allowed_origin

        response.headers.add('Access-Control-Allow-Origin', allowed_origin_site)
        if request.method == "GET":
            response.headers.add('Content-Security-Policy', '; '.join([
                f"default-src 'self' {allowed_origin_assets}",
                f"frame-src https://www.google.comsession_secret_key",
                "form-action 'none'",
                "frame-ancestors 'none'",
                f"manifest-src 'self' {allowed_origin_assets}",
                f"navigate-to 'self' {allowed_origin_site}",
                f"img-src {allowed_origin_assets}",
                f"media-src {allowed_origin_assets}",
                f"object-src {allowed_origin_assets}",
                f"script-src https://www.gstatic.com https://www.google.com {allowed_origin_assets}",
                f"font-src https://fonts.gstatic.com {allowed_origin_assets}",
                f"style-src https://fonts.googleapis.com {allowed_origin_assets}"
            ]))

    return response
