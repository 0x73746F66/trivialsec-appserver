from datetime import datetime
from gunicorn.glogging import logging
from flask import Response, request, redirect, current_app as app
from flask_login import LoginManager, current_user
from trivialsec.models.member import Member
from trivialsec.models.member_mfa import MemberMfa, MemberMfas
from trivialsec.models.account import Account
from trivialsec.models.plan import Plan
from trivialsec.models.apikey import ApiKey
from trivialsec.helpers.config import config


logger = logging.getLogger(__name__)
login_manager = LoginManager()
login_manager.init_app(app)

@app.teardown_request
def teardown_request_func(error: Exception = None):
    if error:
        logger.error(error)

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(config.get_app().get("site_url"), code=401)

@login_manager.user_loader
def load_user(user_id: int) -> Member:
    for unauthenticated_path in config.public_endpoints:
        if request.path.startswith(unauthenticated_path):
            return None
    resp_401 = Response(None, 401)
    member = Member(member_id=user_id)
    member.hydrate(ttl_seconds=30)
    if not isinstance(member, Member):
        return resp_401
    member.get_roles()
    apikey = ApiKey(member_id=member.member_id, comment='public-api')
    apikey.hydrate(['member_id', 'comment'], ttl_seconds=10)
    if apikey.api_key_secret is None or apikey.active is not True:
        return resp_401
    account = Account(account_id=member.account_id)
    account.hydrate(ttl_seconds=30)
    if not isinstance(account, Account):
        return resp_401
    plan = Plan(account_id=account.account_id)
    plan.hydrate('account_id', ttl_seconds=30)
    if not isinstance(plan, Plan):
        return resp_401

    totp_mfa = MemberMfa()
    totp_mfa.member_id = member.member_id
    totp_mfa.type = 'totp'
    totp_mfa.active = True
    if totp_mfa.exists(['member_id', 'type', 'active']):
        totp_mfa.hydrate()
        setattr(member, 'totp_mfa_id', totp_mfa.mfa_id)

    u2f_keys = []
    index = 0
    for u2f_key in MemberMfas().find_by([('member_id', member.member_id), ('type', 'webauthn'), ('active', True)], limit=1000):
        index += 1
        u2f_keys.append({
            'mfa_id': u2f_key.mfa_id,
            'name': u2f_key.name or f'Key {index}',
            'webauthn_id': u2f_key.webauthn_id,
            'registered': u2f_key.created_at if not isinstance(u2f_key.created_at, datetime) else u2f_key.created_at.isoformat()
        })

    setattr(account, 'plan', plan)
    setattr(member, 'account', account)
    setattr(member, 'apikey', apikey)
    setattr(member, 'u2f_keys', u2f_keys)

    return member

@app.before_request
def before_request():
    if request.path in ['/', '/healthcheck']:
        return Response(None, 204)

    if request.method == "OPTIONS":
        return Response(None, 200, {
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
            'Access-Control-Allow-Origin': config.get_app().get("app_url")
        })
    return None

@app.after_request
def after_request(response):
    if request.method in ["GET", "POST"]:
        allowed_origin_socket = config.get_app().get("socket_url")
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
                f"connect-src 'self' {allowed_origin_api} {allowed_origin_socket}",
                f"img-src 'self' data: {allowed_origin_assets}",
                f"script-src https://www.gstatic.com https://www.google.com {allowed_origin_assets}",
                f"font-src https://fonts.gstatic.com {allowed_origin_assets} {allowed_origin_site}",
                f"style-src https://fonts.googleapis.com {allowed_origin_assets} {allowed_origin_site}"
            ]))

    return response
