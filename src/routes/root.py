from datetime import datetime
from flask import session, redirect, url_for, render_template, abort, Blueprint, current_app as app
from flask_login import current_user, logout_user, login_user, login_required
from trivialsec.helpers import messages
from trivialsec.helpers.config import config
from gunicorn.glogging import logging

from trivialsec.models.apikey import ApiKey
from trivialsec.models.activity_log import ActivityLog
from trivialsec.models.account import Account
from trivialsec.models.member import Member
from trivialsec.models.invitation import Invitation
from trivialsec.services.accounts import register, generate_api_key_secret
from trivialsec.services.apikey import get_public_api_key
from templates import public_params


logger = logging.getLogger(__name__)
blueprint = Blueprint('root', __name__)

@blueprint.route('/', methods=['GET'])
@login_required
def page_dashboard():
    return redirect(url_for('dashboard.page_dashboard'))

@blueprint.route('/confirmation/<confirmation_hash>', methods=['GET'])
def confirmation_link(confirmation_hash: str):
    params = public_params()
    params['page'] = 'confirmation'
    params['page_title'] = 'Complete Registration'
    params['confirmation_hash'] = confirmation_hash
    try:
        member = Member()
        invitee = Invitation()
        invitee.confirmation_url = f'/confirmation/{confirmation_hash}'
        if invitee.exists(['confirmation_url']):
            invitee.hydrate()
            if invitee.member_id is None:
                member = register(
                    account_id=invitee.account_id,
                    role_id=invitee.role_id,
                    email_addr=invitee.email,
                    verified=True # emailed confirmation_hash verifies email access
                )
                if not isinstance(member, Member):
                    raise ValueError(messages.ERR_ACCOUNT_UPDATE)
                invitee.member_id = member.member_id
                invitee.persist()

        member = Member()
        member.confirmation_url = f'/confirmation/{confirmation_hash}'
        if member.exists(['confirmation_url']):
            member.hydrate()
            params['account'] = member
            params['apikey'] = get_public_api_key(member.member_id)
            return render_template('public/confirmation.html', **params)

    except Exception as err:
        logger.error(err)

    return abort(403)

@blueprint.route('/recovery', methods=['GET'])
def password_reset(confirmation_hash: str):
    params = public_params()
    params['page'] = 'password-reset'
    params['page_title'] = 'Password Reset'

    member = Member()
    member.confirmation_url = f'/recovery/{confirmation_hash}'
    if member.exists(['confirmation_url']):
        member.hydrate()
        params['account'] = member
        return render_template('public/recovery.html', **params)
    return abort(403)

@blueprint.route('/login/<auth_hash>', methods=['GET'])
def login(auth_hash: str):
    member = Member(confirmation_url=f'/login/{auth_hash}')
    if not member.hydrate('confirmation_url'):
        return redirect(f'{config.get_app().get("site_url")}', code=401)
    if not member.verified:
        logger.debug(f'unverified user {member.member_id}')
        return redirect(f'{config.get_app().get("site_url")}', code=401)
    account = Account(account_id=member.account_id)
    if not account.hydrate():
        logger.debug(f'unverified user {member.member_id}')
        return redirect(f'{config.get_app().get("site_url")}', code=401)

    login_user(member)
    apikey = ApiKey(member_id=member.member_id, comment='public-api')
    if not apikey.hydrate(['member_id', 'comment']):
        logger.debug(f'inactive public-api key for user {member.member_id}')
        return redirect(f'{config.get_app().get("site_url")}', code=401)

    ActivityLog(
        member_id=member.member_id,
        action=ActivityLog.ACTION_USER_KEY_ROTATE,
        description=f'login action triggered {apikey.api_key} secret key rotation'
    ).persist()
    session.permanent = True
    session.session_start = datetime.utcnow().isoformat()
    apikey.active = True
    apikey.api_key_secret = generate_api_key_secret()
    apikey.persist()

    return render_template('app/login.html', hmac_secret=apikey.api_key_secret, is_setup=account.is_setup)

@blueprint.route('/logout', methods=['GET'])
def logout():
    if hasattr(current_user, 'member_id'):
        member_id = current_user.member_id
        if 'session_start' in session:
            session_end = datetime.utcnow()
            session_start = datetime.fromisoformat(session['session_start'])
            session_duration = session_end - session_start
            remainder_hours = int(session_duration.seconds / 60 / 60)
            remainder_minutes = int((session_duration.seconds - (60*60*remainder_hours))/60)
            remainder_seconds = (session_duration.seconds - (60*60*remainder_hours) - (60*remainder_minutes))
            ActivityLog(
                member_id=member_id,
                action=ActivityLog.ACTION_USER_LOGOUT,
                description=f'Session duration {session_duration.days}d {remainder_hours}h {remainder_minutes}m {remainder_seconds}s'
            ).persist()
        if isinstance(current_user.apikey, ApiKey):
            current_user.apikey.active = False
            current_user.apikey.persist()
        app.redis.delete(f'members/member_id/{member_id}')
        app.redis.delete(f'comment|public-api/member_id|{member_id}/table|api_keys')

    try:
        logout_user()
    except Exception:
        pass
    return redirect(config.get_app().get("site_url"))
