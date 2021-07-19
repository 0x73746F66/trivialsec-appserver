from datetime import datetime
from urllib.parse import urlencode
from flask import request, session, redirect, url_for, render_template, abort, jsonify, Blueprint, current_app as app
from flask_login import current_user, logout_user, login_user, login_required
from trivialsec.helpers import messages
from trivialsec.helpers.config import config
from gunicorn.glogging import logging
from pyotp import TOTP

from trivialsec.decorators import control_timing_attacks, require_recaptcha, prepared_json
from trivialsec.models.apikey import ApiKey
from trivialsec.models.activity_log import ActivityLog
from trivialsec.models.account import Account
from trivialsec.models.member import Member
from trivialsec.models.member_mfa import MemberMfa, MemberMfas
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

@control_timing_attacks(seconds=2)
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

@control_timing_attacks(seconds=2)
@blueprint.route('/login/<auth_hash>', methods=['GET'])
def login(auth_hash: str):
    params = public_params()
    params['page'] = 'login'
    params['page_title'] = 'Magic Link Login'
    params['auth_hash'] = auth_hash
    params['totp_message'] = messages.INFO_TOTP_GENERATION
    params['keys'] = []
    try:
        www = config.get_app().get('site_url')
        error401 = messages.ERR_ACCESS_DENIED
        member = Member(confirmation_url=f'/login/{auth_hash}')
        if not member.exists(['confirmation_url']):
            return redirect(f"{www}?{urlencode({'error': error401})}", code=401)

        member.hydrate()
        if not member.verified:
            logger.debug(f'unverified user {member.member_id}')
            return redirect(f"{www}?{urlencode({'error': error401})}", code=401)

        account = Account(account_id=member.account_id)
        if not account.hydrate():
            logger.debug(f'unverified user {member.member_id}')
            return redirect(f"{www}?{urlencode({'error': error401})}", code=401)

        u2f_keys = MemberMfas()
        for u2f_key in u2f_keys.find_by([('member_id', member.member_id), ('type', 'webauthn')], limit=1000):
            params['keys'].append({
                'name': u2f_key.name,
                'webauthn_id': u2f_key.webauthn_id,
                'webauthn_public_key': u2f_key.webauthn_public_key,
                'webauthn_challenge': u2f_key.webauthn_challenge,
            })

    except Exception as err:
        logger.exception(err)
        return redirect(f"{www}?{urlencode({'error': error401})}", code=401)

    return render_template('public/login.html', **params)

@control_timing_attacks(seconds=2)
@require_recaptcha(action='login_action')
@blueprint.route('/verify/totp', methods=['POST'])
@prepared_json
def api_mfa_totp(params):
    try:
        member = Member(confirmation_url=f"/login/{params.get('auth_hash')}")
        if not member.exists(['confirmation_url']):
            logger.info(f'user doesnt exist {member.confirmation_url}')
            return jsonify(params)

        member.hydrate()
        if not member.verified:
            logger.info(f'unverified user {member.member_id}')
            return jsonify(params)

        account = Account(account_id=member.account_id)
        if not account.hydrate():
            logger.info(f'unverified user {member.member_id}')
            return jsonify(params)

        mfa = MemberMfa()
        mfa.member_id = member.member_id
        mfa.type = 'totp'
        if not mfa.hydrate(['member_id', 'type']):
            params['message'] = messages.ERR_ORG_MEMBER
            return jsonify(params)

        if not mfa.active:
            logger.info(f'mfa isnt active member: {member.member_id} mfa: {mfa.mfa_id}')
            return jsonify(params)

        totp = TOTP(mfa.totp_code)
        if not totp.verify(int(params.get("totp_code"))):
            params['message'] = messages.ERR_VALIDATION_TOTP
            return jsonify(params)

        apikey = ApiKey(member_id=member.member_id, comment='public-api')
        if not apikey.exists(['member_id', 'comment']):
            logger.info(f'inactive public-api key for user {member.member_id}')
            return jsonify(params)
        apikey.hydrate()
        if request.headers.getlist("X-Forwarded-For"):
            remote_addr = '\t'.join(request.headers.getlist("X-Forwarded-For"))
        else:
            remote_addr = request.remote_addr

        ActivityLog(
            member_id=member.member_id,
            action=ActivityLog.ACTION_USER_LOGIN,
            description=f'{remote_addr}\t{request.user_agent}'
        ).persist()
        login_user(member)
        session.permanent = True # pylint: disable=assigning-non-slot
        session.session_start = datetime.utcnow().isoformat() # pylint: disable=assigning-non-slot
        apikey.active = True
        apikey.api_key_secret = generate_api_key_secret()
        apikey.persist()
        params['hawk_key'] = apikey.api_key_secret
        params['status'] = 'success'
        params['message'] = messages.OK_AUTHENTICATED
        params['redirect'] = url_for('dashboard.page_dashboard')

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)

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

@blueprint.route('/recovery', methods=['GET'])
def recovery_reset(confirmation_hash: str):
    params = public_params()
    params['page'] = 'recovery'
    params['page_title'] = 'Recovery'

    member = Member()
    member.confirmation_url = f'/recovery/{confirmation_hash}'
    if member.exists(['confirmation_url']):
        member.hydrate()
        params['account'] = member
        return render_template('public/recovery.html', **params)
    return abort(403)
