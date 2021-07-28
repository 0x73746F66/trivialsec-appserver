from datetime import datetime
from urllib.parse import urlencode
from flask import request, session, redirect, url_for, render_template, abort, jsonify, Blueprint, current_app as app
from flask_login import current_user, logout_user, login_user, login_required
from trivialsec.helpers import messages
from trivialsec.helpers.config import config
from gunicorn.glogging import logging
from pyotp import TOTP
import webauthn

from trivialsec.helpers.sendgrid import send_email, upsert_contact
from trivialsec.decorators import control_timing_attacks, require_recaptcha, prepared_json
from trivialsec.models.apikey import ApiKey
from trivialsec.models.activity_log import ActivityLog
from trivialsec.models.account import Account
from trivialsec.models.member import Member
from trivialsec.models.member_mfa import MemberMfa, MemberMfas
from trivialsec.models.invitation import Invitation
from trivialsec.models.role import Role
from trivialsec.services.accounts import generate_api_key, generate_api_key_secret
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
def confirmation_link(confirmation_hash :str):
    params = public_params()
    params['page'] = 'confirmation'
    params['page_title'] = 'Complete Registration'
    params['confirmation_hash'] = confirmation_hash
    try:
        confirmation_url = f'/confirmation/{confirmation_hash}'
        member = Member()
        member.confirmation_url = confirmation_url
        member.exists(['confirmation_url'])
        invitee = Invitation()
        invitee.confirmation_url = confirmation_url
        if invitee.exists(['confirmation_url']):
            invitee.hydrate()
            member.member_id = invitee.member_id
            if invitee.member_id is None:
                member.account_id = invitee.account_id
                member.email = invitee.email
                member.verified = True # emailed confirmation_hash verifies email access
                member.persist()
                member.add_role(Role(role_id=invitee.role_id))
                member.get_roles()
                upsert_contact(recipient_email=member.email, list_name='members')
                #TODO Welcome Email
                invitee.member_id = member.member_id
                invitee.persist()
                ApiKey(
                    api_key=generate_api_key(),
                    api_key_secret=generate_api_key_secret(),
                    member_id=member.member_id,
                    comment='public-api',
                    active=True
                ).persist()

        if member.member_id:
            member.hydrate()
            params['account'] = member
            params['apikey'] = get_public_api_key(member.member_id)
            return render_template('public/confirmation.html', **params)

    except Exception as err:
        logger.exception(err)

    return abort(403)

@control_timing_attacks(seconds=2)
@blueprint.route('/verify/<verify_hash>', methods=['GET'])
def verify_link(verify_hash :str):
    try:
        verify_url = f'/verify/{verify_hash}'
        member = Member()
        member.confirmation_url = verify_url
        member.exists(['confirmation_url'])
        if member.member_id is None:
            raise ValueError(f'no verify_url {verify_url}')
        member.hydrate()
        member.confirmation_url = None
        member.verified = True
        member.persist()
        login_user(member)
        return redirect(url_for('dashboard.page_dashboard'))

    except Exception as err:
        logger.exception(err)

    return abort(403)

@control_timing_attacks(seconds=2)
@blueprint.route('/login/<auth_hash>', methods=['GET'])
def login(auth_hash :str):
    params = public_params()
    params['page'] = 'login'
    params['page_title'] = 'Magic Link Login'
    params['auth_hash'] = auth_hash
    params['totp_message'] = messages.INFO_TOTP_GENERATION
    params['u2f_keys'] = []
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
        index = 0
        for u2f_key in u2f_keys.find_by([('member_id', member.member_id), ('type', 'webauthn'), ('active', True)], limit=1000):
            index += 1
            params['u2f_keys'].append({
                'name': u2f_key.name or f'Key {index}',
                'webauthn_id': u2f_key.webauthn_id,
                'registered': u2f_key.created_at.isoformat()
            })
        params['account'] = member
        params['apikey'] = get_public_api_key(member.member_id)

    except Exception as err:
        logger.exception(err)
        return redirect(f"{www}?{urlencode({'error': error401})}", code=401)

    return render_template('public/login.html', **params)

@control_timing_attacks(seconds=2)
@require_recaptcha(action='login_action')
@blueprint.route('/verify/totp', methods=['POST'])
@prepared_json
def api_verify_totp(params):
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
        member.confirmation_url = None
        member.persist()
        params['api_key_secret'] = apikey.api_key_secret
        params['status'] = 'success'
        params['message'] = messages.OK_AUTHENTICATED

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)

@control_timing_attacks(seconds=2)
@require_recaptcha(action='login_action')
@blueprint.route('/verify/webauthn', methods=['POST'])
@prepared_json
def api_verify_webauthn(params):
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
        mfa.webauthn_id = params['assertion_response'].get('rawId')
        if not mfa.exists(['member_id', 'webauthn_id']):
            params['message'] = messages.ERR_ORG_MEMBER
            return jsonify(params)

        mfa.hydrate()
        if not mfa.active:
            logger.info(f'mfa isnt active member: {member.member_id} mfa: {mfa.mfa_id}')
            return jsonify(params)

        webauthn_user = webauthn.WebAuthnUser(
            user_id=member.email.encode('utf8'),
            username=member.email,
            display_name=member.email,
            icon_url=None,
            sign_count=0,
            credential_id=str(webauthn.webauthn._webauthn_b64_decode(mfa.webauthn_id)),
            public_key=mfa.webauthn_public_key,
            rp_id=config.get_app().get("app_domain")
        )
        webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
            webauthn_user,
            assertion_response=params['assertion_response'],
            challenge=mfa.webauthn_challenge,
            origin=config.get_app().get("app_url"),
            uv_required=False
        )
        webauthn_assertion_response.verify()

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
        member.confirmation_url = None
        member.persist()
        params['api_key_secret'] = apikey.api_key_secret
        params['status'] = 'success'
        params['message'] = messages.OK_AUTHENTICATED

    except Exception as err:
        logger.exception(err)
        if app.debug:
            params['error'] = str(err)

    return jsonify(params)

@control_timing_attacks(seconds=2)
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

@control_timing_attacks(seconds=2)
@blueprint.route('/recovery', methods=['GET'])
def account_recovery():
    params = public_params()
    params['page'] = 'recovery'
    params['page_title'] = 'Account Recovery'
    return render_template('public/recovery.html', **params)

@blueprint.route('/invitation-request/approve/<invitation_hash>', methods=['GET'])
@login_required
def account_recovery_accept(invitation_hash :str):
    params = public_params()
    params['page'] = 'recovery'
    params['page_title'] = 'Account Recovery'
    try:
        params['invitation_hash'] = invitation_hash
        invitee = Invitation()
        invitee.confirmation_url = f'/confirmation/{invitation_hash}'
        if not invitee.exists(['confirmation_url']):
            raise ValueError(messages.ERR_INVITATION_FAILED)
        invitee.hydrate()

        account = Account()
        account.account_id = current_user.account_id
        account.hydrate()

        invitee.invited_by_member_id = current_user.member_id
        invitee.message = f'Your account Owner {current_user.email} approved your Recovery Request'
        send_email(
            subject=f"Invitation to join TrivialSec organisation {account.alias}",
            recipient=invitee.email,
            template='invitations',
            data={
                "invitation_message": invitee.message,
                "activation_url": f"{config.get_app().get('app_url')}{invitee.confirmation_url}"
            }
        )
        invitee.confirmation_sent = True
        invitee.persist()
        ActivityLog(
            member_id=current_user.member_id,
            action=ActivityLog.ACTION_APPROVED_RECOVERY_REQUEST,
            description=invitee.email
        ).persist()
        params['approved'] = True
        params['status'] = 'success'
        params['message'] = messages.OK_INVITED

    except Exception as err:
        logger.exception(err)

    return render_template('public/recovery.html', **params)

@blueprint.route('/invitation-request/deny/<invitation_hash>', methods=['GET'])
@login_required
def account_recovery_deny(invitation_hash :str):
    params = public_params()
    params['page'] = 'recovery'
    params['page_title'] = 'Account Recovery'
    try:
        params['invitation_hash'] = invitation_hash
        invitee = Invitation()
        invitee.confirmation_url = f'/confirmation/{invitation_hash}'
        if not invitee.exists(['confirmation_url']):
            raise ValueError(messages.ERR_INVITATION_FAILED)
        invitee.hydrate()

        ActivityLog(
            member_id=current_user.member_id,
            action=ActivityLog.ACTION_DENY_RECOVERY_REQUEST,
            description=invitee.email
        ).persist()
        params['approved'] = False

    except Exception as err:
        logger.exception(err)

    return render_template('public/recovery.html', **params)
