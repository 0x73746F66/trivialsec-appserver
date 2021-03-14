from random import random
from datetime import datetime
from flask import session, request, redirect, url_for, render_template, abort, jsonify, Blueprint, current_app as app
from flask_login import current_user, logout_user, login_user, login_required
from trivialsec.helpers import messages, oneway_hash, check_password_policy, check_email_rules, hash_password
from trivialsec.helpers.config import config
from trivialsec.helpers.log_manager import logger
from trivialsec.helpers.payments import create_customer
from trivialsec.helpers.sendgrid import send_email, upsert_contact
from trivialsec.decorators import control_timing_attacks, require_recaptcha
from trivialsec.models.apikey import ApiKey
from trivialsec.models.activity_log import ActivityLog
from trivialsec.models.account import Account
from trivialsec.models.member import Member
from trivialsec.models.invitation import Invitation
from trivialsec.models.plan import Plan
from trivialsec.models.subscriber import Subscriber
from trivialsec.services.accounts import register, generate_api_key_secret
from . import get_frontend_conf


blueprint = Blueprint('root', __name__)

@blueprint.route('/', methods=['GET'])
@login_required
def page_dashboard():
    return redirect(url_for('dashboard.page_dashboard'))

@blueprint.route('/campaign/<slug>', methods=['GET'])
@blueprint.route('/', methods=['GET'])
def landing(slug: str = None):
    params = get_frontend_conf()
    params['page'] = 'home'
    params['account'] = current_user
    if slug:
        session['slug'] = slug
        # check_link = Link(slug=params.get('slug'))
        # if check_link.exists(['slug']):
        #     check_link.hydrate('slug')
        # if check_link.expires > datetime.utcnow():
        #     params['link'] = check_link
        #     render_template('public/login.html', **params)
    redis_value = session.get('slug')
    if redis_value:
        params['slug'] = redis_value

    return render_template('public/landing.html', **params)

@control_timing_attacks(seconds=2)
@blueprint.route('/register', methods=['POST'])
@require_recaptcha(action='public_action')
def api_register():
    errors = []
    params = request.get_json()
    del params['recaptcha_token']
    try:
        logout_user()
    except Exception as ex:
        logger.warning(ex)

    if not params.get('privacy'):
        params['status'] = 'warning'
        params['message'] = 'Please accept the Terms of Service and Privacy Policy'
        return jsonify(params)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = "\n".join(errors)
        return jsonify(params)

    try:
        member = register(
            email_addr=params.get('email'),
            company=params.get('company', params.get('email'))
        )
        if not isinstance(member, Member):
            errors.append(messages.ERR_VALIDATION_EMAIL_RULES)
        else:
            plan = Plan(account_id=member.account_id)
            plan.hydrate('account_id')
            stripe_result = create_customer(member.email)
            plan.stripe_customer_id = stripe_result.get('id')
            plan.persist()
            confirmation_url = f"{config.get_app().get('app_url')}{member.confirmation_url}"
            send_email(
                subject="TrivialSec Confirmation",
                recipient=member.email,
                template='registrations',
                data={
                    "invitation_message": "Please click the Activation link below, or copy and paste it into a browser if you prefer.",
                    "activation_url": confirmation_url
                }
            )
            member.confirmation_sent = True
            member.persist()

    except Exception as err:
        logger.exception(err)
        params['error'] = str(err)
        errors.append(messages.ERR_ACCOUNT_UPDATE)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = "\n".join(errors)
    else:
        params['status'] = 'success'
        params['message'] = messages.OK_REGISTERED

    del params['password']
    del params['password2']

    return jsonify(params)

@control_timing_attacks(seconds=2)
@blueprint.route('/confirmation/<confirmation_hash>', methods=['GET'])
def confirmation_link(confirmation_hash: str):
    try:
        member = Member()
        member.confirmation_url = f'/confirmation/{confirmation_hash}'
        if member.exists(['confirmation_url']):
            member.hydrate()
            member.verified = True
            member.persist()

            return redirect(url_for('root.login'))
    except Exception as err:
        logger.error(err)

    return abort(403)

@control_timing_attacks(seconds=2)
@blueprint.route('/invitation/<confirmation_hash>', methods=['GET'])
def invitation(confirmation_hash: str):
    params = get_frontend_conf()
    params['page'] = 'invitation'
    params['page_title'] = 'Complete Invitation'

    invitee = Invitation()
    invitee.confirmation_url = f'/invitation/{confirmation_hash}'
    if invitee.exists(['confirmation_url']):
        invitee.hydrate()
        invitee_dict = {}
        for col in invitee.cols():
            invitee_dict[col] = getattr(invitee, col)

        params['invitee'] = invitee_dict
        return render_template('public/invitation.html', **params)
    return abort(403)

@control_timing_attacks(seconds=2)
@blueprint.route('/password-reset/<confirmation_hash>', methods=['GET'])
def password_reset(confirmation_hash: str):
    params = get_frontend_conf()
    params['page'] = 'password-reset'
    params['page_title'] = 'Password Reset'

    member = Member()
    member.confirmation_url = f'/password-reset/{confirmation_hash}'
    if member.exists(['confirmation_url']):
        member.hydrate()
        params['account'] = member
        return render_template('public/password-reset.html', **params)
    return abort(403)

@control_timing_attacks(seconds=2)
@blueprint.route('/login/<auth_hash>', methods=['GET'])
def login(auth_hash: str):
    member = Member(confirmation_url=auth_hash)
    if not member.hydrate('confirmation_url'):
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

@control_timing_attacks(seconds=2)
@blueprint.route('/login', methods=['POST'])
@require_recaptcha(action='public_action')
def login_post():
    params = request.get_json()
    del params['recaptcha_token']
    email_addr = params.get('email')
    member = Member(email=email_addr)
    member.hydrate('email')
    if member.member_id is None:
        logger.debug(f'No user for {email_addr}')
        params['status'] = 'error'
        params['message'] = messages.ERR_LOGIN_FAILED
        return jsonify(params)

    if not member.verified:
        logger.debug(f'unverified user {member.member_id}')
        params['status'] = 'error'
        params['message'] = messages.ERR_MEMBER_VERIFICATION
        return jsonify(params)

    res = check_email_rules(email_addr)
    if not res:
        params['status'] = 'error'
        params['message'] = messages.ERR_VALIDATION_EMAIL_RULES
        return jsonify(params)

    account = Account(account_id=member.account_id)
    if not account.hydrate():
        logger.debug(f'unverified user {member.member_id}')
        params['status'] = 'error'
        params['message'] = messages.ERR_LOGIN_FAILED
        return jsonify(params)

    if request.headers.getlist("X-Forwarded-For"):
        remote_addr = '\t'.join(request.headers.getlist("X-Forwarded-For"))
    else:
        remote_addr = request.remote_addr

    member.confirmation_url = oneway_hash(f'{random()}{remote_addr}')
    member.persist()
    magic_link = f"{config.get_app().get('app_url')}/login/{member.confirmation_url}"
    send_email(
        subject="TrivialSec Magic Link",
        recipient=member.email,
        template='magic-link',
        data={
            "magic_link": magic_link
        }
    )
    ActivityLog(
        member_id=member.member_id,
        action=ActivityLog.ACTION_USER_LOGIN,
        description=f'{remote_addr}\t{request.user_agent}'
    ).persist()
    params['status'] = 'success'
    params['message'] = messages.OK_MAGIC_LINK_SENT

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
    return redirect(url_for('.landing'))

@control_timing_attacks(seconds=2)
@blueprint.route('/subscribe', methods=['POST'])
@require_recaptcha(action='subscribe_action')
def api_subscribe():
    exists, saved = (False, False)
    error = None
    params = request.get_json()
    del params['recaptcha_token']

    if 'email' not in params or not check_email_rules(params.get('email')):
        error = messages.ERR_VALIDATION_EMAIL_RULES

    if error is not None:
        params['status'] = 'error'
        params['message'] = error
        return jsonify(params)

    try:
        subscriber = Subscriber()
        subscriber.email = params['email']
        exists = subscriber.exists(['email'])
        if exists:
            old_subscriber = Subscriber(subscriber_id=subscriber.subscriber_id)
            old_subscriber.hydrate()
            subscriber.created_at = old_subscriber.created_at
        upsert_contact(recipient_email=subscriber.email)
        saved = subscriber.persist()
        if saved:
            send_email(
                subject="Subscribed to TrivialSec updates",
                recipient=subscriber.email,
                template='subscriptions',
                group='subscriptions',
                data=dict()
            )

    except Exception as err:
        logger.exception(err)
        params['status'] = 'error'
        params['error'] = str(err)
        params['message'] = messages.ERR_VALIDATION_EMAIL_RULES

    if exists or saved:
        params['status'] = 'success'
        params['message'] = messages.OK_SUBSCRIBED

    return jsonify(params)

@control_timing_attacks(seconds=2)
@blueprint.route('/confirm-password', methods=['POST'])
@require_recaptcha(action='invitation_action')
def api_invitation_confirm_password():
    errors = []
    params = request.get_json()
    del params['recaptcha_token']
    try:
        logout_user()
    except Exception as ex:
        logger.warning(ex)

    invitee = Invitation()
    invitee.confirmation_url = params['confirmation_url']
    if invitee.exists(['confirmation_url']):
        invitee.hydrate()
    else:
        return abort(403)

    if 'password1' not in params or 'password2' not in params:
        errors.append(messages.ERR_VALIDATION_PASSWORDS_MATCH)
    if params['password1'] != params['password2']:
        errors.append(messages.ERR_VALIDATION_PASSWORDS_MATCH)

    res = check_password_policy(params['password1'])
    if not res:
        errors.append(messages.ERR_VALIDATION_PASSWORD_POLICY)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = "\n".join(errors)
        return jsonify(params)

    try:
        member = register(
            account_id=invitee.account_id,
            role_id=invitee.role_id,
            email_addr=invitee.email,
            verified=True
        )
        if not isinstance(member, Member):
            errors.append(messages.ERR_ACCOUNT_UPDATE)

        invitee.member_id = member.member_id
        invitee.persist()
        login_user(member)
        if request.headers.getlist("X-Forwarded-For"):
            remote_addr = '\t'.join(request.headers.getlist("X-Forwarded-For"))
        else:
            remote_addr = request.remote_addr
        ActivityLog(
            member_id=member.member_id,
            action=ActivityLog.ACTION_USER_LOGIN,
            description=f'{remote_addr}\t{request.user_agent}'
        ).persist()

    except Exception as err:
        logger.error(err)
        params['error'] = str(err)
        errors.append(messages.ERR_ACCOUNT_UPDATE)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = "\n".join(errors)
    else:
        params['status'] = 'success'
        params['message'] = messages.OK_REGISTERED

    del params['password1']
    del params['password2']

    return jsonify(params)
