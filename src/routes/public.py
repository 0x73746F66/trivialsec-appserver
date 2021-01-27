from datetime import datetime
from flask import session, request, redirect, url_for, render_template, abort, jsonify, Blueprint, current_app as app
from flask_login import current_user, logout_user, login_user
from trivialsec.helpers import messages, oneway_hash, check_password_policy, check_email_rules, hash_password
from trivialsec.helpers.config import config
from trivialsec.helpers.log_manager import logger
from trivialsec.helpers.payments import create_customer
from trivialsec.helpers.sendgrid import send_email, upsert_contact
from trivialsec.decorators import control_timing_attacks, require_recaptcha
from trivialsec.models.apikey import ApiKey
from trivialsec.models.activity_log import ActivityLog
from trivialsec.models.key_value import KeyValues
from trivialsec.models.account import Account
from trivialsec.models.member import Member
from trivialsec.models.invitation import Invitation
from trivialsec.models.plan import Plan
from trivialsec.models.subscriber import Subscriber
from trivialsec.services.accounts import register, generate_api_key_secret
from trivialsec.services.member import handle_login
from . import get_frontend_conf


blueprint = Blueprint('public', __name__)

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
        #     render_template('public/login.html.j2', **params)
    redis_value = session.get('slug')
    if redis_value:
        params['slug'] = redis_value

    return render_template('public/landing.html.j2', **params)

@blueprint.route('/privacy', methods=['GET'])
def privacy():
    params = get_frontend_conf()
    params['page'] = 'privacy'
    params['page_title'] = 'Privacy Policy'
    params['account'] = current_user

    return render_template('public/privacy.html.j2', **params)

@blueprint.route('/faq', methods=['GET'])
def page_faq():
    params = get_frontend_conf()
    params['page'] = 'faq'
    params['page_title'] = 'FAQ'
    params['account'] = current_user

    for section in ['faq_general', 'faq_features', 'faq_security']:
        params[section] = []
        for faq in KeyValues().find_by([('type', section)], limit=50):
            if faq.hidden:
                continue
            if faq.active_date and faq.active_date > datetime.utcnow():
                continue
            params[section].append(faq)

    return render_template('public/faq.html.j2', **params)

@blueprint.route('/register', methods=['GET'])
def get_register():
    params = get_frontend_conf()
    params['page'] = 'register'
    params['page_title'] = 'Registration'
    params['account'] = current_user

    return render_template('public/register.html.j2', **params)

@control_timing_attacks(seconds=2)
@blueprint.route('/register', methods=['POST'])
@require_recaptcha(action='register_action')
def api_register():
    errors = []
    params = request.get_json()
    del params['recaptcha_token']
    try:
        logout_user()
    except Exception as ex:
        logger.warning(ex)

    if 'password' not in params or 'password2' not in params:
        errors.append(messages.ERR_VALIDATION_PASSWORDS_MATCH)
    if params['password'] != params['password2']:
        errors.append(messages.ERR_VALIDATION_PASSWORDS_MATCH)

    res = check_password_policy(params['password'])
    if not res:
        errors.append(messages.ERR_VALIDATION_PASSWORD_POLICY)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = "\n".join(errors)
        return jsonify(params)

    try:
        member = register(
            email_addr=params.get('email'),
            passwd=params.get('password'),
            alias=params.get('alias', params.get('email')),
            selected_plan={'name': 'Pending'}
        )
        if not isinstance(member, Member):
            errors.append(messages.ERR_VALIDATION_EMAIL_RULES)
        else:
            plan = Plan(account_id=member.account_id)
            plan.hydrate('account_id')
            stripe_result = create_customer(member.email)
            plan.stripe_customer_id = stripe_result.get('id')
            plan.persist()
            confirmation_url = f"{config.frontend.get('site_scheme')}{config.frontend.get('site_domain')}{member.confirmation_url}"
            send_email(
                subject="TrivialSec Confirmation",
                recipient=member.email,
                template='registrations',
                data={
                    "invitation_message": "Thank you for your interest in TrivialSec",
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

            return redirect(url_for('.login'))
    except Exception as err:
        logger.exception(err)

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
        return render_template('public/invitation.html.j2', **params)
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
        return render_template('public/password-reset.html.j2', **params)
    return abort(403)

@blueprint.route('/login', methods=['GET'])
def login():
    params = get_frontend_conf()
    params['page'] = 'login'
    params['page_title'] = 'Login'
    params['account'] = current_user

    return render_template('public/login.html.j2', **params)

@control_timing_attacks(seconds=2)
@blueprint.route('/login', methods=['POST'])
def login_post():
    params = request.get_json()
    if not isinstance(params.get('password'), str) or params.get('password').strip() == '':
        params['status'] = 'error'
        params['message'] = messages.ERR_LOGIN_FAILED
        return jsonify(params)

    member = handle_login(params.get('email'), params.get('password'))
    if not isinstance(member, Member):
        logger.debug(f'No user for {params.get("email")}')
        params['status'] = 'error'
        params['message'] = messages.ERR_LOGIN_FAILED
        return jsonify(params)

    apikey = ApiKey(member_id=member.member_id, comment='public-api')
    if not apikey.hydrate(['member_id', 'comment']):
        logger.debug(f'inactive public-api key for user {member.member_id}')
        params['status'] = 'error'
        params['message'] = messages.ERR_LOGIN_FAILED
        return jsonify(params)

    if not member.verified:
        logger.debug(f'unverified user {member.member_id}')
        params['status'] = 'error'
        params['message'] = messages.ERR_MEMBER_VERIFICATION
        return jsonify(params)

    account = Account(account_id=member.account_id)
    if not account.hydrate():
        logger.debug(f'unverified user {member.member_id}')
        params['status'] = 'error'
        params['message'] = messages.ERR_LOGIN_FAILED
        return jsonify(params)

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
    params['hmac_secret'] = apikey.api_key_secret
    params['is_setup'] = account.is_setup
    params['status'] = 'success'

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
@blueprint.route('/password-reset', methods=['POST'])
@require_recaptcha(action='login_action')
def api_password_reset():
    params = request.get_json()
    res = check_email_rules(params.get('email'))
    if res is not True:
        params['status'] = 'error'
        params['message'] = messages.ERR_VALIDATION_EMAIL_RULES
        return jsonify(params)

    check_member = Member(email=params.get('email'))
    check_member.hydrate('email')
    if check_member.exists(['email']) is not True:
        params['status'] = 'error'
        params['message'] = messages.ERR_PASSWORD_RESET_SENT
        return jsonify(params)

    check_member.verified = False
    check_member.confirmation_sent = False
    check_member.confirmation_url = f"/password-reset/{oneway_hash(params.get('email'))}"
    check_member.persist()

    confirmation_url = f"{config.frontend.get('site_scheme')}{config.frontend.get('site_domain')}{check_member.confirmation_url}"
    send_email(
        subject="TrivialSec - password reset request",
        recipient=check_member.email,
        template='reset_password',
        data={
            "activation_url": confirmation_url
        }
    )
    check_member.confirmation_sent = True
    res = check_member.persist()
    if res is not True:
        params['status'] = 'error'
        params['message'] = messages.ERR_PASSWORD_RESET_SENT
        return jsonify(params)

    if request.headers.getlist("X-Forwarded-For"):
        remote_addr = '\t'.join(request.headers.getlist("X-Forwarded-For"))
    else:
        remote_addr = request.remote_addr
    ActivityLog(
        member_id=check_member.member_id,
        action=ActivityLog.ACTION_USER_RESET_PASSWORD_REQUEST,
        description=f'{remote_addr}\t{request.user_agent}'
    ).persist()
    params['status'] = 'info'
    params['message'] = messages.OK_PASSWORD_RESET_SENT

    return jsonify(params)

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
            passwd=params.get('password1'),
            verified=True,
            selected_plan={'name': 'Pending'}
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
        logger.exception(err)
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

@control_timing_attacks(seconds=2)
@blueprint.route('/change-password', methods=['POST'])
@require_recaptcha(action='password_reset_action')
def api_change_password():
    errors = []
    params = request.get_json()
    del params['recaptcha_token']
    try:
        logout_user()
    except Exception as ex:
        logger.warning(ex)

    check_member = Member()
    check_member.confirmation_url = params['confirmation_url']
    if check_member.exists(['confirmation_url']):
        check_member.hydrate()
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
        check_member.password = hash_password(params['password1'])
        check_member.verified = True
        res = check_member.persist()
        if not res:
            errors.append(messages.ERR_ACCOUNT_UPDATE)
            params['status'] = 'error'
            params['message'] = "\n".join(errors)
            return jsonify(params)

        login_user(check_member)
        if request.headers.getlist("X-Forwarded-For"):
            remote_addr = '\t'.join(request.headers.getlist("X-Forwarded-For"))
        else:
            remote_addr = request.remote_addr
        ActivityLog(
            member_id=check_member.member_id,
            action=ActivityLog.ACTION_USER_CHANGED_PASSWORD,
            description=f'{remote_addr}\t{request.user_agent}'
        ).persist()
    except Exception as err:
        logger.exception(err)
        params['error'] = str(err)
        errors.append(messages.ERR_ACCOUNT_UPDATE)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = "\n".join(errors)
    else:
        params['status'] = 'success'
        params['message'] = messages.OK_PASSWORD_RESET

    del params['password1']
    del params['password2']

    return jsonify(params)
