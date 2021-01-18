from datetime import datetime
from flask import session, request, redirect, url_for, render_template, abort, jsonify, Blueprint
from flask_login import current_user, logout_user, login_user
from trivialsec.helpers import messages, check_password_policy
from trivialsec.helpers.config import config
from trivialsec.helpers.log_manager import logger
from trivialsec.helpers.payments import create_customer
from trivialsec.helpers.sendgrid import send_email
from trivialsec.decorators import control_timing_attacks, require_recaptcha
from trivialsec.models import ApiKey, ActivityLog, KeyValues, Account, Member, Invitation, Plan
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
            alias=params.get('alias'),
            selected_plan={
                'name': 'Starter',
                'cost': '2.99',
                'currency': 'AUD',
                'active_daily': 1,
                'scheduled_active_daily': 0,
                'passive_daily': 10,
                'scheduled_passive_daily': 0,
                'git_integration_daily': 0,
                'source_code_daily': 0,
                'dependency_support_rating': 0,
                'alert_email': False,
                'alert_integrations': False,
                'threatintel': True,
                'compromise_indicators': False,
                'typosquatting': False
            }
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
        params['status'] = 'error'
        params['message'] = messages.ERR_LOGIN_FAILED
        return jsonify(params)

    apikey = ApiKey(member_id=member.member_id, comment='public-api')
    apikey.hydrate(['member_id', 'comment'])
    if apikey.api_key_secret is None or apikey.active is not True:
        params['status'] = 'error'
        params['message'] = messages.ERR_LOGIN_FAILED
        return jsonify(params)

    if not member.verified:
        params['status'] = 'error'
        params['message'] = messages.ERR_MEMBER_VERIFICATION
        return jsonify(params)

    account = Account(account_id=member.account_id)
    if not account.hydrate():
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
        api_key = current_user.apikey.api_key
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
        if api_key:
            apikey = ApiKey(api_key=api_key)
            apikey.hydrate()
            apikey.active = False
            apikey.persist()

    try:
        logout_user()
    except Exception:
        pass
    return redirect(url_for('.landing'))
