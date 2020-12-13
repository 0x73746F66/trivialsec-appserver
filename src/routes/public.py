from datetime import datetime, timedelta
from flask import session, request, redirect, url_for, render_template, abort, Blueprint
from flask_login import current_user, logout_user, login_user
from trivialsec.helpers.log_manager import logger
from trivialsec.helpers.config import config
from trivialsec import models
from trivialsec import helpers
import actions


blueprint = Blueprint('public', __name__)

@blueprint.route('/campaign/<slug>', methods=['GET'])
@blueprint.route('/', methods=['GET'])
def landing(slug: str = None):
    params = actions.get_frontend_conf()
    params['page'] = 'home'
    params['account'] = current_user
    if slug:
        session['slug'] = slug
        # check_link = models.Link(slug=params.get('slug'))
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
    params = actions.get_frontend_conf()
    params['page'] = 'privacy'
    params['page_title'] = 'Privacy Policy'
    params['account'] = current_user

    return render_template('public/privacy.html.j2', **params)

@blueprint.route('/faq', methods=['GET'])
def page_faq():
    params = actions.get_frontend_conf()
    params['page'] = 'faq'
    params['page_title'] = 'FAQ'
    params['account'] = current_user

    for section in ['faq_general', 'faq_features', 'faq_security']:
        params[section] = []
        for faq in models.KeyValues().find_by([('type', section)], limit=50):
            if faq.hidden:
                continue
            if faq.active_date and faq.active_date > datetime.utcnow():
                continue
            params[section].append(faq)

    return render_template('public/faq.html.j2', **params)

@blueprint.route('/logout', methods=['GET'])
def logout():
    if hasattr(current_user, 'member_id'):
        member_id = current_user.member_id
        session_end = datetime.utcnow()
        session_start = datetime.utcnow()
        if 'session_start' in session:
            session_start = datetime.fromisoformat(session['session_start'])
        session_duration = session_end - session_start
        remainder_hours = int(session_duration.seconds / 60 / 60)
        remainder_minutes = int((session_duration.seconds - (60*60*remainder_hours))/60)
        remainder_seconds = (session_duration.seconds - (60*60*remainder_hours) - (60*remainder_minutes))
        models.ActivityLog(
            member_id=member_id,
            action=actions.ACTION_USER_LOGOUT,
            description=f'Session duration {session_duration.days}d {remainder_hours}h {remainder_minutes}m {remainder_seconds}s'
        ).persist()
    try:
        logout_user()
    except Exception:
        pass
    return redirect(url_for('.landing'))

@blueprint.route('/register', methods=['GET'])
def register():
    params = actions.get_frontend_conf()
    params['page'] = 'register'
    params['page_title'] = 'Registration'
    params['account'] = current_user

    return render_template('public/register.html.j2', **params)

@helpers.control_timing_attacks(seconds=2)
@blueprint.route('/confirmation/<confirmation_hash>', methods=['GET'])
def confirmation_link(confirmation_hash: str):
    try:
        member = models.Member()
        member.confirmation_url = f'/confirmation/{confirmation_hash}'
        if member.exists(['confirmation_url']):
            member.hydrate()
            member.verified = True
            member.persist()
            login_user(member)
            if request.headers.getlist("X-Forwarded-For"):
                remote_addr = '\t'.join(request.headers.getlist("X-Forwarded-For"))
            else:
                remote_addr = request.remote_addr
            models.ActivityLog(
                member_id=member.member_id,
                action=actions.ACTION_USER_LOGIN,
                description=f'{remote_addr}\t{request.user_agent}'
            ).persist()
            account = models.Account(account_id=member.account_id)
            account.hydrate()
            if account.is_setup:
                return redirect(url_for('app.dashboard'))
            return redirect(url_for('account.account_setup', step=1))
    except Exception as err:
        logger.exception(err)

    return abort(403)

@helpers.control_timing_attacks(seconds=2)
@blueprint.route('/invitation/<confirmation_hash>', methods=['GET'])
def invitation(confirmation_hash: str):
    params = actions.get_frontend_conf()
    params['page'] = 'invitation'
    params['page_title'] = 'Complete Invitation'

    invitee = models.Invitation()
    invitee.confirmation_url = f'/invitation/{confirmation_hash}'
    if invitee.exists(['confirmation_url']):
        invitee.hydrate()
        invitee_dict = {}
        for col in invitee.cols():
            invitee_dict[col] = getattr(invitee, col)

        params['invitee'] = invitee_dict
        return render_template('public/invitation.html.j2', **params)
    return abort(403)

@helpers.control_timing_attacks(seconds=2)
@blueprint.route('/password-reset/<confirmation_hash>', methods=['GET'])
def password_reset(confirmation_hash: str):
    params = actions.get_frontend_conf()
    params['page'] = 'password-reset'
    params['page_title'] = 'Password Reset'

    member = models.Member()
    member.confirmation_url = f'/password-reset/{confirmation_hash}'
    if member.exists(['confirmation_url']):
        member.hydrate()
        params['account'] = member
        return render_template('public/password-reset.html.j2', **params)
    return abort(403)

@helpers.control_timing_attacks(seconds=2)
@blueprint.route('/login', methods=['POST'])
def login_post():
    params = actions.get_frontend_conf()
    params['page'] = 'login'
    params['page_title'] = 'Login'
    params['account'] = current_user
    body = actions.request_body()
    params = {**params, **body}
    if not isinstance(params.get('password'), str) or params.get('password').strip() == '':
        params['error'] = actions.app_messages.ERR_LOGIN_FAILED
        return render_template('public/login.html.j2', **params)

    member = actions.handle_login(params.get('email'), params.get('password'))
    if not isinstance(member, models.Member):
        params['error'] = actions.app_messages.ERR_LOGIN_FAILED
        return render_template('public/login.html.j2', **params)

    if not member.verified:
        params['error'] = actions.app_messages.ERR_MEMBER_VERIFICATION
        return render_template('public/login.html.j2', **params)

    login_user(member)
    if request.headers.getlist("X-Forwarded-For"):
        remote_addr = '\t'.join(request.headers.getlist("X-Forwarded-For"))
    else:
        remote_addr = request.remote_addr
    models.ActivityLog(
        member_id=member.member_id,
        action=actions.ACTION_USER_LOGIN,
        description=f'{remote_addr}\t{request.user_agent}'
    ).persist()
    session.permanent = True
    session['session_start'] = datetime.utcnow().isoformat()
    account = models.Account(account_id=member.account_id)
    if not account.hydrate():
        params['error'] = actions.app_messages.ERR_LOGIN_FAILED
        return render_template('public/login.html.j2', **params)

    if account.is_setup is True:
        return redirect(url_for('app.dashboard'))

    return redirect(url_for('account.account_setup', step=1))

@blueprint.route('/login', methods=['GET'])
def login():
    params = actions.get_frontend_conf()
    params['page'] = 'login'
    params['page_title'] = 'Login'
    params['account'] = current_user

    return render_template('public/login.html.j2', **params)
