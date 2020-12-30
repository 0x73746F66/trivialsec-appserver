from datetime import datetime
from flask import Blueprint, jsonify, request, abort
from flask_login import current_user, login_required, logout_user, login_user
from trivialsec.helpers.config import config
from trivialsec.helpers.log_manager import logger
from trivialsec.helpers.payments import checkout, create_customer
from trivialsec import helpers, models
import actions


blueprint = Blueprint('api', __name__)
EOL = "\r\n"

@blueprint.route('/search/<model>', methods=['POST'])
@login_required
def api_search(model=None):
    params = request.get_json()
    data = {
        'message': 'cannot find results',
        'status': 'info',
        'id': None
    }
    if model == 'domain':
        domain = models.Domain(name=params['domain_name'], account_id=current_user.account_id)
        if domain.exists(['name', 'account_id']):
            data['id'] = domain.domain_id
            data['status'] = 'error'
            data['message'] = ''
    elif model == 'project':
        project = models.Project(name=params['project_name'], account_id=current_user.account_id)
        if project.exists(['name', 'account_id']):
            data['id'] = project.project_id
            data['status'] = 'error'
            data['message'] = ''

    return jsonify(data)

@blueprint.route('/domain-verify/<target>', methods=['GET'])
@login_required
def api_domain_verify(target):
    if not actions.check_domain_rules(target):
        return jsonify({
            'error': actions.app_messages.ERR_VALIDATION_DOMAIN_RULES,
            'registered': False,
            'result': False
        })
    http_metadata = helpers.HTTPMetadata(url=f'https://{target}').verification_check()
    models.ActivityLog(
        member_id=current_user.member_id,
        action=actions.ACTION_DOMAIN_VERIFICATION_CHECK,
        description=f'{target}'
    ).persist()
    return jsonify({
        'error': http_metadata.dns_answer,
        'registered': http_metadata.registered,
        'verification_hash': current_user.account.verification_hash,
        'result': bool(current_user.account.verification_hash == http_metadata.verification_hash)
    })

@blueprint.route('/domain-metadata', methods=['POST'])
@login_required
def api_domain_metadata():
    params = request.get_json()
    domain = models.Domain(domain_id=params['domain_id'], account_id=current_user.account_id)
    domain.hydrate(['domain_id', 'account_id'])
    project = models.Project(project_id=domain.project_id)
    if not project.hydrate():
        params['status'] = 'error'
        params['message'] = actions.app_messages.ERR_DOMAIN_METADATA_CHECK
        return jsonify(params)

    service_type = models.ServiceType(name='metadata')
    service_type.hydrate('name')
    actions.queue_job(
        tracking_id=params.get("project_tracking_id"),
        service_type=service_type,
        member=current_user,
        project=project,
        priority=2,
        params={'target': domain.name}
    )
    models.ActivityLog(
        member_id=current_user.member_id,
        action=actions.ACTION_DOMAIN_METADATA_CHECK,
        description=f'{domain.name}'
    ).persist()

    return jsonify({
        'status': 'success',
        'message': actions.app_messages.OK_DOMAIN_METADATA_CHECK
    })

@blueprint.route('/domain-dns', methods=['POST'])
@login_required
def api_domain_dns():
    params = request.get_json()
    domain = models.Domain(domain_id=params['domain_id'], account_id=current_user.account_id)
    domain.hydrate(['domain_id', 'account_id'])
    project = models.Project(project_id=domain.project_id)
    if not project.hydrate():
        params['status'] = 'error'
        params['message'] = actions.app_messages.ERR_ACCESS_DENIED
        return jsonify(params)

    service_type = models.ServiceType(name='drill')
    service_type.hydrate('name')
    actions.queue_job(
        tracking_id=params.get("project_tracking_id"),
        service_type=service_type,
        member=current_user,
        project=project,
        priority=2,
        params={'target': domain.name}
    )
    models.ActivityLog(
        member_id=current_user.member_id,
        action=actions.ACTION_ON_DEMAND_SCAN,
        description=f'DNS {domain.name}'
    ).persist()

    return jsonify({
        'status': 'success',
        'message': actions.app_messages.OK_SCAN_DNS
    })

@blueprint.route('/domain-subdomains', methods=['POST'])
@login_required
def api_domain_subdomains():
    params = request.get_json()
    domain = models.Domain(domain_id=params['domain_id'], account_id=current_user.account_id)
    domain.hydrate(['domain_id', 'account_id'])
    project = models.Project(project_id=domain.project_id)
    if not project.hydrate():
        params['status'] = 'error'
        params['message'] = actions.app_messages.ERR_ACCESS_DENIED
        return jsonify(params)

    service_type = models.ServiceType(name='amass')
    service_type.hydrate('name')
    actions.queue_job(
        tracking_id=params.get("project_tracking_id"),
        service_type=service_type,
        member=current_user,
        project=project,
        priority=2,
        params={'target': domain.name}
    )
    models.ActivityLog(
        member_id=current_user.member_id,
        action=actions.ACTION_ON_DEMAND_SCAN,
        description=f'Subdomains {domain.name}'
    ).persist()

    return jsonify({
        'status': 'success',
        'message': actions.app_messages.OK_SCAN_SUBDOMAINS
    })

@blueprint.route('/domain-tls', methods=['POST'])
@login_required
def api_domain_tls():
    params = request.get_json()
    domain = models.Domain(domain_id=params['domain_id'], account_id=current_user.account_id)
    domain.hydrate(['domain_id', 'account_id'])
    project = models.Project(project_id=domain.project_id)
    if not project.hydrate():
        params['status'] = 'error'
        params['message'] = actions.app_messages.ERR_ACCESS_DENIED
        return jsonify(params)

    scan_type = 'passive'
    domain.get_stats()
    if hasattr(domain, 'http_last_checked'):
        http_last_checked = datetime.fromisoformat(getattr(domain, 'http_last_checked')).replace(microsecond=0)
        for domain_stat in domain.stats:
            created_at = datetime.fromisoformat(domain_stat.created_at)
            if created_at == http_last_checked and domain_stat.domain_stat == models.DomainStat.APP_VERIFIED and domain_stat.domain_value == '1':
                scan_type = 'active'
                break

    service_type = models.ServiceType(name='testssl')
    service_type.hydrate('name')
    actions.queue_job(
        tracking_id=params.get("project_tracking_id"),
        service_type=service_type,
        member=current_user,
        project=project,
        priority=2,
        params={'target': domain.name, 'scan_type': scan_type}
    )
    models.ActivityLog(
        member_id=current_user.member_id,
        action=actions.ACTION_ON_DEMAND_SCAN,
        description=f'TLS {domain.name}'
    ).persist()

    return jsonify({
        'status': 'success',
        'message': actions.app_messages.OK_SCAN_TLS
    })

@blueprint.route('/create-project', methods=['POST'])
@login_required
def api_create_project():
    errors = []
    params = request.get_json()

    project = models.Project(name=params.get('project_name'))
    project.account_id = current_user.account_id
    if project.exists(['name']):
        project.hydrate()
        project.deleted = False

    project.tracking_id = params.get('project_tracking_id')
    target = params.get('domain_name')
    if not actions.is_valid_ipv4_address(target) and not actions.is_valid_ipv6_address(target) and not actions.check_domain_rules(target):
        errors.append(f'{target} is an invalid target')
    else:
        project.persist()
        params['project_id'] = project.project_id
        if actions.is_valid_ipv4_address(target) or actions.is_valid_ipv6_address(target):
            knownip = models.KnownIp(ip_address=target)
            if not knownip.exists(['ip_address', 'project_id']):
                knownip.account_id = current_user.account.account_id
                knownip.project_id = project.project_id
                knownip.source = 'create_project'
                knownip.ip_version = 'ipv4' if actions.is_valid_ipv4_address(target) else 'ipv6'
                if knownip.persist():
                    models.ActivityLog(
                        member_id=current_user.member_id,
                        action=actions.ACTION_ADDED_IPADDRESS,
                        description=target
                    ).persist()

            knownip_dict = {}
            for col in knownip.cols():
                knownip_dict[col] = getattr(knownip, col)
            params['ip_address'] = knownip_dict
        if actions.check_domain_rules(target):
            domain = actions.handle_add_domain(domain_name=target, project=project)
            if not isinstance(domain, models.Domain):
                errors.append(actions.app_messages.ERR_DOMAIN_ADD)
            else:
                models.ActivityLog(
                    member_id=current_user.member_id,
                    action=actions.ACTION_ADDED_DOMAIN,
                    description=domain.name
                ).persist()
                domain_dict = {}
                for col in domain.cols():
                    domain_dict[col] = getattr(domain, col)
                params['domain'] = domain_dict

        metadata = models.ServiceType(name='metadata')
        metadata.hydrate('name')
        actions.queue_job(
            tracking_id=params.get('project_tracking_id'),
            service_type=metadata,
            priority=3,
            member=current_user,
            project=project,
            params={'target': domain.name}
        )
        amass = models.ServiceType(name='amass')
        amass.hydrate('name')
        actions.queue_job(
            tracking_id=params.get('project_tracking_id'),
            service_type=amass,
            priority=1,
            member=current_user,
            project=project,
            params={'target': domain.name}
        )
        drill = models.ServiceType(name='drill')
        drill.hydrate('name')
        actions.queue_job(
            tracking_id=params.get('project_tracking_id'),
            service_type=drill,
            priority=1,
            member=current_user,
            project=project,
            params={'target': domain.name}
        )

        scan_type = 'passive'
        domain.get_stats()
        if hasattr(domain, 'http_last_checked'):
            http_last_checked = datetime.fromisoformat(getattr(domain, 'http_last_checked')).replace(microsecond=0)
            for domain_stat in domain.stats:
                created_at = datetime.fromisoformat(domain_stat.created_at)
                if created_at == http_last_checked and domain_stat.domain_stat == models.DomainStat.APP_VERIFIED and domain_stat.domain_value == '1':
                    scan_type = 'active'
                    break

        testssl = models.ServiceType(name='testssl')
        testssl.hydrate('name')
        actions.queue_job(
            tracking_id=params.get('project_tracking_id'),
            service_type=testssl,
            priority=1,
            member=current_user,
            project=project,
            params={'target': domain.name, 'scan_type': scan_type}
        )

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = EOL.join(errors)
    else:
        params['status'] = 'success'
        params['message'] = actions.app_messages.OK_ADDED_DOMAIN

    return jsonify(params)

@helpers.control_timing_attacks(seconds=2)
@blueprint.route('/register', methods=['POST'])
@actions.require_recaptcha(action='register_action')
def api_register():
    errors = []
    params = request.get_json()
    del params['recaptcha_token']
    try:
        logout_user()
    except Exception as ex:
        logger.warning(ex)

    if 'password' not in params or 'password2' not in params:
        errors.append(actions.app_messages.ERR_VALIDATION_PASSWORDS_MATCH)
    if params['password'] != params['password2']:
        errors.append(actions.app_messages.ERR_VALIDATION_PASSWORDS_MATCH)

    res = actions.check_password_policy(params['password'])
    if not res:
        errors.append(actions.app_messages.ERR_VALIDATION_PASSWORD_POLICY)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = EOL.join(errors)
        return jsonify(params)

    try:
        member = actions.register_action(
            email=params.get('email'),
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
        if not isinstance(member, models.Member):
            errors.append(actions.app_messages.ERR_VALIDATION_EMAIL_RULES)
        else:
            plan = models.Plan(account_id=member.account_id)
            plan.hydrate('account_id')
            stripe_result = create_customer(member.email)
            plan.stripe_customer_id = stripe_result.get('id')
            plan.persist()
            confirmation_url = f"{config.frontend.get('site_scheme')}{config.frontend.get('site_domain')}{member.confirmation_url}"
            actions.email(
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
        errors.append(actions.app_messages.ERR_ACCOUNT_UPDATE)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = EOL.join(errors)
    else:
        params['status'] = 'success'
        params['message'] = actions.app_messages.OK_REGISTERED

    del params['password']
    del params['password2']

    return jsonify(params)

@helpers.control_timing_attacks(seconds=2)
@blueprint.route('/confirm-password', methods=['POST'])
@actions.require_recaptcha(action='invitation_action')
def api_confirm_password():
    errors = []
    params = request.get_json()
    del params['recaptcha_token']
    try:
        logout_user()
    except Exception as ex:
        logger.warning(ex)

    invitee = models.Invitation()
    invitee.confirmation_url = params['confirmation_url']
    if invitee.exists(['confirmation_url']):
        invitee.hydrate()
    else:
        return abort(403)

    if 'password1' not in params or 'password2' not in params:
        errors.append(actions.app_messages.ERR_VALIDATION_PASSWORDS_MATCH)
    if params['password1'] != params['password2']:
        errors.append(actions.app_messages.ERR_VALIDATION_PASSWORDS_MATCH)

    res = actions.check_password_policy(params['password1'])
    if not res:
        errors.append(actions.app_messages.ERR_VALIDATION_PASSWORD_POLICY)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = EOL.join(errors)
        return jsonify(params)

    try:
        member = actions.register_action(
            account_id=invitee.account_id,
            role_id=invitee.role_id,
            email=invitee.email,
            passwd=params.get('password1'),
            verified=True,
            selected_plan={
                'name': 'Pending',
                'cost': '0.00',
                'currency': 'AUD',
                'active_daily': 0,
                'scheduled_active_daily': 0,
                'passive_daily': 0,
                'scheduled_passive_daily': 0,
                'git_integration_daily': 0,
                'source_code_daily': 0,
                'dependency_support_rating': 0,
                'alert_email': False,
                'alert_integrations': False,
                'threatintel': False,
                'compromise_indicators': False,
                'typosquatting': False
            }
        )
        if not isinstance(member, models.Member):
            errors.append(actions.app_messages.ERR_ACCOUNT_UPDATE)

        invitee.member_id = member.member_id
        invitee.persist()
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

    except Exception as err:
        logger.exception(err)
        params['error'] = str(err)
        errors.append(actions.app_messages.ERR_ACCOUNT_UPDATE)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = EOL.join(errors)
    else:
        params['status'] = 'success'
        params['message'] = actions.app_messages.OK_REGISTERED

    del params['password1']
    del params['password2']

    return jsonify(params)

@helpers.control_timing_attacks(seconds=2)
@blueprint.route('/change-password', methods=['POST'])
@actions.require_recaptcha(action='password_reset_action')
def api_change_password():
    errors = []
    params = request.get_json()
    del params['recaptcha_token']
    try:
        logout_user()
    except Exception as ex:
        logger.warning(ex)

    check_member = models.Member()
    check_member.confirmation_url = params['confirmation_url']
    if check_member.exists(['confirmation_url']):
        check_member.hydrate()
    else:
        return abort(403)

    if 'password1' not in params or 'password2' not in params:
        errors.append(actions.app_messages.ERR_VALIDATION_PASSWORDS_MATCH)
    if params['password1'] != params['password2']:
        errors.append(actions.app_messages.ERR_VALIDATION_PASSWORDS_MATCH)

    res = actions.check_password_policy(params['password1'])
    if not res:
        errors.append(actions.app_messages.ERR_VALIDATION_PASSWORD_POLICY)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = EOL.join(errors)
        return jsonify(params)

    try:
        check_member.password = helpers.hash_password(params['password1'])
        check_member.verified = True
        res = check_member.persist()
        if not res:
            errors.append(actions.app_messages.ERR_ACCOUNT_UPDATE)
            params['status'] = 'error'
            params['message'] = EOL.join(errors)
            return jsonify(params)

        login_user(check_member)
        if request.headers.getlist("X-Forwarded-For"):
            remote_addr = '\t'.join(request.headers.getlist("X-Forwarded-For"))
        else:
            remote_addr = request.remote_addr
        models.ActivityLog(
            member_id=check_member.member_id,
            action=actions.ACTION_USER_CHANGED_PASSWORD,
            description=f'{remote_addr}\t{request.user_agent}'
        ).persist()
    except Exception as err:
        logger.exception(err)
        params['error'] = str(err)
        errors.append(actions.app_messages.ERR_ACCOUNT_UPDATE)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = EOL.join(errors)
    else:
        params['status'] = 'success'
        params['message'] = actions.app_messages.OK_PASSWORD_RESET

    del params['password1']
    del params['password2']

    return jsonify(params)

@blueprint.route('/update-email', methods=['POST'])
@login_required
def api_update_email():
    errors = []
    params = request.get_json()
    params['status'] = 'info'
    params['message'] = 'Email update not available at this time'

    check_member = models.Member(email=params.get('email'))
    if check_member.exists(['email']):
        errors.append(actions.app_messages.ERR_MEMBER_EXIST)

    if 'email' not in params or not actions.check_email_rules(params.get('email')):
        errors.append(actions.app_messages.ERR_VALIDATION_EMAIL_RULES)

    if not helpers.check_encrypted_password(params.get('password'), current_user.password):
        errors.append(actions.app_messages.ERR_VALIDATION_PASSWORD_POLICY)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = EOL.join(errors)
        return jsonify(params)

    current_user.email = params.get('email')
    current_user.verified = False
    current_user.confirmation_sent = False
    current_user.confirmation_url = f"/confirmation/{helpers.make_hash(params.get('email'))}"
    current_user.persist()
    confirmation_url = f"{config.frontend.get('site_scheme')}{config.frontend.get('site_domain')}{current_user.confirmation_url}"
    try:
        actions.email(
            subject="TrivialSec - email address updated",
            recipient=params.get('email'),
            template='updated_email',
            data={
                "activation_url": confirmation_url
            }
        )
        current_user.confirmation_sent = True
        if current_user.persist():
            if request.headers.getlist("X-Forwarded-For"):
                remote_addr = '\t'.join(request.headers.getlist("X-Forwarded-For"))
            else:
                remote_addr = request.remote_addr
            models.ActivityLog(
                member_id=current_user.member_id,
                action=actions.ACTION_USER_CHANGE_EMAIL_REQUEST,
                description=f'{remote_addr}\t{request.user_agent}'
            ).persist()
            params['status'] = 'success'
            params['message'] = actions.app_messages.OK_EMAIL_UPDATE
        return jsonify(params)

    except Exception as ex:
        logger.exception(ex)
        params['error'] = str(ex)
        errors.append(actions.app_messages.ERR_EMAIL_NOT_SENT)

    if len(errors) > 0:
        params['status'] = 'error'
        params['message'] = "\n".join(errors)

    return jsonify(params)

# @helpers.control_timing_attacks(seconds=2)
# @blueprint.route('/change-password', methods=['POST'])
# @login_required
# def api_change_password():
#     errors = []
#     params = request.get_json()

#     if not helpers.check_encrypted_password(params.get('old_password'), current_user.password):
#         errors.append(actions.app_messages.ERR_VALIDATION_WRONG_PASSWORD)
#     if params.get('new_password') != params.get('repeat_password'):
#         errors.append(actions.app_messages.ERR_VALIDATION_PASSWORDS_MATCH)
#     if not actions.check_password_policy(params.get('new_password')):
#         errors.append(actions.app_messages.ERR_VALIDATION_PASSWORD_POLICY)

#     if len(errors) > 0:
#         params['status'] = 'error'
#         params['message'] = EOL.join(errors)
#         return jsonify(params)

#     current_user.password = helpers.hash_password(params.get('new_password'))
#     if current_user.persist():
#         if request.headers.getlist("X-Forwarded-For"):
#             remote_addr = '\t'.join(request.headers.getlist("X-Forwarded-For"))
#         else:
#             remote_addr = request.remote_addr
#         models.ActivityLog(
#             member_id=current_user.member_id,
#             action=actions.ACTION_USER_CHANGED_PASSWORD,
#             description=f'{remote_addr}\t{request.user_agent}'
#         ).persist()
#         params['status'] = 'success'
#         params['message'] = actions.app_messages.OK_CHANGED_PASSWORD
#         return jsonify(params)

#     if len(errors) > 0:
#         params['status'] = 'error'
#         params['message'] = "\n".join(errors)

#     return jsonify(params)

@helpers.control_timing_attacks(seconds=2)
@blueprint.route('/password-reset', methods=['POST'])
@actions.require_recaptcha(action='login_action')
def api_password_reset():
    params = request.get_json()
    res = actions.check_email_rules(params.get('email'))
    if res is not True:
        params['status'] = 'error'
        params['message'] = actions.app_messages.ERR_VALIDATION_EMAIL_RULES
        return jsonify(params)

    check_member = models.Member(email=params.get('email'))
    check_member.hydrate('email')
    if check_member.exists(['email']) is not True:
        params['status'] = 'error'
        params['message'] = actions.app_messages.ERR_PASSWORD_RESET_SENT
        return jsonify(params)

    check_member.verified = False
    check_member.confirmation_sent = False
    check_member.confirmation_url = f"/password-reset/{helpers.make_hash(params.get('email'))}"
    check_member.persist()

    confirmation_url = f"{config.frontend.get('site_scheme')}{config.frontend.get('site_domain')}{check_member.confirmation_url}"
    actions.email(
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
        params['message'] = actions.app_messages.ERR_PASSWORD_RESET_SENT
        return jsonify(params)

    if request.headers.getlist("X-Forwarded-For"):
        remote_addr = '\t'.join(request.headers.getlist("X-Forwarded-For"))
    else:
        remote_addr = request.remote_addr
    models.ActivityLog(
        member_id=current_user.member_id,
        action=actions.ACTION_USER_RESET_PASSWORD_REQUEST,
        description=f'{remote_addr}\t{request.user_agent}'
    ).persist()
    params['status'] = 'info'
    params['message'] = actions.app_messages.OK_PASSWORD_RESET_SENT

    return jsonify(params)

@helpers.control_timing_attacks(seconds=2)
@blueprint.route('/subscribe', methods=['POST'])
@actions.require_recaptcha(action='subscribe_action')
def api_subscribe():
    exists, saved = (False, False)
    error = None
    params = request.get_json()
    del params['recaptcha_token']

    if 'email' not in params or not actions.check_email_rules(params.get('email')):
        error = actions.app_messages.ERR_VALIDATION_EMAIL_RULES

    if error is not None:
        params['status'] = 'error'
        params['message'] = error
        return jsonify(params)

    try:
        subscriber = models.Subscriber()
        subscriber.email = params['email']
        exists = subscriber.exists(['email'])
        if exists:
            old_subscriber = models.Subscriber(subscriber_id=subscriber.subscriber_id)
            old_subscriber.hydrate()
            subscriber.created_at = old_subscriber.created_at
        actions.upsert_contact(recipient_email=subscriber.email)
        saved = subscriber.persist()
        if saved:
            actions.email(
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
        params['message'] = actions.app_messages.ERR_VALIDATION_EMAIL_RULES

    if exists or saved:
        params['status'] = 'success'
        params['message'] = actions.app_messages.OK_SUBSCRIBED

    return jsonify(params)

@blueprint.route('/invitation', methods=['POST'])
@login_required
def api_invitation():
    params = request.get_json()
    error = None

    if 'invite_email' not in params or not actions.check_email_rules(params['invite_email']):
        error = actions.app_messages.ERR_VALIDATION_EMAIL_RULES

    if error is not None:
        params['status'] = 'error'
        params['message'] = error
        return jsonify(params)

    try:
        roles = models.Roles()
        params['role_name'] = None
        for role in roles.load():
            if role.role_id == int(params['invite_role_id']):
                params['role_name'] = role.name

        invitation = models.Invitation()
        invitation.account_id = current_user.account_id
        invitation.invited_by_member_id = current_user.member_id
        invitation.email = params['invite_email']
        invitation.role_id = params['invite_role_id']
        invitation.message = params.get('invite_message', 'Trivial Security monitors public threats and easy attack vectors so you don\'t have to spend your valuable time keeping up-to-date daily.')
        invitation.confirmation_url = f"/invitation/{helpers.make_hash(params['invite_email'])}"

        if invitation.exists(['email']) or not invitation.persist():
            params['status'] = 'error'
            params['message'] = actions.app_messages.ERR_INVITATION_FAILED
            return jsonify(params)

        params['confirmation_url'] = f"{config.frontend.get('site_scheme')}{config.frontend.get('site_domain')}{invitation.confirmation_url}"
        actions.email(
            subject=f"Invitation to join TrivialSec organisation {current_user.account.alias}",
            recipient=invitation.email,
            template='invitations',
            data={
                "invitation_message": invitation.message,
                "activation_url": params['confirmation_url']
            }
        )

        invitation.confirmation_sent = True
        invitation.persist()
        models.ActivityLog(
            member_id=current_user.member_id,
            action=actions.ACTION_USER_CREATED_INVITATION,
            description=invitation.email
        ).persist()
        params['status'] = 'success'
        params['message'] = actions.app_messages.OK_INVITED

    except Exception as err:
        logger.exception(err)
        params['status'] = 'error'
        params['message'] = actions.app_messages.ERR_INVITATION_FAILED
        return jsonify(params)

    params['status'] = 'success'
    return jsonify(params)

@blueprint.route('/account', methods=['POST'])
@login_required
def api_account():
    params = request.get_json()
    changes = []
    err = None
    messages = []
    protected = ['verification_hash', 'registered', 'socket_key', 'plan_id', 'account_id', 'password']
    params_keys = set()
    for param in params:
        if param.get('prop') in protected:
            continue
        if param.get('prop') == 'alias' and current_user.account.alias == param.get('value'):
            messages.append(f"{param.get('prop')} unchanged")
            continue
        if param.get('prop') == 'billing_email':
            password = [i['value'] for i in params if i['prop'] == 'password'][0] or None
            if password is None:
                err = 'password was not provided when changing the billing email'
                messages.append(err)
                break
            if not actions.check_password_policy(password) or not \
                helpers.check_encrypted_password(password, current_user.password):
                err = actions.app_messages.ERR_VALIDATION_PASSWORD_POLICY
                messages.append(err)
                break

        params_keys.add(param.get('prop'))
        from_value = getattr(current_user.account, param.get('prop'))
        setattr(current_user.account, param.get('prop'), param.get('value'))
        changes.append(f"{param.get('prop')} from {from_value} to {param.get('value')}")

    res = None
    if len(changes) > 0:
        res = current_user.account.persist()
    if res is False:
        err = f'Error saving {" ".join(params_keys)}'
        messages.append(actions.app_messages.ERR_ACCOUNT_UPDATE)
    if res is True:
        messages.append(actions.app_messages.OK_ACCOUNT_UPDATED)
        models.ActivityLog(
            member_id=current_user.member_id,
            action=actions.ACTION_USER_CHANGED_ACCOUNT,
            description='\t'.join(changes)
        ).persist()

    account_dict = {}
    for col in current_user.account.cols():
        account_dict[col] = getattr(current_user.account, col)

    return jsonify({
        'status': 'success' if err is None else 'error',
        'error': err,
        'message': "\n".join(messages),
        'account': account_dict,
        'result': err is None
    })

@blueprint.route('/account-config', methods=['POST'])
@login_required
def api_account_config():
    params = request.get_json()
    account_config = models.AccountConfig(account_id=current_user.account_id)
    account_config.hydrate()
    protected = ['account_id']
    params_keys = set()
    changes = []
    custom_nameservers = False
    for param in params:
        if param.get('prop') in protected:
            continue
        if param.get('prop') == 'nameservers':
            custom_nameservers = param.get('value').splitlines()

        if param.get('prop') == 'ignore_list':
            blacklisted_domains = []
            blacklisted_ips = []
            for target in param.get('value').splitlines():
                if actions.is_valid_ipv4_address(target) or actions.is_valid_ipv6_address(target):
                    blacklisted_ips.append(target)
                else:
                    blacklisted_domains.append(target)
            if len(blacklisted_ips) > 0:
                params_keys.add('blacklisted_ips')
                from_val = '' if not isinstance(account_config.blacklisted_ips, str) else '\t'.join(account_config.blacklisted_ips.split('\n'))
                to_val = '\t'.join(blacklisted_ips)
                account_config.blacklisted_ips = '\n'.join(blacklisted_ips)
                changes.append(f"blacklisted_ips from {from_val} to {to_val}")
            if len(blacklisted_domains) > 0:
                params_keys.add('blacklisted_domains')
                from_val = '' if not isinstance(account_config.blacklisted_domains, str) else '\t'.join(account_config.blacklisted_domains.split('\n'))
                to_val = '\t'.join(blacklisted_domains)
                account_config.blacklisted_domains = '\n'.join(blacklisted_domains)
                changes.append(f"blacklisted_domains from {from_val} to {to_val}")
            continue
        params_keys.add(param.get('prop'))
        from_value = getattr(account_config, param.get('prop'))
        setattr(account_config, param.get('prop'), param.get('value'))
        changes.append(f"{param.get('prop')} from {from_value} to {param.get('value')}")

    if custom_nameservers is not False:
        pass #TODO inform support@trivialsec.com to modify AWS VPC DHCP options

    err = None
    message = actions.app_messages.OK_ACCOUNT_CONFIG_UPDATED
    if not account_config.persist():
        err = f'Error saving {" ".join(params_keys)}'
        message = actions.app_messages.ERR_ACCOUNT_UPDATE

    models.ActivityLog(
        member_id=current_user.member_id,
        action=actions.ACTION_USER_CHANGED_ACCOUNT,
        description='\t'.join(changes)
    ).persist()
    account_dict = {}
    for col in account_config.cols():
        account_dict[col] = getattr(account_config, col)

    return jsonify({
        'status': 'success' if err is None else 'error',
        'error': err,
        'message': message,
        'account_config': account_dict,
        'result': err is None
    })

@blueprint.route('/setup-account', methods=['POST'])
@login_required
def api_setup_account():
    params = request.get_json()
    changes = []
    account_changes = False
    account_config_changes = False
    err = None
    messages = []
    protected = ['verification_hash', 'registered', 'socket_key', 'plan_id', 'account_id']
    params_keys = set()
    account_cols = models.Account().cols()
    account_config_cols = models.AccountConfig().cols()
    account_config = models.AccountConfig(account_id=current_user.account_id)
    account_config.hydrate()

    for param in params:
        if param.get('prop') in protected:
            continue
        if param.get('prop') == 'alias' and current_user.account.alias == param.get('value'):
            continue
        if param.get('prop') == 'default_role_id' and \
            int(account_config.default_role_id) > 0 and \
            int(account_config.default_role_id) == int(param.get('value')):
            continue
        if param.get('prop') in account_cols:
            from_value = getattr(current_user.account, param.get('prop'), param.get('value'))
            params_keys.add(param.get('prop'))
            setattr(current_user.account, param.get('prop'), param.get('value'))
            changes.append(f"{param.get('prop')} from {from_value} to {param.get('value')}")
            account_changes = True
        if param.get('prop') in account_config_cols:
            from_value = getattr(account_config, param.get('prop'), param.get('value'))
            params_keys.add(param.get('prop'))
            setattr(account_config, param.get('prop'), param.get('value'))
            changes.append(f"{param.get('prop')} from {from_value} to {param.get('value')}")
            account_config_changes = True

    if account_changes and current_user.account.persist() is False:
        err = f'Error saving {" ".join(params_keys)}'
        messages.append(actions.app_messages.ERR_ACCOUNT_UPDATE)
    if account_config_changes and account_config.persist() is False:
        err = f'Error saving {" ".join(params_keys)} {type(account_config.default_role_id)}'
        messages.append(actions.app_messages.ERR_ACCOUNT_CONFIG_UPDATE)

    if err is None:
        models.ActivityLog(
            member_id=current_user.member_id,
            action=actions.ACTION_USER_CHANGED_ACCOUNT,
            description='\t'.join(changes)
        ).persist()
        messages.append(actions.app_messages.OK_ACCOUNT_UPDATED)

    return jsonify({
        'status': 'success' if err is None else 'error',
        'error': err,
        'message': "\n".join(messages),
        'result': err is None
    })

@blueprint.route('/checkout', methods=['POST'])
@login_required
def api_checkout():
    params = request.get_json()
    plan = models.Plan(account_id=current_user.account_id)
    plan.hydrate('account_id')
    if params.get('selection') == 'plan_professional_annual':
        price_id = config.stripe['products']['professional'].get('yearly')
    elif params.get('selection') == 'plan_professional_monthly':
        price_id = config.stripe['products']['professional'].get('monthly')
    elif params.get('selection') == 'plan_standard_annual':
        price_id = config.stripe['products']['standard'].get('yearly')
    elif params.get('selection') == 'plan_standard_monthly':
        price_id = config.stripe['products']['standard'].get('monthly')
    elif params.get('selection') == 'plan_enterprise':
        return jsonify({
            'status': 'info',
            'message': 'Please contact us to activate your Enterprise plan',
            'result': None
        })
    else:
        return jsonify({
            'status': 'error',
            'error': f"invalid selection {params.get('selection')}",
            'message': actions.app_messages.ERR_SUBSCRIPTION,
            'result': None
        })

    stripe_result = checkout(
        price_id=price_id,
        customer_id=plan.stripe_customer_id
    )
    models.ActivityLog(
        member_id=current_user.member_id,
        action=actions.ACTION_USER_CHANGED_ACCOUNT,
        description='Started subscription checkout session'
    ).persist()

    return jsonify({
        'status': 'success',
        'message': actions.app_messages.OK_CHECKOUT_SESSION,
        'result': stripe_result
    })

@blueprint.route('/organisation/member', methods=['POST'])
@login_required
def api_organisation_member():
    params = request.get_json()
    err = None
    messages = []
    member_dict = {}
    member = models.Member(
        member_id=params.get('member_id'),
        account_id=current_user.account_id
    )
    if not member.hydrate(['member_id', 'account_id']):
        err = actions.app_messages.ERR_ORG_MEMBER
    if member.email != params.get('email', member.email):
        prior_email = member.email
        member.email = params.get('email')
        member.verified = False
        member.confirmation_sent = False
        member.confirmation_url = f"/confirmation/{helpers.make_hash(params.get('email'))}"
        member.persist()
        confirmation_url = f"{config.frontend.get('site_scheme')}{config.frontend.get('site_domain')}{member.confirmation_url}"
        try:
            actions.email(
                subject="TrivialSec - email address updated",
                recipient=params.get('email'),
                template='updated_email',
                data={
                    "activation_url": confirmation_url
                }
            )
            member.confirmation_sent = True
            if member.persist():
                messages.append(actions.app_messages.OK_EMAIL_UPDATE)
                models.ActivityLog(
                    member_id=current_user.member_id,
                    action=actions.ACTION_USER_CHANGED_MEMBER,
                    description=f'changed {prior_email} to {member.email}'
                ).persist()

        except Exception as ex:
            logger.exception(ex)
            err = str(ex)
            messages.append(actions.app_messages.ERR_EMAIL_NOT_SENT)

    new_roles = []
    current_roles = []
    member.get_roles()
    roles_changed = False
    for role_id in params.get('roles'):
        new_roles.append(int(role_id))
    for role in member.roles:
        if int(role.role_id) not in new_roles:
            member.remove_role(role)
            roles_changed = True
            models.ActivityLog(
                member_id=current_user.member_id,
                action=actions.ACTION_USER_CHANGED_MEMBER,
                description=f'removed role {role.name} from {member.email}'
            ).persist()
        else:
            current_roles.append(int(role.role_id))

    for role_id in new_roles:
        if role_id not in current_roles:
            new_role = models.Role(role_id=role_id)
            new_role.hydrate()
            member.add_role(new_role)
            models.ActivityLog(
                member_id=current_user.member_id,
                action=actions.ACTION_USER_CHANGED_MEMBER,
                description=f'granted role {new_role.name} to {member.email}'
            ).persist()
            roles_changed = True

    if roles_changed is True:
        messages.append(actions.app_messages.OK_ACCOUNT_UPDATED)

    return jsonify({
        'status': 'success' if err is None else 'error',
        'error': err,
        'message': '\n'.join(messages),
        'result': member_dict
    })

@blueprint.route('/archive-project', methods=['POST'])
@login_required
def api_archive_project():
    params = request.get_json()
    project = models.Project(
        account_id=current_user.account_id,
        project_id=int(params.get('project_id'))
    )
    project.hydrate(['account_id', 'project_id'])
    if not isinstance(project, models.Project):
        return abort(403)

    project.deleted = True
    project.persist()
    models.ActivityLog(
        member_id=current_user.member_id,
        action=actions.ACTION_DELETE_PROJECT,
        description=project.name
    ).persist()
    domains = models.Domains()
    for domain in domains.find_by([('account_id', current_user.account_id), ('project_id', project.project_id)], limit=1000):
        domain.deleted = True
        domain.enabled = False
        domain.persist()

    return jsonify({
        'status': 'success',
        'message': actions.app_messages.OK_PROJECT_DELETE
    })

@blueprint.route('/enable-domain', methods=['POST'])
@login_required
def api_enable_domain():
    params = request.get_json()
    domain = models.Domain(
        account_id=current_user.account_id,
        domain_id=int(params.get('domain_id'))
    )
    domain.hydrate(['account_id', 'domain_id'])
    if not isinstance(domain, models.Domain):
        return abort(403)

    domain.enabled = True
    domain.persist()
    models.ActivityLog(
        member_id=current_user.member_id,
        action=actions.ACTION_ENABLE_DOMAIN,
        description=domain.name
    ).persist()

    return jsonify({
        'status': 'success',
        'message': actions.app_messages.OK_DOMAIN_ENABLED
    })

@blueprint.route('/disable-domain', methods=['POST'])
@login_required
def api_disable_domain():
    params = request.get_json()
    domain = models.Domain(
        account_id=current_user.account_id,
        domain_id=int(params.get('domain_id'))
    )
    domain.hydrate(['account_id', 'domain_id'])
    if not isinstance(domain, models.Domain):
        return abort(403)

    domain.enabled = False
    domain.persist()
    models.ActivityLog(
        member_id=current_user.member_id,
        action=actions.ACTION_DISABLE_DOMAIN,
        description=domain.name
    ).persist()

    return jsonify({
        'status': 'success',
        'message': actions.app_messages.OK_DOMAIN_DISABLED
    })

@blueprint.route('/delete-domain', methods=['POST'])
@login_required
def api_delete_domain():
    params = request.get_json()
    domain = models.Domain(
        account_id=current_user.account_id,
        domain_id=int(params.get('domain_id'))
    )
    domain.hydrate(['account_id', 'domain_id'])
    if not isinstance(domain, models.Domain):
        return abort(403)

    domain.deleted = True
    domain.persist()
    models.ActivityLog(
        member_id=current_user.member_id,
        action=actions.ACTION_DELETE_DOMAIN,
        description=domain.name
    ).persist()

    return jsonify({
        'status': 'success',
        'message': actions.app_messages.OK_DOMAIN_DELETE
    })
