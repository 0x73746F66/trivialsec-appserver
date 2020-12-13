from functools import wraps
from datetime import date, datetime, timedelta
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib import request as urlrequest
import json
import time
import base64
import os
import uuid
import re
import socket
import requests
import boto3
from passlib.hash import pbkdf2_sha256
from flask import request, abort, redirect, url_for
from flask_login import current_user
from requests.status_codes import _codes
from requests.exceptions import ReadTimeout, ConnectTimeout
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from trivialsec.helpers.config import config
from trivialsec.helpers.log_manager import logger
from trivialsec import models
from trivialsec import helpers
from . import app_messages


EOL = "\r\n"
ACTION_USER_LOGIN = 'user_login'
ACTION_USER_LOGOUT = 'user_logout'
ACTION_DOMAIN_VERIFICATION_CHECK = 'domain_verification_check'
ACTION_DOMAIN_METADATA_CHECK = 'domain_metadata_check'
ACTION_CREATE_PROJECT = 'create_project'
ACTION_ADDED_IPADDRESS = 'added_ipaddress'
ACTION_ADDED_DOMAIN = 'added_domain'
ACTION_ENABLE_DOMAIN = 'enabled_domain_automation'
ACTION_DISABLE_DOMAIN = 'disabled_domain_automation'
ACTION_ENABLE_PROJECT = 'enabled_project_automation'
ACTION_DISABLE_PROJECT = 'disabled_project_automation'
ACTION_DELETE_DOMAIN = 'deleted_domain'
ACTION_DELETE_PROJECT = 'deleted_project'
ACTION_ON_DEMAND_SCAN = 'on_demand_scan'
ACTION_USER_CHANGED_PASSWORD = 'user_changed_password'
ACTION_USER_CHANGE_EMAIL_REQUEST = 'user_change_email_request'
ACTION_USER_CHANGED_PASSWORD = 'user_changed_password'
ACTION_USER_RESET_PASSWORD_REQUEST = 'user_reset_password_request'
ACTION_USER_CREATED_INVITATION = 'user_created_invitation'
ACTION_USER_CHANGED_ACCOUNT = 'user_changed_account'
ACTION_USER_CHANGED_MEMBER = 'user_changed_member'

def require_recaptcha(action: str):
    def deco(func):
        @wraps(func)
        def f_require_recaptcha(*args, **kwargs):
            body = request_body()
            if 'recaptcha_token' not in body:
                logger.warning('missing recaptcha_token')
                return abort(403)

            params = urlencode({
                'secret': config.recaptcha_secret_key,
                'response': body['recaptcha_token']
            }).encode('ascii')
            url = 'https://www.google.com/recaptcha/api/siteverify'
            req = urlrequest.Request(url)
            if config.http_proxy is not None:
                req.set_proxy(config.http_proxy, 'http')
            if config.https_proxy is not None:
                req.set_proxy(config.https_proxy, 'https')
            with urlrequest.urlopen(req, data=params) as resp:
                siteverify = json.loads(resp.read().decode('utf8'))
                logger.info(siteverify)
                logger.info(f'resp.code {resp.code}')
                if resp.code != 200:
                    logger.warning(f'{action} recaptcha code {resp.code}')
                    return abort(403)
                if siteverify['success']:
                    if siteverify['score'] < 0.6:
                        logger.warning(f'recaptcha score {siteverify["score"]}')
                        return abort(403)
                    if action and siteverify['action'] != action:
                        logger.warning(f'{action} recaptcha code {resp.code}')
                        return abort(403)
                elif len(siteverify['error-codes']) > 0:
                    logger.error(f"recaptcha {'|'.join(siteverify['error-codes'])}")
                    return abort(403)
            try:
                ret = func(*args, **kwargs)
            except Exception as err:
                ret = err

            return ret

        return f_require_recaptcha
    return deco

def request_body():
    body1 = request.get_json() or {}
    data = request.stream.read()
    body = parse_qs(data.decode('unicode-escape'))
    body2 = {}
    for _, key in enumerate(body):
        if isinstance(body[key], list) and len(body[key]) == 1:
            val = body[key][0]
        else:
            val = body[key]
        ktype = None
        if key[-2:] == '[]':
            ktype = list
        if key[-1:] == ']' and '[' in key:
            ktype = dict
        if ktype:
            new_key = key[:key.find('[')]
            if new_key not in body2:
                if ktype == list:
                    body2[new_key] = []
                    body2[new_key].append(val)
            elif ktype == list:
                body2[new_key].append(val)
            if ktype == dict:
                dkey = key[key.find('[')+1:key.find(']')]
                if new_key not in body2:
                    body2[new_key] = {}
                body2[new_key][dkey] = val
        else:
            body2[key] = val

    new_body = {**body1, **body2}

    return new_body

def check_password_policy(passwd: str) -> bool:
    if len(passwd) < 16:
        return False
    return True

def check_email_rules(email: str) -> bool:
    parts = email.split('@')
    if len(parts) != 2:
        logger.info('check_email_rules: invalid format')
        return False

    res = check_domain_rules(parts[1])
    if not res:
        logger.info('check_email_rules: invalid domain')
        return False

    if not is_valid_email(email):
        logger.info('check_email_rules: validation error')
        return False

    return True

def check_domain_rules(domain: str) -> bool:
    # TODO implement
    return True

def check_subdomain_rules(subdomain: str) -> bool:
    parts = subdomain.split('.')
    if len(parts) > 2:
        return False

    return True

def queue_job(tracking_id: str, params: dict, service_type: models.ServiceType, member: models.Member, project=models.Project, priority: int = 0) -> models.JobRun:
    queue_data = helpers.QueueData(
        scan_type=params.get('scan_type', 'passive'),
        tracking_id=tracking_id,
        service_type_id=service_type.service_type_id,
        service_type_name=service_type.name,
        service_type_category=service_type.category,
        target=params.get('target')
    )
    new_job_run = models.JobRun(
        account_id=member.account_id,
        project_id=project.project_id,
        tracking_id=tracking_id,
        service_type_id=service_type.service_type_id,
        queue_data=str(queue_data),
        state=models.ServiceType.STATE_QUEUED,
        priority=priority
    )
    if not new_job_run.persist():
        raise ValueError(f'tracking_id {tracking_id} persist error')
    models.ActivityLog(
        member_id=member.member_id,
        action=ACTION_ON_DEMAND_SCAN,
        description=f'{queue_data.scan_type} {service_type.category} {queue_data.target}'
    ).persist()

def handle_add_domain(domain_name: str, project: models.Project) -> models.Domain:
    res = check_domain_rules(domain_name)
    if not res:
        return None

    domain = models.Domain(
        name=domain_name,
        account_id=current_user.account_id,
        project_id=project.project_id,
    )
    if domain.exists(['name', 'project_id', 'account_id']):
        domain.hydrate()
        domain.deleted = False
    domain.source = f'Project {project.name}'
    domain.enabled = False

    if domain.persist():
        models.ActivityLog(member_id=current_user.member_id, action='added_domain', description=domain_name).persist()

    return domain

def handle_upsert_feeds(params: dict, member: models.Member) -> models.Feed:
    feed = models.Feed(feed_id=params.get('feed_id'))
    feed.name = params.get('name')
    feed.description = params.get('description')
    feed.url = params.get('url')
    feed.alert_title = params.get('alert_title')
    feed.feed_site = params.get('feed_site')
    feed.abuse_email = params.get('abuse_email')
    feed.disabled = params.get('disabled')
    feed.schedule = params.get('schedule')
    feed.category = params.get('category')
    feed.type = params.get('type')
    feed.method = params.get('method')
    feed.username = params.get('username')
    feed.credential_key = params.get('credential_key')

    if feed.persist():
        models.ActivityLog(member_id=member.member_id, action='edited_feed', description=feed.name).persist()
        return feed

    return None

def handle_upsert_keyvalues(params: dict, member: models.Member) -> models.KeyValue:
    keyvalue = models.KeyValue(key_value_id=params.get('key_value_id'))
    keyvalue.type = params.get('type')
    keyvalue.key = params.get('key')
    keyvalue.value = params.get('value')
    keyvalue.hidden = params.get('hidden')
    keyvalue.active_date = params.get('active_date')

    if keyvalue.persist():
        models.ActivityLog(member_id=member.member_id, action='edited_keyvalue', description=keyvalue.key).persist()
        return keyvalue

    return None

def handle_update_recommendations_review(params: dict, member: models.Member) -> models.FindingDetail:
    review = models.FindingDetail(finding_detail_id=params.get('finding_detail_id'))
    review.hydrate()
    review.title = params.get('title')
    review.description = params.get('description')
    review.recommendation = params.get('recommendation')
    review.recommendation_url = params.get('recommendation_url')
    review.type_namespace = params.get('type_namespace')
    review.type_category = params.get('type_category')
    review.type_classifier = params.get('type_classifier')
    review.criticality = params.get('criticality')
    review.confidence = params.get('confidence')
    review.severity_product = params.get('severity_product')
    review.review = 0
    review.updated_at = datetime.utcnow()
    review.modified_by_id = member.member_id

    if review.persist():
        models.ActivityLog(member_id=member.member_id, action='edited_finding_detail', description=review.finding_detail_id).persist()
        return review

    return None

def handle_finding_actions(params: dict, member: models.Member) -> models.Finding:
    action = params.get('action')
    finding_id = params.get('finding_id')
    if action == 'archive':
        finding = models.Finding(finding_id=finding_id)
        finding.hydrate()
        finding.archived = True
        finding.updated_at = datetime.utcnow()
        if finding.persist():
            models.ActivityLog(member_id=member.member_id, action='archived_finding', description=finding.finding_id).persist()
            return finding

    if action == 'assign':
        assignee_id = params.get('assignee_id')
        if assignee_id:
            finding = models.Finding(finding_id=finding_id)
            finding.hydrate()
            finding.assignee_id = assignee_id
            finding.workflow_state = finding.WORKFLOW_ASSIGNED
            finding.updated_at = datetime.utcnow()
            finding.persist()
            models.ActivityLog(member_id=member.member_id, action='assigned_finding', description=assignee_id).persist()
            return finding

    if action == 'project':
        project_id = params.get('project_id')
        if project_id:
            finding = models.Finding(finding_id=finding_id)
            finding.hydrate()
            finding.project_id = project_id
            finding.updated_at = datetime.utcnow()
            finding.persist()
            models.ActivityLog(member_id=member.member_id, action='finding_project_changed', description=project_id).persist()
            return finding

    if action == 'verify':
        verification_state = params.get('verification_state').upper()
        if verification_state:
            finding = models.Finding(finding_id=finding_id)
            finding.hydrate()
            finding.verification_state = verification_state
            if verification_state in [finding.VERIFY_BENIGN_POSITIVE, finding.VERIFY_FALSE_POSITIVE]:
                finding.workflow_state = finding.WORKFLOW_RESOLVED
            finding.updated_at = datetime.utcnow()
            finding.persist()
            models.ActivityLog(member_id=member.member_id, action='verify_finding', description=verification_state).persist()
            return finding

    if action == 'severity':
        severity = params.get('severity')
        if severity:
            finding = models.Finding(finding_id=finding_id)
            finding.hydrate()
            finding.severity_normalized = rating_to_score(severity)
            finding.updated_at = datetime.utcnow()
            finding.persist()
            models.ActivityLog(member_id=member.member_id, action='severity_finding', description=severity).persist()
            return finding

    if action == 'defer':
        defer = params.get('defer')
        if defer:
            finding = models.Finding(finding_id=finding_id)
            finding.hydrate()
            finding.defer_to = defer
            finding.updated_at = datetime.utcnow()
            finding.workflow_state = finding.WORKFLOW_DEFERRED
            finding.persist()
            models.ActivityLog(member_id=member.member_id, action='defer_finding', description=defer).persist()
            return finding

    if action == 'workflow':
        workflow_state = params.get('workflow_state').upper()
        if workflow_state:
            finding = models.Finding(finding_id=finding_id)
            finding.hydrate()
            finding.workflow_state = workflow_state
            finding.updated_at = datetime.utcnow()
            finding.persist()
            models.ActivityLog(member_id=member.member_id, action='finding_workflow', description=workflow_state).persist()
            return finding

    if action == 'unassign':
        finding = models.Finding(finding_id=finding_id)
        finding.hydrate()
        finding.assignee_id = None
        finding.workflow_state = finding.WORKFLOW_NEW
        finding.updated_at = datetime.utcnow()
        finding.persist()
        models.ActivityLog(member_id=member.member_id, action='unassigned_finding', description=assignee_id).persist()
        return finding

    if action == 'resolve':
        text = params.get('reason')
        finding = models.Finding(finding_id=finding_id)
        finding.hydrate()
        note = models.FindingNote(
            finding_id=finding_id,
            account_id=member.account_id,
            member_id=member.member_id,
            text=text,
        )
        if note.persist():
            finding.assignee_id = member.member_id
            finding.workflow_state = finding.WORKFLOW_RESOLVED
            finding.updated_at = datetime.utcnow()
            finding.persist()
            models.ActivityLog(member_id=member.member_id, action='resolved_finding', description=note.finding_note_id).persist()
            return finding

    if action == 'note':
        text = params.get('text')
        finding = models.Finding(finding_id=finding_id)
        finding.hydrate()
        note = models.FindingNote(
            finding_id=finding_id,
            account_id=member.account_id,
            member_id=member.member_id,
            text=text,
        )
        if note.persist():
            finding.assignee_id = member.member_id
            finding.workflow_state = finding.WORKFLOW_IN_PROGRESS
            finding.updated_at = datetime.utcnow()
            finding.persist()
            models.ActivityLog(member_id=member.member_id, action='noted_finding', description=note.finding_note_id).persist()
            return finding

    return None

def register_action(email: str, passwd: str, selected_plan: dict, alias=None, verified=False, account_id=None, role_id=models.Role.ROLE_OWNER_ID) -> models.Member:
    res = check_email_rules(email)
    if not res:
        return None

    member = models.Member(email=email)
    if member.exists(['email']):
        return None

    account = models.Account(
        billing_email=email,
        account_id=account_id,
        alias=alias or email,
        verification_hash=helpers.make_hash(email),
        socket_key=str(uuid.uuid5(uuid.NAMESPACE_URL, email))
    )
    if account_id is not None:
        account.hydrate()
    elif account.exists(['verification_hash']):
        account.hydrate(by_column='verification_hash')
    else:
        account.persist()
        account_config = models.AccountConfig(account_id=account.account_id)
        account_config.persist()
        selected_plan['account_id'] = account.account_id
        plan = models.Plan(**selected_plan)
        plan.persist()

    member.account_id = account.account_id
    member.password = helpers.hash_password(passwd)
    member.confirmation_url = f"/confirmation/{account.verification_hash}" if not verified else 'verified'
    if verified:
        member.verified = True
    member.persist()
    member.add_role(models.Role(role_id=role_id))
    member.get_roles()

    return member

def handle_login(email: str, password: str) -> models.Member:
    res = check_email_rules(email)
    if not res:
        return None

    member = models.Member(email=email)
    if not member.exists(['email']):
        return None
    member.hydrate('email')

    if not helpers.check_encrypted_password(password, member.password):
        return None

    return member

def score_to_rating(score: int) -> str:
    if score == 0:
        return 'INFO'
    if score >= 1 and score < 40:
        return 'LOW'
    if score >= 40 and score < 70:
        return 'MEDIUM'
    if score >= 70 and score < 90:
        return 'HIGH'
    if score >= 90 and score <= 100:
        return 'CRITICAL'

    return 'NOT SCORED'

def rating_to_score(rating: str) -> int:
    if rating == 'INFO':
        return 0
    if rating == 'LOW':
        return 35
    if rating == 'MEDIUM':
        return 65
    if rating == 'HIGH':
        return 85
    if rating == 'CRITICAL':
        return 95

    return -1

def score_to_confidence(score: int) -> str:
    if score >= 0 and score < 45:
        return 'LOW'
    if score >= 45 and score < 85:
        return 'MEDIUM'
    if score >= 85 and score <= 100:
        return 'HIGH'

    return 'NOT SCORED'

def aggregate_sum(findings: list, rating: str, using: str, scoring_func: str) -> int:
    return sum(1 for i in findings if globals()[scoring_func](getattr(i, using)) == rating)

def internal_users(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        authorised = is_internal_member()

        if not current_user.is_authenticated:
            return redirect(url_for('public.login', next=request.url))

        if not authorised:
            return abort(403)

        return func(*args, **kwargs)
    return decorated_view

def requires_support(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        authorised = is_support_member()

        if not current_user.is_authenticated:
            return redirect(url_for('public.login', next=request.url))

        if not authorised:
            return abort(403)

        return func(*args, **kwargs)
    return decorated_view

def requires_billing(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        authorised = is_billing_member()

        if not current_user.is_authenticated:
            return redirect(url_for('public.login', next=request.url))

        if not authorised:
            return abort(403)

        return func(*args, **kwargs)
    return decorated_view

def requires_audit(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        authorised = is_audit_member()

        if not current_user.is_authenticated:
            return redirect(url_for('public.login', next=request.url))

        if not authorised:
            return abort(403)

        return func(*args, **kwargs)
    return decorated_view

def requires_owner(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        authorised = is_owner_member()

        if not current_user.is_authenticated:
            return redirect(url_for('public.login', next=request.url))

        if not authorised:
            return abort(403)

        return func(*args, **kwargs)
    return decorated_view

def is_valid_ipv4_address(address) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

def is_valid_ipv6_address(address) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True

def is_valid_email(address) -> bool:
    try:
        matched = re.match(r'^[a-z\d]([\w\-]*[a-z\d]|[\w\+\-\.]*[a-z\d]{2,}|[a-z\d])*@[a-z\d]([\w\-]*[a-z\d]|[\w\-\.]*[a-z\d]{2,}|[a-z\d]){4,}?.[a-z]{2,}$', address)
        return bool(matched)
    except Exception:  # not a valid address
        return False
    return False

def is_internal_member() -> bool:
    if not current_user.is_authenticated:
        return False

    if not current_user.verified:
        return False

    current_user.get_roles()
    for role in current_user.roles:
        if role.internal_only:
            return True

    return False

def is_support_member() -> bool:
    if not current_user.is_authenticated:
        return False

    if not current_user.verified:
        return False

    current_user.get_roles()
    for role in current_user.roles:
        if role.role_id == models.Role.ROLE_SUPPORT_ID:
            return True

    return False

def is_billing_member() -> bool:
    if not current_user.is_authenticated:
        return False

    if not current_user.verified:
        return False

    current_user.get_roles()
    for role in current_user.roles:
        if role.role_id in [models.Role.ROLE_BILLING_ID, models.Role.ROLE_OWNER_ID]:
            return True

    return False

def is_audit_member() -> bool:
    if not current_user.is_authenticated:
        return False

    if not current_user.verified:
        return False

    current_user.get_roles()
    for role in current_user.roles:
        if role.role_id in [models.Role.ROLE_AUDIT_ID, models.Role.ROLE_OWNER_ID]:
            return True

    return False

def is_owner_member() -> bool:
    if not current_user.is_authenticated:
        return False

    if not current_user.verified:
        return False

    current_user.get_roles()
    for role in current_user.roles:
        if role.role_id == models.Role.ROLE_OWNER_ID:
            return True

    return False

def is_readonly_member() -> bool:
    if not current_user.is_authenticated:
        return False

    if not current_user.verified:
        return False

    current_user.get_roles()
    for role in current_user.roles:
        if role.role_id == models.Role.ROLE_RO_ID:
            return True

    return False

def get_frontend_conf() -> dict:
    conf = {
        'app_version': config.app_version,
        'recaptcha_site_key': config.recaptcha_site_key,
        'public_bucket': config.aws.get('public_bucket'),
        'public_object_prefix': config.aws.get('public_object_prefix'),
        'stripe_publishable_key': config.stripe_publishable_key,
        'year': date.today().year,
        'roles': {
            'is_internal_member': is_internal_member(),
            'is_support_member': is_support_member(),
            'is_billing_member': is_billing_member(),
            'is_audit_member': is_audit_member(),
            'is_owner_member': is_owner_member(),
            'is_readonly_member': is_readonly_member(),
        }
    }
    return {**conf, **config.get_app()}

def email(subject: str, template: str, data: dict, recipient: str, group: str = 'notifications', sender: str = 'support@trivialsec.com'):
    sendgrid = SendGridAPIClient(config.sendgrid_api_key)
    tmp_url = sendgrid.client.mail.send._build_url(query_params={})
    req_body = {
        'subject': subject,
        'from': {'email': sender},
        'template_id': config.sendgrid.get('templates').get(template),
        'asm': {
            'group_id': config.sendgrid.get('groups').get(group)
        },
        'personalizations': [
            {
                'dynamic_template_data': {**data, **{'email': recipient}},
                'to': [
                    {
                        'email': recipient
                    }
                ]
            }
        ]
    }
    # https://github.com/sendgrid/sendgrid-python/issues/409
    proxies = None
    if config.http_proxy or config.https_proxy:
        proxies = {
            'http': config.http_proxy,
            'https': config.https_proxy
        }

    res = requests.post(url=tmp_url,
        json=req_body,
        headers=sendgrid.client.request_headers,
        proxies=proxies,
        timeout=10
    )
    logger.debug(res.__dict__)
    return res

def upsert_contact(recipient_email: str, list_name: str = 'subscribers'):
    sendgrid = SendGridAPIClient(config.sendgrid_api_key)
    # https://github.com/sendgrid/sendgrid-python/issues/409
    proxies = None
    if config.http_proxy or config.https_proxy:
        proxies = {
            'http': config.http_proxy,
            'https': config.https_proxy
        }

    res = requests.put(url='https://api.sendgrid.com/v3/marketing/contacts',
        json={
            "list_ids": [
                config.sendgrid.get('lists').get(list_name)
            ],
            "contacts": [{
                "email": recipient_email
            }]
        },
        headers=sendgrid.client.request_headers,
        proxies=proxies,
        timeout=10
    )
    logger.debug(res.__dict__)
    return res
