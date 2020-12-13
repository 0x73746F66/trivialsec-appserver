from flask import request, render_template, Blueprint
from flask_login import current_user, login_required
from trivialsec.helpers.config import config
from trivialsec import models
import actions

blueprint = Blueprint('backend', __name__)

@blueprint.route('/', methods=['GET'])
@login_required
@actions.internal_users
def backend():
    params = actions.get_frontend_conf()
    params['page_title'] = 'Backend'
    params['page'] = 'backend'
    params['account'] = current_user

    return render_template('backend/backend.html.j2', **params)

@blueprint.route('/domains/<page>', methods=['GET'])
@blueprint.route('/domains', methods=['GET'])
@login_required
@actions.internal_users
def domains_backend(page: int = 1):
    params = actions.get_frontend_conf()
    params['page_title'] = 'Domains'
    params['page'] = 'domains'
    params['account'] = current_user
    domains_arr = []
    page_size = 20
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    params['pagination'] = models.Domains().pagination(page_size=page_size, page_num=page_num)
    domains = models.Domains().load(limit=page_size, offset=offset)

    for domain in domains:
        project = models.Project(project_id=domain.project_id)
        project.hydrate()
        domains_arr.append({
            'id': domain.domain_id,
            'project': project,
            'name': domain.name,
            'schedule': domain.schedule,
            'screenshot': domain.screenshot,
            'created_at': domain.created_at,
            'enabled': domain.enabled,
            'verification_hash': current_user.account.verification_hash,
            'verified': domain.verified,
            'deleted': domain.deleted,
            'thumbnail_url': f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/{config.aws.get("public_object_prefix")}{domain.name}-render-320x240.jpeg' if domain.screenshot else None,
            'screen_url': f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/{config.aws.get("public_object_prefix")}{domain.name}-full.jpeg' if domain.screenshot else None
        })

    params['domains'] = domains_arr
    return render_template('backend/domains.html.j2', **params)

@blueprint.route('/recommendations/<page>', methods=['GET'])
@blueprint.route('/recommendations', methods=['GET', 'POST'])
@login_required
@actions.internal_users
def recommendations(page: int = 1):
    params = actions.get_frontend_conf()
    if request.method == 'POST':
        body = actions.request_body()
        params = {**params, **body}
        if params['action'] == 'review_details':
            actions.handle_update_recommendations_review(params, current_user)

    params['page_title'] = 'Recommendations'
    params['page'] = 'recommendations'
    params['account'] = current_user
    page_size = 20
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    params['pagination'] = models.FindingDetails().pagination(page_size=page_size, page_num=page_num)
    params['finding_details'] = models.FindingDetails().load(limit=page_size, offset=offset, order_by=['created_at', 'DESC']).to_list()
    params['datalists'] = [{
        'name':
        'namespaces',
        'options': [
            'Software and Configuration Checks',
            'TTPs',
            'Effects',
            'Unusual Behaviors',
            'Sensitive Data Identifications',
        ]
    }, {
        'name':
        'softwareandconfigurationchecks',
        'options': [
            'Vulnerabilities',
            'AWS Security Best Practices',
            'Industry and Regulatory Standards',
        ]
    }, {
        'name':
        'ttps',
        'options': [
            'Data Exposure',
            'Data Exfiltration',
            'Data Destruction',
            'Denial of Service',
            'Resource Consumption',
        ]
    }, {
        'name':
        'effects',
        'options': [
            'Initial Access',
            'Execution',
            'Persistence',
            'Privilege Escalation',
            'Defense Evasion',
            'Credential Access',
            'Discovery',
            'Lateral Movement',
            'Collection',
            'Command and Control',
        ]
    }, {
        'name':
        'unusualbehaviors',
        'options': [
            'Application',
            'Network Flow',
            'IP address',
            'User',
            'VM',
            'Container',
            'Serverless',
            'Process',
            'Database',
            'Data',
        ]
    }, {
        'name':
        'sensitivedataidentifications',
        'options': [
            'PII',
            'Passwords',
            'Legal',
            'Financial',
            'Security',
            'Business',
        ]
    }, {
        'name': 'vulnerabilities',
        'options': [
            'CVE',
            'CWE',
        ]
    }, {
        'name':
        'awssecuritybestpractices',
        'options': [
            'Network Reachability',
            'Runtime Behavior Analysis',
        ]
    }, {
        'name':
        'industryandregulatorystandards',
        'options': [
            'CIS Host Hardening Benchmarks',
            'CIS AWS Foundations Benchmark',
            'PCI-DSS Controls',
            'Cloud Security Alliance Controls',
            'ISO 90001 Controls',
            'ISO 27001 Controls',
            'ISO 27017 Controls',
            'ISO 27018 Controls',
            'SOC 1',
            'SOC 2',
            'HIPAA Controls (USA)',
            'NIST 800-53 Controls (USA)',
            'NIST CSF Controls (USA)',
            'IRAP Controls (Australia)',
            'K-ISMS Controls (Korea)',
            'MTCS Controls (Singapore)',
            'FISC Controls (Japan)',
            'My Number Act Controls (Japan)',
            'ENS Controls (Spain)',
            'Cyber Essentials Plus Controls (UK)',
            'G-Cloud Controls (UK)',
            'C5 Controls (Germany)',
            'IT-Grundschutz Controls (Germany)',
            'GDPR Controls (Europe)',
            'TISAX Controls (Europe)',
        ]
    }]

    return render_template('backend/recommendations.html.j2', **params)

@blueprint.route('/services', methods=['GET'])
@login_required
@actions.internal_users
def services():
    params = actions.get_frontend_conf()
    params['page_title'] = 'Services'
    params['page'] = 'services'
    params['account'] = current_user
    # params['services'] = []
    # service_categories = [
    #     ('subdomains', 'Subdomains'),
    #     ('fingerprinting', 'Fingerprinting'),
    #     ('dns', 'DNS'),
    #     ('dast', 'DAST'),
    #     ('sast', 'SAST'),
    #     ('sca', 'SCA'),
    #     ('source_code', 'Source Code'),
    #     ('secrets', 'Secrets'),
    #     ('crawler', 'Crawler'),
    #     ('https', 'SSL/TLS'),
    #     ('threatintel', 'Threat Intel'),
    #     ('oci', 'Containers')
    # ]
    # for category, display_name in service_categories:
    #     default_data = {'status': 'connecting', 'category': category, 'name': display_name}
    #     data = models.JobRuns().get_active(category=category)
    #     params['services'].append({**default_data, **data})

    return render_template('backend/services.html.j2', **params)

@blueprint.route('/links', methods=['GET'])
@blueprint.route('/links/<page>', methods=['GET'])
@login_required
@actions.internal_users
def links_backend(page: int = 1):
    params = actions.get_frontend_conf()
    params['page_title'] = 'Links'
    params['page'] = 'links'
    params['account'] = current_user
    links_arr = []
    page_size = 20
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    params['pagination'] = models.Links().pagination(page_size=page_size, page_num=page_num)
    links = models.Links().load(limit=page_size, offset=offset)

    for link in links:
        links_arr.append({
            'campaign': link.campaign,
            'channel': link.channel,
            'slug': link.slug,
            'deleted': link.deleted,
            'expires': link.expires,
            'created_at': link.created_at,
        })

    params['links'] = links_arr

    return render_template('backend/links.html.j2', **params)

@blueprint.route('/subscribers', methods=['GET'])
@blueprint.route('/subscribers/<page>', methods=['GET'])
@login_required
@actions.internal_users
def subscribers_backend(page: int = 1):
    params = actions.get_frontend_conf()
    params['page_title'] = 'Subscribers'
    params['page'] = 'subscribers'
    params['account'] = current_user
    subscribers_arr = []
    page_size = 20
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    params['pagination'] = models.Subscribers().pagination(page_size=page_size, page_num=page_num)
    subscribers = models.Subscribers().load(limit=page_size, offset=offset)

    for subscriber in subscribers:
        subscribers_arr.append({
            'id': subscriber.subscriber_id,
            'email': subscriber.email,
            'deleted': subscriber.deleted,
            'created_at': subscriber.created_at,
        })

    params['subscriptions'] = subscribers_arr

    return render_template('backend/subscriptions.html.j2', **params)

@blueprint.route('/invitations/<page>', methods=['GET'])
@blueprint.route('/invitations', methods=['GET'])
@login_required
@actions.internal_users
def invitations_backend(page: int = 1):
    params = actions.get_frontend_conf()
    params['page_title'] = 'Invitations'
    params['page'] = 'invitations'
    params['account'] = current_user
    invitations_arr = []
    page_size = 20
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    params['pagination'] = models.Invitations().pagination(page_size=page_size, page_num=page_num)
    invitations = models.Invitations().load(limit=page_size, offset=offset)
    for invitation in invitations:
        account = models.Account(account_id=invitation.account_id)
        member = models.Member(member_id=invitation.member_id)
        invitations_arr.append({
            'id': invitation.invitation_id,
            'account': account,
            'member': member,
            'email': invitation.email,
            'message': invitation.message,
            'deleted': invitation.deleted,
            'created_at': invitation.created_at,
        })

    params['invitations'] = invitations_arr

    return render_template('backend/invitations.html.j2', **params)

@blueprint.route('/accounts/<page>', methods=['GET'])
@blueprint.route('/accounts', methods=['GET'])
@login_required
@actions.internal_users
def accounts_backend(page: int = 1):
    params = actions.get_frontend_conf()
    params['page_title'] = 'Accounts'
    params['page'] = 'accounts'
    params['account'] = current_user
    accounts_arr = []
    page_size = 20
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    params['pagination'] = models.Accounts().pagination(page_size=page_size, page_num=page_num)
    accounts = models.Accounts().load(order_by=['registered', 'DESC'], limit=page_size, offset=offset)
    plans = models.Plans().load(order_by=['name'])
    params['plans'] = plans

    for account in accounts:
        plan = models.Plan(plan_id=account.plan_id)
        plan.hydrate()
        accounts_arr.append({
            'id': account.account_id,
            'alias': account.alias,
            'plan': plan,
            'socket_key': account.socket_key,
            'registered': account.registered,
        })

    params['accounts'] = accounts_arr

    return render_template('backend/accounts.html.j2', **params)

@blueprint.route('/users/<page>', methods=['GET'])
@blueprint.route('/users', methods=['GET'])
@login_required
@actions.internal_users
def users(page: int = 1):
    params = actions.get_frontend_conf()
    params['page_title'] = 'Users'
    params['page'] = 'users'
    params['account'] = current_user
    members_arr = []
    page_size = 20
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    params['pagination'] = models.Members().pagination(page_size=page_size, page_num=page_num)
    members = models.Members().load(limit=page_size, offset=offset)
    for member in members:
        account = models.Account(account_id=member.account_id)
        account.hydrate()
        member.get_roles()
        members_arr.append({
            'id': member.member_id,
            'account': account,
            'email': member.email,
            'registered': member.registered,
            'roles': member.roles,
        })

    params['members'] = members_arr

    return render_template('backend/users.html.j2', **params)

@blueprint.route('/keyvalues/<page>', methods=['GET'])
@blueprint.route('/keyvalues', methods=['GET', 'POST'])
@login_required
@actions.internal_users
def keyvalues(page: int = 1):
    params = actions.get_frontend_conf()
    if request.method == 'POST':
        body = actions.request_body()
        params = {**params, **body}
        actions.handle_upsert_keyvalues(params, current_user)

    params = actions.get_frontend_conf()
    params['page_title'] = 'Public Content'
    params['page'] = 'keyvalues'
    params['account'] = current_user
    kv_arr = []
    page_size = 20
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    params['pagination'] = models.KeyValues().pagination(page_size=page_size, page_num=page_num)
    key_values = models.KeyValues().load(limit=page_size, offset=offset)
    for kv in key_values:
        kv_arr.append({
            'id': kv.key_value_id,
            'type': kv.type,
            'key': kv.key,
            'value': kv.value,
            'hidden': kv.hidden,
            'active_date': kv.active_date,
            'created_at': kv.created_at,
        })

    params['keyvalues'] = kv_arr

    return render_template('backend/keyvalues.html.j2', **params)

@blueprint.route('/feeds', methods=['GET', 'POST'])
@blueprint.route('/feeds/<page>', methods=['GET'])
@login_required
@actions.internal_users
def feeds_backend(page: int = 1):
    params = actions.get_frontend_conf()
    if request.method == 'POST':
        body = actions.request_body()
        params = {**params, **body}
        actions.handle_upsert_feeds(params, current_user)

    params['page_title'] = 'Data Sources'
    params['page'] = 'feeds'
    params['account'] = current_user
    params['schedule_opts'] = [
        'hourly', 'daily', 'monthly'
    ]
    params['datalists'] = [{
        'name': 'methods',
        'options': ['http', 'ftp']
    }, {
        'name': 'types',
        'options': models.Feeds().distinct('type')
    }, {
        'name': 'categories',
        'options': models.Feeds().distinct('category')
    }]
    feeds_arr = []
    page_size = 15
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    params['pagination'] = models.Feeds().pagination(page_size=page_size, page_num=page_num)
    feeds = models.Feeds().load(limit=page_size, offset=offset)

    for feed in feeds:
        feeds_arr.append({
            'id': feed.feed_id,
            'name': feed.name,
            'category': feed.category,
            'description': feed.description,
            'url': feed.url,
            'type': feed.type,
            'method': feed.method,
            'http_status': feed.http_status or '',
            'http_code': feed.http_code or 'Not Checked',
            'username': feed.username or '',
            'credential_key': feed.credential_key or '',
            'alert_title': feed.alert_title,
            'schedule': feed.schedule,
            'feed_site': feed.feed_site or '',
            'abuse_email': feed.abuse_email or '',
            'disabled': feed.disabled,
            'running': False if not feed.start_check or not feed.last_checked else feed.start_check > feed.last_checked,
            'start_check': feed.start_check or '',
            'last_checked': feed.last_checked or '',
        })

    params['feeds'] = feeds_arr

    return render_template('backend/feeds.html.j2', **params)
