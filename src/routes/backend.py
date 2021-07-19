from flask import render_template, Blueprint
from flask_login import current_user, login_required
from trivialsec.decorators import internal_users
from trivialsec.helpers.config import config
from trivialsec.helpers.datalists import namespaces, software_and_configuration_checks, ttps, effects, unusual_behaviors, sensitive_data_identifications, vulnerabilities, aws_security_best_practices, industry_and_regulatory_standards, methods, types, categories
from trivialsec.models.domain import Domains
from trivialsec.models.project import Project
from trivialsec.models.finding_detail import FindingDetails
from trivialsec.models.link import Links
from trivialsec.models.invitation import Invitations
from trivialsec.models.account import Account, Accounts
from trivialsec.models.plan import Plan, Plans
from trivialsec.models.member import Member, Members
from trivialsec.models.key_value import KeyValues
from trivialsec.models.feed import Feeds
from templates import public_params


blueprint = Blueprint('backend', __name__)

@blueprint.route('/', methods=['GET'])
@login_required
@internal_users
def backend():
    params = public_params()
    params['page_title'] = 'Backend'
    params['page'] = 'backend'
    params['account'] = current_user

    return render_template('backend/backend.html', **params)

@blueprint.route('/domains/<page>', methods=['GET'])
@blueprint.route('/domains', methods=['GET'])
@login_required
@internal_users
def domains_backend(page: int = 1):
    params = public_params()
    params['page_title'] = 'Domains'
    params['page'] = 'domains'
    params['account'] = current_user
    domains_arr = []
    page_size = 20
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    params['pagination'] = Domains().pagination(page_size=page_size, page_num=page_num)
    domains = Domains().load(limit=page_size, offset=offset)

    for domain in domains:
        project = Project(project_id=domain.project_id)
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
    return render_template('backend/domains.html', **params)

@blueprint.route('/recommendations/<page>', methods=['GET'])
@blueprint.route('/recommendations', methods=['GET'])
@login_required
@internal_users
def recommendations(page: int = 1):
    params = public_params()
    params['page_title'] = 'Recommendations'
    params['page'] = 'recommendations'
    params['account'] = current_user
    page_size = 20
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    params['pagination'] = FindingDetails().pagination(page_size=page_size, page_num=page_num)
    params['finding_details'] = FindingDetails().load(limit=page_size, offset=offset, order_by=['created_at', 'DESC']).to_list()
    params['datalists'] = [
        namespaces,
        software_and_configuration_checks,
        ttps,
        effects,
        unusual_behaviors,
        sensitive_data_identifications,
        vulnerabilities,
        aws_security_best_practices,
        industry_and_regulatory_standards
    ]

    return render_template('backend/recommendations.html', **params)

@blueprint.route('/services', methods=['GET'])
@login_required
@internal_users
def services():
    params = public_params()
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
    #     data = JobRuns().get_active(category=category)
    #     params['services'].append({**default_data, **data})

    return render_template('backend/services.html', **params)

@blueprint.route('/links', methods=['GET'])
@blueprint.route('/links/<page>', methods=['GET'])
@login_required
@internal_users
def links_backend(page: int = 1):
    params = public_params()
    params['page_title'] = 'Links'
    params['page'] = 'links'
    params['account'] = current_user
    links_arr = []
    page_size = 20
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    params['pagination'] = Links().pagination(page_size=page_size, page_num=page_num)
    links = Links().load(limit=page_size, offset=offset)

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

    return render_template('backend/links.html', **params)

@blueprint.route('/subscribers', methods=['GET'])
@blueprint.route('/subscribers/<page>', methods=['GET'])
@login_required
@internal_users
def subscribers_backend(page: int = 1):
    params = public_params()
    params['page_title'] = 'Subscribers'
    params['page'] = 'subscribers'
    params['account'] = current_user
    subscribers_arr = []
    # page_size = 20
    # page = int(page)
    # page_num = max(1, page)
    # offset = max(0, page-1) * page_size
    # params['pagination'] = Subscribers().pagination(page_size=page_size, page_num=page_num)
    # subscribers = Subscribers().load(limit=page_size, offset=offset)

    # for subscriber in subscribers:
    #     subscribers_arr.append({
    #         'id': subscriber.subscriber_id,
    #         'email': subscriber.email,
    #         'deleted': subscriber.deleted,
    #         'created_at': subscriber.created_at,
    #     })

    params['subscriptions'] = subscribers_arr

    return render_template('backend/subscriptions.html', **params)

@blueprint.route('/invitations/<page>', methods=['GET'])
@blueprint.route('/invitations', methods=['GET'])
@login_required
@internal_users
def invitations_backend(page: int = 1):
    params = public_params()
    params['page_title'] = 'Invitations'
    params['page'] = 'invitations'
    params['account'] = current_user
    invitations_arr = []
    page_size = 20
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    params['pagination'] = Invitations().pagination(page_size=page_size, page_num=page_num)
    invitations = Invitations().load(limit=page_size, offset=offset)
    for invitation in invitations:
        account = Account(account_id=invitation.account_id)
        member = Member(member_id=invitation.member_id)
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

    return render_template('backend/invitations.html', **params)

@blueprint.route('/accounts/<page>', methods=['GET'])
@blueprint.route('/accounts', methods=['GET'])
@login_required
@internal_users
def accounts_backend(page: int = 1):
    params = public_params()
    params['page_title'] = 'Accounts'
    params['page'] = 'accounts'
    params['account'] = current_user
    accounts_arr = []
    page_size = 20
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    params['pagination'] = Accounts().pagination(page_size=page_size, page_num=page_num)
    accounts = Accounts().load(order_by=['registered', 'DESC'], limit=page_size, offset=offset)
    plans = Plans().load(order_by=['name'])
    params['plans'] = plans

    for account in accounts:
        plan = Plan(account_id=account.account_id)
        plan.hydrate('account_id')
        accounts_arr.append({
            'id': account.account_id,
            'alias': account.alias,
            'plan': plan,
            'socket_key': account.socket_key,
            'registered': account.registered,
        })

    params['accounts'] = accounts_arr

    return render_template('backend/accounts.html', **params)

@blueprint.route('/users/<page>', methods=['GET'])
@blueprint.route('/users', methods=['GET'])
@login_required
@internal_users
def users(page: int = 1):
    params = public_params()
    params['page_title'] = 'Users'
    params['page'] = 'users'
    params['account'] = current_user
    members_arr = []
    page_size = 20
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    params['pagination'] = Members().pagination(page_size=page_size, page_num=page_num)
    members = Members().load(limit=page_size, offset=offset)
    for member in members:
        account = Account(account_id=member.account_id)
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

    return render_template('backend/users.html', **params)

@blueprint.route('/keyvalues/<page>', methods=['GET'])
@blueprint.route('/keyvalues', methods=['GET'])
@login_required
@internal_users
def keyvalues(page: int = 1):
    params = public_params()
    params['page_title'] = 'Public Content'
    params['page'] = 'keyvalues'
    params['account'] = current_user
    kv_arr = []
    page_size = 20
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    params['pagination'] = KeyValues().pagination(page_size=page_size, page_num=page_num)
    key_values = KeyValues().load(limit=page_size, offset=offset)
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

    return render_template('backend/keyvalues.html', **params)

@blueprint.route('/feeds/<page>', methods=['GET'])
@blueprint.route('/feeds', methods=['GET'])
@login_required
@internal_users
def feeds_backend(page: int = 1):
    params = public_params()
    params['page_title'] = 'Data Sources'
    params['page'] = 'feeds'
    params['account'] = current_user
    params['schedule_opts'] = [
        'hourly', 'daily', 'monthly'
    ]
    params['datalists'] = [methods, types, categories]
    feeds_arr = []
    page_size = 15
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    params['pagination'] = Feeds().pagination(page_size=page_size, page_num=page_num)
    feeds = Feeds().load(limit=page_size, offset=offset)

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

    return render_template('backend/feeds.html', **params)
