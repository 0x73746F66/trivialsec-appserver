from datetime import datetime
from flask import render_template, Blueprint, abort
from flask_login import current_user, login_required
from trivialsec.helpers.config import config
from trivialsec.models.domain import Domains, Domain
from trivialsec.models.finding import Findings
from trivialsec.models.dns_record import DnsRecords
from trivialsec.models.known_ip import KnownIps
from trivialsec.models.job_run import JobRuns
from trivialsec.models.inventory import InventoryItems
from trivialsec.models.project import Project
from actions import charts
from templates import public_params


blueprint = Blueprint('domain', __name__)

@blueprint.route('/<domain_id>', methods=['GET'])
@login_required
def page_domain(domain_id):
    params = public_params()
    params['page'] = 'domains'
    params['account'] = current_user
    domain = Domain(domain_id=int(domain_id))
    if not domain.hydrate() or domain.account_id != current_user.account_id or domain.deleted:
        return abort(404)

    params['page_title'] = domain.name
    params['schedule_opts'] = [
        'hourly', 'daily', 'monthly'
    ]
    domain.get_stats()
    findings_arr = Findings().find_by([
        ('state', 'ACTIVE'),
        ('account_id', current_user.account_id),
        ('archived', 0),
        ('domain_id', domain.domain_id)
    ], limit=10000).load_details().to_list()
    domain_dict = {'findings_severity': charts.findings_severity_horizontal_bar(findings_arr)}
    dns_arr = DnsRecords().find_by([
        ('domain_id', domain.domain_id),
    ], limit=1000).to_list()
    params['dns_records'] = dns_arr

    for col in domain.cols():
        domain_dict[col] = getattr(domain, col)
    domain_dict['thumbnail_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/captures/{domain.name}-render-320x240.jpeg' if domain.screenshot else None
    domain_dict['screen_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/captures/{domain.name}-full.jpeg' if domain.screenshot else None
    if hasattr(domain, 'http_last_checked'):
        http_last_checked = datetime.fromisoformat(getattr(domain, 'http_last_checked')).replace(microsecond=0)
        for domain_stat in domain.stats:
            created_at = datetime.fromisoformat(domain_stat.created_at)
            if created_at == http_last_checked or domain_stat.domain_value == getattr(domain, 'http_last_checked'):
                domain_dict[domain_stat.domain_stat] = {
                    'value': domain_stat.domain_value,
                    'data': domain_stat.domain_data,
                }
    domain_dict['verification_hash'] = current_user.account.verification_hash
    project = Project(project_id=domain.project_id)
    project.hydrate()
    domain_dict['project'] = {
        'project_id': project.project_id,
        'name': project.name
    }
    if domain.parent_domain_id:
        parent_domain = Domain(domain_id=domain.parent_domain_id)
        parent_domain.hydrate()
        parent_dict = {}
        for pcol in parent_domain.cols():
            parent_dict[pcol] = getattr(parent_domain, pcol)
        domain_dict['parent'] = parent_dict

    params['domain'] = domain_dict

    return render_template('app/domain.html', **params)

@blueprint.route('/<domain_id>/jobs', methods=['GET'])
@login_required
def page_domain_jobs(domain_id):
    params = public_params()
    params['page'] = 'domains'
    params['account'] = current_user
    domain = Domain(domain_id=int(domain_id))
    if not domain.hydrate() or domain.account_id != current_user.account_id:
        return abort(404)

    params['page_title'] = domain.name
    params['schedule_opts'] = [
        'hourly', 'daily', 'monthly'
    ]
    domain.get_stats()
    findings_arr = Findings().find_by([
        ('state', 'ACTIVE'),
        ('account_id', current_user.account_id),
        ('archived', 0),
        ('domain_id', domain.domain_id)
    ], limit=1000).load_details().to_list()
    domain_dict = {'findings_severity': charts.findings_severity_horizontal_bar(findings_arr)}
    job_runs_arr = []
    for job_run in JobRuns().query_json([('$.target', domain.name)], limit=1000):
        if job_run.project_id == domain.project_id:
            job_runs_arr.append(job_run)
    params['job_runs'] = job_runs_arr

    for col in domain.cols():
        domain_dict[col] = getattr(domain, col)
    domain_dict['thumbnail_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/captures/{domain.name}-render-320x240.jpeg' if domain.screenshot else None
    domain_dict['screen_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/captures/{domain.name}-full.jpeg' if domain.screenshot else None
    if hasattr(domain, 'http_last_checked'):
        http_last_checked = datetime.fromisoformat(getattr(domain, 'http_last_checked')).replace(microsecond=0)
        for domain_stat in domain.stats:
            created_at = datetime.fromisoformat(domain_stat.created_at)
            if created_at == http_last_checked or domain_stat.domain_value == getattr(domain, 'http_last_checked'):
                domain_dict[domain_stat.domain_stat] = {
                    'value': domain_stat.domain_value,
                    'data': domain_stat.domain_data,
                }
    domain_dict['verification_hash'] = current_user.account.verification_hash
    project = Project(project_id=domain.project_id)
    project.hydrate()
    domain_dict['project'] = {
        'project_id': project.project_id,
        'name': project.name,
    }
    if domain.parent_domain_id:
        parent_domain = Domain(domain_id=domain.parent_domain_id)
        parent_domain.hydrate()
        parent_dict = {}
        for pcol in parent_domain.cols():
            parent_dict[pcol] = getattr(parent_domain, pcol)
        domain_dict['parent'] = parent_dict
    params['domain'] = domain_dict

    return render_template('app/domain-jobs.html', **params)

@blueprint.route('/<domain_id>/findings', methods=['GET'])
@login_required
def page_domain_findings(domain_id):
    params = public_params()
    params['page'] = 'domains'
    params['account'] = current_user
    domain = Domain(domain_id=int(domain_id))
    if not domain.hydrate() or domain.account_id != current_user.account_id:
        return abort(404)

    params['page_title'] = domain.name
    params['schedule_opts'] = [
        'hourly', 'daily', 'monthly'
    ]
    domain.get_stats()
    findings_arr = Findings().find_by([
        ('state', 'ACTIVE'),
        ('account_id', current_user.account_id),
        ('archived', 0),
        ('domain_id', domain.domain_id)
    ], limit=1000).load_details().to_list()
    domain_dict = {'findings_severity': charts.findings_severity_horizontal_bar(findings_arr)}
    for col in domain.cols():
        domain_dict[col] = getattr(domain, col)
    domain_dict['thumbnail_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/captures/{domain.name}-render-320x240.jpeg' if domain.screenshot else None
    domain_dict['screen_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/captures/{domain.name}-full.jpeg' if domain.screenshot else None
    if hasattr(domain, 'http_last_checked'):
        http_last_checked = datetime.fromisoformat(getattr(domain, 'http_last_checked')).replace(microsecond=0)
        for domain_stat in domain.stats:
            created_at = datetime.fromisoformat(domain_stat.created_at)
            if created_at == http_last_checked or domain_stat.domain_value == getattr(domain, 'http_last_checked'):
                domain_dict[domain_stat.domain_stat] = {
                    'value': domain_stat.domain_value,
                    'data': domain_stat.domain_data,
                }
    domain_dict['verification_hash'] = current_user.account.verification_hash
    project = Project(project_id=domain.project_id)
    project.hydrate()
    domain_dict['project'] = {
        'project_id': project.project_id,
        'name': project.name,
    }
    if domain.parent_domain_id:
        parent_domain = Domain(domain_id=domain.parent_domain_id)
        parent_domain.hydrate()
        parent_dict = {}
        for pcol in parent_domain.cols():
            parent_dict[pcol] = getattr(parent_domain, pcol)
        domain_dict['parent'] = parent_dict
    params['domain'] = domain_dict
    params['findings'] = Findings().find_by([
        ('domain_id', domain.domain_id),
    ]).load_details()

    return render_template('app/domain-findings.html', **params)

@blueprint.route('/<domain_id>/inventory', methods=['GET'])
@login_required
def page_domain_inventory(domain_id):
    params = public_params()
    params['page'] = 'domains'
    params['account'] = current_user
    domain = Domain(domain_id=int(domain_id))
    if not domain.hydrate() or domain.account_id != current_user.account_id:
        return abort(404)

    params['page_title'] = domain.name
    params['schedule_opts'] = [
        'hourly', 'daily', 'monthly'
    ]
    domain.get_stats()
    findings_arr = Findings().find_by([
        ('state', 'ACTIVE'),
        ('account_id', current_user.account_id),
        ('archived', 0),
        ('domain_id', domain.domain_id)
    ], limit=1000).load_details().to_list()
    domain_dict = {'findings_severity': charts.findings_severity_horizontal_bar(findings_arr)}
    for col in domain.cols():
        domain_dict[col] = getattr(domain, col)
    domain_dict['thumbnail_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/captures/{domain.name}-render-320x240.jpeg' if domain.screenshot else None
    domain_dict['screen_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/captures/{domain.name}-full.jpeg' if domain.screenshot else None
    if hasattr(domain, 'http_last_checked'):
        http_last_checked = datetime.fromisoformat(getattr(domain, 'http_last_checked')).replace(microsecond=0)
        for domain_stat in domain.stats:
            created_at = datetime.fromisoformat(domain_stat.created_at)
            if created_at == http_last_checked or domain_stat.domain_value == getattr(domain, 'http_last_checked'):
                domain_dict[domain_stat.domain_stat] = {
                    'value': domain_stat.domain_value,
                    'data': domain_stat.domain_data,
                }
    domain_dict['verification_hash'] = current_user.account.verification_hash
    project = Project(project_id=domain.project_id)
    project.hydrate()
    domain_dict['project'] = {
        'project_id': project.project_id,
        'name': project.name,
    }
    if domain.parent_domain_id:
        parent_domain = Domain(domain_id=domain.parent_domain_id)
        parent_domain.hydrate()
        parent_dict = {}
        for pcol in parent_domain.cols():
            parent_dict[pcol] = getattr(parent_domain, pcol)
        domain_dict['parent'] = parent_dict
    params['domain'] = domain_dict
    params['programs'] = InventoryItems().find_by([
        ('domain_id', domain.domain_id),
    ])
    known_ip_arr = KnownIps().find_by([
        ('domain_id', domain.domain_id),
    ], limit=1000).to_list()
    params['known_ips'] = known_ip_arr

    return render_template('app/domain-inventory.html', **params)

@blueprint.route('/<domain_id>/subdomains/<page>', methods=['GET'])
@blueprint.route('/<domain_id>/subdomains', methods=['GET'])
@login_required
def page_domain_subdomains(domain_id, page=1):
    params = public_params()
    params['page'] = 'domains'
    params['uri_page'] = 'domain'
    params['account'] = current_user
    domain = Domain(domain_id=int(domain_id))
    if not domain.hydrate() or domain.account_id != current_user.account_id:
        return abort(404)

    params['page_title'] = domain.name
    params['schedule_opts'] = [
        'hourly', 'daily', 'monthly'
    ]
    domain.get_stats()
    findings_arr = Findings().find_by([
        ('state', 'ACTIVE'),
        ('account_id', current_user.account_id),
        ('archived', 0),
        ('domain_id', domain.domain_id)
    ], limit=1000).load_details().to_list()
    domain_dict = {
        'subdomains': [],
        'findings_severity': charts.findings_severity_horizontal_bar(findings_arr),
    }
    for col in domain.cols():
        domain_dict[col] = getattr(domain, col)
    domain_dict['thumbnail_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/captures/{domain.name}-render-320x240.jpeg' if domain.screenshot else None
    domain_dict['screen_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/captures/{domain.name}-full.jpeg' if domain.screenshot else None
    if hasattr(domain, 'http_last_checked'):
        http_last_checked = datetime.fromisoformat(getattr(domain, 'http_last_checked')).replace(microsecond=0)
        for domain_stat in domain.stats:
            created_at = datetime.fromisoformat(domain_stat.created_at)
            if created_at == http_last_checked or domain_stat.domain_value == getattr(domain, 'http_last_checked'):
                domain_dict[domain_stat.domain_stat] = {
                    'value': domain_stat.domain_value,
                    'data': domain_stat.domain_data,
                }
    domain_dict['verification_hash'] = current_user.account.verification_hash
    project = Project(project_id=domain.project_id)
    project.hydrate()
    domain_dict['project'] = {
        'project_id': project.project_id,
        'name': project.name,
    }

    page_size = 10
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    search_filter = [
        ('account_id', current_user.account_id),
        ('project_id', project.project_id),
        ('deleted', 0),
        ('parent_domain_id', domain.domain_id),
    ]
    params['pagination'] = Domains().pagination(
        search_filter=search_filter,
        page_size=page_size,
        page_num=page_num
    )
    params['pagination']['page_id'] = domain_id
    params['pagination']['sub_page'] = 'subdomains'
    for subdomain in Domains().find_by(search_filter, limit=page_size, offset=offset, cache_key=None):
        subdomain.get_stats()
        subdomain_dict = {}
        for col in subdomain.cols():
            subdomain_dict[col] = getattr(subdomain, col)
        subdomain_dict['thumbnail_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/captures/{subdomain.name}-render-320x240.jpeg' if subdomain.screenshot else None
        subdomain_dict['screen_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/captures/{subdomain.name}-full.jpeg' if subdomain.screenshot else None
        if hasattr(subdomain, 'http_last_checked'):
            http_last_checked = datetime.fromisoformat(getattr(subdomain, 'http_last_checked')).replace(microsecond=0)
            for domain_stat in subdomain.stats:
                created_at = datetime.fromisoformat(domain_stat.created_at)
                if created_at == http_last_checked or domain_stat.domain_value == getattr(subdomain, 'http_last_checked'):
                    subdomain_dict[domain_stat.domain_stat] = {
                        'value': domain_stat.domain_value,
                        'data': domain_stat.domain_data,
                    }
        domain_dict['subdomains'].append(subdomain_dict)

    if domain.parent_domain_id:
        parent_domain = Domain(domain_id=domain.parent_domain_id)
        parent_domain.hydrate()
        parent_dict = {}
        for pcol in parent_domain.cols():
            parent_dict[pcol] = getattr(parent_domain, pcol)
        domain_dict['parent'] = parent_dict
    params['domain'] = domain_dict

    return render_template('app/domain-subdomains.html', **params)
