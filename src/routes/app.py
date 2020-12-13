from datetime import datetime
from flask import render_template, Blueprint, jsonify, request, abort
from flask_login import current_user, login_required
from trivialsec.helpers.config import config
from trivialsec.helpers.log_manager import logger
from trivialsec import models
import actions
from actions import charts


blueprint = Blueprint('app', __name__)

@blueprint.route('/domains/<page>', methods=['GET'])
@blueprint.route('/domains', methods=['GET'])
@login_required
def domains_page(page: int = 1):
    params = actions.get_frontend_conf()
    params['page_title'] = 'Domains'
    params['page'] = 'domains'
    params['uri_page'] = 'domains'
    params['account'] = current_user
    page_size = 10
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    search_filter = [
        ('account_id', current_user.account_id),
        ('deleted', 0),
    ]
    params['pagination'] = models.Domains().pagination(
        search_filter=search_filter,
        page_size=page_size,
        page_num=page_num
    )
    domains = models.Domains().find_by(search_filter, limit=page_size, offset=offset)
    domains_arr = []
    for domain in domains:
        domain.get_stats()
        domain_dict = {}
        for col in domain.cols():
            domain_dict[col] = getattr(domain, col)
        domain_dict['thumbnail_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/{config.aws.get("public_object_prefix")}{domain.name}-render-320x240.jpeg' if domain.screenshot else None
        domain_dict['screen_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/{config.aws.get("public_object_prefix")}{domain.name}-full.jpeg' if domain.screenshot else None
        if hasattr(domain, 'http_last_checked'):
            http_last_checked = datetime.fromisoformat(getattr(domain, 'http_last_checked')).replace(microsecond=0)
            for domain_stat in domain.stats:
                created_at = datetime.fromisoformat(domain_stat.created_at)
                if created_at == http_last_checked or domain_stat.domain_value == getattr(domain, 'http_last_checked'):
                    domain_dict[domain_stat.domain_stat] = {
                        'value': domain_stat.domain_value,
                        'data': domain_stat.domain_data,
                    }
        domains_arr.append(domain_dict)

    params['domains'] = domains_arr

    return render_template('app/domains.html.j2', **params)

@blueprint.route('/domain/<domain_id>', methods=['GET'])
@login_required
def domain_page(domain_id):
    params = actions.get_frontend_conf()
    params['page'] = 'domains'
    params['account'] = current_user
    domain = models.Domain(domain_id=int(domain_id))
    if not domain.hydrate() or domain.account_id != current_user.account_id:
        return abort(404)

    params['page_title'] = domain.name
    params['schedule_opts'] = [
        'hourly', 'daily', 'monthly'
    ]
    domain.get_stats()
    findings_arr = models.Findings().find_by([
        ('state', 'ACTIVE'),
        ('account_id', current_user.account_id),
        ('archived', 0),
        ('domain_id', domain.domain_id)
    ], limit=1000).load_details().to_list()
    domain_dict = {
        'findings_severity': charts.findings_severity_horizontal_bar(findings_arr),
        'findings_count': len(findings_arr),
    }
    dns_arr = models.DnsRecords().find_by([
        ('domain_id', domain.domain_id),
    ], limit=1000).to_list()
    params['dns_records'] = dns_arr
    known_ip_arr = models.KnownIps().find_by([
        ('domain_id', domain.domain_id),
    ], limit=1000).to_list()
    params['known_ips'] = known_ip_arr

    for col in domain.cols():
        domain_dict[col] = getattr(domain, col)
    domain_dict['thumbnail_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/{config.aws.get("public_object_prefix")}{domain.name}-render-320x240.jpeg' if domain.screenshot else None
    domain_dict['screen_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/{config.aws.get("public_object_prefix")}{domain.name}-full.jpeg' if domain.screenshot else None
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
    project = models.Project(project_id=domain.project_id)
    project.hydrate()
    domain_dict['project'] = {
        'project_id': project.project_id,
        'name': project.name,
        'tracking_id': project.tracking_id,
    }
    params['domain'] = domain_dict
    params['jobs_count'] = len(models.JobRuns().query_json([
        ('state', ['queued', 'starting', 'processing', 'finalising']),
        ('$.target', domain.name),
    ]))
    params['programs_count'] = models.Programs().count([
        ('domain_id', domain.domain_id),
    ])
    params['subdomains_count'] = models.Domains().count([
        ('deleted', 0),
        ('parent_domain_id', domain.domain_id),
    ])
    params['findings_count'] = models.Findings().count([
        ('domain_id', domain.domain_id),
        ('archived', 0),
    ])
    return render_template('app/domain.html.j2', **params)

@blueprint.route('/domain/<domain_id>/jobs', methods=['GET'])
@login_required
def domain_page_jobs(domain_id):
    params = actions.get_frontend_conf()
    params['page'] = 'domains'
    params['account'] = current_user
    domain = models.Domain(domain_id=int(domain_id))
    if not domain.hydrate() or domain.account_id != current_user.account_id:
        return abort(404)

    params['page_title'] = domain.name
    params['schedule_opts'] = [
        'hourly', 'daily', 'monthly'
    ]
    domain.get_stats()
    findings_arr = models.Findings().find_by([
        ('state', 'ACTIVE'),
        ('account_id', current_user.account_id),
        ('archived', 0),
        ('domain_id', domain.domain_id)
    ], limit=1000).load_details().to_list()
    domain_dict = {
        'findings_severity': charts.findings_severity_horizontal_bar(findings_arr),
        'findings_count': len(findings_arr),
    }
    job_runs_arr = []
    for job_run in models.JobRuns().query_json([('$.target', domain.name)], limit=1000):
        if job_run.project_id == domain.project_id:
            job_runs_arr.append(job_run)
    params['job_runs'] = job_runs_arr

    for col in domain.cols():
        domain_dict[col] = getattr(domain, col)
    domain_dict['thumbnail_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/{config.aws.get("public_object_prefix")}{domain.name}-render-320x240.jpeg' if domain.screenshot else None
    domain_dict['screen_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/{config.aws.get("public_object_prefix")}{domain.name}-full.jpeg' if domain.screenshot else None
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
    project = models.Project(project_id=domain.project_id)
    project.hydrate()
    domain_dict['project'] = {
        'project_id': project.project_id,
        'name': project.name,
    }
    params['domain'] = domain_dict
    params['jobs_count'] = len(models.JobRuns().query_json([
        ('state', ['queued', 'starting', 'processing', 'finalising']),
        ('$.target', domain.name),
    ]))
    params['programs_count'] = models.Programs().count([
        ('domain_id', domain.domain_id),
    ])
    params['subdomains_count'] = models.Domains().count([
        ('deleted', 0),
        ('parent_domain_id', domain.domain_id),
    ])
    params['findings_count'] = models.Findings().count([
        ('domain_id', domain.domain_id),
        ('archived', 0),
    ])
    return render_template('app/domain-jobs.html.j2', **params)

@blueprint.route('/domain/<domain_id>/findings', methods=['GET'])
@login_required
def domain_page_findings(domain_id):
    params = actions.get_frontend_conf()
    params['page'] = 'domains'
    params['account'] = current_user
    domain = models.Domain(domain_id=int(domain_id))
    if not domain.hydrate() or domain.account_id != current_user.account_id:
        return abort(404)

    params['page_title'] = domain.name
    params['schedule_opts'] = [
        'hourly', 'daily', 'monthly'
    ]
    domain.get_stats()
    findings_arr = models.Findings().find_by([
        ('state', 'ACTIVE'),
        ('account_id', current_user.account_id),
        ('archived', 0),
        ('domain_id', domain.domain_id)
    ], limit=1000).load_details().to_list()
    domain_dict = {
        'findings_severity': charts.findings_severity_horizontal_bar(findings_arr),
        'findings_count': len(findings_arr),
    }
    for col in domain.cols():
        domain_dict[col] = getattr(domain, col)
    domain_dict['thumbnail_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/{config.aws.get("public_object_prefix")}{domain.name}-render-320x240.jpeg' if domain.screenshot else None
    domain_dict['screen_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/{config.aws.get("public_object_prefix")}{domain.name}-full.jpeg' if domain.screenshot else None
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
    project = models.Project(project_id=domain.project_id)
    project.hydrate()
    domain_dict['project'] = {
        'project_id': project.project_id,
        'name': project.name,
    }
    params['domain'] = domain_dict
    params['findings'] = []
    params['findings'] = models.Findings().find_by([
        ('domain_id', domain.domain_id),
    ]).load_details()

    params['jobs_count'] = len(models.JobRuns().query_json([
        ('state', ['queued', 'starting', 'processing', 'finalising']),
        ('$.target', domain.name),
    ]))
    params['programs_count'] = models.Programs().count([
        ('domain_id', domain.domain_id),
    ])
    params['subdomains_count'] = models.Domains().count([
        ('deleted', 0),
        ('parent_domain_id', domain.domain_id),
    ])
    params['findings_count'] = models.Findings().count([
        ('domain_id', domain.domain_id),
        ('archived', 0),
    ])
    return render_template('app/domain-findings.html.j2', **params)

@blueprint.route('/domain/<domain_id>/inventory', methods=['GET'])
@login_required
def domain_page_inventory(domain_id):
    params = actions.get_frontend_conf()
    params['page'] = 'domains'
    params['account'] = current_user
    domain = models.Domain(domain_id=int(domain_id))
    if not domain.hydrate() or domain.account_id != current_user.account_id:
        return abort(404)

    params['page_title'] = domain.name
    params['schedule_opts'] = [
        'hourly', 'daily', 'monthly'
    ]
    domain.get_stats()
    findings_arr = models.Findings().find_by([
        ('state', 'ACTIVE'),
        ('account_id', current_user.account_id),
        ('archived', 0),
        ('domain_id', domain.domain_id)
    ], limit=1000).load_details().to_list()
    domain_dict = {
        'findings_severity': charts.findings_severity_horizontal_bar(findings_arr),
        'findings_count': len(findings_arr),
    }
    for col in domain.cols():
        domain_dict[col] = getattr(domain, col)
    domain_dict['thumbnail_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/{config.aws.get("public_object_prefix")}{domain.name}-render-320x240.jpeg' if domain.screenshot else None
    domain_dict['screen_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/{config.aws.get("public_object_prefix")}{domain.name}-full.jpeg' if domain.screenshot else None
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
    project = models.Project(project_id=domain.project_id)
    project.hydrate()
    domain_dict['project'] = {
        'project_id': project.project_id,
        'name': project.name,
    }
    params['domain'] = domain_dict
    params['programs'] = models.Programs().find_by([
        ('domain_id', domain.domain_id),
    ])

    params['jobs_count'] = len(models.JobRuns().query_json([
        ('state', ['queued', 'starting', 'processing', 'finalising']),
        ('$.target', domain.name),
    ]))
    params['programs_count'] = models.Programs().count([
        ('domain_id', domain.domain_id),
    ])
    params['subdomains_count'] = models.Domains().count([
        ('deleted', 0),
        ('parent_domain_id', domain.domain_id),
    ])
    params['findings_count'] = models.Findings().count([
        ('domain_id', domain.domain_id),
        ('archived', 0),
    ])
    return render_template('app/domain-inventory.html.j2', **params)

@blueprint.route('/domain/<domain_id>/subdomains/<page>', methods=['GET'])
@blueprint.route('/domain/<domain_id>/subdomains', methods=['GET'])
@login_required
def domain_page_subdomains(domain_id, page=1):
    params = actions.get_frontend_conf()
    params['page'] = 'domains'
    params['uri_page'] = 'domain'
    params['account'] = current_user
    domain = models.Domain(domain_id=int(domain_id))
    if not domain.hydrate() or domain.account_id != current_user.account_id:
        return abort(404)

    params['page_title'] = domain.name
    params['schedule_opts'] = [
        'hourly', 'daily', 'monthly'
    ]
    domain.get_stats()
    findings_arr = models.Findings().find_by([
        ('state', 'ACTIVE'),
        ('account_id', current_user.account_id),
        ('archived', 0),
        ('domain_id', domain.domain_id)
    ], limit=1000).load_details().to_list()
    domain_dict = {
        'subdomains': [],
        'findings_severity': charts.findings_severity_horizontal_bar(findings_arr),
        'findings_count': len(findings_arr),
    }
    for col in domain.cols():
        domain_dict[col] = getattr(domain, col)
    domain_dict['thumbnail_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/{config.aws.get("public_object_prefix")}{domain.name}-render-320x240.jpeg' if domain.screenshot else None
    domain_dict['screen_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/{config.aws.get("public_object_prefix")}{domain.name}-full.jpeg' if domain.screenshot else None
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
    project = models.Project(project_id=domain.project_id)
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
    params['pagination'] = models.Domains().pagination(
        search_filter=search_filter,
        page_size=page_size,
        page_num=page_num
    )
    params['pagination']['page_id'] = domain_id
    params['pagination']['sub_page'] = 'subdomains'
    subdomains = models.Domains()
    for subdomain in subdomains.find_by(search_filter, limit=page_size, offset=offset):
        subdomain.get_stats()
        subdomain_dict = {}
        for col in subdomain.cols():
            subdomain_dict[col] = getattr(subdomain, col)
        subdomain_dict['thumbnail_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/{config.aws.get("public_object_prefix")}{subdomain.name}-render-320x240.jpeg' if subdomain.screenshot else None
        subdomain_dict['screen_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/{config.aws.get("public_object_prefix")}{subdomain.name}-full.jpeg' if subdomain.screenshot else None
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

    params['domain'] = domain_dict
    params['jobs_count'] = len(models.JobRuns().query_json([
        ('state', ['queued', 'starting', 'processing', 'finalising']),
        ('$.target', domain.name),
    ]))
    params['programs_count'] = models.Programs().count([
        ('domain_id', domain.domain_id),
    ])
    params['subdomains_count'] = models.Domains().count([
        ('deleted', 0),
        ('parent_domain_id', domain.domain_id),
    ])
    params['findings_count'] = models.Findings().count([
        ('domain_id', domain.domain_id),
        ('archived', 0),
    ])
    return render_template('app/domain-subdomains.html.j2', **params)

@blueprint.route('/projects', methods=['GET'])
@login_required
def app_projects():
    params = actions.get_frontend_conf()
    params['page_title'] = 'Projects'
    params['page'] = 'projects'
    params['account'] = current_user

    project_arr = []
    projects = models.Projects().find_by([
        ('account_id', current_user.account_id),
        ('deleted', 0),
    ], limit=10)
    domain_names = []
    project_names = []
    for project in projects:
        domains = models.Domains()
        project_names.append(project.name)
        project_arr.append({
            'project_id': project.project_id,
            'name': project.name,
            'domains': domains.count([
                ('parent_domain_id', None),
                ('deleted', 0),
                ('account_id', current_user.account_id),
                ('project_id', project.project_id)
            ]),
        })
    params['projects'] = project_arr
    domains = models.Domains()
    for domain in domains.find_by([('account_id', current_user.account_id)], order_by=['created_at', 'DESC'], limit=1000):
        domain_names.append(domain.name)
    params['datalists'] = [{
        'name': 'projects',
        'options': project_names
    },{
        'name': 'domains',
        'options': domain_names
    }]

    return render_template('app/projects.html.j2', **params)

@blueprint.route('/project/<project_id>/domains/<page>', methods=['GET'])
@blueprint.route('/project/<project_id>', methods=['GET'])
@login_required
def project_page(project_id, page: int = 1):
    params = actions.get_frontend_conf()
    params['page'] = 'projects'
    params['uri_page'] = 'project'
    params['account'] = current_user
    project = models.Project(project_id=int(project_id))
    if not project.hydrate() or project.account_id != current_user.account_id:
        return abort(404)

    params['page_title'] = project.name
    page_size = 10
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    search_filter = [
        ('account_id', current_user.account_id),
        ('project_id', project.project_id),
        ('deleted', 0),
        ('parent_domain_id', None),
    ]
    params['pagination'] = models.Domains().pagination(
        search_filter=search_filter,
        page_size=page_size,
        page_num=page_num
    )
    params['pagination']['page_id'] = project_id
    params['pagination']['sub_page'] = 'domains'
    params['jobs_count'] = models.JobRuns().count([
        ('project_id', project.project_id),
        ('state', ['queued', 'starting', 'processing', 'finalising']),
    ])
    params['reports_count'] = 0

    project_dict = {'domains': []}
    for col in project.cols():
        project_dict[col] = getattr(project, col)

    domains = models.Domains()
    for domain in domains.find_by(search_filter, limit=page_size, offset=offset):
        domain.get_stats()
        domain_dict = {}
        for col in domain.cols():
            domain_dict[col] = getattr(domain, col)
        domain_dict['thumbnail_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/{config.aws.get("public_object_prefix")}{domain.name}-render-320x240.jpeg' if domain.screenshot else None
        domain_dict['screen_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/{config.aws.get("public_object_prefix")}{domain.name}-full.jpeg' if domain.screenshot else None
        if hasattr(domain, 'http_last_checked'):
            http_last_checked = datetime.fromisoformat(getattr(domain, 'http_last_checked')).replace(microsecond=0)
            for domain_stat in domain.stats:
                created_at = datetime.fromisoformat(domain_stat.created_at)
                if created_at == http_last_checked or domain_stat.domain_value == getattr(domain, 'http_last_checked'):
                    domain_dict[domain_stat.domain_stat] = {
                        'value': domain_stat.domain_value,
                        'data': domain_stat.domain_data,
                    }
        project_dict['domains'].append(domain_dict)

    params['domains_count'] = len(project_dict['domains'])
    params['project'] = project_dict

    return render_template('app/project.html.j2', **params)

@blueprint.route('/project/<project_id>/jobs', methods=['GET'])
@login_required
def project_page_jobs(project_id, page: int = 1):
    params = actions.get_frontend_conf()
    params['page'] = 'projects'
    params['uri_page'] = 'project'
    params['account'] = current_user
    project = models.Project(project_id=int(project_id))
    if not project.hydrate() or project.account_id != current_user.account_id:
        return abort(404)

    params['page_title'] = project.name
    page_size = 10
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    search_filter = [
        ('account_id', current_user.account_id),
        ('project_id', project.project_id),
        ('deleted', 0),
    ]
    params['pagination'] = models.Domains().pagination(
        search_filter=search_filter,
        page_size=page_size,
        page_num=page_num
    )
    params['pagination']['page_id'] = project_id
    params['pagination']['sub_page'] = 'domains'
    project_dict = {'domains': []}
    for col in project.cols():
        project_dict[col] = getattr(project, col)

    params['domains_count'] = models.Domains().count([
        ('account_id', current_user.account_id),
        ('project_id', project.project_id),
        ('deleted', 0),
        ('parent_domain_id', None),
    ])
    params['jobs_count'] = models.JobRuns().count([
        ('project_id', project.project_id),
        ('state', ['queued', 'starting', 'processing', 'finalising']),
    ])
    params['reports_count'] = 0
    params['project'] = project_dict
    params['error_jobs'] = models.JobRuns().find_by([
        ('project_id', project.project_id),
        ('state', ['error', 'aborted']),
    ], limit=1000).to_list()
    params['complete_jobs'] = models.JobRuns().find_by([
        ('project_id', project.project_id),
        ('state', 'completed'),
    ], limit=1000).to_list()
    params['processing_jobs'] = models.JobRuns().find_by([
        ('project_id', project.project_id),
        ('state', ['starting', 'processing', 'finalising']),
    ], limit=1000).to_list()
    params['queued_jobs'] = models.JobRuns().find_by([
        ('project_id', project.project_id),
        ('state', 'queued'),
    ], limit=1000).to_list()

    return render_template('app/project-jobs.html.j2', **params)

@blueprint.route('/project/<project_id>/reports', methods=['GET'])
@blueprint.route('/project/<project_id>/reports/<page>', methods=['GET'])
@login_required
def project_reports(project_id, page: int = 1):
    params = actions.get_frontend_conf()
    params['page'] = 'projects'
    params['uri_page'] = 'project'
    params['account'] = current_user
    project = models.Project(project_id=int(project_id))
    if not project.hydrate() or project.account_id != current_user.account_id:
        return abort(404)

    params['page_title'] = project.name
    page_size = 10
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    search_filter = [
        ('account_id', current_user.account_id),
        ('project_id', project.project_id),
        ('deleted', 0),
    ]
    params['domains_count'] = models.Domains().count([
        ('account_id', current_user.account_id),
        ('project_id', project.project_id),
        ('deleted', 0),
        ('parent_domain_id', None),
    ])
    params['jobs_count'] = models.JobRuns().count([
        ('project_id', project.project_id),
        ('state', ['queued', 'starting', 'processing', 'finalising']),
    ])
    params['reports_count'] = 0
    project_dict = {'reports': []}
    for col in project.cols():
        project_dict[col] = getattr(project, col)

    params['project'] = project_dict

    return render_template('app/project-reports.html.j2', **params)

@blueprint.route('/notifications', methods=['GET'])
@login_required
def notifications():
    noti_arr = []
    notis = models.Notifications().find_by([('account_id', current_user.account_id)])
    for noti in notis:
        if noti.marked_read == 1:
            continue
        noti_arr.append({
            'id': noti.notification_id,
            'description': noti.description,
            'url': noti.url,
            'created_at': noti.created_at
        })

    params = actions.get_frontend_conf()
    params['page_title'] = 'Notifications'
    params['page'] = 'notifications'
    params['account'] = current_user
    params['notifications'] = noti_arr
    return render_template('app/notifications.html.j2', **params)

@blueprint.route('/repositories', methods=['GET'])
@login_required
def repositories():
    params = actions.get_frontend_conf()
    params['page_title'] = 'Repositories'
    params['page'] = 'repositories'
    params['account'] = current_user

    return render_template('app/repositories.html.j2', **params)

@blueprint.route('/inventory', methods=['GET'])
@login_required
def inventory():
    params = actions.get_frontend_conf()
    params['page_title'] = 'Inventory'
    params['page'] = 'inventory'
    params['account'] = current_user

    return render_template('app/inventory.html.j2', **params)

@blueprint.route('/findings/<page>', methods=['GET'])
@blueprint.route('/findings', methods=['GET', 'POST'])
@login_required
def findings(page: int = 1):
    params = actions.get_frontend_conf()
    params['page_title'] = 'Findings'
    params['page'] = 'findings'
    params['account'] = current_user
    page_size = 10
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size

    search_filter = [
        ('state', 'ACTIVE'),
        ('account_id', current_user.account_id),
        ('archived', 0),
    ]
    findings = models.Findings().find_by(search_filter, limit=page_size, offset=offset).load_details()
    all_findings = models.Findings().find_by(search_filter, limit=1000).load_details().to_list()
    params['pagination'] = models.Findings().pagination(search_filter=search_filter, page_size=page_size, page_num=page_num)
    labels = [
        models.Finding.RATING_INFO,
        models.Finding.RATING_LOW,
        models.Finding.RATING_MEDIUM,
        models.Finding.RATING_HIGH,
        models.Finding.RATING_CRITICAL,
    ]
    params['agg_severity_normalized'] = charts.findings_severity_donut(all_findings)
    params['agg_confidence'] = charts.findings_confidence_donut(all_findings)
    params['agg_criticality'] = charts.findings_criticality_donut(all_findings)

    params['members'] = []
    members = models.Members().find_by([('account_id', current_user.account_id)], limit=1000)
    for member in members:
        params['members'].append({
            'id': member.member_id,
            'email': member.email,
            'verified': member.verified
        })
    params['projects'] = []
    projects = models.Projects().find_by([('account_id', current_user.account_id)], limit=1000)
    for project in projects:
        if project.deleted:
            continue
        params['projects'].append({
            'id': project.project_id,
            'name': project.name
        })

    params['findings'] = []
    for finding in findings:
        finding.get_notes()
        params['findings'].append(finding)

    return render_template('app/findings.html.j2', **params)

@blueprint.route('/reports', methods=['GET'])
@login_required
def reports():
    params = actions.get_frontend_conf()
    params['page_title'] = 'Reports'
    params['page'] = 'reports'
    params['account'] = current_user

    return render_template('app/reports.html.j2', **params)

@blueprint.route('/feed', methods=['GET'])
@login_required
def feed():
    params = actions.get_frontend_conf()
    params['page_title'] = 'Feed'
    params['page'] = 'feed'
    params['account'] = current_user

    return render_template('app/feed.html.j2', **params)

@blueprint.route('/', methods=['GET'])
@login_required
def dashboard():
    params = actions.get_frontend_conf()
    params['page_title'] = 'Dashboard'
    params['page'] = 'dashboard'
    params['account'] = current_user
    return render_template('app/dashboard.html.j2', **params)
