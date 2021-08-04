from datetime import datetime
from flask import render_template, Blueprint, abort
from flask_login import current_user, login_required
from trivialsec.helpers.config import config
from trivialsec.models.domain import Domains
from trivialsec.models.job_run import JobRuns
from trivialsec.models.project import Project
from trivialsec.models.finding import Findings
from templates import public_params


blueprint = Blueprint('project', __name__)

@blueprint.route('/<project_id>/domains/<page>', methods=['GET'])
@blueprint.route('/<project_id>', methods=['GET'])
@login_required
def page_project(project_id, page: int = 1):
    params = public_params()
    params['page'] = 'projects'
    params['uri_page'] = 'project'
    params['account'] = current_user
    project = Project(project_id=int(project_id))
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
    params['pagination'] = Domains().pagination(
        search_filter=search_filter,
        page_size=page_size,
        page_num=page_num
    )
    params['pagination']['page_id'] = project_id
    params['pagination']['sub_page'] = 'domains'

    project_dict = {'domains': []}
    project_dict['findings_info'] = Findings().count_informational([
        ('state', 'ACTIVE'),
        ('archived', 0),
        ('account_id', current_user.account_id),
        ('project_id', project.project_id)
    ])
    project_dict['findings_low'] = Findings().count_low_severity([
        ('state', 'ACTIVE'),
        ('archived', 0),
        ('account_id', current_user.account_id),
        ('project_id', project.project_id)
    ])
    project_dict['findings_med'] = Findings().count_medium_severity([
        ('state', 'ACTIVE'),
        ('archived', 0),
        ('account_id', current_user.account_id),
        ('project_id', project.project_id)
    ])
    project_dict['findings_high'] = Findings().count_high_severity([
        ('state', 'ACTIVE'),
        ('archived', 0),
        ('account_id', current_user.account_id),
        ('project_id', project.project_id)
    ])
    project_dict['jobs_completed'] = JobRuns().count([
        ('state', 'completed'),
        ('account_id', current_user.account_id),
        ('project_id', project.project_id)
    ])
    project_dict['jobs_total'] = JobRuns().count([
        ('account_id', current_user.account_id),
        ('project_id', project.project_id)
    ])

    for col in project.cols():
        project_dict[col] = getattr(project, col)

    domains = Domains()
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

    params['project'] = project_dict

    return render_template('app/project.html', **params)

@blueprint.route('/<project_id>/jobs', methods=['GET'])
@login_required
def page_project_jobs(project_id, page: int = 1):
    params = public_params()
    params['page'] = 'projects'
    params['uri_page'] = 'project'
    params['account'] = current_user
    project = Project(project_id=int(project_id))
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
    params['pagination'] = Domains().pagination(
        search_filter=search_filter,
        page_size=page_size,
        page_num=page_num
    )
    params['pagination']['page_id'] = project_id
    params['pagination']['sub_page'] = 'domains'
    project_dict = {'domains': []}
    for col in project.cols():
        project_dict[col] = getattr(project, col)

    params['project'] = project_dict
    params['error_jobs'] = JobRuns().find_by([
        ('project_id', project.project_id),
        ('state', ['error', 'aborted']),
    ], limit=1000).to_list()
    params['complete_jobs'] = JobRuns().find_by([
        ('project_id', project.project_id),
        ('state', 'completed'),
    ], limit=1000).to_list()
    params['processing_jobs'] = JobRuns().find_by([
        ('project_id', project.project_id),
        ('state', ['starting', 'processing', 'finalising']),
    ], limit=1000).to_list()
    params['queued_jobs'] = JobRuns().find_by([
        ('project_id', project.project_id),
        ('state', 'queued'),
    ], limit=1000).to_list()
    project_dict['findings_info'] = Findings().count_informational([
        ('state', 'ACTIVE'),
        ('archived', 0),
        ('account_id', current_user.account_id),
        ('project_id', project.project_id)
    ])
    project_dict['findings_low'] = Findings().count_low_severity([
        ('state', 'ACTIVE'),
        ('archived', 0),
        ('account_id', current_user.account_id),
        ('project_id', project.project_id)
    ])
    project_dict['findings_med'] = Findings().count_medium_severity([
        ('state', 'ACTIVE'),
        ('archived', 0),
        ('account_id', current_user.account_id),
        ('project_id', project.project_id)
    ])
    project_dict['findings_high'] = Findings().count_high_severity([
        ('state', 'ACTIVE'),
        ('archived', 0),
        ('account_id', current_user.account_id),
        ('project_id', project.project_id)
    ])
    project_dict['jobs_completed'] = JobRuns().count([
        ('state', 'completed'),
        ('account_id', current_user.account_id),
        ('project_id', project.project_id)
    ])
    project_dict['jobs_total'] = JobRuns().count([
        ('account_id', current_user.account_id),
        ('project_id', project.project_id)
    ])

    return render_template('app/project-jobs.html', **params)

@blueprint.route('/<project_id>/reports', methods=['GET'])
@blueprint.route('/<project_id>/reports/<page>', methods=['GET'])
@login_required
def page_project_reports(project_id, page: int = 1):
    params = public_params()
    params['page'] = 'projects'
    params['uri_page'] = 'project'
    params['account'] = current_user
    project = Project(project_id=int(project_id))
    if not project.hydrate() or project.account_id != current_user.account_id:
        return abort(404)

    params['page_title'] = project.name
    page_size = 10
    page = int(page)
    project_dict = {'reports': []}
    for col in project.cols():
        project_dict[col] = getattr(project, col)
    project_dict['findings_info'] = Findings().count_informational([
        ('state', 'ACTIVE'),
        ('archived', 0),
        ('account_id', current_user.account_id),
        ('project_id', project.project_id)
    ])
    project_dict['findings_low'] = Findings().count_low_severity([
        ('state', 'ACTIVE'),
        ('archived', 0),
        ('account_id', current_user.account_id),
        ('project_id', project.project_id)
    ])
    project_dict['findings_med'] = Findings().count_medium_severity([
        ('state', 'ACTIVE'),
        ('archived', 0),
        ('account_id', current_user.account_id),
        ('project_id', project.project_id)
    ])
    project_dict['findings_high'] = Findings().count_high_severity([
        ('state', 'ACTIVE'),
        ('archived', 0),
        ('account_id', current_user.account_id),
        ('project_id', project.project_id)
    ])
    project_dict['jobs_completed'] = JobRuns().count([
        ('state', 'completed'),
        ('account_id', current_user.account_id),
        ('project_id', project.project_id)
    ])
    project_dict['jobs_total'] = JobRuns().count([
        ('account_id', current_user.account_id),
        ('project_id', project.project_id)
    ])

    params['project'] = project_dict

    return render_template('app/project-reports.html', **params)
