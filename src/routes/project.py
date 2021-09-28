from flask import render_template, Blueprint, abort
from flask_login import current_user, login_required
from trivialsec.helpers.config import config
from trivialsec.models.domain import Domain, DomainMonitoring
from trivialsec.models.job_run import JobRuns
from trivialsec.models.project import Project
from trivialsec.models.finding import Findings
from templates import public_params


blueprint = Blueprint('project', __name__)

@blueprint.route('/<canonical_id>/domains/<page>', methods=['GET'])
@blueprint.route('/<canonical_id>', methods=['GET'])
@login_required
def page_project(canonical_id :str, page: int = 1):
    params = public_params()
    params['page'] = 'projects'
    params['uri_page'] = 'project'
    params['account'] = current_user
    params['js_includes'] = [
        "vendor/timeago.min.js",
        "vendor/chart.3.5.1.min.js",
        "app/project.min.js"
    ]
    params['css_includes'] = [
        "app/main.css",
        "app/project.css"
    ]
    project = Project(canonical_id=canonical_id)
    if not project.hydrate('canonical_id') or project.account_id != current_user.account_id:
        return abort(404)

    params['page_title'] = project.name
    page_size = 10
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    search_filter = [
        ('account_id', current_user.account_id),
        ('project_id', project.project_id),
    ]
    params['pagination'] = DomainMonitoring().pagination(
        search_filter=search_filter,
        page_size=page_size,
        page_num=page_num
    )
    params['pagination']['page_id'] = project.canonical_id
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

    for domain_record in DomainMonitoring().find_by(search_filter, limit=page_size, offset=offset):
        domain = Domain()
        domain.hydrate()
        domain_dict = domain.get_doc()
        domain_dict['domain_monitoring_id'] = domain_record.domain_monitoring_id
        domain_dict['schedule'] = domain_record.schedule
        domain_dict['enabled'] = domain_record.enabled
        domain_dict['account_id'] = domain_record.account_id
        domain_dict['project_id'] = domain_record.project_id
        # domain_dict['thumbnail_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/captures/{domain.domain_name}-render-320x240.jpeg' if domain.screenshot else None
        # domain_dict['screen_url'] = f'https://{config.aws.get("public_bucket")}.s3-{config.aws.get("region_name")}.amazonaws.com/captures/{domain.domain_name}-full.jpeg' if domain.screenshot else None
        project_dict['domains'].append(domain_dict)

    params['project'] = project_dict
    params['page_title'] = project.name
    params['toasts'] = []
    if len(params['project']['domains']) == 1:
        params['toasts'].append({
            'type': 'warning',
            'heading': 'Loading',
            'message': 'Please allow a moment to prepare the new project',
        })

    return render_template('app/project.html', **params)

@blueprint.route('/<canonical_id>/jobs', methods=['GET'])
@login_required
def page_project_jobs(canonical_id :str, page :int = 1):
    params = public_params()
    params['page'] = 'projects'
    params['uri_page'] = 'project'
    params['account'] = current_user
    project = Project(project_id=canonical_id)
    if not project.hydrate() or project.account_id != current_user.account_id:
        return abort(404)

    params['page_title'] = project.name
    page_size = 10
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    # search_filter = [
    #     ('account_id', current_user.account_id),
    #     ('project_id', project.project_id),
    #     ('deleted', 0),
    # ]
    # params['pagination'] = Domains().pagination(
    #     search_filter=search_filter,
    #     page_size=page_size,
    #     page_num=page_num
    # )
    # params['pagination']['page_id'] = project_id
    # params['pagination']['sub_page'] = 'domains'
    # project_dict = {'domains': []}
    # for col in project.cols():
    #     project_dict[col] = getattr(project, col)

    # params['project'] = project_dict
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
    # project_dict['findings_info'] = Findings().count_informational([
    #     ('state', 'ACTIVE'),
    #     ('archived', 0),
    #     ('account_id', current_user.account_id),
    #     ('project_id', project.project_id)
    # ])
    # project_dict['findings_low'] = Findings().count_low_severity([
    #     ('state', 'ACTIVE'),
    #     ('archived', 0),
    #     ('account_id', current_user.account_id),
    #     ('project_id', project.project_id)
    # ])
    # project_dict['findings_med'] = Findings().count_medium_severity([
    #     ('state', 'ACTIVE'),
    #     ('archived', 0),
    #     ('account_id', current_user.account_id),
    #     ('project_id', project.project_id)
    # ])
    # project_dict['findings_high'] = Findings().count_high_severity([
    #     ('state', 'ACTIVE'),
    #     ('archived', 0),
    #     ('account_id', current_user.account_id),
    #     ('project_id', project.project_id)
    # ])
    # project_dict['jobs_completed'] = JobRuns().count([
    #     ('state', 'completed'),
    #     ('account_id', current_user.account_id),
    #     ('project_id', project.project_id)
    # ])
    # project_dict['jobs_total'] = JobRuns().count([
    #     ('account_id', current_user.account_id),
    #     ('project_id', project.project_id)
    # ])

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
