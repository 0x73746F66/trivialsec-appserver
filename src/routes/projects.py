from flask import render_template, Blueprint
from flask_login import current_user, login_required
from trivialsec.models.domain import Domains
from trivialsec.models.project import Projects
from trivialsec.models.finding import Findings
from . import get_frontend_conf


blueprint = Blueprint('projects', __name__)

@blueprint.route('/', methods=['GET'])
@login_required
def page_projects():
    params = get_frontend_conf()
    params['page_title'] = 'Scopes'
    params['page'] = 'scopes'
    params['account'] = current_user

    project_arr = []
    projects = Projects().find_by([
        ('account_id', current_user.account_id),
        ('deleted', 0),
    ], limit=10)
    domain_names = []
    project_names = []
    for project in projects:
        project_names.append(project.name)
        project_arr.append({
            'project_id': project.project_id,
            'name': project.name,
            'domains': Domains().count([
                ('parent_domain_id', None),
                ('deleted', 0),
                ('account_id', current_user.account_id),
                ('project_id', project.project_id)
            ]),
            'findings_info': Findings().count_informational([
                ('state', 'ACTIVE'),
                ('archived', 0),
                ('account_id', current_user.account_id),
                ('project_id', project.project_id)
            ]),
            'findings_low': Findings().count_low_severity([
                ('state', 'ACTIVE'),
                ('archived', 0),
                ('account_id', current_user.account_id),
                ('project_id', project.project_id)
            ]),
            'findings_med': Findings().count_medium_severity([
                ('state', 'ACTIVE'),
                ('archived', 0),
                ('account_id', current_user.account_id),
                ('project_id', project.project_id)
            ]),
            'findings_high': Findings().count_high_severity([
                ('state', 'ACTIVE'),
                ('archived', 0),
                ('account_id', current_user.account_id),
                ('project_id', project.project_id)
            ]),
        })
    params['projects'] = project_arr

    # for domain in Domains().find_by(
    #     [('account_id', current_user.account_id)],
    #     order_by=['created_at', 'DESC'],
    #     limit=1000,
    #     cache_key=f'page_projects/{current_user.account_id}'
    #     ):
    #     domain_names.append(domain.name)

    params['datalists'] = [{
        'name': 'projects',
        'options': project_names
    },{
        'name': 'domains',
        'options': domain_names
    }]

    return render_template('app/projects.html.j2', **params)
