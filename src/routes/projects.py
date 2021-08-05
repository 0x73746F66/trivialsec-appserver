from flask import render_template, Blueprint
from flask_login import current_user, login_required
from trivialsec.models.domain import Domains
from trivialsec.models.project import Projects
from trivialsec.models.finding import Findings
from templates import public_params


blueprint = Blueprint('projects', __name__)

@blueprint.route('/', methods=['GET'])
@login_required
def page_projects():
    params = public_params()
    params['page_title'] = 'Projects'
    params['page'] = 'projects'
    params['account'] = current_user
    params['js_includes'] = [
        "websocket.min.js",
        "utils.min.js",
        "api.min.js",
        "app/projects.min.js"
    ]
    params['css_includes'] = [
        "app/main.css",
        "app/projects.css"
    ]
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

    for domain in Domains().find_by([
            ('account_id', current_user.account_id),
            ('deleted', 0),
        ],
        order_by=['created_at', 'DESC'],
        limit=1000,
        cache_key=f'domains/account_id/{current_user.account_id}'
        ):
        domain_names.append(domain.name)

    params['datalists'] = [{
        'name': 'projects',
        'options': project_names
    },{
        'name': 'domains',
        'options': domain_names
    }]

    return render_template('app/projects.html', **params)
