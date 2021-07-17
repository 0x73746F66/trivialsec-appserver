from flask import render_template, Blueprint
from flask_login import current_user, login_required
from templates import public_params


blueprint = Blueprint('finding', __name__)

@blueprint.route('/', methods=['GET'])
@login_required
def page_finding():
    params = public_params()
    params['page_title'] = 'Findings'
    params['page'] = 'findings'
    params['account'] = current_user
    # page_size = 10
    # page = int(page)
    # page_num = max(1, page)
    # offset = max(0, page-1) * page_size

    # search_filter = [
    #     ('state', 'ACTIVE'),
    #     ('account_id', current_user.account_id),
    #     ('archived', 0),
    # ]
    # findings = Findings().find_by(search_filter, limit=page_size, offset=offset).load_details()
    # all_findings = Findings().find_by(search_filter, limit=1000).load_details().to_list()
    # params['pagination'] = Findings().pagination(search_filter=search_filter, page_size=page_size, page_num=page_num)
    # labels = [
    #     Finding.RATING_INFO,
    #     Finding.RATING_LOW,
    #     Finding.RATING_MEDIUM,
    #     Finding.RATING_HIGH,
    #     Finding.RATING_CRITICAL,
    # ]

    # params['members'] = []
    # members = Members().find_by([('account_id', current_user.account_id)], limit=1000)
    # for member in members:
    #     params['members'].append({
    #         'id': member.member_id,
    #         'email': member.email,
    #         'verified': member.verified
    #     })
    # params['projects'] = []
    # projects = Projects().find_by([('account_id', current_user.account_id)], limit=1000)
    # for project in projects:
    #     if project.deleted:
    #         continue
    #     params['projects'].append({
    #         'id': project.project_id,
    #         'name': project.name
    #     })

    # params['findings'] = []
    # for finding in findings:
    #     finding.get_notes()
    #     params['findings'].append(finding)

    return render_template('app/findings.html', **params)
