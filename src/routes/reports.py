from flask import render_template, Blueprint
from flask_login import current_user, login_required
from templates import public_params


blueprint = Blueprint('reports', __name__)

@blueprint.route('/', methods=['GET'])
@login_required
def page_reports():
    params = public_params()
    params['page_title'] = 'Reports'
    params['page'] = 'reports'
    params['account'] = current_user

    return render_template('app/reports.html', **params)
