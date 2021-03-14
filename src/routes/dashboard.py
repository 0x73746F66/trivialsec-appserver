from flask import render_template, Blueprint
from flask_login import current_user, login_required
from . import get_frontend_conf


blueprint = Blueprint('dashboard', __name__)

@blueprint.route('/', methods=['GET'])
@login_required
def page_dashboard():
    params = get_frontend_conf()
    params['page_title'] = 'Dashboard'
    params['page'] = 'dashboard'
    params['account'] = current_user
    return render_template('app/dashboard.html', **params)
