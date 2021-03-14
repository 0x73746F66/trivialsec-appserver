from flask import render_template, Blueprint
from flask_login import current_user, login_required
from . import get_frontend_conf


blueprint = Blueprint('repositories', __name__)

@blueprint.route('/', methods=['GET'])
@login_required
def page_repositories():
    params = get_frontend_conf()
    params['page_title'] = 'Repositories'
    params['page'] = 'repositories'
    params['account'] = current_user

    return render_template('app/repositories.html', **params)
