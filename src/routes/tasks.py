from flask import render_template, Blueprint
from flask_login import current_user, login_required
from . import get_frontend_conf


blueprint = Blueprint('tasks', __name__)

@blueprint.route('/', methods=['GET'])
@login_required
def page_reports():
    params = get_frontend_conf()
    params['page_title'] = 'My Tasks'
    params['page'] = 'tasks'
    params['account'] = current_user

    return render_template('app/tasks.html.j2', **params)
