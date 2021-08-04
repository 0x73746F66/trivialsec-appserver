from flask import render_template, Blueprint
from flask_login import current_user, login_required
from templates import public_params


blueprint = Blueprint('tasks', __name__)

@blueprint.route('/', methods=['GET'])
@login_required
def page_reports():
    params = public_params()
    params['page_title'] = 'My Tasks'
    params['page'] = 'tasks'
    params['account'] = current_user
    params['js_includes'] = [
        "utils.min.js",
        "api.min.js",
        "app/tasks.min.js"
    ]
    params['css_includes'] = [
        "app/main.css",
        "app/tasks.css"
    ]

    return render_template('app/tasks.html', **params)
