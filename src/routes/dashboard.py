from flask import render_template, Blueprint
from flask_login import current_user, login_required
from templates import public_params


blueprint = Blueprint('dashboard', __name__)

@blueprint.route('/', methods=['GET'])
@login_required
def page_dashboard():
    params = public_params()
    params['page_title'] = 'Dashboard'
    params['page'] = 'dashboard'
    params['account'] = current_user
    params['js_includes'] = [
        "app/dashboard.min.js"
    ]
    params['css_includes'] = [
        "app/main.css",
        "app/dashboard.css"
    ]
    return render_template('app/dashboard.html', **params)
