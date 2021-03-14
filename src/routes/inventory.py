from flask import render_template, Blueprint
from flask_login import current_user, login_required
from . import get_frontend_conf


blueprint = Blueprint('inventory', __name__)

@blueprint.route('/', methods=['GET'])
@login_required
def page_inventory():
    params = get_frontend_conf()
    params['page_title'] = 'Inventory'
    params['page'] = 'inventory'
    params['account'] = current_user

    return render_template('app/inventory.html', **params)
