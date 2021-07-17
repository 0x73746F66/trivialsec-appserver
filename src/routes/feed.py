from flask import render_template, Blueprint
from flask_login import current_user, login_required
from templates import public_params


blueprint = Blueprint('feed', __name__)

@blueprint.route('/', methods=['GET'])
@login_required
def page_feed():
    params = public_params()
    params['page_title'] = 'Feed'
    params['page'] = 'feed'
    params['account'] = current_user

    return render_template('app/feed.html', **params)
