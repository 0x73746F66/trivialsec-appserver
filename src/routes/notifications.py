from flask import render_template, Blueprint
from flask_login import current_user, login_required
from trivialsec.models.notification import Notifications
from . import get_frontend_conf


blueprint = Blueprint('notifications', __name__)

@blueprint.route('/', methods=['GET'])
@login_required
def page_notifications():
    noti_arr = []
    notis = Notifications().find_by([('account_id', current_user.account_id)])
    for noti in notis:
        if noti.marked_read == 1:
            continue
        noti_arr.append({
            'id': noti.notification_id,
            'description': noti.description,
            'url': noti.url,
            'created_at': noti.created_at
        })

    params = get_frontend_conf()
    params['page_title'] = 'Notifications'
    params['page'] = 'notifications'
    params['account'] = current_user
    params['notifications'] = noti_arr
    return render_template('app/notifications.html.j2', **params)
