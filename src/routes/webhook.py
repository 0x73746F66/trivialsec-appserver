from flask import Blueprint, jsonify, request
from trivialsec.helpers.payments import webhook_received


blueprint = Blueprint('webhook', __name__)

@blueprint.route('/stripe', methods=['POST'])
def wh_stripe():
    webhook_received(request)
    return jsonify({'status': 'success'})
