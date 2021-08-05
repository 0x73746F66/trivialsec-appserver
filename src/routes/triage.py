from flask import render_template, Blueprint
from flask_login import current_user, login_required
from templates import public_params
from trivialsec.models.finding import Findings

blueprint = Blueprint('triage', __name__)

@blueprint.route('/', methods=['GET'])
@login_required
def page_triage():
    params = public_params()
    params['page_title'] = 'Triage'
    params['page'] = 'triage'
    params['account'] = current_user
    params['js_includes'] = [
        "utils.min.js",
        "api.min.js",
        "app/triage.min.js"
    ]
    params['css_includes'] = [
        "app/main.css",
        "app/triage.css"
    ]
    params['assigned_issues'] = Findings().find_by([('assignee_id', current_user.member_id), ('state', 'ACTIVE'), ('verification_state', 'UNKNOWN')], limit=10).load_details()
    params['watched_issues'] = Findings().get_watched_findings(member_id=current_user.member_id, limit=10).load_details()
    params['triage_issues'] = Findings().find_by([('verification_state', 'UNKNOWN')], limit=10).load_details()

    return render_template('app/triage.html', **params)

@blueprint.route('/unknown', methods=['GET'])
@login_required
def page_triage_unknown():
    params = public_params()
    params['page_title'] = 'Unknown Findings'
    params['page'] = 'triage'
    params['account'] = current_user
    params['js_includes'] = [
        "utils.min.js",
        "api.min.js",
        "app/triage-unknown.min.js"
    ]
    params['css_includes'] = [
        "app/main.css",
        "app/triage-unknown.css"
    ]
    findings = Findings().find_by([('verification_state', 'UNKNOWN')]).load_details()
    params['triage_issues'] = sorted(findings, key=lambda k: k.severity_normalized, reverse=True) 

    return render_template('app/triage-unknown.html', **params)
