from flask import render_template, Blueprint, redirect, url_for
from flask_login import current_user, login_required
from trivialsec.models.account_config import AccountConfig
from trivialsec.models.activity_log import ActivityLog, ActivityLogs
from trivialsec.models.domain import Domains
from trivialsec.models.member import Member, Members
from trivialsec.models.role import Role, Roles
from trivialsec.models.invitation import Invitations
from trivialsec.models.plan import Plan
from trivialsec.models.plan_invoice import PlanInvoices
from trivialsec.helpers.config import config
from templates import public_params


blueprint = Blueprint('account', __name__)

@blueprint.route('/', methods=['GET'])
@blueprint.route('/preferences', methods=['GET'])
@login_required
def account_preferences():
    params = public_params()
    params['page_title'] = 'Preferences'
    params['page'] = 'preferences'
    params['js_includes'] = ["account/preferences.min.js"]
    params['css_includes'] = [
        "vendor/choices.9.0.1.min.css",
        "account/scaffolding.css",
        "account/tables.css",
        "account/main.css",
        "account/preferences.css"
    ]
    params['account'] = current_user
    account_config = AccountConfig(account_id=current_user.account_id)
    if account_config.hydrate():
        params['account_config'] = account_config

    return render_template('account/preferences.html', **params)

@blueprint.route('/organisation/<page>', methods=['GET'])
@blueprint.route('/organisation', methods=['GET'])
@login_required
def account_organisation(page: int = 1):
    params = public_params()
    params['page_title'] = 'Organisation'
    params['page'] = 'organisation'
    params['js_includes'] = ["account/organisation.min.js"]
    params['css_includes'] = [
        "vendor/choices.9.0.1.min.css",
        "account/scaffolding.css",
        "account/tables.css",
        "account/main.css",
        "account/organisation.css"
    ]
    params['account'] = current_user
    account_config = AccountConfig(account_id=current_user.account_id)
    if account_config.hydrate():
        params['account_config'] = account_config

    members = Members()
    members_arr = []
    for member in members.find_by([('account_id', current_user.account_id)], limit=1000):
        member.get_roles()
        members_arr.append(member)
    params['members'] = members_arr

    roles = Roles()
    roles_arr = []
    for role in roles.load():
        if role.internal_only is False:
            roles_arr.append(role)
    params['roles'] = roles_arr

    page_size = 10
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    params['pagination'] = Invitations().pagination(
        search_filter=[
            ('account_id', current_user.account_id)
        ],
        page_size=page_size,
        page_num=page_num
    )
    invitations = Invitations()
    invitations_arr = []
    for invitation in invitations.find_by([('account_id', current_user.account_id)], limit=page_size, offset=offset):
        if invitation.deleted is True or invitation.member_id is not None:
            continue
        invited_by = Member(member_id=invitation.invited_by_member_id)
        invited_by.hydrate()
        setattr(invitation, 'invited_by', invited_by)
        invitation_role = Role(role_id=invitation.role_id)
        invitation_role.hydrate()
        setattr(invitation, 'role', invitation_role)
        invitations_arr.append(invitation)
    params['invitations'] = invitations_arr

    return render_template('account/organisation.html', **params)

@blueprint.route('/member/<member_id>/<page>', methods=['GET'])
@blueprint.route('/member/<member_id>', methods=['GET'])
@login_required
def account_member(member_id: int, page: int = 1):
    params = public_params()
    params['page_title'] = 'Organisation'
    params['page'] = 'organisation'
    params['js_includes'] = ["account/organisation.min.js"]
    params['css_includes'] = [
        "vendor/choices.9.0.1.min.css",
        "account/scaffolding.css",
        "account/tables.css",
        "account/main.css",
        "account/organisation.css"
    ]
    params['account'] = current_user

    member = Member(member_id=member_id, account_id=current_user.account_id)
    member.hydrate(['member_id', 'account_id'])
    member.get_roles()
    params['member'] = member

    page_size = 10
    page = int(page)
    page_num = max(1, page)
    offset = max(0, page-1) * page_size
    params['pagination'] = ActivityLogs().pagination(
        search_filter=[
            ('member_id', member_id)
        ],
        page_size=page_size,
        page_num=page_num
    )
    params['activity_logs'] = ActivityLogs().load(limit=page_size, offset=offset)

    roles = Roles()
    roles_arr = []
    for role in roles.load():
        if role.internal_only is False:
            roles_arr.append(role)
    params['roles'] = roles_arr

    return render_template('account/member.html', **params)

@blueprint.route('/subscription', methods=['GET'])
@login_required
def account_subscription():
    params = public_params()
    params['page_title'] = 'Subscription'
    params['page'] = 'subscription'
    params['js_includes'] = [
        "vendor/timeago.min.js",
        "vendor/chart.min.js",
        "utils.min.js",
        "api.min.js",
        "account/subscription.min.js",
    ]
    params['css_includes'] = [
        "vendor/choices.9.0.1.min.css",
        "account/scaffolding.css",
        "account/tables.css",
        "account/main.css",
        "account/subscription.css"
    ]
    params['account'] = current_user
    account_config = AccountConfig(account_id=current_user.account_id)
    if account_config.hydrate():
        params['account_config'] = account_config
    params['invoices'] = PlanInvoices().find_by([
        ('plan_id', current_user.account.plan.plan_id)
    ])
    params['monitored_domains'] = Domains().count([
        ('account_id', current_user.account_id),
        ('enabled', True)
    ])
    members = set()
    for member in Members().find_by([('account_id', current_user.account_id)], limit=1000):
        members.add(member.member_id)
    params['on_demand_active'] = ActivityLogs().count([
        ('member_id', list(members)),
        ('action', ActivityLog.ACTION_ON_DEMAND_ACTIVE_SCAN)
    ])
    params['on_demand_passive'] = ActivityLogs().count([
        ('member_id', list(members)),
        ('action', ActivityLog.ACTION_ON_DEMAND_PASSIVE_SCAN)
    ])

    return render_template('account/subscription.html', **params)

@blueprint.route('/integrations', methods=['GET'])
@login_required
def account_integrations():
    params = public_params()
    params['page_title'] = 'Integrations'
    params['page'] = 'integrations'
    params['js_includes'] = ["account/integrations.min.js"]
    params['css_includes'] = [
        "vendor/choices.9.0.1.min.css",
        "account/scaffolding.css",
        "account/tables.css",
        "account/main.css",
        "account/integrations.css"
    ]
    params['account'] = current_user
    account_config = AccountConfig(account_id=current_user.account_id)
    if account_config.hydrate(no_cache=True):
        params['account_config'] = account_config

    return render_template('account/integrations.html', **params)

@blueprint.route('/notifications', methods=['GET'])
@login_required
def account_notifications():
    params = public_params()
    params['page_title'] = 'Notifications'
    params['page'] = 'notifications'
    params['js_includes'] = ["account/notifications.min.js"]
    params['css_includes'] = [
        "vendor/choices.9.0.1.min.css",
        "account/scaffolding.css",
        "account/tables.css",
        "account/main.css",
        "account/notifications.css"
    ]
    params['account'] = current_user
    account_config = AccountConfig(account_id=current_user.account_id)
    if account_config.hydrate():
        params['account_config'] = account_config

    return render_template('account/notifications.html', **params)

@blueprint.route('/setup/<step>', methods=['GET'])
@login_required
def account_setup(step: int):
    params = public_params()
    params['page'] = 'setup'
    params['step'] = step
    params['page_title'] = 'Account Setup'
    params['js_includes'] = [
        f"account/setup-{step}.min.js",
        "vendor/stripe-v3.min.js"
    ]
    params['css_includes'] = [
        "vendor/choices.9.0.1.min.css",
        "account/scaffolding.css",
        "account/tables.css",
        "account/main.css",
        f"account/setup-{step}.css",
    ]
    params['account'] = current_user

    account_config = AccountConfig(account_id=current_user.account_id)
    plan = Plan(account_id=current_user.account_id)
    if not account_config.hydrate() or not plan.hydrate('account_id'):
        return redirect(config.get_app().get("site_url"), code=401)

    if current_user.account.is_setup:
        return redirect(url_for('dashboard.page_dashboard'))
    params['account_config'] = account_config
    params['plan'] = plan
    roles = Roles()
    roles_arr = []
    for role in roles.load():
        if role.internal_only == 0:
            roles_arr.append(role)

    params['roles'] = roles_arr
    return render_template(f'account/setup-step-{step}.html', **params)
