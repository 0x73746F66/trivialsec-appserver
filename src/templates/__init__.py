import json
from datetime import date
from flask_login import current_user
from trivialsec.helpers.config import config
from trivialsec.services.roles import is_internal_member, is_audit_member, is_billing_member, is_owner_member, is_support_member, is_readonly_member


def public_params() -> dict:
    conf = {
        'account': {'account': {}},
        'app_version': config.app_version,
        'recaptcha_site_key': config.recaptcha_site_key,
        'archive_bucket': config.aws.get('public_bucket'),
        'public_bucket': config.aws.get('public_bucket'),
        'env_prefix': config.aws.get('env_prefix'),
        'stripe_publishable_key': config.stripe_publishable_key,
        'year': date.today().year,
        'roles': {
            'is_internal_member': is_internal_member(current_user),
            'is_support_member': is_support_member(current_user),
            'is_billing_member': is_billing_member(current_user),
            'is_audit_member': is_audit_member(current_user),
            'is_owner_member': is_owner_member(current_user),
            'is_readonly_member': is_readonly_member(current_user),
        }
    }
    return {**conf, **config.get_app()}

def autoversion_filter(filename :str) -> str:
    return f"{filename}?v={config.app_version}"

def from_json_filter(s :str) -> dict:
    return json.loads(s)

def to_json_filter(s :str) -> dict:
    return json.dumps(s)

def http_code_group_filter(s: int) -> str:
    if str(s).startswith('1'):
        return 'info'
    if str(s).startswith('2'):
        return 'success'
    if str(s).startswith('3'):
        return 'redirect'
    if str(s).startswith('4'):
        return 'error'
    if str(s).startswith('5'):
        return 'critical'
    return ''
