from os import getenv
from flask import Flask
from flask_session import Session
from werkzeug.debug import DebuggedApplication
from werkzeug.middleware.proxy_fix import ProxyFix
from trivialsec.helpers.config import config
from templates import from_json_filter, to_json_filter, http_code_group_filter


def create_app() -> Flask:
    app = Flask(__name__, root_path='/srv/app', instance_relative_config=False)
    app.config.update(
        PREFERRED_URL_SCHEME='https',
        SECRET_KEY=config.session_secret_key,
        SESSION_TYPE='redis',
        SESSION_USE_SIGNER=False,
        SESSION_REDIS=config.redis_client
    )

    if getenv('FLASK_DEBUG') == '1':
        app.config.update(
            DEBUG=True,
            PROPAGATE_EXCEPTIONS=True
        )
        app.wsgi_app = DebuggedApplication(app.wsgi_app, True)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)
    Session(app)

    with app.app_context():
        from routes.root import blueprint as public_blueprint
        from routes.account import blueprint as account_blueprint
        from routes.domain import blueprint as domain_blueprint
        from routes.project import blueprint as project_blueprint
        from routes.projects import blueprint as projects_blueprint
        from routes.dashboard import blueprint as dashboard_blueprint
        from routes.notifications import blueprint as notifications_blueprint
        from routes.repositories import blueprint as repositories_blueprint
        from routes.inventory import blueprint as inventory_blueprint
        from routes.finding import blueprint as finding_blueprint
        from routes.reports import blueprint as reports_blueprint
        from routes.feed import blueprint as feed_blueprint
        from routes.triage import blueprint as triage_blueprint
        from routes.user import blueprint as user_blueprint
        from routes.webhook import blueprint as webhook_blueprint
        app.add_template_filter(to_json_filter, name='to_json')
        app.add_template_filter(from_json_filter, name='from_json')
        app.add_template_filter(http_code_group_filter, name='http_code_group')
        app.register_blueprint(public_blueprint, url_prefix='/')
        app.register_blueprint(domain_blueprint, url_prefix='/domain')
        app.register_blueprint(project_blueprint, url_prefix='/project')
        app.register_blueprint(projects_blueprint, url_prefix='/projects')
        app.register_blueprint(notifications_blueprint, url_prefix='/notifications')
        app.register_blueprint(repositories_blueprint, url_prefix='/repositories')
        app.register_blueprint(inventory_blueprint, url_prefix='/inventory')
        app.register_blueprint(finding_blueprint, url_prefix='/finding')
        app.register_blueprint(reports_blueprint, url_prefix='/reports')
        app.register_blueprint(feed_blueprint, url_prefix='/feed')
        app.register_blueprint(triage_blueprint, url_prefix='/triage')
        app.register_blueprint(dashboard_blueprint, url_prefix='/dashboard')
        app.register_blueprint(account_blueprint, url_prefix='/account')
        app.register_blueprint(user_blueprint, url_prefix='/me')
        app.register_blueprint(webhook_blueprint, url_prefix='/webhook')

    return app
