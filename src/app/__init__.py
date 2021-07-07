from os import getenv
import redis
from flask import Flask
from flask_sessionstore import Session
from werkzeug.debug import DebuggedApplication
from trivialsec.helpers.config import config
from templates import autoversion_filter, from_json_filter, http_code_group_filter


def create_app() -> Flask:
    app = Flask(__name__, root_path='/srv/app', instance_relative_config=False)

    if getenv('FLASK_DEBUG') == '1':
        app.config.update(
            DEBUG=True,
            PROPAGATE_EXCEPTIONS=True
        )
        app.wsgi_app = DebuggedApplication(app.wsgi_app, True)

    app.config['SECRET_KEY'] = config.session_secret_key
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_REDIS'] = redis.Redis(host=config.redis.get('host'), ssl=bool(config.redis.get('ssl')))
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
        from routes.tasks import blueprint as tasks_blueprint
        from routes.backend import blueprint as backend_blueprint
        from routes.webhook import blueprint as webhook_blueprint
        app.add_template_filter(autoversion_filter, name='autoversion')
        app.add_template_filter(from_json_filter, name='from_json')
        app.add_template_filter(http_code_group_filter, name='http_code_group')
        app.register_blueprint(public_blueprint, url_prefix='/')
        app.register_blueprint(domain_blueprint, url_prefix='/domain')
        app.register_blueprint(project_blueprint, url_prefix='/scope')
        app.register_blueprint(projects_blueprint, url_prefix='/scopes')
        app.register_blueprint(notifications_blueprint, url_prefix='/notifications')
        app.register_blueprint(repositories_blueprint, url_prefix='/repositories')
        app.register_blueprint(inventory_blueprint, url_prefix='/inventory')
        app.register_blueprint(finding_blueprint, url_prefix='/finding')
        app.register_blueprint(reports_blueprint, url_prefix='/reports')
        app.register_blueprint(feed_blueprint, url_prefix='/feed')
        app.register_blueprint(tasks_blueprint, url_prefix='/tasks')
        app.register_blueprint(dashboard_blueprint, url_prefix='/dashboard')
        app.register_blueprint(account_blueprint, url_prefix='/account')
        app.register_blueprint(backend_blueprint, url_prefix='/backend')
        app.register_blueprint(webhook_blueprint, url_prefix='/webhook')

    return app
