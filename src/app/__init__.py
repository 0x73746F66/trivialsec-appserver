import redis
from flask import Flask
from flask_sessionstore import Session
from trivialsec.helpers.log_manager import logger
from trivialsec.helpers.config import config

logger.configure(log_level=config.log_level)
logger.create_stream_logger()
logger.create_file_logger(file_path=config.log_file)
app = Flask(__name__, root_path='/srv/app', instance_relative_config=False)

app.config['SECRET_KEY'] = config.session_secret_key
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_REDIS'] = redis.Redis(host=config.redis.get('host'), ssl=bool(config.redis.get('ssl')))
Session(app)
with app.app_context():
    from routes.public import blueprint as public_blueprint
    from routes.account import blueprint as account_blueprint
    from routes.app import blueprint as app_blueprint
    from routes.backend import blueprint as backend_blueprint
    app.register_blueprint(public_blueprint)
    app.register_blueprint(account_blueprint, url_prefix='/account')
    app.register_blueprint(app_blueprint, url_prefix='/app')
    app.register_blueprint(backend_blueprint, url_prefix='/backend')
