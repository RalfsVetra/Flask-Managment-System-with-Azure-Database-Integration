from flask import Flask
from config import Config


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    from .auth import auth
    app.register_blueprint(auth, url_prefix='/')

    return app
