from flask import Flask
from config import Config


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    from app.auth.auth import auth
    from app.views.home import home_bp
    app.register_blueprint(auth, url_prefix='/')
    app.register_blueprint(home_bp, url_prefix='/')

    return app
