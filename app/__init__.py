from flask import Flask
from config import Config


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    from app.auth.auth import auth
    from app.views.member import member_bp
    from app.views.admin import admin_bp
    app.register_blueprint(admin_bp, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')
    app.register_blueprint(member_bp, url_prefix='/')

    return app
