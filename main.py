import os
from flask import Flask

from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from dotenv import load_dotenv
from app.views import auth_blueprint
from database.database import db

jwt = JWTManager()


def create_app():
    load_dotenv()

    app = Flask(__name__)
    app.config.from_object('config.DevelopmentConfig')
    db.init_app(app)
    jwt.init_app(app)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    with app.app_context():
        app.register_blueprint(auth_blueprint)

        db.create_all()

    return app


if __name__ == "__main__":
    create_app().run()
