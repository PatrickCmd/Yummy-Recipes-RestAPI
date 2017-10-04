# recipe/__init__.py

from flask_api import FlaskAPI
from flask_sqlalchemy import SQLAlchemy
from flask import request, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

# local import
from instance.config import app_config

# initialize sqlalchemy
db = SQLAlchemy()


def create_app(config_name):
    from recipe_app.models import User

    app = FlaskAPI(__name__, instance_relative_config=True)
    app.config.from_object(app_config[config_name])
    app.config.from_pyfile('config.py')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)

    @app.route('/auth/register', methods=['POST'])
    def register():
        data = request.get_json(force=True)

        if data:
            print(data)
            hashed_password = generate_password_hash(data['password'], 
                                                    method='sha256')
            new_user = User(public_id=str(uuid.uuid4()), email=data['email'], 
                            password=hashed_password, 
                            first_name=data['first_name'], 
                            last_name=data['last_name'])
            new_user.save()

            response = jsonify('message', 'New user created!'), 201
        else:
            response = jsonify('message', 'New user not created!')
        return response
    
    @app.route('/auth/login', methods=['POST'])
    def login():
        pass

    return app
