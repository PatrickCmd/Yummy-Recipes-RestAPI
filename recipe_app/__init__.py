# recipe/__init__.py

from flask_api import FlaskAPI
from flask_sqlalchemy import SQLAlchemy
from flask import request, jsonify, abort, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from func_tools import wraps
import uuid
import jwt
import datetime

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
    
    @app.route('/users', methods=['GET'])
    def get_users():
        users = User.get_all()
        print(users)
        user_list = []

        for user in users:
            user_data = {}
            user_data['id'] = user.id
            user_data['public_id'] = user.public_id
            user_data['email'] = user.email
            user_data['first_name'] = user.first_name
            user_data['last_name'] = user.last_name
            user_list.append(user_data)
        response = jsonify({'users': user_list}), 200
        return response

    # decorator to prevent unauthenticated users from accessing 
    # the endpoints
    def token_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = None
            if 'x-access-token' in request.headers:
                token = request.headers['x-access-token']
            
            if not token:
                return jsonify({'message': 'Token is missing'}), 401

            try:
                data = jwt.decode(token, app.config['SECRET_KEY'])
                print(data)
                current_user = User.query.filter_by(public_id=\
                                            data['public_id']).first()
            except:
                return jsonify({'message': 'Token is invalid'}), 401
            return f(current_user, *args, **kwargs)
        return decorated

    @app.route('/auth/login')
    def login():
        '''logs in user into app'''
        auth = request.authorization
        print(auth)
        if not auth or not auth.username or not auth.password:
            return make_response('Could not verify user' , 401, 
                                  {'WWW-Authenticate': 'Basic realm=\
                                  "Login required"'})
        user = User.query.filter_by(email=auth.username).first()

        if not user:
            return make_response('Could not verify user' , 401, 
                                 {'WWW-Authenticate': 'Basic realm=\
                                 "Login required"'})

        if check_password_hash(user.password, auth.password):
            # generating tokens
            token = jwt.encode({'public_id': user.public_id, 
                                'exp': datetime.datetime.utcnow()+
                                datetime.timedelta(minutes=30)}, 
                                app.config['SECRET_KEY'])
            return jsonify({'token': token.decode('UTF-8')})
        return make_response('Could not verify user' , 401, 
                                  {'WWW-Authenticate': 'Basic realm=\
                                  "Login required"'})

    return app
