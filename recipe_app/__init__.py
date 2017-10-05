# recipe/__init__.py

from flask_api import FlaskAPI
from flask_sqlalchemy import SQLAlchemy
from flask import request, jsonify, abort, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from validate_email import validate_email
import uuid
import jwt
import datetime

# local import
from instance.config import app_config

# initialize sqlalchemy
db = SQLAlchemy()


def create_app(config_name):
    from recipe_app.models import User, RecipeCategory

    app = FlaskAPI(__name__, instance_relative_config=True)
    app.config.from_object(app_config[config_name])
    app.config.from_pyfile('config.py')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)

    @app.route('/auth/register', methods=['POST'])
    def register():
        data = request.get_json(force=True)

        if data:
            if data['email'] == "" or data['password'] == "" or \
                data['first_name'] == "" or data['last_name'] == "":
                return jsonify({'message': 
                                'All fields must be filled'}), 200
            if not validate_email(data['email']):
                return jsonify({'Error': 'Invalid Email'}), 200
            if len(data['password']) < 6:
                return jsonify({'Error': 'Password is too short'}), 200
            hashed_password = generate_password_hash(data['password'], 
                                                    method='sha256')
            if User.query.filter_by(email=data['email']).first():
                return jsonify({'message': 'User already exists'}), 200
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

    # user create recipe category
    @app.route('/recipe_category', methods=['POST'])
    @token_required
    def create_category(current_user):
        data = request.get_json(force=True)

        if data:
            if data['name'] == "" or data["description"] == "":
                return jsonify({'message': 
                               'Category name not provided'}), 200
            if RecipeCategory.query.filter_by(name=data['name']).first():
                return jsonify({'message': 
                                'Category already exists'}), 200
            category = RecipeCategory(name=data['name'], 
                                       description=data['description'], 
                                       user_id=current_user.id)
            category.save()
            response = \
            jsonify({'message': 'New recipe category created!'}), 201
        else:
            response = \
            jsonify({'message': 'New recipe category not created!'}), 201
        return response
    
    # user retrieves recipe categories
    @app.route('/recipe_category', methods=['GET'])
    @token_required
    def get_all_recipe_categories(current_user):
        '''Returns recipes of current logged in user'''
        categories = RecipeCategory.query.\
                                         filter_by(user_id=\
                                         current_user.id).all()
        category_list = []
        for category in categories:
            category_data = {}
            category_data['id'] = category.id
            category_data['name'] = category.name
            category_data['description'] = category.description
            category_list.append(category_data)
        return jsonify({'recipe categories': category_list}), 200
        
    
    # get single recipe category
    @app.route('/recipe_category/<cat_id>', methods=['GET'])
    @token_required
    def get_one_category(current_user, cat_id):
        category = RecipeCategory.query.filter_by(id=cat_id, 
                                                  user_id=\
                                                  current_user.id).\
                                                  first()
        if not category:
            return jsonify({'message': 'No category found'}), 200
        category_data = {}
        category_data['id'] = category.id
        category_data['name'] = category.name
        category_data['description'] = category.description
        return jsonify(category_data), 200
    
    # user editd recipe category
    @app.route('/recipe_category/<cat_id>', methods=['PUT'])
    @token_required
    def edit_recipe_category(current_user, cat_id):
        data = request.get_json(force=True)
        category = RecipeCategory.query.filter_by(id=cat_id, 
                                                  user_id=\
                                                  current_user.id).\
                                                  first()
        if not category:
            return jsonify({'message': 'No category found'}), 200
        category.name = data['name']
        category.description = data['description']
        category.save()
        return jsonify({'message': 'Recipe Category updated'}), 200
        
    
    # delete recipe category
    @app.route('/recipe_category/<cat_id>', methods=['DELETE'])
    @token_required
    def delete_recipe_category(current_user, cat_id):
        category = RecipeCategory.query.filter_by(id=cat_id, 
                                                  user_id=\
                                                  current_user.id).\
                                                  first()
        if not category:
            return jsonify({'message': 'No category found'}), 200
        category.delete()
        return jsonify({'message': 'Recipe category deleted'})

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
