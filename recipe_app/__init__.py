# recipe/__init__.py

from flask_api import FlaskAPI
from flask_sqlalchemy import SQLAlchemy
from flask import request, jsonify, abort, make_response, Response, redirect
from werkzeug.security import generate_password_hash, \
     check_password_hash
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
    from recipe_app.models import (User, RecipeCategory, Recipe, 
                                   BlacklistToken)

    app = FlaskAPI(__name__, instance_relative_config=True)
    app.config.from_object(app_config[config_name])
    app.config.from_pyfile('config.py')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    @app.route('/')
    @app.route('/index')
    def index():
        return redirect('/apidocs/')

    # method to check for special characters and validate a name
    def is_valid(name_string):
        special_character = "~!@#$%^&*()_={}|\[]<>?/,;:"
        return any(char in special_character for char in name_string)    

    @app.route('/auth/register', methods=['POST'])
    def register():
        data = request.get_json(force=True)

        if data:
            if is_valid(data['first_name']) or \
                        is_valid(data['last_name']):
                return jsonify({'message': 
                               'Name contains special characters'}),200
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
                return jsonify({'message': 'User already exists'}), 202
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
        auth_token = request.headers['x-access-token']
        if auth_token:
            resp = current_user.decode_auth_token(auth_token, 
                                          app.config['SECRET_KEY'])
            if not isinstance(resp, str): 
                data = request.get_json(force=True)

                if data:
                    if data['name'] == "" or data["description"] == "":
                        return jsonify({'message': 
                                    'Category name not provided'}), 200
                    if RecipeCategory.query.filter_by(name=data['name']).\
                                                    first():
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
                    jsonify({'message': 'New recipe category not created!'}), 
                    201
                return response
            else:
                responseObject = {
                        'status': 'fail',
                        'message': resp
                    }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403
    
    # user retrieves recipe categories
    @app.route('/recipe_category', methods=['GET'])
    @token_required
    def get_all_recipe_categories(current_user):
        '''Returns recipes of current logged in user'''
        categories = RecipeCategory.query.\
                                         filter_by(user_id=\
                                         current_user.id).all()
        # pagination
        limit = request.args.get('limit', 0)
        search = request.args.get('q', "")
        if limit:
            limit = int(limit)
            # offset = int(request.args.get('offset', 0))
            categories = RecipeCategory.get_all_limit_offset(
                                        current_user.id, limit)
        if search:
            categories = [category for category in categories if 
                          category.name == search]
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
            return jsonify({'message': 'No category found'}), 404
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
            return jsonify({'message': 'No category found'}), 404
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
            return jsonify({'message': 'No category found'}), 404
        category.delete()
        return jsonify({'message': 'Recipe category deleted'})

    # add recipe to category
    @app.route('/recipe_category/<cat_id>/recipes', methods=['POST'])
    @token_required
    def add_recipe(current_user, cat_id):
        category = RecipeCategory.query.filter_by(id=cat_id, 
                                                  user_id=\
                                                  current_user.id).\
                                                  first()
        if not category:
            return jsonify({'message': 'Category not found'}), 404
        data = request.get_json(force=True)
        if data:
            if Recipe.query.filter_by(name=data['name'], 
                                      user_id=current_user.id).\
                                      first():
                return jsonify({'message': 
                                'Recipe already exists'}), 200
            recipe = Recipe(name=data['name'], 
                            cat_id=cat_id, 
                            user_id=current_user.id,
                            ingredients=data['ingredients'],
                            description=data['description'])
            recipe.save()
            response = \
            jsonify({'message': 'New recipe added to category'}), 201
        else:
            response = \
            jsonify({'message': 'New recipe not created!'}), 
            201
        return response
    
    # view recipes in category
    @app.route('/recipe_category/<cat_id>/recipes', methods=['GET'])
    @token_required
    def get_all_recipes_in_category(current_user, cat_id):
        category = RecipeCategory.query.filter_by(id=cat_id, 
                                                  user_id=\
                                                  current_user.id).\
                                                  first()
        if not category:
            return jsonify({'message': 'Category not found'}), 404
        '''Returns recipes of current logged in user'''
        recipes = Recipe.query.filter_by(cat_id=cat_id, user_id=\
                                         current_user.id).all()
        # pagination
        limit = request.args.get('limit', 0)
        if limit:
            limit = int(limit)
            # offset = int(request.args.get('offset', 0))
            recipes = Recipe.get_all_limit_offset(cat_id,
                                                  current_user.id, 
                                                  limit)
        recipe_list = []
        for recipe in recipes:
            recipe_data = {}
            recipe_data['id'] = recipe.id
            recipe_data['cat_id'] = recipe.cat_id
            recipe_data['user_id'] = recipe.user_id
            recipe_data['name'] = recipe.name
            recipe_data['ingredients'] = recipe.ingredients
            recipe_data['description'] = recipe.description
            recipe_list.append(recipe_data)
        return jsonify({'recipes in category': recipe_list}), 200
    
    # view single recipe in category
    @app.route('/recipe_category/<cat_id>/recipes/<recipe_id>', 
               methods=['GET'])
    @token_required
    def get_recipe_single_in_category(current_user, cat_id, recipe_id):
        category = RecipeCategory.query.filter_by(id=cat_id, 
                                                  user_id=\
                                                  current_user.id).\
                                                  first()
        if not category:
            return jsonify({'message': 'Category not found'}), 404
        recipe = Recipe.query.filter_by(id=recipe_id,
                                        cat_id=cat_id, 
                                        user_id=current_user.id).\
                                        first()
        if not recipe:
            return jsonify({'message': 'Recipe not found'}), 404
        recipe_data = {}
        recipe_data['id'] = recipe.id
        recipe_data['cat_id'] = recipe.cat_id
        recipe_data['user_id'] = recipe.user_id
        recipe_data['name'] = recipe.name
        recipe_data['ingredients'] = recipe.ingredients
        recipe_data['description'] = recipe.description
        return jsonify(recipe_data), 200
    
    # edit single recipe in category
    @app.route('/recipe_category/<cat_id>/recipes/<recipe_id>', 
               methods=['PUT'])
    @token_required
    def edit_recipe_in_category(current_user, cat_id, recipe_id):
        data = request.get_json(force=True)
        recipe = Recipe.query.filter_by(id=recipe_id,
                                        cat_id=cat_id, 
                                        user_id=current_user.id).\
                                        first()
        if not recipe:
            return jsonify({'message': 'Recipe not found'}), 404
        recipe.name = data['name']
        recipe.ingredients = data['ingredients']
        recipe.description = data['description']
        recipe.save()
        return jsonify({'message': 'Recipe has been updated'}), 200

    # delete single recipe in category
    @app.route('/recipe_category/<cat_id>/recipes/<recipe_id>', 
                methods=['DELETE'])
    @token_required
    def delete_recipe_from_category(current_user, cat_id, recipe_id):
        recipe = Recipe.query.filter_by(id=recipe_id,
                                        cat_id=cat_id, 
                                        user_id=current_user.id).\
                                        first()
        if not recipe:
            return jsonify({'message': 'Recipe not found'}), 404
        recipe.delete()
        return jsonify({'message': 'Recipe item deleted'}), 200

    # user logs out
    @app.route('/auth/logout', methods=['POST'])
    @token_required
    def logout(current_user):
        auth_token = request.headers['x-access-token']
        if auth_token:
            resp = current_user.decode_auth_token(auth_token, 
                                          app.config['SECRET_KEY'])
            if not isinstance(resp, str):
                # mark the token as blacklisted
                blacklist_token = BlacklistToken(token=auth_token)
                try:
                    # insert the token
                    db.session.add(blacklist_token)
                    db.session.commit()
                    responseObject = {
                        'status': 'success',
                        'message': 'User has logged out successfully.'
                    }
                    return make_response(jsonify(responseObject)), 200
                except Exception as e:
                    responseObject = {
                        'status': 'fail',
                        'message': e
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403


    @app.route('/auth/login')
    def login():
        '''logs in user into app'''
        auth = request.authorization
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
                                'user_id':user.id, 
                                'exp': datetime.datetime.utcnow()+
                                datetime.timedelta(minutes=30)}, 
                                app.config['SECRET_KEY'])
            return jsonify({'token': token.decode('UTF-8')})
        return make_response('Could not verify user' , 401, 
                                  {'WWW-Authenticate': 'Basic realm=\
                                  "Login required"'})

    return app
