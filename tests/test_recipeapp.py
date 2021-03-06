# tests/test_recipeapp.py

import unittest
import os
import json
import base64

from recipe_app import create_app, db

class RecipeAppTestCase(unittest.TestCase):
    """Class represents recipe app testcase"""

    def setUp(self):
        """Define test variables and initialize app"""
        self.app = create_app(config_name='testing')
        self.client = self.app.test_client
        self.user = json.dumps({"first_name": "Patrick",
                                "last_name": "Walukagga",
                                "email": "pwalukagga@gmail.com",
                                "password": "telnetcmd123"})

        # binds the app to the current context
        with self.app.app_context():
            # create all database tables
            db.create_all()
    
    def open_with_auth(self, url, username, password):
        return self.client().get(url,headers={'Authorization': 
                                 'Basic ' + base64.b64encode(bytes
                                  (username + ":" + password, 'ascii')).
                                   decode('ascii')})

    def tearDown(self):
        """teardown all initialized variables."""
        with self.app.app_context():
            # drop all tables
            db.session.remove()
            db.drop_all()
    
    def test_user_registration(self):
        '''Test API can register user (POST request)'''
        response = self.client().post('/auth/register', data=self.user)
        self.assertEqual(response.status_code, 201)
        self.assertIn('New user created!', str(response.data))
    
    def test_user_registration_fails_with_invalid_email(self):
        '''Test API can register user (POST request)'''
        user = json.dumps({"first_name": "Patrick",
                           "last_name": "Walukagga",
                           "email": "pwalukaggagmail.com",
                           "password": "telnetcmd123"})
        response = self.client().post('/auth/register', data=user)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Invalid Email', str(response.data))
    
    def test_user_registration_fails_with_name_having_special_characters(self):
        '''Test API can register user (POST request)'''
        user = json.dumps({"first_name": "Patrick@34&*%",
                           "last_name": "Walukagga@#$%$!^@&",
                           "email": "pwalukagga@gmail.com",
                           "password": "telnet123"})
        response = self.client().post('/auth/register', data=user)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Name contains special character', 
                      str(response.data))
    
    def test_user_registration_fails_with_short_password(self):
        '''Test API can register user (POST request)'''
        user = json.dumps({"first_name": "Patrick",
                           "last_name": "Walukagga",
                           "email": "pwalukagga@gmail.com",
                           "password": "teln"})
        response = self.client().post('/auth/register', data=user)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Password is too short', str(response.data))
    
    def test_user_registration_fails_with_empty_credintials(self):
        '''Test API can register user (POST request)'''
        user = json.dumps({"first_name": "",
                           "last_name": "",
                           "email": "",
                           "password": ""})
        response = self.client().post('/auth/register', data=user)
        self.assertEqual(response.status_code, 200)
        self.assertIn('All fields must be filled', str(response.data))
    
    def test_user_registration_fails_with_same_email(self):
        '''Test API can register user (POST request)'''
        response = self.client().post('/auth/register', data=self.user)
        user = json.dumps({"first_name": "Patrick",
                           "last_name": "Walukagga",
                           "email": "pwalukagga@gmail.com",
                           "password": "telnetcmd123"})
        response = self.client().post('/auth/register', data=user)
        self.assertEqual(response.status_code, 202)
        self.assertIn('User already exists', str(response.data))
    
    def test_get_users(self):
        '''Tests that users are return successfully'''
        response = self.client().post('/auth/register', data=self.user)
        response = self.client().get('/users')
        self.assertEqual(response.status_code, 200)
    
    def test_logout_user(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
                           decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        response = self.client().post('/auth/logout', 
                                      headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn("User has logged out successfully", 
                      str(response.data))
    
    
    def test_user_creates_recipe_category(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
                           decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/auth/logout', 
                                      headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn("User has logged out successfully", 
                      str(response.data))
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        self.assertEqual(response.status_code, 401)
        self.assertIn('Token blacklisted. Please log in again.', 
                       str(response.data))
    
    def test_try_create_recipe_category_when_logged_out(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
                           decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        self.assertEqual(response.status_code, 201)
        self.assertIn('New recipe category created!', 
                       str(response.data))
    
    def test_user_retrieves_recipe_categories(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
                           decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        response = self.client().get('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        self.assertEqual(response.status_code, 200)
        self.assertIn('recipe categories', str(response.data))
        self.assertIn('How to make breakfast', str(response.data))
    
    def test_user_retrieves_recipe_categories_with_limit(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
                           decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "Lunch", 
                                     "description": 
                                     "How to make lunch"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "Dinner", 
                                     "description": 
                                     "How to make Dinner"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        response = self.client().get('/recipe_category?limit=2', 
                                      headers=headers,
                                      data=category_data)
        self.assertEqual(response.status_code, 200)
        self.assertIn('recipe categories', str(response.data))
        self.assertIn('How to make breakfast', str(response.data))
        self.assertIn('How to make lunch', str(response.data))
    
    def test_user_retrieves_recipe_category_with_search(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
                           decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "Lunch", 
                                     "description": 
                                     "How to make lunch"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "Dinner", 
                                     "description": 
                                     "How to make Dinner"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        response = self.client().get('/recipe_category?q=Dinner', 
                                      headers=headers,
                                      data=category_data)
        self.assertEqual(response.status_code, 200)
        self.assertIn('recipe categories', str(response.data))
        self.assertIn('How to make Dinner', str(response.data))
    
    def test_user_get_recipe_category(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
                           decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "LunchBuffe", 
                                     "description": 
                                     "How to make lunch buffe"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        response = self.client().get('/recipe_category/2', 
                                      headers=headers,
                                      data=category_data)
        self.assertEqual(response.status_code, 200)
        self.assertIn('How to make lunch buffe', str(response.data))
    
    def test_user_get_recipe_category_not_in_database(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
                           decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "LunchBuffe", 
                                     "description": 
                                     "How to make lunch buffe"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        response = self.client().get('/recipe_category/4', 
                                      headers=headers,
                                      data=category_data)
        self.assertEqual(response.status_code, 404)
        self.assertIn('No category found', str(response.data))
    
    def test_user_edit_recipe_category(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
                           decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "LunchBuffe", 
                                     "description": 
                                     "How to make lunch buffe"})
        response = self.client().put('/recipe_category/1', 
                                      headers=headers,
                                      data=category_data)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Recipe Category updated', str(response.data))
    
    def test_user_delete_recipe_category(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
                           decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "LunchBuffe", 
                                     "description": 
                                     "How to make lunch buffe"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        response = self.client().delete('/recipe_category/2', 
                                      headers=headers,
                                      data=category_data)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Recipe category deleted', str(response.data))
    
    def test_user_delete_recipe_category_not_in_database(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
        decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "LunchBuffe", 
                                     "description": 
                                     "How to make lunch buffe"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        response = self.client().delete('/recipe_category/4', 
                                      headers=headers,
                                      data=category_data)
        self.assertEqual(response.status_code, 404)
        self.assertIn('No category found', str(response.data))
    
    def test_add_recipe_in_category(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
        decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "LunchBuffe", 
                                     "description": 
                                     "How to make lunch buffe"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        recipe_data = json.dumps({"name": "Chicken Lunch Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        self.assertEqual(response.status_code, 201)
        self.assertIn('New recipe added to category', 
                       str(response.data))
    
    def test_add_recipe_in_category_which_doesnot_exist(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
        decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "LunchBuffe", 
                                     "description": 
                                     "How to make lunch buffe"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        recipe_data = json.dumps({"name": "Chicken Lunch Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/3/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        self.assertEqual(response.status_code, 404)
        self.assertIn('Category not found', 
                       str(response.data))
    
    def test_add_recipe_in_category_which_already_exists(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
        decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "LunchBuffe", 
                                     "description": 
                                     "How to make lunch buffe"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        recipe_data = json.dumps({"name": "Chicken Lunch Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Recipe already exists', 
                       str(response.data))

    def test_get_all_recipes_in_category(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
        decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "LunchBuffe", 
                                     "description": 
                                     "How to make lunch buffe"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        recipe_data = json.dumps({"name": "Chicken Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        recipe_data = json.dumps({"name": "Beef Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        response = self.client().get('/recipe_category/2/recipes', 
                                      headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Chicken Buffe', str(response.data))
        self.assertIn('Beef Buffe', str(response.data))
    
    def test_get_all_recipes_in_category_with_limit(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
        decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "LunchBuffe", 
                                     "description": 
                                     "How to make lunch buffe"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        recipe_data = json.dumps({"name": "Chicken Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        recipe_data = json.dumps({"name": "Beef Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        recipe_data = json.dumps({"name": "Pork Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        response = self.client().get('/recipe_category/2/recipes?limit=3', 
                                      headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Chicken Buffe', str(response.data))
        self.assertIn('Beef Buffe', str(response.data))
        self.assertIn('Pork Buffe', str(response.data))
    
    def test_get_all_recipes_in_category_which_doesnot_exist(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
        decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "LunchBuffe", 
                                     "description": 
                                     "How to make lunch buffe"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        recipe_data = json.dumps({"name": "Chicken Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        recipe_data = json.dumps({"name": "Beef Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        response = self.client().get('/recipe_category/5/recipes', 
                                      headers=headers)
        self.assertEqual(response.status_code, 404)
        self.assertIn('Category not found', str(response.data))
    
    def test_get_single_recipe_in_category(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
        decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "LunchBuffe", 
                                     "description": 
                                     "How to make lunch buffe"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        recipe_data = json.dumps({"name": "Chicken Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        recipe_data = json.dumps({"name": "Beef Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        response = self.client().get('/recipe_category/2/recipes/1', 
                                      headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Chicken Buffe', str(response.data))
    
    def test_get_single_recipe_in_recipe_which_doesnot_edit(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
        decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "LunchBuffe", 
                                     "description": 
                                     "How to make lunch buffe"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        recipe_data = json.dumps({"name": "Chicken Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        recipe_data = json.dumps({"name": "Beef Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        response = self.client().get('/recipe_category/2/recipes/4', 
                                      headers=headers)
        self.assertEqual(response.status_code, 404)
        self.assertIn('Recipe not found', str(response.data))
    
    def test_get_single_recipe_in_category_which_doesnot_edit(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
        decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "LunchBuffe", 
                                     "description": 
                                     "How to make lunch buffe"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        recipe_data = json.dumps({"name": "Chicken Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        recipe_data = json.dumps({"name": "Beef Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        response = self.client().get('/recipe_category/5/recipes/4', 
                                      headers=headers)
        self.assertEqual(response.status_code, 404)
        self.assertIn('Category not found', str(response.data))
    
    def test_edit_recipe_in_category(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
        decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "LunchBuffe", 
                                     "description": 
                                     "How to make lunch buffe"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        recipe_data = json.dumps({"name": "Chicken Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        recipe_data = json.dumps({"name": "Beef Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        recipe_data = json.dumps({"name": "Chicken Buffes", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes, Vegetables",
                                  "description": "Mix and boil"})
        response = self.client().put('/recipe_category/2/recipes/1', 
                                      headers=headers, 
                                      data=recipe_data)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Recipe has been updated', str(response.data))
        response = self.client().get('/recipe_category/2/recipes/1', 
                                      headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Chicken Buffes', str(response.data))
    
    def test_delete_recipe_from_category(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
        decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "LunchBuffe", 
                                     "description": 
                                     "How to make lunch buffe"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        recipe_data = json.dumps({"name": "Chicken Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        recipe_data = json.dumps({"name": "Beef Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        response = self.client().delete('/recipe_category/2/recipes/2', 
                                      headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Recipe item deleted', str(response.data))
    
    def test_delete_recipe_which_doesnot_exist(self):
        response = self.client().post('/auth/register', data=self.user)        
        username = "pwalukagga@gmail.com" 
        password = "telnetcmd123"
        url = '/auth/login'
        response_login = self.open_with_auth(url, username, password)
        # getting token after login
        token = json.loads(response_login.get_data().
        decode('utf-8'))['token']
        # adding custom 'x-access-token' to request headers
        headers = {"x-access-token": token, 
                   "Content-Type": "application/json"}
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        category_data = json.dumps({"name": "LunchBuffe", 
                                     "description": 
                                     "How to make lunch buffe"})
        response = self.client().post('/recipe_category', 
                                      headers=headers,
                                      data=category_data)
        recipe_data = json.dumps({"name": "Chicken Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        recipe_data = json.dumps({"name": "Beef Buffe", 
                                  "ingredients": "oil, Onions,\
                                  Tomatoes",
                                  "description": "Mix and boil"})
        response = self.client().post('/recipe_category/2/recipes', 
                                      headers=headers, 
                                      data=recipe_data)
        response = self.client().delete('/recipe_category/2/recipes/3', 
                                      headers=headers)
        self.assertEqual(response.status_code, 404)
        self.assertIn('Recipe not found', str(response.data))
    
    def test_user_fails_to_creates_recipe_category_if_not_loggedin(self):
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      data=category_data)
        self.assertEqual(response.status_code, 401)
        self.assertIn('Token is missing', str(response.data))
    
    def test_user_fails_to_retrieve_recipe_categories_if_not_loggedin(self):
        response = self.client().get('/recipe_category')
        self.assertEqual(response.status_code, 401)
        self.assertIn('Token is missing', str(response.data))
    
    def test_user_fails_to_retrieve_recipe_category_if_not_loggedin(self):
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      data=category_data)
        response = self.client().get('/recipe_category/1')
        self.assertEqual(response.status_code, 401)
        self.assertIn('Token is missing', str(response.data))
    
    def test_user_fails_to_edit_recipe_category_if_not_loggedin(self):
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      data=category_data)
        category_data = json.dumps({"name": "Breakfast", 
                                    "description": 
                                    "How to make breakfast"})
        response = self.client().put('/recipe_category/1', 
                                      data=category_data)
        self.assertEqual(response.status_code, 401)
        self.assertIn('Token is missing', str(response.data))
    
    def test_user_fails_to_delete_recipe_category_if_not_loggedin(self):
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": 
                                     "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      data=category_data)
        response = self.client().delete('/recipe_category/1')
        self.assertEqual(response.status_code, 401)
        self.assertIn('Token is missing', str(response.data))

if __name__ == '__main__':
    unittest.main()