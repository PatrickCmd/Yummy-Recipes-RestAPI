# tests/test_recipeapp.py

import unittest
import os
import json


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
        self.assertEqual(response.status_code, 200)
        self.assertIn('User already exists', str(response.data))
    
    def test_get_users(self):
        '''Tests that users are return successfully'''
        response = self.client().post('/auth/register', data=self.user)
        response = self.client().get('/users')
        self.assertEqual(response.status_code, 200)
    
    '''
    def test_user_creates_recipe_category(self):
        response = self.client().post('/auth/register', data=self.user)
        login_user = json.dumps({"username": "pwalukagga@gmail.com", 
                                 "password": "telnetcmd123"})
        response_login = self.client().get('/auth/login', 
                                            data=login_user)
        print(response_login)
        # getting token after login
        token = json.loads(response_login)["token"]
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      data=category_data)
        self.assertEqual(response.status_code, 201)
        self.assertIn('New recipe category created!', 
                       str(response.data))'''
    
    def test_user_fails_to_creates_recipe_category_if_not_loggedin(self):
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": "How to make breakfast"})
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
                                     "description": "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      data=category_data)
        response = self.client().get('/recipe_category/1')
        self.assertEqual(response.status_code, 401)
        self.assertIn('Token is missing', str(response.data))
    
    def test_user_fails_to_edit_recipe_category_if_not_loggedin(self):
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      data=category_data)
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": "How to make breakfast"})
        response = self.client().put('/recipe_category/1', 
                                      data=category_data)
        self.assertEqual(response.status_code, 401)
        self.assertIn('Token is missing', str(response.data))
    
    def test_user_fails_to_delete_recipe_category_if_not_loggedin(self):
        category_data = json.dumps({"name": "Breakfast", 
                                     "description": "How to make breakfast"})
        response = self.client().post('/recipe_category', 
                                      data=category_data)
        response = self.client().delete('/recipe_category/1')
        self.assertEqual(response.status_code, 401)
        self.assertIn('Token is missing', str(response.data))

if __name__ == '__main__':
    unittest.main()