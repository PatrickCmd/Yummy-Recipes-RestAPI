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
    
    def test_get_users(self):
        '''Tests that users are return successfully'''
        response = self.client().post('/auth/register', data=self.user)
        response = self.client().get('/users')
        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()