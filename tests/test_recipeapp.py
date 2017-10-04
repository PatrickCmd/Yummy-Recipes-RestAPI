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
                                "email": "pwalukagga123456@gmail.com",
                                "password": "telnetcmd123"})

        # binds the app to the current context
        with self.app.app_context():
            # create all database tables
            db.create_all()
    
    def test_user_registration(self):
        '''Test API can register user (POST request)'''
        response = self.client().post('/auth/register', data=self.user)
        self.assertEqual(response.status_code, 201)
        self.assertIn('New user created!', str(response.data))

if __name__ == '__main__':
    unittest.main()