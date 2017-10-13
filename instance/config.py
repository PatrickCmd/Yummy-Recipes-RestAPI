# app_instance/config.py

'''configuration settings for different app environments'''

import os


class BaseConfig(object):
    '''Default configuration settings'''
    DEBUG = False
    CSRF_ENABLED = True
    SECRET_KEY = os.urandom(24)
    # SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']
    SQLALCHEMY_DATABASE_URI = 'postgresql://@localhost/yummy_restapi'

class TestConfig(BaseConfig):
    '''Configurations for Testing, with a separate database'''
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///memory' # memory sqlite database

class DevelopmentConfig(BaseConfig):
    '''Configurations for development'''
    DEBUG = True

class ProductionConfig(BaseConfig):
    '''Configurations for production'''
    DEBUG = False
    TESTING = False

# dictionary for different app environments
app_config = {
    'development': DevelopmentConfig,
    'testing': TestConfig,
    'production': ProductionConfig
}
