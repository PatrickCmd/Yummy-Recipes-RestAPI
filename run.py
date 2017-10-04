import os

from recipe_app import create_app

config_name = os.environ['APP_SETTINGS'] # conf_name = 'development'
app = create_app(config_name)

if __name__ == '__main__':
    app.run()
