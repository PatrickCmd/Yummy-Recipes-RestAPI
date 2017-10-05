# Yummy-Recipes-RestAPI
Yummy recipes app is an application that allows users  to create, save and share meeting the needs of keeping track of awesome food recipes.

## Requirements(Building Blocks)
- `Python3` - A programming language that lets us work more quickly (The universe loves speed!).
- `Flask` - A microframework for Python based on Werkzeug, Jinja 2 and good intentions
- `Virtualenv` - A tool to create isolated virtual environment
- `PostgreSQL` – Postgres database offers many advantages over others.
- `Psycopg2` – A Python adapter for Postgres.
- `Flask-SQLAlchemy` – A Flask extension that provides support for SQLAlchemy.
- `Flask-Migrate` – Offers SQLAlchemy database migrations for Flask apps using Alembic.

## Installation
First clone this repository
```
$ git clone https://github.com/PatrickCmd/Yummy-Recipes-RestAPI.git
$ cd Yummy-Recipes-RestAPI
```
Create virtual environment and install it
```
$ virtualenv env
$ source/env/bin/activate
```
Then install all the necessary dependencies
```
pip install -r requirements.txt
```

## Initialize the database and create database tables
```
$ python manage.py db init
$ python manage.py db migrate
$ python manage.py db upgrade
```

## Run the server
At the terminal or console type
```
python run.py
```
To run tests run this command at the console/terminal
```
nosetests
```
