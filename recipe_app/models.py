# recipe_app/models.py

from recipe_app import db


class User(db.Model):
    '''Class to represent the users table'''

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(100), unique=True, nullable=False)
    first_name = db.Column(db.String(120), nullable=False)
    last_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    category = db.relationship('RecipeCategory', backref='users', 
                                lazy=True)

    def __init__(self, public_id, email, password, first_name, 
                  last_name):
        '''initialize with email'''
        self.public_id = public_id
        self.email = email
        self.password = password
        self.first_name = first_name 
        self.last_name = last_name
    
    def save(self):
        db.session.add(self)
        db.session.commit()
    
    @staticmethod
    def get_all():
        return User.query.all()

    def delete(self):
        db.session.delete(self)
        db.session.commit()
    
    def __repr__(self):
        return "<User: {}>". format(self.email)


class RecipeCategory(db.Model):
    '''class to represent recipe category table'''

    __tablename__ = 'recipe_category'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), 
                        nullable=False)
    
    def __init__(self, name, description, user_id):
        self.name = name
        self.description = description
        self.user_id = user_id
    
    def save(self):
        db.session.add(self)
        db.session.commit()
    
    @staticmethod
    def get_all():
        return RecipeCategory.query.all()

    def delete(self):
        db.session.delete(self)
        db.session.commit()
    
    def __repr__(self):
        return "<Category: {}>". format(self.name)


class Recipe(db.Model):
    '''Class to represent recipe table'''

    __tablename__ = 'recipe'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    ingredients = db.Column(db.String(250))
    description = db.Column(db.Text)
    cat_id = db.Column(db.Integer, db.ForeignKey('recipe_category.id'), 
                        nullable=False)
    user_id = db.Column(db.Integer, nullable=False)

    def __init__(self, name, cat_id, user_id,  ingredients=None, 
                 description=None):
        self.name = name
        self.ingredients = ingredients
        self.description = description
        self.cat_id = cat_id
        self.user_id = user_id
    
    def save(self):
        db.session.add(self)
        db.session.commit()
    
    @staticmethod
    def update():
        db.session.commit()
    
    @staticmethod
    def get_all():
        return Recipe.query.all()

    def delete(self):
        db.session.delete(self)
        db.session.commit()
    
    def __repr__(self):
        return "<Recipe: {}>". format(self.name)