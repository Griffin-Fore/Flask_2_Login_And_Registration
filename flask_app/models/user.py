
from flask_app import app
from flask_app.config.mysqlconnection import connectToMySQL
from flask import flash, session
import re
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)
class User:
    DB = 'login_and_registration'

    def __init__( self , data ):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']

    # Create/Insert
    @classmethod
    def create_user(cls, user_data):
        if not cls.validate_user_data(user_data):
            return False
        # cls.parse_user_data(user_data)
        user_data = user_data.copy()
        user_data['password'] =  bcrypt.generate_password_hash(user_data['password'])
        query = """
        INSERT INTO users (
            first_name, 
            last_name, 
            email, 
            password) 
        VALUES (
            %(first_name)s, 
            %(last_name)s, 
            %(email)s,
            %(password)s)
        ;"""
        user_id = connectToMySQL(cls.DB).query_db(query, user_data)
        session['user_id'] = user_id
        session['user_name'] = f'{user_data["first_name"]} {user_data["last_name"]}'
        return user_id
        
    @classmethod
    def validate_user_data(cls, data):
        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
        is_valid = True
        if len(data['first_name']) < 2:
            flash('First name must contain at least two characters!')
            is_valid = False
        if len(data['last_name']) < 2:
            flash('Last name must contain at least 2 characters!')
            is_valid = False
        # if 'id' not in data:
        if len(data['password']) < 8:
            flash('Password must be at least eight characters')
            is_valid = False
        if data['password'] != data['confirm_password']:
            flash('Passwords do not match')
            is_valid = False
        # if 'id' not in data or data['email'] != User.get_user_by_id(data[id]).email : #if new user or if user wants to change email
        if not EMAIL_REGEX.match(data['email']):
            flash('invalid email address')
            is_valid = False
        if User.get_user_by_email(data['email']):
            flash('Email already taken')
            is_valid = False
        return is_valid

    # @staticmethod
    # def parse_user_data(data):
    #     parsed_data = {
    #         'email' : data['email'],
    #         'first_name' : data['first_name'],
    #         'last_name' : data['last_name'],
    #         'password' : bcrypt.generate_password_hash(data['password'])
    #     }
    #     print('88888888888888888 Parsed_Data', parsed_data)
    #     return parsed_data

    @classmethod
    def get_user_by_email(cls, email):
        query = "SELECT * FROM users WHERE email = %(email)s"
        data = { 'email' : email }
        user_data = connectToMySQL(cls.DB).query_db(query, data)
        if not user_data:
            return False
        return cls(user_data[0])
    
    @classmethod
    def get_user_by_id(cls, id):
        query = "SELECT * FROM users WHERE id = %(id)s"
        data = { 'id' : id }
        user_data = connectToMySQL(cls.DB).query_db(query, data)
        return cls(user_data[0])
    
    @staticmethod
    def login(data):
        this_user = User.get_user_by_email(data['email'])
        print('this user = ', this_user)
        if this_user:
            if bcrypt.check_password_hash(this_user.password, data['password']):
                session['user_id'] = this_user.id
                session['user_name'] = f'{this_user.first_name} {this_user.last_name}'
                return True
        flash('Email or Password incorrect')
        return False