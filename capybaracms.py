import os
import time
import mysql.connector
from functools import wraps
from flask import  request, redirect, make_response, request
from jose import jwt





class CapyBaraCMS:
    def __init__(self, config, app):
        self.secret = os.urandom(32)
        self.config = config
        self.app = app

    def connect_to_mysql(self, attempts=3, delay=2):
        attempt = 1
        # Implement a reconnection routine
        while attempt < attempts + 1:
            try:
                res =  mysql.connector.connect(**self.config)
                self.app.logger.debug("Connected to MySQL! %s", res)
                return res
            except (mysql.connector.Error, IOError) as err:
                if (attempts is attempt):
                    # Attempts to reconnect failed; returning None
                    self.app.logger.debug("Failed to connect, exiting without a connection: %s", err)
                    return None
                # progressive reconnect delay
                time.sleep(delay ** attempt)
                attempt += 1
        return None

    
    def token_required(self, f):
        @wraps(f)
        def decorator(*args, **kwargs):
            token = request.cookies.get('SESSION', None)
            if token is None:
                return make_response(redirect('/login'))
            try:
                data = jwt.decode(token, self.secret, algorithms=["HS256"])
                current_user = data["username"]
            except:
                return make_response(redirect('/login'))
            return f(current_user, *args, **kwargs)
        return decorator
    

    def token_read(self, f):
        @wraps(f)
        def decorator(*args, **kwargs):
            token = request.cookies.get('SESSION', None)
            if token is None:
                return f(None, *args, **kwargs)
            try:
                data = jwt.decode(token, self.secret, algorithms=["HS256"])
                current_user = data["username"]
            except:
                return f(None, *args, **kwargs)
            return f(current_user, *args, **kwargs)
        return decorator
    
    def login(self, username, password):
        mysql = DBSingleton(self).get_instance()
        cursor = mysql.cursor()
        # use prepared statement to prevent SQL injection
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()

        if user and user[2] == password:
            return  jwt.encode({"username": username}, self.secret, algorithm="HS256")
            
        return None
        
    def logout(self):
        return True

        
    def is_admin(self, username):
        if username is None:
            return False
        mysql = DBSingleton(self).get_instance()
        cursor = mysql.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        return user and user[3] == True
    
    def get_user(self, id):
        try:
            id = int(id)
        except Exception as e:
            return 'Invalid user id. Must be an integer.'
        mysql = DBSingleton(self).get_instance()
        cursor = mysql.cursor()
        cursor.execute("SELECT * FROM users WHERE id = %s", (id,))
        user = cursor.fetchone()
        # return json user object without password
        return {'id':str(id), 'username': user[1], 'admin': user[3]}
    
    def get_users(self, current_user):
        mysql = DBSingleton(self).get_instance()
        if self.is_admin(current_user) == False:
            return 'Invalid user.', 401
        cursor = mysql.cursor()
        cursor.execute("SELECT * FROM users")
        # returrn list of all users
        users = cursor.fetchall()
        cursor.close()
        return users

        
class DBSingleton:
    instance = None
    capybara = None
    def __init__(self, c):
        DBSingleton.capybara = c
        if DBSingleton.instance is None:
            DBSingleton.instance = DBSingleton.capybara.connect_to_mysql()

    @classmethod
    def get_instance(cls):
        if cls.instance is None:
            
            cls.instance = cls.capybara.connect_to_mysql()
        return cls.instance