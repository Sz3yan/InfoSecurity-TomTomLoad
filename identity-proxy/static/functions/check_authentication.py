from functools import wraps
from flask import request, jsonify, session


# ----- Webpage authentication -----
def authenticated(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if "id_info" in session:
            return func(*args, **kwargs)

    return decorated_function


# ----- API Authentication -----
def ttl_jwt_authentication(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        try:
            bearer_token = request.headers['Authorization']
            return func(*args, **kwargs)
        except:
            if KeyError:
                print("hhelp")
                return jsonify(message="Please input a authorization token"),401
    
    return decorated_function