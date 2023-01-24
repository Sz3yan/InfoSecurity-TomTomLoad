from functools import wraps
from flask import request, jsonify, session, redirect, url_for
from static.security.session_management import TTLSession


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
        if not ttl_check_user_agent():
            try:
                bearer_token = request.headers['Authorization']
                return func(*args, **kwargs)
            except:
                if KeyError:
                    return jsonify(message="Please input a authorization token"),401
    
    return decorated_function


# ----- Redirect User -----
def ttl_redirect_user(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        ttlSession = TTLSession()
        ttlSession.write_data_to_session("route_from","api")
        print(ttlSession.get_data_from_session("route_from", data=True))
        if ttl_check_user_agent():
            return redirect(url_for("potential_user.login"))

    return decorated_function


# ----- Check User Agent -----
def ttl_check_user_agent():
    request_header = request.headers["User_agent"]
    browser_list = ["Chrome", "Mozilla", "AppleWebKit", "Safari"]
    for browser in browser_list:
        if browser in request_header:
            return True
    
    return False
    