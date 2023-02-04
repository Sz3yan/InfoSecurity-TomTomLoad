from functools import wraps
from flask import request, jsonify, session, redirect, url_for
from static.security.session_management import TTLSession
from static.security.secure_data import GoogleCloudKeyManagement
from static.classes.config import CONSTANTS, SECRET_CONSTANTS
from datetime import datetime, timedelta
import jwt

KeyManagement = GoogleCloudKeyManagement()

# ----- Webpage authentication -----
def authenticated(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        ttlSession = TTLSession()
        if "id_info" in session and ttlSession.verfiy_Ptoken("id_info"):
            return func(*args, **kwargs)

    return decorated_function


# ----- API Authentication -----
def ttl_jwt_authentication(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not ttl_check_user_agent():
            try:
                bearer_token = request.headers['Authorization'].split(" ")[1]
                # print(bearer_token)
                jwt.decode(
                    bearer_token, 
                    algorithms = "HS256",
                    key = str(KeyManagement.retrieve_key(
                            project_id = CONSTANTS.GOOGLE_PROJECT_ID,
                            location_id = CONSTANTS.GOOGLE_LOCATION_ID,
                            key_ring_id = CONSTANTS.GOOGLE_KEY_RING_ID,
                            key_id = CONSTANTS.JWT_ACCESS_TOKEN_SECRET_KEY
                        ))
                )
                return func(*args, **kwargs)
            except KeyError:
                return jsonify(message="Please input a authorization token"),401
            except jwt.ExpiredSignatureError:
                return jsonify(message="Token has expired"),401
            except jwt.InvalidTokenError:
                return jsonify(message="Forbidden access"),403
    
    return decorated_function


# ----- Redirect User -----
def ttl_redirect_user(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        ttlSession = TTLSession()
        ttlSession.write_data_to_session("route_from","api")
        
        if ttl_check_user_agent():
            return redirect(url_for("potential_user.login"))
        else:
            return func(*args, **kwargs)

    return decorated_function


# ----- Check User Agent -----
def ttl_check_user_agent():
    request_header = request.headers["User_agent"]
    browser_list = ["Chrome", "Mozilla", "AppleWebKit", "Safari"]
    for browser in browser_list:
        if browser in request_header:
            return True
    
    return False