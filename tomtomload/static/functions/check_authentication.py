from functools import wraps
from flask import request, jsonify, session, redirect, url_for
from static.security.session_management import TTLSession
from static.security.secure_data import GoogleCloudKeyManagement
from static.classes.config import CONSTANTS
import jwt

KeyManagement = GoogleCloudKeyManagement()

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
        
        else:
            print("here is unsafe")
            return func(*args, **kwargs)
    
    return decorated_function

# ----- Redirect User -----
def ttl_redirect_user(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        
        try:
            print(ttl_check_user_agent())
            print(check_session())
            if (ttl_check_user_agent() and check_session()):
                return func(*args, **kwargs)
            elif ttl_check_user_agent():
                return redirect("https://127.0.0.1:8080")
            elif request.headers['Authorization']:
                return func(*args, **kwargs)
            else:
                return jsonify(message="Please login")
        except KeyError:
            return jsonify(message="Please input a authorization token"),401
            

    return decorated_function

# ----- Check User Agent -----
def ttl_check_user_agent():
    request_header = request.headers["User_agent"]
    browser_list = ["Chrome", "Mozilla", "AppleWebKit", "Safari"]
    for browser in browser_list:
        if browser in request_header:
            return True
    
    return False


def check_session():
    ttlSession = TTLSession()
    counter = 0
    try:
        if ttlSession.verfiy_Ptoken("TTLAuthenticatedUserName"):
            counter += 1
        else:
            print("Please use the same browser")
    except:
        print("TTLAuthenticatedUserName not found")

    try:
        if ttlSession.verfiy_Ptoken("TTLJWTAuthenticatedUser"):
            counter += 1
        else:
            print("Please use the same browser")
    except:
        print("TTLAuthenticatedUserName not found")
    
    try:
        if ttlSession.verfiy_Ptoken("TTLContextAwareAccess"):
            counter += 1
        else:
            print("Please use the same browser")
    except:
        print("TTLAuthenticatedUserName not found")

    print(counter)
    if counter == 3:
        return True
    else:
        return False