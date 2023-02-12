from functools import wraps
from flask import request, jsonify, session, redirect, url_for
from static.security.session_management import TTLSession
from static.security.secure_data import GoogleCloudKeyManagement
from static.classes.storage import GoogleCloudStorage
from static.classes.config import CONSTANTS, SECRET_CONSTANTS
from datetime import datetime, timedelta
import jwt
import json
import requests

KeyManagement = GoogleCloudKeyManagement()
ttlSession = TTLSession()
storage = GoogleCloudStorage()

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
                
                decode_jwt = jwt.decode(
                    bearer_token, 
                    algorithms = "HS256",
                    key = str(KeyManagement.retrieve_key(
                            project_id = CONSTANTS.GOOGLE_PROJECT_ID,
                            location_id = CONSTANTS.GOOGLE_LOCATION_ID,
                            key_ring_id = CONSTANTS.GOOGLE_KEY_RING_ID,
                            key_id = CONSTANTS.JWT_ACCESS_TOKEN_SECRET_KEY
                        ))
                )

                if check_blacklist(decode_jwt["name"]):
                    return func(*args, **kwargs)
                else:
                    return jsonify(Error="Forbidden access"),403

            except KeyError:
                return jsonify(Error="Please input a authorization token"),401
            except jwt.ExpiredSignatureError:
                return jsonify(Error="Token has expired"),401
            except jwt.InvalidTokenError:
                return jsonify(Error="Forbidden access"),403
    
    return decorated_function


# ----- Redirect User -----
def ttl_redirect_user(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        ttlSession.write_data_to_session("route_from","api")
        
        try:
            if ttl_check_user_agent() and not ttlSession.verfiy_Ptoken("TTLAuthenticatedUserName"):
                return redirect(url_for("potential_user.login"))
            else:
                return func(*args, **kwargs)
        except:
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


# ----- Check Blacklist -----
def check_blacklist(username):
    storage.download_blob(CONSTANTS.STORAGE_BUCKET_NAME, CONSTANTS.BLACKLISTED_FILE_NAME, CONSTANTS.IP_CONFIG_FOLDER.joinpath("blacklisted.json"))
    try:
        
        with open(CONSTANTS.IP_CONFIG_FOLDER.joinpath("blacklisted.json"), "r") as f:
            blacklisted = json.load(f)

        request_header = request.headers["User_agent"]
        device_ip_addr = requests.get("https://api64.ipify.org?format=json").text

        if (username not in blacklisted["blacklisted_users"]) and \
        (request_header not in blacklisted["blacklisted_useragent"]) and \
        (device_ip_addr not in blacklisted["blacklisted_ip"]):
            return True
        
        return False
    except:
        print("Cannot find blacklist")
        return False
    
