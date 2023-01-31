import requests
import jwt
import google.auth.transport.requests

from static.classes.config import CONSTANTS, SECRET_CONSTANTS
from static.functions.check_authentication import ttl_jwt_authentication, ttl_redirect_user
from static.security.secure_data import GoogleCloudKeyManagement
from static.security.session_management import TTLSession
from static.security.ttl_limiter import TTL_Limiter

from flask import Blueprint, request, session, redirect, abort, jsonify, url_for, make_response
from datetime import datetime, timedelta
from google.oauth2 import id_token
from google_auth_oauthlib.flow import InstalledAppFlow
from pip._vendor import cachecontrol

api = Blueprint('api', __name__, url_prefix="/api", template_folder="templates", static_folder='static')

client_secrets_file = CONSTANTS.IP_CONFIG_FOLDER.joinpath("client_secret_2.json")
flow = InstalledAppFlow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
)
    # redirect_uri=CONSTANTS.API_CALLBACK_URL

# -----------------  START OF INITIALISATION ----------------- #

ttlSession = TTLSession()
KeyManagement = GoogleCloudKeyManagement()
ttlLimiter = TTL_Limiter()

# -----------------  END OF INITIALISATION ----------------- #

# ----- Change to Identity Proxy JWT -----
def api_ip_to_ttl_jwt():
    decoded_jwt = jwt.decode(
                    request.headers['Authorization'].split(" ")[1], 
                    algorithms = "HS256",
                    key = str(KeyManagement.retrieve_key(
                            project_id = CONSTANTS.GOOGLE_PROJECT_ID,
                            location_id = CONSTANTS.GOOGLE_LOCATION_ID,
                            key_ring_id = CONSTANTS.GOOGLE_KEY_RING_ID,
                            key_id = CONSTANTS.JWT_ACCESS_TOKEN_SECRET_KEY
                        ))
                )

    ttl_encoded_jwt = jwt.encode(
                        {
                            "iss": "identity-proxy",
                            "exp": datetime.utcnow() + timedelta(minutes=CONSTANTS.JWT_ACCESS_TOKEN_EXPIRATION_TIME) + (2 * timedelta(seconds=CONSTANTS.JWT_ACCESS_TOKEN_SKEW_TIME)),
                            "iat":  datetime.utcnow() - timedelta(seconds=30) + timedelta(seconds=CONSTANTS.JWT_ACCESS_TOKEN_SKEW_TIME),
                            "google_id": decoded_jwt.get("google_id"),
                            "name": decoded_jwt.get("name"),
                            "email": decoded_jwt.get("email"),
                            "picture": decoded_jwt.get("picture"),
                            "role" : decoded_jwt.get("role"),
                        },
                    SECRET_CONSTANTS.JWT_SECRET_KEY,
                    algorithm=CONSTANTS.JWT_ALGORITHM
                )
    
    return ttl_encoded_jwt

# -----------------  START OF AUTHENTICATION ----------------- #
@api.route("/login")
@ttl_redirect_user
def verification():

    ttlSession.write_data_to_session("route_from","api")
    print("User-Agent", request.headers['User-Agent'])

    verified_user = flow.run_local_server(port=8081)
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token = verified_user.id_token,
        request = token_request,
        audience = CONSTANTS.GOOGLE_CLIENT_ID2,
        clock_skew_in_seconds = CONSTANTS.GOOGLE_OAUTH_SKEW_TIME,
    )
    
    ttlSession.write_data_to_session('id_info',id_info)

    print(id_info)

    return redirect(url_for("potential_user.authorisation"))

# @api.route("/callback")
# def callback():
#     return jsonify(token=flow.credentials.id_token),200
    

@api.route("/v1/<route>", methods=['GET', 'POST'])
@ttl_redirect_user
@ttl_jwt_authentication
@ttlLimiter.limit_user(limit_value="10/day")
def ip_api_route(route):
    
    # print("Authorization", request.headers['Authorization'])
    
    response = make_response(redirect(f"{CONSTANTS.API_ROUTE_URL}/{route}", code=302))

    response.headers['Authorization'] = api_ip_to_ttl_jwt()

    return response


@api.route("/v1/<route>/<regex('(\d{21})|([0-9a-z]{32})'):id>", methods=['GET', 'PUT', 'DELETE'])
@ttl_redirect_user
@ttl_jwt_authentication
@ttlLimiter.limit_user(limit_value="10/day")
def ip_api_route_wif_id(route, id):
    
    # print("Authorization", request.headers['Authorization'])
    if len(id) == 21 or len(id) == 32:

        response = make_response(redirect(f"{CONSTANTS.API_ROUTE_URL}/{route}/{id}", code=302))

        response.headers['Authorization'] = api_ip_to_ttl_jwt()

        return response
    else:
        return jsonify(message="Invalid ID input"),404