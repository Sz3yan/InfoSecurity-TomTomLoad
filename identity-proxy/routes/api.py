import requests
import jwt
import google.auth.transport.requests

from static.classes.config import CONSTANTS, SECRET_CONSTANTS
from static.functions.check_authentication import ttl_jwt_authentication

from flask import Blueprint, request, session, redirect, abort, jsonify
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

# -----------------  START OF AUTHENTICATION ----------------- #
@api.route("/login")
def verification():
    verified_user = flow.run_local_server(port=8081)
    # print("User-Agent", request.headers['User-Agent'])
    
    # print(verified_user.id_token)
    
    return jsonify(token=verified_user.id_token),200
    

@api.route("/v1/<route>")
@ttl_jwt_authentication
def ip_api_login(route):
    # flow.fetch_token(authorization_response=request.url)
    print("Authorization", request.headers['Authorization'])
    
    verified_user = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token = verified_user.id_token,
        request = token_request,
        audience = CONSTANTS.GOOGLE_CLIENT_ID2,
        clock_skew_in_seconds = CONSTANTS.GOOGLE_OAUTH_SKEW_TIME,
    )

    if id_info != None:
        print(id_info)
        # return jsonify(message="hi"),200
        return redirect("https://127.0.0.1:5000/api/view_user")
    else:
        return jsonify(error="User profile not found.")
