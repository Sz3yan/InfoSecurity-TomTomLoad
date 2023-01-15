import requests
import google.auth.transport.requests

from static.classes.config import CONSTANTS, SECRET_CONSTANTS
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
    print(request.headers['User-Agent'])
    
    return jsonify(token=flow.run_local_server(port=8081).token)
    
    

@api.route("/callback")
def ip_api_login():
    flow.fetch_token(authorization_response=request.url)
    print(request.headers['User-Agent'])