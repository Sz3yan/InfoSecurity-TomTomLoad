import requests
import google.auth.transport.requests

from static.classes.config import CONSTANTS, SECRET_CONSTANTS
from flask import Blueprint, request, session, redirect, abort
from google.oauth2 import id_token
from google_auth_oauthlib.flow import InstalledAppFlow
from pip._vendor import cachecontrol

api = Blueprint('api', __name__, url_prefix="/api", template_folder="templates", static_folder='static')

client_secrets_file = CONSTANTS.IP_CONFIG_FOLDER.joinpath("client_secret.json")
flow = InstalledAppFlow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri=CONSTANTS.API_CALLBACK_URL
)


@api.route("/login")
def verification():
    print(request.headers['User-Agent'])
    # authorization_url, state = flow.authorization_url(prompt="consent")
    flow.run_console()
    # print(authorization_url)
    # return redirect(authorization_url)
    

@api.route("/callback")
def ip_api_login():
    print(request.headers['User-Agent'])