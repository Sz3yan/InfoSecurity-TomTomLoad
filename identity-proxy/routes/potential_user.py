import requests
import google.auth.transport.requests

from static.classes.config import CONSTANTS
from flask import Blueprint, request, session, redirect, abort
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol


potential_user = Blueprint('potential_user', __name__, template_folder="templates", static_folder='static')


client_secrets_file = CONSTANTS.IP_CONFIG_FOLDER.joinpath("client_secret.json")
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],  #here we are specifing what do we get after the authorization
    redirect_uri="https://127.0.0.1:8080/callback"
)


@potential_user.route("/")
def login():
    authorization_url, state = flow.authorization_url()  #asking the flow class for the authorization (login) url
    session["state"] = state
    return redirect(authorization_url)


@potential_user.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=CONSTANTS.GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")  #defing the results to show on the page
    session["name"] = id_info.get("name")

    print(session["name"])

    # redirect to tomtomload server
    return redirect("https://127.0.0.1:5000/")
