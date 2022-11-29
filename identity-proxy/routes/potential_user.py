import jwt
import requests
import socket
import google.auth.transport.requests

from static.classes.config import CONSTANTS
from flask import Blueprint, request, session, redirect, abort, make_response
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol

# from ..static.security.secret_manager import SecretManager


potential_user = Blueprint('potential_user', __name__, template_folder="templates", static_folder='static')


client_secrets_file = CONSTANTS.IP_CONFIG_FOLDER.joinpath("client_secret.json")
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],  #here we are specifing what do we get after the authorization
    redirect_uri="https://127.0.0.1:8080/callback"
)

# wrapper to check for session
def authenticated(function):
    def wrapper(*args, **kwargs):
        if "id_info" in session:
            return function()
        else:
            return {"error": "User not authorized"}

    wrapper.__name__ = function.__name__
    return wrapper


@potential_user.route("/")
def login():
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        prompt='consent'
    )

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

    session['id_info'] = id_info

    print(session['id_info'])

    return redirect("/signed-header")


@potential_user.route("/signed-header")
@authenticated
def signed_header():
    # Signed Token (previously signed headers) will consist of 
    #  1. user's name
    #  2. user's email
    #  3. user's JWT = id_info
    # these will be stored in google secret manager.
    # the point of signed tokens is to verify that the user is who they say they are,
    # in case they managed to bypass the identity proxy.

    jwt_token = jwt.encode(
        {
            "google_id": session['id_info'].get("sub"),
            "name": session['id_info'].get("name"),
            "email": session['id_info'].get("email"),
            "picture": session['id_info'].get("picture")
        },
        CONSTANTS.JWT_ACCESS_TOKEN_SECRET_KEY,
        algorithm=CONSTANTS.JWT_ACCESS_TOKEN_ALGORITHM
    )

    signed_headers = {
        "TTL-Authenticated-User-Name": session['id_info'].get("name"),
        "TTL-Authenticated-User-Email": session['id_info'].get("email"),
        "TTL-JWTAuthenticated-User": jwt_token,
    }

    print(f"signed_headers {signed_headers}", "\n")

    host = socket.gethostname()  # as both code is running on same pc
    port = 5001  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server
    client_socket.send(str(signed_headers).encode())
    client_socket.close()  # close the connection

    print("Signed Headers Sent")


    # Identity proxy will then check for the role and see if the user is allowed to access the page.
    # if the user is allowed to access the page, the identity proxy will then redirect the user to Tom Tom Load.
    # if the user is not allowed to access the page, the identity proxy will then redirect the user to the error page.
    # only correct authentication and authorisation will ever reach Tom Tom Load.
    
    # if session['id_info'].get("name") not in CONSTANTS.AUTHORIZED_USERS:
    #     return {"error": "User not authorized"}

    # else:
    return redirect("https://127.0.0.1:5000/")
