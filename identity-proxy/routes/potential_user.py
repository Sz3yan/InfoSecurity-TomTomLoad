import jwt
import json
import requests
import base64
from datetime import datetime, timedelta
import google.auth.transport.requests

from static.classes.config import CONSTANTS, SECRET_CONSTANTS
from flask import Blueprint, request, session, redirect, abort, make_response
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
from functools import wraps

from static.classes.storage import GoogleCloudStorage


potential_user = Blueprint('potential_user', __name__, template_folder="templates", static_folder='static')

client_secrets_file = CONSTANTS.IP_CONFIG_FOLDER.joinpath("client_secret.json")
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="https://127.0.0.1:8080/callback"
)

# -----------------  START OF WRAPPER ----------------- #

def authenticated(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if "id_info" in session:
            return func(*args, **kwargs)

    return decorated_function

# -----------------  END OF WRAPPER ----------------- #


# -----------------  START OF AUTHENTICATION ----------------- #

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
    print(session['id_info'].get("name"))

    return redirect("/authorisation")

# -----------------  END OF AUTHENTICATION ----------------- #


# -----------------  START OF AUTHORISATION ----------------- #

@authenticated
@potential_user.route("/authorisation", methods=["GET", "POST"])
def authorisation():

    # -----------------  START OF CONTEXT-AWARE ACCESS ----------------- #

    TTLContextAwareAccessClientIP = request.headers.get('X-Forwarded-For', request.remote_addr)
    TTLContextAwareAccessClientUserAgent = request.headers.get('User-Agent')
    TTLContextAwareAccessClientCertificate = "request.headers.get('TTL-Certificate')"

    # -----------------  END OF CONTEXT-AWARE ACCESS ----------------- #

    latest_blacklisted = GoogleCloudStorage()
    latest_blacklisted.download_blob(CONSTANTS.STORAGE_BUCKET_NAME, CONSTANTS.BLACKLISTED_FILE_NAME, CONSTANTS.IP_CONFIG_FOLDER.joinpath("blacklisted.json"))

    # open blacklisted json and convert it into a list
    with open(CONSTANTS.IP_CONFIG_FOLDER.joinpath("blacklisted.json"), "r") as f:
        blacklisted = json.load(f)
        print(blacklisted, type(blacklisted))


    if (session['id_info'].get("name") not in blacklisted["blacklisted_users"]) and \
        (TTLContextAwareAccessClientUserAgent not in blacklisted["blacklisted_useragent"]) and \
        (TTLContextAwareAccessClientIP not in blacklisted["blacklisted_ip"]):

        signed_header = {
            "TTL-Authenticated-User-Name": session['id_info'].get("name"),
            "TTL-JWTAuthenticated-User": 
                jwt.encode(
                    {
                        "iss": "identity-proxy",
                        "exp": datetime.utcnow() + timedelta(minutes=CONSTANTS.JWT_ACCESS_TOKEN_EXPIRATION_TIME) + (2 * timedelta(seconds=CONSTANTS.JWT_ACCESS_TOKEN_SKEW_TIME)),      
                        "iat":  datetime.utcnow() - timedelta(seconds=30) + timedelta(seconds=CONSTANTS.JWT_ACCESS_TOKEN_SKEW_TIME),
                        "google_id": session['id_info'].get("sub"),
                        "name": session['id_info'].get("name"),
                        "email": session['id_info'].get("email"),
                        "picture": session['id_info'].get("picture"),
                    },
                SECRET_CONSTANTS.JWT_SECRET_KEY,
                algorithm=CONSTANTS.JWT_ALGORITHM
            )
        }
        
        context_aware_access = {
            "TTL-Context-Aware-Access-Client-IP": TTLContextAwareAccessClientIP,
            "TTL-Context-Aware-Access-Client-User-Agent": TTLContextAwareAccessClientUserAgent,
            "TTL-Context-Aware-Access-Client-Certificate": "request.headers.get('TTL-Certificate')"
        }
        
        response = make_response(redirect("https://127.0.0.1:5000/admin", code=302))

        response.set_cookie(
            'TTL-Authenticated-User-Name',
            value=base64.b64encode(str(session['id_info'].get("name")).encode("utf-8")),
            httponly=True,
            secure=True
        )

        response.set_cookie(
            'TTL-JWTAuthenticated-User', 
            value=base64.b64encode(str(signed_header).encode("utf-8")),
            httponly=True, 
            secure=True)

        response.set_cookie(
            'TTL-Context-Aware-Access',
            value=base64.b64encode(str(context_aware_access).encode("utf-8")),
            httponly=True,
            secure=True
        )

        return response

    else:
        return {"message": "You are not authorised to access this page"}

# -----------------  END OF AUTHORISATION ----------------- #
