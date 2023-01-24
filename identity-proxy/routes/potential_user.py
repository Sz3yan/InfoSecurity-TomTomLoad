import jwt
import json
import requests
import base64
import ipinfo
from datetime import datetime, timedelta
import google.auth.transport.requests

from flask import Blueprint, request, session, redirect, abort, make_response, jsonify, url_for

from static.classes.config import CONSTANTS, SECRET_CONSTANTS
from static.classes.storage import GoogleCloudStorage
from static.security.session_management import TTLSession
from static.security.certificate_authority import CertificateAuthority, Certificates
from static.functions.check_authentication import authenticated

from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
from functools import wraps

# todo
# 1. setup certificate authority 
# 2. setup certificate for identity proxy and tomtomload, run if valid


potential_user = Blueprint('potential_user', __name__, template_folder="templates", static_folder='static')

ttlSession = TTLSession()
storage = GoogleCloudStorage()
certificate_authority = CertificateAuthority()
certificate = Certificates()

client_secrets_file = CONSTANTS.IP_CONFIG_FOLDER.joinpath("client_secret.json")
flow = Flow.from_client_secrets_file(
    client_secrets_file = client_secrets_file,
    scopes = ["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri = CONSTANTS.CALLBACK_URL
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
    
    # print(authorization_url)
    # print(state)
    return redirect(authorization_url)


@potential_user.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)
    # print("callback")
    if not session["state"] == request.args["state"]:
        abort(500)

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token = credentials._id_token,
        request = token_request,
        audience = CONSTANTS.GOOGLE_CLIENT_ID,
        clock_skew_in_seconds = CONSTANTS.GOOGLE_OAUTH_SKEW_TIME,
    )

    session['id_info'] = id_info

    try:
        if ttlSession.get_data_from_session("route_from", data=True) != "api":
            ttlSession.write_data_to_session("route_from", "web")
    except:
        ttlSession.write_data_to_session("route_from", "web")


    return redirect("/authorisation")

# -----------------  END OF AUTHENTICATION ----------------- #


# -----------------  START OF AUTHORISATION ----------------- #

@potential_user.route("/authorisation", methods=["GET", "POST"])
@authenticated
def authorisation():
    # -----------------  START OF CONTEXT-AWARE ACCESS ----------------- #
    print(ttlSession.get_data_from_session("route_from", data=True))
    handler = ipinfo.getHandler(SECRET_CONSTANTS.IPINFO_TOKEN)
    details = handler.getDetails().all

    custom_ip = {
        "ip": details["ip"],
        "city": details["city"],
        "hostname": details["region"],
        "loc": details["loc"],
    }

    TTLContextAwareAccessClientIP = custom_ip
    TTLContextAwareAccessClientUserAgent = request.headers.get('User-Agent')
    TTLContextAwareAccessClientCertificate = "cert"

    # -----------------  END OF CONTEXT-AWARE ACCESS ----------------- #

    # -----------------  START OF BLACKLIST ----------------- #

    storage.download_blob(CONSTANTS.STORAGE_BUCKET_NAME, CONSTANTS.BLACKLISTED_FILE_NAME, CONSTANTS.IP_CONFIG_FOLDER.joinpath("blacklisted.json"))

    with open(CONSTANTS.IP_CONFIG_FOLDER.joinpath("blacklisted.json"), "r") as f:
        blacklisted = json.load(f)

    # -----------------  END OF BLACKLIST ----------------- #

    # -----------------  START OF ACCESS CONTROL LIST ----------------- #

    storage.download_blob(CONSTANTS.STORAGE_BUCKET_NAME, CONSTANTS.ACL_FILE_NAME, CONSTANTS.IP_CONFIG_FOLDER.joinpath("acl.json"))

    with open(CONSTANTS.IP_CONFIG_FOLDER.joinpath("acl.json"), "r") as s:
        acl = json.load(s)

    if (session['id_info'].get("name") not in blacklisted["blacklisted_users"]) and \
        (TTLContextAwareAccessClientUserAgent not in blacklisted["blacklisted_useragent"]) and \
        (TTLContextAwareAccessClientIP not in blacklisted["blacklisted_ip"]):

        role = 'Admins'

        for user, value in acl['SuperAdmins'].items():
            if session['id_info'].get("email") == user:
                role = 'SuperAdmins'

        if session['id_info'].get("email") not in acl['SuperAdmins']:
            if session['id_info'].get("email") not in acl['Admins']:
                w = open(CONSTANTS.IP_CONFIG_FOLDER.joinpath("acl.json"), "r")
                dict_acl = json.loads(w.read())
                dict_acl[session['id_info'].get("email")] = ["read", "write", "delete"]
                w.close()

                r = open(CONSTANTS.IP_CONFIG_FOLDER.joinpath("acl.json"), "w")
                r.write(json.dumps(dict_acl))
                r.close()

                storage.upload_blob(
                    bucket_name=CONSTANTS.STORAGE_BUCKET_NAME,
                    source_file_name=CONSTANTS.IP_CONFIG_FOLDER.joinpath("acl.json"),
                    destination_blob_name="acl.json"
                )

            else:
                print("You are already Admin.")

        else:
            print("You are already SuperAdmin.")

        # -----------------  END OF ACCESS CONTROL LIST ----------------- #

        # -----------------  START OF CERTIFICATE AUTHORITY ----------------- #

        # CREATE CERTIFICATE AUTHORITY IF NOT EXISTS

        # -----------------  END OF CERTIFICATE AUTHORITY ----------------- #

        # -----------------  START OF PACKAGING UP ----------------- #

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
                        "role" : role,
                    },
                SECRET_CONSTANTS.JWT_SECRET_KEY,
                algorithm=CONSTANTS.JWT_ALGORITHM
            )
        }

        context_aware_access = {
            "TTL-Context-Aware-Access-Client-IP": TTLContextAwareAccessClientIP,
            "TTL-Context-Aware-Access-Client-User-Agent": TTLContextAwareAccessClientUserAgent,
            "TTL-Context-Aware-Access-Client-Certificate": TTLContextAwareAccessClientCertificate
        }

        if ttlSession.get_data_from_session("route_from", data=True) != "api" and ttlSession.get_data_from_session("route_from", Ptoken=True) == ttlSession.get_token():
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
                secure=True
            )

            response.set_cookie(
                'TTL-Context-Aware-Access',
                value=base64.b64encode(str(context_aware_access).encode("utf-8")),
                httponly=True,
                secure=True
            )

            return response
        elif ttlSession.get_data_from_session("route_from", data=True) == "api" and ttlSession.get_data_from_session("route_from", Ptoken=True) == ttlSession.get_token():
            # print("\nEntering api back route\n")
            # return jsonify(message="This is for api")
            return redirect(url_for("api.callback"))
        
        else:
            abort(401)

    else:
        return abort(401)

    # -----------------  END OF PACKAGING UP ----------------- #

# -----------------  END OF AUTHORISATION ----------------- #
