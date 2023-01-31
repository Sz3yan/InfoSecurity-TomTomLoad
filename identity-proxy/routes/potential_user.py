import os
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
        if "id_info" in session and ttlSession.verfiy_Ptoken("id_info"):
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
    ttlSession.write_data_to_session("state",state)
    # session["state"] = state
    
    # print(authorization_url)
    # print(state)
    return redirect(authorization_url)


@potential_user.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)
    print(request.args["state"])
    print(not ttlSession.get_data_from_session("state",data=True) == request.args["state"])
    if not ttlSession.get_data_from_session("state",data=True) == request.args["state"] and ttlSession.verfiy_Ptoken("state"):
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

    ttlSession.write_data_to_session('id_info',id_info)
    # session['id_info'] = id_info

    ttlSession.write_data_to_session("route_from","web")

    return redirect("/authorisation")

# -----------------  END OF AUTHENTICATION ----------------- #


# -----------------  START OF AUTHORISATION ----------------- #

@potential_user.route("/authorisation", methods=["GET", "POST"])
@authenticated
def authorisation():
    # -----------------  START OF CONTEXT-AWARE ACCESS ----------------- #

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
    
    if (ttlSession.get_data_from_session('id_info', data=True).get("name") not in blacklisted["blacklisted_users"]) and \
        (TTLContextAwareAccessClientUserAgent not in blacklisted["blacklisted_useragent"]) and \
        (TTLContextAwareAccessClientIP not in blacklisted["blacklisted_ip"]) and \
        (ttlSession.verfiy_Ptoken('id_info')):
        
        role = 'Admins'

        for user, value in acl['SuperAdmins'].items():
            if ttlSession.get_data_from_session('id_info', data=True).get("email") == user:
                role = 'SuperAdmins'

        if ttlSession.get_data_from_session('id_info', data=True).get("email") not in acl['SuperAdmins']:
            if ttlSession.get_data_from_session('id_info', data=True).get("email") not in acl['Admins']:
                w = open(CONSTANTS.IP_CONFIG_FOLDER.joinpath("acl.json"), "r")
                dict_acl = json.loads(w.read())
                dict_acl[ttlSession.get_data_from_session('id_info', data=True).get("email")] = ["read", "write", "delete"]
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

        certificate_directory = CONSTANTS.IP_CONFIG_FOLDER.joinpath("certificates")

        sub_certificate = os.path.join(certificate_directory, "SUBORDINATE_IDENTITY_PROXY")
        super_admin = os.path.join(certificate_directory, "SUPER_ADMIN.crt")

        used = 0

        if ttlSession.get_data_from_session("id_info", data=True).get("email") in acl['SuperAdmins']:

            w = open(CONSTANTS.IP_CONFIG_FOLDER.joinpath("acl.json"), "r")
            dict_acl = json.loads(w.read())
            used = dict_acl['SuperAdmins'][ttlSession.get_data_from_session("id_info", data=True).get("email")][3]

            if used == 1:
                if not os.path.exists(super_admin):
                    print("SUPER ADMIN ACCESS DENIED")

                    return abort(401)

                else:
                    print("SUPER ADMIN ACCESS GRANTED")
                    TTLContextAwareAccessClientCertificate = str(super_admin)

            if used == 0:
                certificate.create_certificate_csr(ca_name="SUPER_ADMIN")
                certificate_authority.create_certificate_from_csr(
                    csr_file="SUPER_ADMIN",
                    ca_name=sub_certificate,
                    ca_duration=100 * 24 * 60 * 60
                )

                used = 1

                r = open(CONSTANTS.IP_CONFIG_FOLDER.joinpath("acl.json"), "w")
                dict_acl['SuperAdmins'][ttlSession.get_data_from_session("id_info", data=True).get("email")][3] = used
                r.write(json.dumps(dict_acl))
                r.close()

                storage.upload_blob(
                    bucket_name=CONSTANTS.STORAGE_BUCKET_NAME,
                    source_file_name=CONSTANTS.IP_CONFIG_FOLDER.joinpath("acl.json"),
                    destination_blob_name="acl.json"
                )

        # -----------------  END OF CERTIFICATE AUTHORITY ----------------- #

        # -----------------  START OF PACKAGING UP ----------------- #

        if ttlSession.get_data_from_session("route_from", data=True) != "api" and ttlSession.verfiy_Ptoken("route_from"):
            signed_header = {
                "TTL-Authenticated-User-Name": ttlSession.get_data_from_session('id_info', data=True).get("name"),
                "TTL-JWTAuthenticated-User":
                    jwt.encode(
                        {
                            "iss": "identity-proxy",
                            "exp": datetime.utcnow() + timedelta(minutes=CONSTANTS.JWT_ACCESS_TOKEN_EXPIRATION_TIME) + (2 * timedelta(seconds=CONSTANTS.JWT_ACCESS_TOKEN_SKEW_TIME)),
                            "iat":  datetime.utcnow() - timedelta(seconds=30) + timedelta(seconds=CONSTANTS.JWT_ACCESS_TOKEN_SKEW_TIME),
                            "google_id": ttlSession.get_data_from_session('id_info', data=True).get("sub"),
                            "name": ttlSession.get_data_from_session('id_info', data=True).get("name"),
                            "email": ttlSession.get_data_from_session('id_info', data=True).get("email"),
                            "picture": ttlSession.get_data_from_session('id_info', data=True).get("picture"),
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

            response = make_response(redirect(CONSTANTS.ADMIN_URL, code=302))

            response.set_cookie(
                'TTL-Authenticated-User-Name',
                value=base64.b64encode(str(ttlSession.get_data_from_session('id_info', data=True).get("name")).encode("utf-8")),
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

        elif ttlSession.get_data_from_session("route_from", data=True) == "api" and ttlSession.verfiy_Ptoken("route_from"):
            print("\nEntering api back route\n")
            ttlJwtToken =jwt.encode(
                            {
                                "iss": "public",
                                "exp": ttlSession.get_data_from_session('id_info', data=True).get("exp"),
                                "iat":  ttlSession.get_data_from_session('id_info', data=True).get("iat"),
                                "google_id": ttlSession.get_data_from_session('id_info', data=True).get("sub"),
                                "name": ttlSession.get_data_from_session('id_info', data=True).get("name"),
                                "email": ttlSession.get_data_from_session('id_info', data=True).get("email"),
                                "picture": ttlSession.get_data_from_session('id_info', data=True).get("picture"),
                                "role" : role,
                            },
                        SECRET_CONSTANTS.JWT_SECRET_KEY,
                        algorithm=CONSTANTS.JWT_ALGORITHM
                    )

            return jsonify(token=ttlJwtToken)
        
        else:
            abort(401)

    else:
        return abort(401)

    # -----------------  END OF PACKAGING UP ----------------- #

# -----------------  END OF AUTHORISATION ----------------- #
