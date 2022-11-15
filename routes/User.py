import vt
import requests
import google.auth.transport.requests

from static.classes.constants import CONSTANTS, SECRET_CONSTANTS
from flask import Blueprint, render_template, request, session, redirect, abort, make_response
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol

user = Blueprint('user', __name__, template_folder="templates", static_folder='static')


client_secrets_file = CONSTANTS.CONFIG_FOLDER.joinpath("client_secret.json")  #enter your client secret file path


flow = Flow.from_client_secrets_file(  #Flow is OAuth 2.0 a class that stores all the information on how we want to authorize our users
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],  #here we are specifing what do we get after the authorization
    redirect_uri="https://127.0.0.1:8080/callback"  #and the redirect URI is the point where the user will end up after the authorization
)


@user.route("/login")
def login():
    authorization_url, state = flow.authorization_url()  #asking the flow class for the authorization (login) url
    session["state"] = state
    return redirect(authorization_url)


@user.route("/callback")
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
    return redirect("/admin")  #the final page where the authorized users will end up


@user.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@user.route('/')
def home():
    # add http headers
    resp = make_response("Hello World", 200)
    resp.headers.extend({'X-TTL-Authenticated-Email': 'll@gmail.com'})
    resp.headers.extend({'X-TTL-Authenticated-id': 'asdfafgafa'})
    resp.headers.extend({'X-TTL-JWTAuthenticated': 'AT-5000'})
    return resp

    # return render_template('user/home.html')
