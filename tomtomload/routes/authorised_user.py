import json
import base64
import jwt

from static.classes.config import CONSTANTS, SECRET_CONSTANTS
from flask import Blueprint, render_template, session, redirect, request, make_response
from functools import wraps


authorised_user = Blueprint('authorised_user', __name__, url_prefix="/admin", template_folder="templates", static_folder='static')


# -----------------  START OF WRAPPER ----------------- #

def check_signed_credential(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if "TTLJWTAuthenticatedUser" not in session:
            return {"error": "User not authorized"}
        else:
            global decoded

            decoded = jwt.decode(
                session["TTLJWTAuthenticatedUser"]["TTL-JWTAuthenticated-User"], 
                algorithms="HS256", 
                key=SECRET_CONSTANTS.JWT_SECRET_KEY
            )

            return func(*args, **kwargs)

    return decorated_function

# -----------------  END OF WRAPPER ----------------- #


# -----------------  START OF AUTHENTICATED SIGNED TRAFFIC ----------------- #

@authorised_user.route('/')
def home():
    TTLAuthenticatedUserName = base64.b64decode(request.cookies.get('TTL-Authenticated-User-Name')).decode('utf-8')
    TTLJWTAuthenticatedUser_raw = base64.b64decode(request.cookies.get('TTL-JWTAuthenticated-User')).decode('utf-8')
    TTLContextAwareAccess_raw = base64.b64decode(request.cookies.get('TTL-Context-Aware-Access')).decode('utf-8')

    # -----------------  START OF SESSION (for easy access) ----------------- #

    cleanup_TTLJWTAuthenticatedUser = TTLJWTAuthenticatedUser_raw.replace("'", '"')
    TTLJWTAuthenticatedUser = json.loads(cleanup_TTLJWTAuthenticatedUser)

    cleanup_TTLContextAwareAccess = TTLContextAwareAccess_raw.replace("'", '"')
    TTLContextAwareAccess = json.loads(cleanup_TTLContextAwareAccess)

    session["TTLAuthenticatedUserName"] = TTLAuthenticatedUserName
    session["TTLJWTAuthenticatedUser"] = TTLJWTAuthenticatedUser
    session["TTLContextAwareAccess"] = TTLContextAwareAccess

    # -----------------  END OF SESSION ----------------- #

    decoded_TTLJWTAuthenticatedUser = jwt.decode(
        TTLJWTAuthenticatedUser["TTL-JWTAuthenticated-User"], 
        algorithms="HS256", 
        key=SECRET_CONSTANTS.JWT_SECRET_KEY
    )
    
    return render_template('authorised_admin/dashboard.html', user=TTLAuthenticatedUserName, pic=decoded_TTLJWTAuthenticatedUser["picture"])


@authorised_user.route("/logout")
@check_signed_credential
def logout():
    session.clear()

    # -----------------  START OF REMOVING COOKIE ----------------- #

    response = make_response(redirect("https://127.0.0.1:8080/", code=302))
    response.set_cookie("TTL-Authenticated-User-Name", request.cookies.get('TTL-Authenticated-User-Name') ,expires=0)
    response.set_cookie("TTL-JWTAuthenticated-User", request.cookies.get('TTL-JWTAuthenticated-User'), expires=0)
    response.set_cookie("TTL-Context-Aware-Access", request.cookies.get('TTL-Context-Aware-Access'), expires=0)

    # -----------------  END OF REMOVING COOKIE ----------------- #

    return response


@authorised_user.route("/media")
def media():
    return render_template('authorised_admin/media.html')


@authorised_user.route("/media/<string:id>")
def media_id(id):
    return render_template('authorised_admin/media_id.html')


@authorised_user.route("/posts")
def post():
    return render_template('authorised_admin/post.html')


@authorised_user.route("/posts/<string:id>")
def post_id(id):
    return render_template('authorised_admin/post_id.html')


@authorised_user.route("/users")
def users():
    return render_template('authorised_admin/users.html')


@authorised_user.route("/users/<string:id>")
def users_id(id):
    return render_template('authorised_admin/user_id.html')


@authorised_user.route("/users/create/<string:id>")
def create_users(id):
    return render_template('authorised_admin/user_create.html')


@authorised_user.route("/account")
def profile():
    return render_template('authorised_admin/profile.html')

# -----------------  END OF AUTHENTICATED SIGNED TRAFFIC ----------------- #
