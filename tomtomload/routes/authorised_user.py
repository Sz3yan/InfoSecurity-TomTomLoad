import json
import base64
from flask import Blueprint, render_template, session, redirect, request


authorised_user = Blueprint('authorised_user', __name__, url_prefix="/admin", template_folder="templates", static_folder='static')


def check_signed_credential(function):
    def wrapper(*args, **kwargs):
        if "signed_jwt" not in session:
            return {"error": "User not authorized"}
        else:
            cleanup = session["signed_jwt"].replace("'", '"')

            global str_to_dict
            str_to_dict = json.loads(cleanup)

            return function()

    wrapper.__name__ = function.__name__
    return wrapper


@authorised_user.route('/')
def home():
    signed_jwt = base64.b64decode(request.cookies.get('TTL-JWTAuthenticated-User')).decode('utf-8')
    print(request.headers.get("Authorization"))
    session["signed_jwt"] = signed_jwt
    cleanup = session["signed_jwt"].replace("'", '"')
    str_to_dict = json.loads(cleanup)
    
    return render_template('authorised_admin/dashboard.html', user=str_to_dict["TTL-Authenticated-User-Name"])


@authorised_user.route("/logout")
@check_signed_credential
def logout():
    print(str_to_dict)
    session.clear()

    return redirect("https://127.0.0.1:8080/")


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