import json
import base64
from flask import Blueprint, render_template, session, redirect, request


authorised_user = Blueprint('authorised_user', __name__, template_folder="templates", static_folder='static')


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
    # signed_name = base64.b64decode(request.cookies.get('TTL-Authenticated-User-Name')).decode('utf-8')
    signed_jwt = base64.b64decode(request.cookies.get('TTL-JWTAuthenticated-User')).decode('utf-8')

    session["signed_jwt"] = signed_jwt
    
    return render_template('authorised_admin/dashboard.html', user=signed_jwt)


@authorised_user.route("/logout")
@check_signed_credential
def logout():
    print(str_to_dict)
    session.pop("signed_credential", None)
    session.clear()

    return redirect("https://127.0.0.1:8080/")
