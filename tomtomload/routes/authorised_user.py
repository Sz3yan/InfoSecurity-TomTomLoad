import json
from flask import Blueprint, render_template, session, redirect, request


authorised_user = Blueprint('authorised_user', __name__, template_folder="templates", static_folder='static')


def check_signed_credential(function):
    def wrapper(*args, **kwargs):
        cleanup = session["signed_credential"].replace("'", '"')
        global str_dict
        str_dict = json.loads(cleanup)

        # need check validity of JWT here

        if "signed_credential" not in session:
            return {"error": "User not authorized"}
        else:
            return function()

    wrapper.__name__ = function.__name__
    return wrapper


@authorised_user.route('/')
def home():
    try:
        signed_credential = request.args["signed_credential"]
        session["signed_credential"] = signed_credential
        
        return redirect("/dashboard")
    except:
        return {"error": "User not authorized"}


@authorised_user.route('/dashboard')
@check_signed_credential
def dashboard():
    return render_template('authorised_admin/dashboard.html', user=str_dict["TTL-Authenticated-User-Name"])


@authorised_user.route("/logout")
def logout():
    session.clear()
    return redirect("https://127.0.0.1:8080/")
