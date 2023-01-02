from static.classes.config import CONSTANTS
from flask import Blueprint, request, session, redirect, abort
#from static.classes.form import login 
from flask import Blueprint, render_template, request

api = Blueprint('api', __name__, url_prefix="/user", template_folder="templates", static_folder='static')

# ------ Login API ------
@api.route("/login")
def api_login():
    return render_template('api/login.html')

@api.route("/signup")
def api_signup():
    return render_template('api/signup.html')

@api.route("/forget")
def api_forget():
    return render_template('api/forget.html')


# ------ User API ------
@api.route("/create_user")
def api_create_user():
    pass


@api.route("/view_user")
def api_view_user():
    pass


@api.route("/edit_user")
def api_edit_user():
    pass


@api.route("/delete_user")
def api_delete_user():
    pass


# ------ Admin API ------
@api.route("/create_admin")
def api_create_admin():
    pass


@api.route("/view_admin")
def api_view_admin():
    pass


@api.route("/edit_admin")
def api_edit_admin():
    pass


@api.route("/delete_admin")
def api_delete_admin():
    pass


# ------ Post API ------
@api.route("/create_post")
def api_create_post():
    pass


@api.route("/view_post")
def api_view_post():
    pass


@api.route("/update_post")
def api_update_post():
    pass


@api.route("/delete_post")
def api_delete_post():
    pass

