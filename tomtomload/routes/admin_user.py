from static.classes.config import CONSTANTS
from static.classes.storage import GoogleCloudStorage
#from static.classes.form import login 
from flask import Blueprint, render_template, request, redirect, abort


admin_user = Blueprint('admin_user', __name__, url_prefix="/user", template_folder="templates", static_folder='static')


# ------ Admin User ------
@admin_user.route("/login")
def api_admin_user_login():
    return render_template('user/login.html')


@admin_user.route("/signup")
def api_admin_user_signup():
    return render_template('user/signup.html')


@admin_user.route("/forget")
def api_admin_user_forget():
    return render_template('user/forget.html')