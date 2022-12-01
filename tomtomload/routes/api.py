import requests
import google.auth.transport.requests

from static.classes.config import CONSTANTS, SECRET_CONSTANTS
from flask import Blueprint, request, session, redirect, abort
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol

api = Blueprint('api', __name__, template_folder="templates", static_folder='static')

# ------ Login API ------
@api.route("/login")
def api_login():
    pass


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

