import requests
import google.auth.transport.requests

from static.classes.config import CONSTANTS, SECRET_CONSTANTS
from flask import Blueprint, request, session, redirect, abort
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol

api = Blueprint('api', __name__, template_folder="templates", static_folder='static')

@api.route("/login")
def ip_api_login():
    pass