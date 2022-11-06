import vt

from static.classes.constants import CONSTANTS, SECRET_CONSTANTS
from static.classes.firebase import Firebase
from flask import Blueprint, render_template, request, session, redirect, abort

user = Blueprint('user', __name__, template_folder="templates", static_folder='static')


@user.route('/')
def home():
    return render_template('user/home.html')
