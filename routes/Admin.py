from static.classes.constants import CONSTANTS
from static.classes.firebase import Firebase
from flask import Blueprint, render_template, request, session, redirect, url_for


admin = Blueprint('admin', __name__, url_prefix='/admin', static_folder="static", template_folder="template")


@admin.route('/')
def hi():
    return render_template('admin/admin.html')