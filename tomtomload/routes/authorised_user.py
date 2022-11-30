from flask import Blueprint, render_template, session, redirect

from static.security.server_socket import start_server_socket


authorised_user = Blueprint('authorised_user', __name__, template_folder="templates", static_folder='static')


@authorised_user.route('/')
def home():
    
    
    return render_template('authorised_admin/dashboard.html')


@authorised_user.route('/hi')
def hi():
    return {'hi': 'hi'}


@authorised_user.route("/logout")
def logout():
    session.clear()
    return redirect("https://127.0.0.1:8080/")
