from flask import Blueprint, render_template, session, redirect

authorised_user = Blueprint('authorised_user', __name__, template_folder="templates", static_folder='static')


@authorised_user.route('/')
def home():
    print("TOMTOMLOAD")
    return render_template('authorised_admin/dashboard.html')

@authorised_user.route("/logout")
def logout():
    session.clear()
    return redirect("https://127.0.0.1:8080/")
