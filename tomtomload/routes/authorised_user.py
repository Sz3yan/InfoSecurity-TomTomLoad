import requests
from flask import Blueprint, render_template, session, redirect

authorised_user = Blueprint('authorised_user', __name__, template_folder="templates", static_folder='static')


# create a wrapper that checks if the user is logged in
# def signed_token(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if session.get("user_id") is None:
#             return redirect("/login")
#         return f(*args, **kwargs)
#     return decorated_function


@authorised_user.route('/')
def home():
    request = requests.get("https://127.0.0.1:5000/signed-header", verify=False)
    print(request.headers)
    
    return render_template('authorised_admin/dashboard.html')


@authorised_user.route("/logout")
def logout():
    session.clear()
    return redirect("https://127.0.0.1:8080/")
