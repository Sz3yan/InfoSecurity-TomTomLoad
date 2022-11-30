from flask import Blueprint, render_template, session, redirect, request


authorised_user = Blueprint('authorised_user', __name__, template_folder="templates", static_folder='static')


# # check for session
# def check_signed_headers(function):
#     def wrapper(*args, **kwargs):
#         if "signed_headers" in session:
#             return function()
#         else:
#             return {"error": "User not authorized"}

#     wrapper.__name__ = function.__name__
#     return wrapper


@authorised_user.route('/')
def home():
    # get headers from request
    signed_headers = request.args["signed_headers"]
    session["signed_headers"] = signed_headers
    print(signed_headers)

    return redirect("/dashboard")


# @check_signed_headers
@authorised_user.route('/dashboard')
def dashboard():
    return render_template('authorised_admin/dashboard.html')


@authorised_user.route("/logout")
def logout():
    session.clear()
    return redirect("https://127.0.0.1:8080/")
