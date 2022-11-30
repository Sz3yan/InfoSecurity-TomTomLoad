from flask import Blueprint, render_template, session, redirect, request


authorised_user = Blueprint('authorised_user', __name__, template_folder="templates", static_folder='static')


# def check_signed_query(function):
#     def wrapper(*args, **kwargs):
#         if "signed_query" in session:
#             return function()
#         else:
#             return {"error": "User not authorized"}

#     wrapper.__name__ = function.__name__
#     return wrapper


@authorised_user.route('/')
def home():
    signed_query = request.args["signed_query"]
    session["signed_query"] = signed_query
    print(f"signed_query: {signed_query}")
    print(f"session: {session}")

    return redirect("/dashboard")


# @check_signed_query
@authorised_user.route('/dashboard')
def dashboard():
    print(f"session: {session}")
    return render_template('authorised_admin/dashboard.html')


@authorised_user.route("/logout")
def logout():
    session.clear()
    return redirect("https://127.0.0.1:8080/")
