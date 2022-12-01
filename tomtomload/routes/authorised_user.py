from flask import Blueprint, render_template, session, redirect, request


authorised_user = Blueprint('authorised_user', __name__, template_folder="templates", static_folder='static')


# wrapper to check for session
def check_signed_header(function):
    def wrapper(*args, **kwargs):
        print(session)
        if "signed_header" not in session:
            return {"error": "User not authorized"}
        else:
            return function()

    wrapper.__name__ = function.__name__
    return wrapper


@authorised_user.route('/')
def home():
    try:
        signed_header = request.args["signed_header"]
        session["signed_header"] = signed_header

        print(f"signed_header: {signed_header}")
        
        return redirect("/dashboard")
    except:
        return {"error": "User not authorized"}


@authorised_user.route('/dashboard')
@check_signed_header
def dashboard():
    return render_template('authorised_admin/dashboard.html', user=session["signed_header"])


@authorised_user.route("/logout")
def logout():
    session.clear()
    return redirect("https://127.0.0.1:8080/")
