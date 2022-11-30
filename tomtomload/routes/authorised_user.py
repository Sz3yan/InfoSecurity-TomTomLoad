from flask import Blueprint, render_template, session, redirect, request


authorised_user = Blueprint('authorised_user', __name__, template_folder="templates", static_folder='static')


# wrapper to check for session
def check_signed_header(function):
    def wrapper(*args, **kwargs):
        if session["TTL-Authenticated-User-Name"] == None:
            return {"error": "User not authorized"}
        else:
            return function()

    wrapper.__name__ = function.__name__
    return wrapper


@authorised_user.route('/')
def home():
    # signed_header = request.args["signed_header"]
    # session["signed_header"] = signed_header
    # print(f"signed_header: {signed_header}")
    # print(f"session: {session}")

    print(f"request headers: {request.headers}")
    print(f"TTL-Authenticated-User-Name: {request.headers.get('Ttl-Authenticated-User-Name')}")
    print(f"TTL-JWTAuthenticated-User: {request.headers.get('Ttl-JWTAuthenticated-User')}")

    session["TTL-Authenticated-User-Name"] = request.headers.get("Ttl-Authenticated-User-Name")
    session["TTL-JWTAuthenticated-User"] = request.headers.get("Ttl-JWTAuthenticated-User")
        
    return redirect("/dashboard")


@authorised_user.route('/dashboard')
@check_signed_header
def dashboard():
    return render_template('authorised_admin/dashboard.html', user=session["TTL-Authenticated-User-Name"])


@authorised_user.route("/logout")
def logout():
    session.clear()
    return redirect("https://127.0.0.1:8080/")
