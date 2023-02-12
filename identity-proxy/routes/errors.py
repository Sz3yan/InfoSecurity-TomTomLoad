from flask import Blueprint, render_template

from static.classes.config import CONSTANTS

error = Blueprint("error", __name__, static_folder="static", template_folder="templates")


@error.app_errorhandler(400)
def error400(e):
    return render_template(
        "error_base.html", title="400 Bad Request", errorNo=400,  IP=CONSTANTS.IDENTITY_PROXY_URL,
        description="Your request was a malformed or illegal request."
    ), 400


@error.app_errorhandler(401)
def error401(e):
    return render_template(
        "error_base.html", title="401 Unauthorised", errorNo=401,  IP=CONSTANTS.IDENTITY_PROXY_URL,
        description="Identity Proxy is unable to authorise your request"
    ), 401


@error.app_errorhandler(403)
def error403(e):
    return render_template(
        "error_base.html", title="403 Forbidden", errorNo=403,  IP=CONSTANTS.IDENTITY_PROXY_URL,
        description="You do not have permission to access this resource."
    ), 403


@error.app_errorhandler(404)
def error404(e):
    return render_template(
        "error_base.html", title="404 Not Found", errorNo=404,  IP=CONSTANTS.IDENTITY_PROXY_URL,
        description="We're sorry but it looks like that page doesn't exist anymore."
    ), 404


@error.app_errorhandler(405)
def error405(e):
    return render_template(
        "error_base.html", title="405 Method Not Allowed", errorNo=405,  IP=CONSTANTS.IDENTITY_PROXY_URL,
        description="The page you are looking for cannot be displayed because the requested method is not allowed."
    ), 405


@error.app_errorhandler(429)
def error429(e):
    return render_template(
        "error_base.html", title="429 Too Many Requests", errorNo=429,  IP=CONSTANTS.IDENTITY_PROXY_URL,
        description="Sorry! Rate limit exceeded. Please try again later."
    ), 429


@error.app_errorhandler(500)
def error500(e):
    return render_template(
        "error_base.html", title="500 Internal Server Error", errorNo=500,  IP=CONSTANTS.IDENTITY_PROXY_URL,
        description="The server encountered an internal error or misconfiguration and was unable to complete your request."
    ), 500
