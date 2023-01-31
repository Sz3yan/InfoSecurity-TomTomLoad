from flask import Blueprint, render_template

from static.classes.config import CONSTANTS

error = Blueprint("error", __name__, static_folder="static", template_folder="templates")


# Bad Request
@error.app_errorhandler(400)
def error400(e):
    return render_template(
        "error_base.html", title="400 Bad Request", errorNo=400, endpoint=CONSTANTS.ADMIN_URL, IP=CONSTANTS.IDENTITY_PROXY_URL,
        description="Your request was a malformed or illegal request."
    ), 400


# Unauthorised
@error.app_errorhandler(401)
def error401(e):
    return render_template(
        "error_base.html", title="401 Unauthorised", errorNo=401, endpoint=CONSTANTS.ADMIN_URL, IP=CONSTANTS.IDENTITY_PROXY_URL,
        description="TomTomLoad is unable to authorise your request, JWT Signature expired"
    ), 401


# Forbidden
@error.app_errorhandler(403)
def error403(e):
    return render_template(
        "error_base.html", title="403 Forbidden", errorNo=403, endpoint=CONSTANTS.ADMIN_URL, IP=CONSTANTS.IDENTITY_PROXY_URL,
        description="You do not have permission to access this resource."
    ), 403


# Not Found
@error.app_errorhandler(404)
def error404(e):
    return render_template(
        "error_base.html", title="404 Not Found", errorNo=404, endpoint=CONSTANTS.ADMIN_URL, IP=CONSTANTS.IDENTITY_PROXY_URL,
        description="We're sorry but it looks like that page doesn't exist anymore."
    ), 404


# Method Not Allowed
@error.app_errorhandler(405)
def error405(e):
    return render_template(
        "error_base.html", title="405 Method Not Allowed", errorNo=405, endpoint=CONSTANTS.ADMIN_URL, IP=CONSTANTS.IDENTITY_PROXY_URL,
        description="The page you are looking for cannot be displayed because the requested method is not allowed."
    ), 405


# Payload Too Large
@error.app_errorhandler(413)
def error413(e):
    return render_template(
        "error_base.html", title="413 Payload Too Large", errorNo=413, endpoint=CONSTANTS.ADMIN_URL, IP=CONSTANTS.IDENTITY_PROXY_URL,
        description="Request entity is larger than limits defined by TomTomLoad's server."
    ), 413


# Invalid File Format
@error.app_errorhandler(415)
def error413(e):
    return render_template(
        "error_base.html", title="415 Invalid file format", errorNo=415, endpoint=CONSTANTS.ADMIN_URL, IP=CONSTANTS.IDENTITY_PROXY_URL,
        description="The request entity has a media type which the server or resource does not support."
    ), 415


# Too Many Requests
@error.app_errorhandler(429)
def error429(e):
    return render_template(
        "error_base.html", title="429 Too Many Requests", errorNo=429, endpoint=CONSTANTS.ADMIN_URL, IP=CONSTANTS.IDENTITY_PROXY_URL,
        description="Sorry! Rate limit exceeded. Please try again later."
    ), 429


# Internal Server Error
@error.app_errorhandler(500)
def error500(e):
    return render_template(
        "error_base.html", title="500 Internal Server Error", errorNo=500, endpoint=CONSTANTS.ADMIN_URL, IP=CONSTANTS.IDENTITY_PROXY_URL,
        description="The server encountered an internal error or misconfiguration and was unable to complete your request."
    ), 500


# Not Implemented
@error.app_errorhandler(501)
def error501(e):
    return render_template(
        "error_base.html", title="501 Not Implemented", errorNo=501, endpoint=CONSTANTS.ADMIN_URL, IP=CONSTANTS.IDENTITY_PROXY_URL,
        description="The server is unable to process your request."
    ), 501


# Bad Gateway
@error.app_errorhandler(502)
def error502(e):
    return render_template(
        "error_base.html", title="502 Bad Gateway", errorNo=502, endpoint=CONSTANTS.ADMIN_URL, IP=CONSTANTS.IDENTITY_PROXY_URL,
        description="The server encountered a temporary error and was unable to complete your request. Please try again later."
    ), 502


# Service Temporarily Unavailable
@error.app_errorhandler(503)
def error503(e):
    return render_template(
        "error_base.html", title="503 Service Temporarily Unavailable", errorNo=503, endpoint=CONSTANTS.ADMIN_URL, IP=CONSTANTS.IDENTITY_PROXY_URL,
        description="This could be due to maintenance downtime or capacity problems. Please try again later."
    ), 503
