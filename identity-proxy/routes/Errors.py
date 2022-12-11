from flask import Blueprint, render_template

error = Blueprint("error", __name__, static_folder="static", template_folder="templates")


# Unauthorised
@error.app_errorhandler(401)
def error401(e):
    return render_template(
        "error_base.html", title="You are not authorised to access this page", errorNo=401,
        description="Contact your administrator for access."
    ), 401


# Forbidden
@error.app_errorhandler(403)
def error403(e):
    return render_template(
        "error_base.html", title="403 Forbidden", errorNo=403,
        description="You do not have permission to access this resource."
    ), 403
