from static.classes.config import CONSTANTS
from static.classes.storage import GoogleCloudStorage
from static.functions.check_authentication import ttl_redirect_user
from flask import Blueprint, render_template, request, redirect, abort, jsonify

api = Blueprint('api', __name__, url_prefix="/api", template_folder="templates", static_folder='static')

# ------ User API ------
@api.route("/create_user", methods=["POST"])
@ttl_redirect_user
def api_create_user():
    pass


@api.route("/view_user", methods=["GET"])
@ttl_redirect_user
def api_view_users():
    return jsonify(message="hello"),200


@api.route("/view_user/<regex('[0-9]{21}'):id>", methods=["GET"])
@ttl_redirect_user
def api_view_user():
    pass


@api.route("/edit_user/<regex('[0-9]{21}'):id>", methods=["PUT"])
@ttl_redirect_user
def api_edit_user():
    pass


@api.route("/delete_user/<regex('[0-9]{21}'):id>", methods=["DELETE"])
@ttl_redirect_user
def api_delete_user():
    pass


# ------ Admin API ------
@api.route("/create_admin", methods=["POST"])
@ttl_redirect_user
def api_create_admin():
    pass


@api.route("/view_admin", methods=["GET"])
@ttl_redirect_user
def api_view_admins():
    pass


@api.route("/view_admin/<regex('[0-9]{21}'):id>", methods=["GET"])
@ttl_redirect_user
def api_view_admin():
    pass


@api.route("/edit_admin/<regex('[0-9]{21}'):id>", methods=["PUT"])
@ttl_redirect_user
def api_edit_admin():
    pass


@api.route("/delete_admin/<regex('[0-9]{21}'):id>", methods=["DELETE"])
@ttl_redirect_user
def api_delete_admin():
    pass


# ------ Post API ------
@api.route("/create_post", methods=["POST"])
@ttl_redirect_user
def api_create_post():
    pass


@api.route("/view_post", methods=["GET"])
@ttl_redirect_user
def api_view_posts():
    pass


@api.route("/view_post/<regex('[0-9a-f]{32}'):id>", methods=["GET"])
@ttl_redirect_user
def api_view_post():
    pass


@api.route("/update_post/<regex('[0-9a-f]{32}'):id>", methods=["PUT"])
@ttl_redirect_user
def api_update_post():
    pass


@api.route("/delete_post/<regex('[0-9a-f]{32}'):id>", methods=["DELETE"])
@ttl_redirect_user
def api_delete_post():
    pass

