from static.classes.config import CONSTANTS
from static.classes.storage import GoogleCloudStorage
from static.functions.check_authentication import ttl_redirect_user, ttl_jwt_authentication
from flask import Blueprint, render_template, request, redirect, abort, jsonify

api = Blueprint('api', __name__, url_prefix="/api", template_folder="templates", static_folder='static')

# ------ User API ------
@api.route("/create_user", methods=["POST"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_create_user():
    return jsonify(message="Work in progress"),200


@api.route("/view_user", methods=["GET"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_view_users():
    return jsonify(message="Work in progress"),200


@api.route("/view_user/<regex('[0-9]{21}'):id>", methods=["GET"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_view_user(id):
    return jsonify(message="Work in progress"),200


@api.route("/edit_user/<regex('[0-9]{21}'):id>", methods=["PUT"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_edit_user(id):
    return jsonify(message="Work in progress"),200


@api.route("/delete_user/<regex('[0-9]{21}'):id>", methods=["DELETE"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_delete_user(id):
    return jsonify(message="Work in progress"),200


# ------ Admin API ------
@api.route("/create_admin", methods=["POST"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_create_admin():
    return jsonify(message="Work in progress"),200


@api.route("/view_admin", methods=["GET"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_view_admins():
    return jsonify(message="Work in progress"),200


@api.route("/view_admin/<regex('[0-9]{21}'):id>", methods=["GET"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_view_admin(id):
    return jsonify(message="Work in progress"),200


@api.route("/edit_admin/<regex('[0-9]{21}'):id>", methods=["PUT"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_edit_admin(id):
    return jsonify(message="Work in progress"),200


@api.route("/delete_admin/<regex('[0-9]{21}'):id>", methods=["DELETE"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_delete_admin(id):
    return jsonify(message="Work in progress"),200


# ------ Post API ------
@api.route("/create_post", methods=["POST"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_create_post():
    return jsonify(message="Work in progress"),200


@api.route("/view_post", methods=["GET"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_view_posts():
    return jsonify(message="Work in progress"),200


@api.route("/view_post/<regex('[0-9a-f]{32}'):id>", methods=["GET"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_view_post(id):
    return jsonify(message="Work in progress"),200


@api.route("/update_post/<regex('[0-9a-f]{32}'):id>", methods=["PUT"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_update_post(id):
    return jsonify(message="Work in progress"),200


@api.route("/delete_post/<regex('[0-9a-f]{32}'):id>", methods=["DELETE"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_delete_post(id):
    return jsonify(message="Work in progress"),200

