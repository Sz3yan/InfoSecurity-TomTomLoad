import jwt
import json
import os

from static.functions.check_authentication import ttl_redirect_user, ttl_jwt_authentication
from flask import Blueprint, request, jsonify

from static.classes.config import CONSTANTS
from static.classes.storage import GoogleCloudStorage
from static.security.secure_data import GoogleCloudKeyManagement
from static.security.session_management import TTLSession

from ast import literal_eval


api = Blueprint('api', __name__, url_prefix="/api", template_folder="templates", static_folder='static')

KeyManagement = GoogleCloudKeyManagement()
ttlSession = TTLSession()
storage = GoogleCloudStorage()

def decoded_jwt():
    try:
        bearer_token = request.headers['Authorization'].split(" ")[1]
        
        return jwt.decode(
            bearer_token, 
            algorithms = "HS256",
            key = str(KeyManagement.retrieve_key(
                    project_id = CONSTANTS.GOOGLE_PROJECT_ID,
                    location_id = CONSTANTS.GOOGLE_LOCATION_ID,
                    key_ring_id = CONSTANTS.GOOGLE_KEY_RING_ID,
                    key_id = CONSTANTS.JWT_ACCESS_TOKEN_SECRET_KEY
                ))
        )
    except:
        if ttlSession.verfiy_Ptoken("TTLJWTAuthenticatedUser"):
            signed_header = ttlSession.get_data_from_session("TTLJWTAuthenticatedUser",data=True)
            return jwt.decode(
                signed_header["TTL-JWTAuthenticated-User"],
                algorithms = "HS256",
                key = str(KeyManagement.retrieve_key(
                    project_id = CONSTANTS.GOOGLE_PROJECT_ID,
                    location_id = CONSTANTS.GOOGLE_LOCATION_ID,
                    key_ring_id = CONSTANTS.GOOGLE_KEY_RING_ID,
                    key_id = CONSTANTS.JWT_ACCESS_TOKEN_SECRET_KEY
                ))
            )
        return jsonify(Error="Please the same browser to access")
        


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
    with open(CONSTANTS.TTL_CONFIG_FOLDER.joinpath("acl.json"), "r") as acl:
        decoded_dict = decoded_jwt()
        if decoded_jwt()["role"] == "SuperAdmins":
            return_dict1 = {"SuperAdmin_Details":{"id":decoded_dict['google_id'], "name":decoded_dict['name'], "email":decoded_dict['email'], "role":decoded_dict['role']}}
            return_dict2 = {}
            decoded_dict = json.loads(acl.readline())
            
            for key, value in decoded_dict["Admins"].items():
                return_dict2[key] = value

            return_dict1["Admins"] = return_dict2
            return jsonify(details=return_dict1),200
        

        return_dict = {"id":decoded_dict['google_id'], "name":decoded_dict['name'], "email":decoded_dict['email'], "role":decoded_dict['role']}
        return jsonify(admin_details=return_dict),200


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
    decoded_dict = decoded_jwt()
    if id != decoded_dict['google_id'] and decoded_dict['role'] == "SuperAdmins":
        try:
            if request.args['confirmation']:
                if ttlSession.verfiy_Ptoken("TTLAuthenticatedUserName"):
                    post_delete_id = id

                    storage.delete_blob(
                        bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
                        blob_name = decoded_dict["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/post/" + post_delete_id + ".json",
                    )

                    # -----------------  START OF DELETING FILE LOCALLY ----------------- #

                    temp_post_path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "post", post_delete_id)
                    temp_post_path = temp_post_path + ".json"

                    if os.path.isfile(temp_post_path):
                        os.remove(temp_post_path)

                    # -----------------  END OF DELETING FILE LOCALLY ----------------- #

                else:
                    return jsonify(Error="Unauthorized Access"),401
            
            return jsonify(message="Admin will not be deleted")
            
        except:
            return jsonify(Error="Please add a confirmation to delete")


    else:
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
    decoded_dict = decoded_jwt()
    if ttlSession.verfiy_Ptoken("TTLAuthenticatedUserName"):
        list_post = storage.list_blobs_with_prefix(
            bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
            prefix = decoded_dict["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/post/",
            delimiter = "/"
        )
    else:
        return jsonify(Error="Unauthorized Access"),401


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


# ------ Media API ------
@api.route("/create_media", methods=["POST"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_create_media():
    return jsonify(message="Work in progress"),200


@api.route("/view_media", methods=["GET"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_view_medias():
    decoded_dict = decoded_jwt()

    if ttlSession.verfiy_Ptoken("TTLAuthenticatedUserName"):
        list_media = storage.list_blobs_with_prefix(
            bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
            prefix = decoded_dict["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/media/",
            delimiter = "/"
        )

        return jsonify(media=list_media)
    else:
        return jsonify(Error="Unauthorized Access"),401


@api.route("/view_media/<regex('[0-9a-f]{32}'):id>", methods=["GET"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_view_media(id):
    return jsonify(message="Work in progress"),200


@api.route("/update_media/<regex('[0-9a-f]{32}'):id>", methods=["PUT"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_update_media(id):
    return jsonify(message="Work in progress"),200


@api.route("/delete_media/<regex('[0-9a-f]{32}'):id>", methods=["DELETE"])
@ttl_redirect_user
@ttl_jwt_authentication
def api_delete_media(id):
    return jsonify(message="Work in progress"),200

