import jwt
import json
import os

from flask import Blueprint, request, jsonify, redirect, url_for
from static.classes.config import Constants

from static.functions.check_authentication import ttl_redirect_user, ttl_jwt_authentication, ttl_check_user_agent
from static.classes.config import CONSTANTS
from static.classes.storage import GoogleCloudStorage
from static.security.secure_data import GoogleCloudKeyManagement, Encryption
from static.security.session_management import TTLSession
from static.security.ttl_limiter import TTL_Limiter

from ast import literal_eval


api = Blueprint('api', __name__, url_prefix="/api/v1", template_folder="templates", static_folder='static')

KeyManagement = GoogleCloudKeyManagement()
ttlSession = TTLSession()
storage = GoogleCloudStorage()
encryption = Encryption()
ttlLimiter = TTL_Limiter()

def decoded_jwt():
    try:
        bearer_token = request.headers['Authorization'].split(" ")[1]
        
        return jwt.decode(
            bearer_token, 
            algorithms = CONSTANTS.JWT_ALGORITHM,
            key = str(KeyManagement.retrieve_key(
                    project_id = CONSTANTS.GOOGLE_PROJECT_ID,
                    location_id = CONSTANTS.GOOGLE_LOCATION_ID,
                    key_ring_id = CONSTANTS.GOOGLE_KEY_RING_ID,
                    key_id = CONSTANTS.JWT_ACCESS_TOKEN_SECRET_KEY
                ))
        )
    except:
        if ttlSession.verfiy_Ptoken("TTLJWTAuthenticatedUser"):
            print("decode jwt")
            signed_header = ttlSession.get_data_from_session("TTLJWTAuthenticatedUser",data=True)
            return jwt.decode(
                signed_header["TTL-JWTAuthenticated-User"],
                algorithms = CONSTANTS.JWT_ALGORITHM,
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
@ttlLimiter.limit_user(limit_value="10/day")
def api_create_user():
    return jsonify(message="Work in progress"),200


@api.route("/view_user", methods=["GET"])
@ttl_redirect_user
@ttl_jwt_authentication
@ttlLimiter.limit_user(limit_value="10/day")
def api_view_users():
    
    return jsonify(message="Work in progress")


@api.route("/view_user/<regex('[0-9]{21}'):id>", methods=["GET"])
@ttl_redirect_user
@ttl_jwt_authentication
@ttlLimiter.limit_user(limit_value="10/day")
def api_view_user(id):
    return jsonify(message="Work in progress"),200


@api.route("/edit_user/<regex('[0-9]{21}'):id>", methods=["PUT"])
@ttl_redirect_user
@ttl_jwt_authentication
@ttlLimiter.limit_user(limit_value="10/day")
def api_edit_user(id):
    return jsonify(message="Work in progress"),200


@api.route("/delete_user/<regex('[0-9]{21}'):id>", methods=["DELETE"])
@ttl_redirect_user
@ttl_jwt_authentication
@ttlLimiter.limit_user(limit_value="10/day")
def api_delete_user(id):
    return jsonify(message="Work in progress"),200


# ------ Admin API ------
@api.route("/create_admin", methods=["POST"])
@ttl_redirect_user
@ttl_jwt_authentication
@ttlLimiter.limit_user(limit_value="10/day")
def api_create_admin():
    return jsonify(message="Work in progress"),200


@api.route("/view_admin", methods=["GET"])
@ttl_redirect_user
@ttl_jwt_authentication
@ttlLimiter.limit_user(limit_value="10/day")
def api_view_admins():
    with open(CONSTANTS.TTL_CONFIG_FOLDER.joinpath("acl.json"), "r") as acl:
        decoded_dict = decoded_jwt()
        print(decoded_dict)
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
    
    


# @api.route("/view_admin/<regex('[0-9]{21}'):id>", methods=["GET"])
# @ttl_redirect_user
# @ttl_jwt_authentication
# @ttlLimiter.limit_user(limit_value="10/day")
# def api_view_admin(id):
#     if decoded_jwt()["role"] == "SuperAdmins":
#         pass
#     else:
#         return jsonify(Error="Unauthorized access"),401

#     return jsonify(message="Work in progress"),200


@api.route("/edit_admin/<regex('[0-9]{21}'):id>", methods=["PUT"])
@ttl_redirect_user
@ttl_jwt_authentication
@ttlLimiter.limit_user(limit_value="10/day")
def api_edit_admin(id):
    return jsonify(message="Work in progress"),200


@api.route("/delete_admin/<regex('[0-9]{21}'):id>", methods=["DELETE"])
@ttl_redirect_user
@ttl_jwt_authentication
@ttlLimiter.limit_user(limit_value="10/day")
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
@ttlLimiter.limit_user(limit_value="10/day")
def api_create_post():
    if ttl_check_user_agent():
        return jsonify(message="Web Create post"),200
        # return redirect(url_for("authorised_user.post"))
    
    return jsonify(message="Work in progress"),200


@api.route("/view_post", methods=["GET"])
@ttl_redirect_user
@ttl_jwt_authentication
@ttlLimiter.limit_user(limit_value="10/day")
def api_view_posts():
    decoded_dict = decoded_jwt()
    
    if not ttl_check_user_agent():
        print("\n\nHello world")
        name = decoded_dict["name"]

    elif ttl_check_user_agent() and ttlSession.verfiy_Ptoken("TTLAuthenticatedUserName"):
        print("web browser")
        name = ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True)

    else:
        print("\n\nelse")
        return jsonify(Error="Unauthorized Access"),401

    list_post = storage.list_blobs_with_prefix(
        bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
        prefix = decoded_dict["role"] + "/" + name + "/post/",
        delimiter = "/"
    )

    id_list = []
    
    for media in list_post:
        remove_slash = media.split("/")[3]
        remove_extension = remove_slash.split(".")[0]

        id_list.append(remove_extension)

    print("\n\nid_list",id_list)
    post_metadata = []

    for list_id in id_list:
        metadata_dict = {}
        try:
            metadata = storage.blob_metadata(
                bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
                blob_name = decoded_dict["role"] + "/" + name + "/post/" + list_id + ".json"
            )
            metadata_dict["id"] = list_id
            metadata_dict["api_uri"] = "/api/v1/view_post/"+list_id
            metadata_dict["creator"] = name
            metadata_dict["time_created"] = metadata["time_created"]
            metadata_dict["updated"] = metadata["updated"]

        except TypeError:
            return jsonify(err="Type error")
        except:
            return jsonify(err="IDK wat error")
        
        post_metadata.append(metadata_dict)
    
    
    return jsonify(post=post_metadata)


@api.route("/view_post/<regex('[0-9a-f]{32}'):id>", methods=["GET"])
@ttl_redirect_user
@ttl_jwt_authentication
@ttlLimiter.limit_user(limit_value="10/day")
def api_view_post(id):
    decoded_dict = decoded_jwt()

    if not ttl_check_user_agent():
        print("\n\nHello world")
        name = decoded_dict["name"]

    elif ttl_check_user_agent() and ttlSession.verfiy_Ptoken("TTLAuthenticatedUserName"):
        print("web browser")
        name = ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True)

    else:
        print("\n\nelse")
        return jsonify(Error="Unauthorized Access"),401

    temp_Postfile_path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "post", id)
    temp_Postfile_path = temp_Postfile_path + ".json"

    storage.download_blob(
        bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
        source_blob_name = decoded_dict["role"] + "/" + name + "/post/" + id + ".json",
        destination_file_name = temp_Postfile_path
    )

    if os.path.isfile(temp_Postfile_path):
        with open(temp_Postfile_path, 'rb') as f:

            # -----------------  START OF DECRYPTION ----------------- #

            decrypted_content = encryption.decrypt_symmetric(
                project_id = CONSTANTS.GOOGLE_PROJECT_ID,
                location_id = CONSTANTS.GOOGLE_LOCATION_ID,
                key_ring_id = CONSTANTS.KMS_TTL_KEY_RING_ID,
                key_id = CONSTANTS.KMS_KEY_ID,
                ciphertext = f.read()
            )

            post_data = decrypted_content.plaintext.decode("utf-8")
            post_data = json.loads(post_data)
        
        post_value_dict = {"creator": name, "content":post_data["blocks"][0]["data"]["text"]}
        return jsonify(post=post_value_dict)


    return jsonify(message="Work in progress"),200


@api.route("/update_post/<regex('[0-9a-f]{32}'):id>", methods=["PUT"])
@ttl_redirect_user
@ttl_jwt_authentication
@ttlLimiter.limit_user(limit_value="10/day")
def api_update_post(id):
    return jsonify(message="Work in progress"),200


@api.route("/delete_post/<regex('[0-9a-f]{32}'):id>", methods=["DELETE"])
@ttl_redirect_user
@ttl_jwt_authentication
@ttlLimiter.limit_user(limit_value="10/day")
def api_delete_post(id):
    return jsonify(message="Work in progress"),200


# ------ Media API ------
@api.route("/create_media", methods=["POST"])
@ttl_redirect_user
@ttl_jwt_authentication
@ttlLimiter.limit_user(limit_value="10/day")
def api_create_media():
    return jsonify(message="Work in progress"),200


@api.route("/view_media", methods=["GET"])
@ttl_redirect_user
@ttl_jwt_authentication
@ttlLimiter.limit_user(limit_value="10/day")
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
@ttlLimiter.limit_user(limit_value="10/day")
def api_view_media(id):
    return jsonify(message="Work in progress"),200


# @api.route("/update_media/<regex('[0-9a-f]{32}'):id>", methods=["PUT"])
# @ttl_redirect_user
# @ttl_jwt_authentication
# @ttlLimiter.limit_user(limit_value="10/day")
# def api_update_media(id):
#     return jsonify(message="Work in progress"),200


@api.route("/delete_media/<regex('[0-9a-f]{32}'):id>", methods=["DELETE"])
@ttl_redirect_user
@ttl_jwt_authentication
@ttlLimiter.limit_user(limit_value="10/day")
def api_delete_media(id):
    return jsonify(message="Work in progress"),200

