import json
import base64
import jwt
import os

from static.classes.config import CONSTANTS
from static.classes.unique_id import UniqueID
from static.security.storage import GoogleCloudStorage
from static.security.secure_data import GoogleCloudKeyManagement, Encryption
from static.security.session_management import TTLSession
from static.security.malware_analysis import malwareAnalysis
from werkzeug.utils import secure_filename

from flask import Blueprint, render_template, session, redirect, request, make_response, url_for, abort
from functools import wraps


authorised_user = Blueprint('authorised_user', __name__, url_prefix="/admin", template_folder="templates", static_folder='static')

# -----------------  START OF INITIALISATION ----------------- #

ttlSession = TTLSession()
keymanagement = GoogleCloudKeyManagement()
encryption = Encryption()
storage = GoogleCloudStorage()

storage.download_blob(CONSTANTS.STORAGE_BUCKET_NAME, CONSTANTS.ACL_FILE_NAME, CONSTANTS.TTL_CONFIG_FOLDER.joinpath("acl.json"))

# -----------------  END OF INITIALISATION ----------------- #


# -----------------  START OF WRAPPER ----------------- #

def check_signed_credential(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if "TTLJWTAuthenticatedUser" not in session:
            return abort(401)

        else:

            # -----------------  START OF DECODING  ----------------- #

            global decoded_jwt

            try:
                decoded_jwt = jwt.decode(
                    ttlSession.get_data_from_session("TTLJWTAuthenticatedUser")["data"]["TTL-JWTAuthenticated-User"], 
                    algorithms = "HS256", 
                    key = keymanagement.retrieve_key(
                        project_id = CONSTANTS.GOOGLE_PROJECT_ID,
                        location_id = CONSTANTS.GOOGLE_LOCATION_ID,
                        key_ring_id = CONSTANTS.KMS_IP_KEY_RING_ID,
                        key_id = CONSTANTS.JWT_ACCESS_TOKEN_SECRET_KEY
                    )
                )

            except jwt.ExpiredSignatureError:
                return abort(401)

            except jwt.InvalidTokenError:
                return abort(403)

            return func(*args, **kwargs)

            # -----------------  END OF DECODING  ----------------- #

    return decorated_function


def check_role_read(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        with open(CONSTANTS.TTL_CONFIG_FOLDER.joinpath("acl.json"), "r") as s:
            acl = json.load(s)

        role = decoded_jwt["role"]
        user = decoded_jwt["email"]

        if "read" in acl[role][user]:
            return func(*args, **kwargs)

        else:
            return abort(403)

    return decorated_function


def check_role_write(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        with open(CONSTANTS.TTL_CONFIG_FOLDER.joinpath("acl.json"), "r") as s:
            acl = json.load(s)

        role = decoded_jwt["role"]
        user = decoded_jwt["email"]

        if "write" in acl[role][user]:
            return func(*args, **kwargs)

        else:
            return abort(403)

    return decorated_function


def check_role_delete(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        with open(CONSTANTS.TTL_CONFIG_FOLDER.joinpath("acl.json"), "r") as s:
            acl = json.load(s)

        role = decoded_jwt["role"]
        user = decoded_jwt["email"]

        if "delete" in acl[role][user]:
            return func(*args, **kwargs)

        else:
            return abort(403)

    return decorated_function

# -----------------  END OF WRAPPER ----------------- #


# -----------------  START OF AUTHENTICATED SIGNED TRAFFIC ----------------- #

@authorised_user.route('/')
def home():
    try:
        TTLAuthenticatedUserName = base64.b64decode(request.cookies.get('TTL-Authenticated-User-Name')).decode('utf-8')
        TTLJWTAuthenticatedUser_raw = base64.b64decode(request.cookies.get('TTL-JWTAuthenticated-User')).decode('utf-8')
        TTLContextAwareAccess_raw = base64.b64decode(request.cookies.get('TTL-Context-Aware-Access')).decode('utf-8')
    
    except TypeError:
        return abort(403)
    
    # -----------------  START OF SESSION (for easy access) ----------------- #

    cleanup_TTLJWTAuthenticatedUser = TTLJWTAuthenticatedUser_raw.replace("'", '"')
    TTLJWTAuthenticatedUser = json.loads(cleanup_TTLJWTAuthenticatedUser)

    cleanup_TTLContextAwareAccess = TTLContextAwareAccess_raw.replace("'", '"')
    TTLContextAwareAccess = json.loads(cleanup_TTLContextAwareAccess)

    ttlSession.write_data_to_session("TTLAuthenticatedUserName",ttlSession.get_token(),TTLAuthenticatedUserName)
    ttlSession.write_data_to_session("TTLJWTAuthenticatedUser",ttlSession.get_token(),TTLJWTAuthenticatedUser)
    ttlSession.write_data_to_session("TTLContextAwareAccess",ttlSession.get_token(),TTLContextAwareAccess)

    # -----------------  END OF SESSION ----------------- #

    try:
        decoded_TTLJWTAuthenticatedUser = jwt.decode(
            TTLJWTAuthenticatedUser["TTL-JWTAuthenticated-User"], 
            algorithms="HS256", 
            key = keymanagement.retrieve_key(
                    project_id = CONSTANTS.GOOGLE_PROJECT_ID,
                    location_id = CONSTANTS.GOOGLE_LOCATION_ID,
                    key_ring_id = CONSTANTS.KMS_IP_KEY_RING_ID,
                    key_id = CONSTANTS.JWT_ACCESS_TOKEN_SECRET_KEY
                )
        )

    except jwt.ExpiredSignatureError:
        return abort(401)

    except jwt.InvalidTokenError:
        return abort(403)

    media_id = UniqueID()
    post_id = UniqueID()
    admin_user_id = UniqueID()
    
    return render_template('authorised_admin/dashboard.html', user=TTLAuthenticatedUserName, media_id=media_id, post_id=post_id, admin_user_id=admin_user_id, pic=decoded_TTLJWTAuthenticatedUser["picture"])


@authorised_user.route("/logout")
@check_signed_credential
def logout():
    session.clear()

    # -----------------  START OF REMOVING COOKIE ----------------- #

    response = make_response(redirect(url_for('authorised_user.logout_screen'), code=302))
    response.set_cookie("TTL-Authenticated-User-Name", request.cookies.get('TTL-Authenticated-User-Name') ,expires=0)
    response.set_cookie("TTL-JWTAuthenticated-User", request.cookies.get('TTL-JWTAuthenticated-User'), expires=0)
    response.set_cookie("TTL-Context-Aware-Access", request.cookies.get('TTL-Context-Aware-Access'), expires=0)

    # -----------------  END OF REMOVING COOKIE ----------------- #

    return response


@authorised_user.route("/logout/screen")
def logout_screen():
    return render_template('authorised_admin/logout.html')


@authorised_user.route("/media")
@check_signed_credential
@check_role_read
def media():
    media_id = UniqueID()

    print(decoded_jwt["role"])

    # -----------------  START OF RETRIEVING MEDIA ----------------- #

    list_media = storage.list_blobs_with_prefix(
        bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
        prefix = "Admins/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/media/",
        delimiter = "/"
    )

    id_list = []

    for media in list_media:
        remove_slash = media.split("/")[3]
        remove_extension = remove_slash.split(".")[0]

        id_list.append(remove_extension)

    # -----------------  START OF CHECKING LOCAL MEDIA ----------------- #

    for id in id_list:
        temp_Mediafile_path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "media", id)
        temp_Mediafile_path = temp_Mediafile_path + ".png"

        if os.path.isfile(temp_Mediafile_path):
            return render_template('authorised_admin/media.html', media_id=media_id, id_list=id_list, media=list_media, pic=decoded_jwt["picture"])

        else:
            storage.download_blob(
                bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
                source_blob_name = "Admins/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/media/" + id + ".png",
                destination_file_name = temp_Mediafile_path
            )

    # -----------------  END OF CHECKING LOCAL MEDIA ----------------- #
    
    # -----------------  END OF RETRIEVING MEDIA ----------------- #
        
    return render_template('authorised_admin/media.html', media_id=media_id, id_list=id_list, media=list_media, pic=decoded_jwt["picture"])


@authorised_user.route("/media/<regex('[0-9a-f]{32}'):id>")
@check_signed_credential
def media_id(id):
    media_id = id

    path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "media" , media_id)
    path = path + ".png"

    # -----------------  START OF RETRIEVING FROM GCS ----------------- #

    Ptoken = ttlSession.get_data_from_session("TTLAuthenticatedUserName", Ptoken=True)

    if ttlSession.verfiy_Ptoken(Ptoken):
        get_media = GoogleCloudStorage()

        metadata = get_media.blob_metadata(
            bucket_name=CONSTANTS.STORAGE_BUCKET_NAME,
            blob_name="Admins/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/media/" + media_id + ".png"
        )

        # -----------------  START OF CHECK FILE EXIST ----------------- #

        if os.path.isfile(path):
            return render_template('authorised_admin/media_id.html', media_id=media_id, metadata=metadata, pic=decoded_jwt["picture"])

        get_media.download_blob(
            bucket_name=CONSTANTS.STORAGE_BUCKET_NAME,
            source_blob_name="Admins/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/media/" + media_id + ".png",
            destination_file_name=path
        )
        
    else:
        abort(403)
        # -----------------  END OF CHECK FILE EXIST ----------------- #

    # -----------------  END OF RETRIEVING FROM GCS ----------------- #

    return render_template('authorised_admin/media_id.html', media_id=media_id, metadata=metadata, pic=decoded_jwt["picture"])


@authorised_user.route("/media/upload/<regex('[0-9a-f]{32}'):id>", methods=['GET', 'POST'])
@check_signed_credential
@check_role_write
def media_upload(id):
    media_upload_id = id

    if request.method == 'POST':

        # -----------------  START OF EXTENSION CHECKING ----------------- #

        f = request.files['file']

        if f.filename == '':
            return redirect(request.url)

        file_extension = f.filename.rsplit('.', 1)[1].lower()
        if file_extension not in CONSTANTS.ALLOWED_MEDIA_EXTENSIONS:
            abort(415)

        # -----------------  END OF EXTENSION CHECKING ----------------- #

        # -----------------  START OF MALWARE CHECKING ----------------- #

        # virus total stuff here

        # -----------------  END OF MALWARE CHECKING ----------------- #

        malwareAnalysis()
        if not malwareAnalysis:

            # -----------------  START OF SAVING FILE LOCALLY ----------------- #

            temp_Mediafile_path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, secure_filename(f.filename))
            f.save(os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, secure_filename(f.filename)))

            # -----------------  END OF SAVING FILE LOCALLY ----------------- #

            # -----------------  START OF UPLOADING TO GCS ----------------- #
            Ptoken = ttlSession.get_data_from_session("TTLAuthenticatedUserName", Ptoken=True)

            if ttlSession.verfiy_Ptoken(Ptoken):

                # can compute hash here

                storage.upload_blob(
                    bucket_name=CONSTANTS.STORAGE_BUCKET_NAME,
                    source_file_name=temp_Mediafile_path,
                    destination_blob_name="Admins/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/media/" + media_upload_id + "." + file_extension,
                )

            else:
                abort(403)

            # -----------------  END OF UPLOADING TO GCS ----------------- #

            return redirect(url_for('authorised_user.media_id', id=media_upload_id))

    return render_template('authorised_admin/media_upload.html', upload_id=media_upload_id, name="k", pic=decoded_jwt["picture"])


@authorised_user.route("/posts")
@check_signed_credential
@check_role_read
def post():
    post_id = UniqueID()

    # -----------------  START OF RETRIEVING MEDIA ----------------- #

    list_post = storage.list_blobs_with_prefix(
        bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
        prefix = "Admins/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/post/",
        delimiter = "/"
    )

    id_list = []

    for post in list_post:
        remove_slash = post.split("/")[3]
        remove_extension = remove_slash.split(".")[0]
        id_list.append(remove_extension)

    # -----------------  START OF CHECKING LOCAL MEDIA ----------------- #

    for id in id_list:
        temp_Postfile_path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "post", id)
        temp_Postfile_path = temp_Postfile_path + ".json"

        if os.path.isfile(temp_Postfile_path):
            return render_template('authorised_admin/post.html', post_id=post_id, id_list=id_list, post=list_post, pic=decoded_jwt["picture"])

        else:

            storage.download_blob(
                bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
                source_blob_name = "Admins/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/post/" + id + ".json",
                destination_file_name = temp_Postfile_path
            )

            return redirect(url_for('authorised_user.post'))

    # -----------------  END OF CHECKING LOCAL MEDIA ----------------- #

    return render_template('authorised_admin/post.html', post_id=post_id, id_list=id_list, post=list_post, pic=decoded_jwt["picture"])


@authorised_user.route("/posts/<regex('[0-9a-f]{32}'):id>")
@check_signed_credential
def post_id(id):
    post_id = id
    create_new_post_id = UniqueID()

    path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "post" , post_id)
    path = path + ".json"

    # -----------------  START OF RETRIEVING FROM GCS ----------------- #

    Ptoken = ttlSession.get_data_from_session("TTLAuthenticatedUserName", Ptoken=True)

    if ttlSession.verfiy_Ptoken(Ptoken):

        metadata = storage.blob_metadata(
            bucket_name=CONSTANTS.STORAGE_BUCKET_NAME,
            blob_name="Admins/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/post/" + post_id + ".json"
        )

        # -----------------  START OF CHECK FILE EXIST ----------------- #

        if os.path.isfile(path):
            with open(path, 'rb') as f:

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

                # -----------------  END OF DECRYPTION ----------------- #

            return render_template('authorised_admin/post_id.html', post_id=post_id, metadata=metadata, post_data=post_data, create_new_post_id=create_new_post_id, pic=decoded_jwt["picture"])

        # -----------------  END OF CHECK FILE EXIST ----------------- #

        storage.download_blob(
            bucket_name=CONSTANTS.STORAGE_BUCKET_NAME,
            source_blob_name="Admins/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/post/" + post_id + ".json",
            destination_file_name=path
        )

        return redirect(url_for('authorised_user.post_id'))

    else:
        abort(403)

    return render_template('authorised_admin/post_id.html', post_id=post_id, create_new_post_id=create_new_post_id, pic=decoded_jwt["picture"])


@authorised_user.route("/posts/upload/<regex('[0-9a-f]{32}'):id>", methods=['GET', 'POST'])
@check_signed_credential
@check_role_write
def post_upload(id):
    post_upload_id = id

    if request.method == 'POST':
        post_content = request.form['post_content']

        # -----------------  START OF SAVING FILE LOCALLY ----------------- #

        temp_post_path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "post", post_upload_id)
        temp_post_path = temp_post_path + ".json"

        post_data = {
            "post_content": post_content,
        }

        with open(temp_post_path, 'wb') as outfile:

            # -----------------  START OF ENCRYPTION ---------------- #

            encrypted_content = encryption.encrypt_symmetric(
                project_id = CONSTANTS.GOOGLE_PROJECT_ID,
                location_id = CONSTANTS.GOOGLE_LOCATION_ID,
                key_ring_id = CONSTANTS.KMS_TTL_KEY_RING_ID,
                key_id = CONSTANTS.KMS_KEY_ID,
                plaintext = post_data["post_content"]
            )

            # -----------------  END OF ENCRYPTION ---------------- #

            # save encrypted content to file in json format
            outfile.write(encrypted_content.ciphertext)

        # -----------------  END OF SAVING FILE LOCALLY ----------------- #

        # -----------------  START OF UPLOADING TO GCS ---------------- #

        Ptoken = ttlSession.get_data_from_session("TTLAuthenticatedUserName", Ptoken=True)

        if ttlSession.verfiy_Ptoken(Ptoken):

            storage.upload_blob(
                bucket_name=CONSTANTS.STORAGE_BUCKET_NAME,
                source_file_name=temp_post_path,
                destination_blob_name="Admins/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/post/" + post_upload_id + ".json",
            )

        else:
            abort(403)

        # -----------------  END OF UPLOADING TO GCS ----------------- #

        return redirect(url_for('authorised_user.post_id', id=post_upload_id))
    
    return render_template('authorised_admin/post_upload.html', post_id=post_upload_id, pic=decoded_jwt["picture"])


@authorised_user.route("/posts/delete/<regex('[0-9a-f]{32}'):id>", methods=['GET', 'POST'])
@check_signed_credential
@check_role_delete
def post_delete(id):
    post_delete_id = id

    Ptoken = ttlSession.get_data_from_session("TTLAuthenticatedUserName", Ptoken=True)

    if ttlSession.verfiy_Ptoken(Ptoken):

        storage.delete_blob(
            bucket_name=CONSTANTS.STORAGE_BUCKET_NAME,
            blob_name="Admins/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/post/" + post_delete_id + ".json",
        )

        # -----------------  START OF DELETING FILE LOCALLY ----------------- #

        temp_post_path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "post", post_delete_id)
        temp_post_path = temp_post_path + ".json"

        if os.path.isfile(temp_post_path):
            os.remove(temp_post_path)

        # -----------------  END OF DELETING FILE LOCALLY ----------------- #

    else:
        abort(403)

    return redirect(url_for('authorised_user.post'))


@authorised_user.route("/posts/update/<regex('[0-9a-f]{32}'):id>", methods=['GET', 'POST'])
@check_signed_credential
@check_role_write
def post_update(id):
    post_update_id = id

    if request.method == 'POST':
        post_content = request.form['post_content']

        # -----------------  START OF SAVING FILE LOCALLY ----------------- #

        temp_post_path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "post", post_update_id)
        temp_post_path = temp_post_path + ".json"

        post_data = {
            "post_content": post_content,
        }

        with open(temp_post_path, 'wb') as outfile:

            # -----------------  START OF ENCRYPTION ---------------- #

            encrypted_content = encryption.encrypt_symmetric(
                project_id = CONSTANTS.GOOGLE_PROJECT_ID,
                location_id = CONSTANTS.GOOGLE_LOCATION_ID,
                key_ring_id = CONSTANTS.KMS_TTL_KEY_RING_ID,
                key_id = CONSTANTS.KMS_KEY_ID,
                plaintext = post_data["post_content"]
            )

            # -----------------  END OF ENCRYPTION ---------------- #

            outfile.write(encrypted_content.ciphertext)

        # -----------------  END OF SAVING FILE LOCALLY ----------------- #

        # -----------------  START OF UPLOADING TO GCS ---------------- #

        Ptoken = ttlSession.get_data_from_session("TTLAuthenticatedUserName", Ptoken=True)

        if ttlSession.verfiy_Ptoken(Ptoken):

            storage.upload_blob(
                bucket_name=CONSTANTS.STORAGE_BUCKET_NAME,
                source_file_name=temp_post_path,
                destination_blob_name="Admins/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/post/" + post_update_id + ".json",
            )

        else:
            abort(403)

        # -----------------  END OF UPLOADING TO GCS ----------------- #

        return redirect(url_for('authorised_user.post_id', id=post_update_id))

    return redirect(url_for('authorised_user.post_id', id=post_update_id))


@authorised_user.route("/users")
@check_signed_credential
def users():
    user_id = decoded_jwt["google_id"]

    return render_template('authorised_admin/users.html', user_id=user_id, email=decoded_jwt["email"], pic=decoded_jwt["picture"])


@authorised_user.route("/users/<regex('[0-9]{21}'):id>")
@check_signed_credential
def users_id(id):
    user_id = id

    return render_template('authorised_admin/user_id.html', user_id=user_id, email=decoded_jwt["email"], pic=decoded_jwt["picture"])


@authorised_user.route("/users/create/<regex('[0-9]{21}'):id>")
@check_signed_credential
@check_role_write
def create_users(id):
    return render_template('authorised_admin/user_create.html', pic=decoded_jwt["picture"])


@authorised_user.route("/account")
@check_signed_credential
def profile():
    return render_template('authorised_admin/profile.html', pic=decoded_jwt["picture"])

# -----------------  END OF AUTHENTICATED SIGNED TRAFFIC ----------------- #


@authorised_user.route("/users/edit_access")
@check_signed_credential
def edit_access():
    return render_template('authorised_admin/user_access.html', pic=decoded_jwt["picture"], email=decoded_jwt["email"])

