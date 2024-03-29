import os
import jwt
import json
import base64
import hashlib
import datetime
import shutil
import smtplib

from static.classes.config import CONSTANTS
from static.classes.unique_id import UniqueID
from static.classes.storage import GoogleCloudStorage
from static.security.secure_data import GoogleCloudKeyManagement, Encryption
from static.security.session_management import TTLSession
from static.security.malware_analysis import malwareAnalysis
from static.security.steganography import Decode
from static.security.DatalossPrevention import DataLossPrevention, OpticalCharacterRecognition
from static.security.log import TTLLogger

from flask import Blueprint, render_template, session, redirect, request, make_response, url_for, abort, flash, send_file
from functools import wraps
from werkzeug.utils import secure_filename
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler

 
authorised_user = Blueprint('authorised_user', __name__, url_prefix="/admin", template_folder="templates", static_folder='static')

# -----------------  START OF INITIALISATION ----------------- #

TomTomLoadLogging = TTLLogger("authorised_user")

ttlSession = TTLSession()
KeyManagement = GoogleCloudKeyManagement()
encryption = Encryption()
storage = GoogleCloudStorage()

TomTomLoadLogging.info(f"Initialising {__name__}")

# -----------------  START OF DOWNLOAD ACL ----------------- #

@authorised_user.before_app_request
def download_acl():
    storage.download_blob(CONSTANTS.STORAGE_BUCKET_NAME, CONSTANTS.ACL_FILE_NAME, CONSTANTS.TTL_CONFIG_FOLDER.joinpath("acl.json"))

    TomTomLoadLogging.info(f"Downloaded ACL from {CONSTANTS.STORAGE_BUCKET_NAME} to {CONSTANTS.TTL_CONFIG_FOLDER.joinpath('acl.json')}")

    storage.download_blob(CONSTANTS.STORAGE_BUCKET_NAME, "adminuser.json", CONSTANTS.TTL_CONFIG_FOLDER.joinpath("adminuser.json"))

    TomTomLoadLogging.info(f"Downloaded ADMINUSER from {CONSTANTS.STORAGE_BUCKET_NAME} to {CONSTANTS.TTL_CONFIG_FOLDER.joinpath('adminuser.json')}")

# -----------------  END OF DOWNLOAD ACL ----------------- #

# -----------------  END OF INITIALISATION ----------------- #

def retention_policy():
    TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Data Retention Policy started")

    current_time_pre = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    current_time = datetime.strptime(current_time_pre,"%Y-%m-%d %H:%M:%S")

    # -----------------  START OF RETRIEVING MEDIA ----------------- #

    list_media = storage.list_blobs_with_prefix(
        bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
        prefix = decoded_TTLJWTAuthenticatedUser["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/media/",
        delimiter = "/"
    )

    TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Retrieved {len(list_media)} media from {CONSTANTS.STORAGE_BUCKET_NAME}")

    id_list = []

    for media in list_media:
        remove_slash = media.split("/")[3]
        remove_extension = remove_slash.split(".")[0]

        id_list.append(remove_extension)

    # -----------------  START OF CHECKING LOCAL MEDIA ----------------- #

    for id in id_list:
        file_time = storage.blob_metadata(CONSTANTS.STORAGE_BUCKET_NAME, decoded_TTLJWTAuthenticatedUser["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName",  data=True) + "/media/" + id + ".png")["updated"]

        file_time_pre = file_time.strftime("%Y-%m-%d %H:%M:%S")
        file_time = datetime.strptime(file_time_pre, "%Y-%m-%d %H:%M:%S")

        if (current_time - file_time).days >= 365:
            storage.move_blob(
                bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
                blob_name = decoded_TTLJWTAuthenticatedUser["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName",  data=True) + "/media/" + id + ".png",
                destination_bucket_name = 'ttl_backup',
                destination_blob_name = 'archive/' + decoded_TTLJWTAuthenticatedUser["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/media/" + id + ".png",
            )
            TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Moved media {id} from {CONSTANTS.STORAGE_BUCKET_NAME} to archive")
        elif (current_time - file_time).days >= 730:
            storage.delete_blob(CONSTANTS.STORAGE_BUCKET_NAME, decoded_TTLJWTAuthenticatedUser["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName",  data=True) + "/media/" + id + ".png")
            TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Deleted media {id} from {CONSTANTS.STORAGE_BUCKET_NAME}")

    # -----------------  END OF CHECKING LOCAL MEDIA ----------------- #

    # -----------------  END OF RETRIEVING MEDIA ----------------- #

    # -----------------  START OF RETRIEVING POST ----------------- #

        list_post = storage.list_blobs_with_prefix(
            bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
            prefix = decoded_TTLJWTAuthenticatedUser["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/post/",
            delimiter = "/"
        )

        TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Retrieved {len(list_post)} post from {CONSTANTS.STORAGE_BUCKET_NAME}")

        id_list = []

        for post in list_post:
            remove_slash = post.split("/")[3]
            remove_extension = remove_slash.split(".")[0]
            id_list.append(remove_extension)

        # -----------------  START OF CHECKING LOCAL MEDIA ----------------- #

        for id in id_list:
            file_time = storage.blob_metadata(CONSTANTS.STORAGE_BUCKET_NAME, decoded_TTLJWTAuthenticatedUser["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName",  data=True) + "/post/" + id + ".json")["updated"]

            file_time_pre = file_time.strftime("%Y-%m-%d %H:%M:%S")
            file_time = datetime.strptime(file_time_pre, "%Y-%m-%d %H:%M:%S")

            if (current_time - file_time).days >= 365:
                storage.move_blob(
                    bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
                    blob_name = decoded_TTLJWTAuthenticatedUser["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName",  data=True) + "/post/" + id + ".json",
                    destination_bucket_name = 'ttl_backup',
                    destination_blob_name = 'archive/' + decoded_jwt["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/post/" + id + ".json",
                )

                TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Moved post {id} from {CONSTANTS.STORAGE_BUCKET_NAME} to archive")
            elif (current_time - file_time).days >= 730:
                storage.delete_blob(CONSTANTS.STORAGE_BUCKET_NAME, decoded_TTLJWTAuthenticatedUser["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName",  data=True) + "/post/" + id + ".json")
                TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Deleted post {id} from {CONSTANTS.STORAGE_BUCKET_NAME}")

        # -----------------  END OF CHECKING LOCAL MEDIA ----------------- #

        TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Data Retention Policy Initialised")


# scheduler = BackgroundScheduler()
# scheduler.configure(timezone="Asia/Singapore")
#
# scheduler.add_job(
#     retention_policy,
#     "interval", hours=0, minutes=0, seconds=30
#     # "interval", hours=23, minutes=59, seconds=59
# )
# scheduler.start()

# -----------------  START OF WRAPPER ----------------- #


def check_signed_credential(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if "TTLJWTAuthenticatedUser" not in session:

            TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)} not authenticated. Redirecting to {CONSTANTS.IDENTITY_PROXY_URL}")

            return abort(401)

        else:

            # -----------------  START OF DECODING  ----------------- #

            global decoded_jwt

            try:
                decoded_jwt = jwt.decode(
                    ttlSession.get_data_from_session("TTLJWTAuthenticatedUser",data=True)["TTL-JWTAuthenticated-User"], 
                    algorithms = CONSTANTS.JWT_ALGORITHM, 
                    key = KeyManagement.retrieve_key(
                        project_id = CONSTANTS.GOOGLE_PROJECT_ID,
                        location_id = CONSTANTS.GOOGLE_LOCATION_ID,
                        key_ring_id = CONSTANTS.KMS_IP_KEY_RING_ID,
                        key_id = CONSTANTS.JWT_ACCESS_TOKEN_SECRET_KEY
                    )
                )

                TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Decoded TTLJWTAuthenticatedUser")

            except jwt.ExpiredSignatureError:

                TomTomLoadLogging.warning(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. TTLJWTAuthenticatedUser has expired. Redirecting to {CONSTANTS.IDENTITY_PROXY_URL}")

                return abort(401)

            except jwt.InvalidTokenError:

                TomTomLoadLogging.warning(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. TTLJWTAuthenticatedUser is invalid. Redirecting to {CONSTANTS.IDENTITY_PROXY_URL}")

                return abort(403)

            except:

                TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. TTLJWTAuthenticatedUser error (not expired nor invalid). Redirecting to {CONSTANTS.IDENTITY_PROXY_URL}")

                return redirect(CONSTANTS.IDENTITY_PROXY_URL)

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
        TomTomLoadLogging.info("decoded TTLAuthenticatedUserName")

        TTLJWTAuthenticatedUser_raw = base64.b64decode(request.cookies.get('TTL-JWTAuthenticated-User')).decode('utf-8')
        TomTomLoadLogging.info("decoded TTLJWTAuthenticatedUser")

        TTLContextAwareAccess_raw = base64.b64decode(request.cookies.get('TTL-Context-Aware-Access')).decode('utf-8')
        TomTomLoadLogging.info("decoded TTLContextAwareAccess")
    
    except TypeError:

        TomTomLoadLogging.error(f"failed to decode. Redirecting to {CONSTANTS.IDENTITY_PROXY_URL}")

        return abort(403)
    
    # -----------------  START OF SESSION ----------------- #

    cleanup_TTLJWTAuthenticatedUser = TTLJWTAuthenticatedUser_raw.replace("'", '"')
    TTLJWTAuthenticatedUser = json.loads(cleanup_TTLJWTAuthenticatedUser)

    cleanup_TTLContextAwareAccess = TTLContextAwareAccess_raw.replace("'", '"')
    TTLContextAwareAccess = json.loads(cleanup_TTLContextAwareAccess)

    ttlSession.write_data_to_session("TTLAuthenticatedUserName",TTLAuthenticatedUserName)
    ttlSession.write_data_to_session("TTLJWTAuthenticatedUser",TTLJWTAuthenticatedUser)
    ttlSession.write_data_to_session("TTLContextAwareAccess",TTLContextAwareAccess)

    # -----------------  END OF SESSION ----------------- #

    try:
        global decoded_TTLJWTAuthenticatedUser

        decoded_TTLJWTAuthenticatedUser = jwt.decode(
            TTLJWTAuthenticatedUser["TTL-JWTAuthenticated-User"],
            algorithms = CONSTANTS.JWT_ALGORITHM,
            key = KeyManagement.retrieve_key(
                    project_id = CONSTANTS.GOOGLE_PROJECT_ID,
                    location_id = CONSTANTS.GOOGLE_LOCATION_ID,
                    key_ring_id = CONSTANTS.KMS_IP_KEY_RING_ID,
                    key_id = CONSTANTS.JWT_ACCESS_TOKEN_SECRET_KEY
                )
        )

        TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)} decoded TTLJWTAuthenticatedUser")

    except jwt.ExpiredSignatureError:

        TomTomLoadLogging.warning(f"TTLJWTAuthenticatedUser has expired. Redirecting to {CONSTANTS.IDENTITY_PROXY_URL}")

        return abort(401)

    except jwt.InvalidTokenError:

        TomTomLoadLogging.warning(f"TTLJWTAuthenticatedUser is invalid. Redirecting to {CONSTANTS.IDENTITY_PROXY_URL}")

        return abort(403)

    media_id = UniqueID()
    post_id = UniqueID()
    admin_user_id = UniqueID()

    return render_template('authorised_admin/dashboard.html', user=TTLAuthenticatedUserName, media_id=media_id, post_id=post_id, admin_user_id=admin_user_id, role=decoded_TTLJWTAuthenticatedUser['role'], pic=decoded_TTLJWTAuthenticatedUser["picture"])


@authorised_user.route("/logout")
@check_signed_credential
def logout():

    TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Logged out")

    session.clear()

    # -----------------  START OF REMOVING COOKIE ----------------- #

    response = make_response(redirect(url_for('authorised_user.logout_screen'), code=302))
    response.set_cookie("TTL-Authenticated-User-Name", request.cookies.get('TTL-Authenticated-User-Name') ,expires=0)
    response.set_cookie("TTL-JWTAuthenticated-User", request.cookies.get('TTL-JWTAuthenticated-User'), expires=0)
    response.set_cookie("TTL-Context-Aware-Access", request.cookies.get('TTL-Context-Aware-Access'), expires=0)

    # -----------------  END OF REMOVING COOKIE ----------------- #

    TomTomLoadLogging.info(f"Redirecting to {CONSTANTS.IDENTITY_PROXY_URL}")

    return response


@authorised_user.route("/logout/screen")
def logout_screen():
    return render_template('authorised_admin/logout.html')


@authorised_user.route("/media")
@check_signed_credential
@check_role_read
def media():
    media_id = UniqueID()
    metadata = ""

    # -----------------  START OF RETRIEVING MEDIA ----------------- #

    list_media = storage.list_blobs_with_prefix(
        bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
        prefix = decoded_jwt["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/media/",
        delimiter = "/"
    )

    TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Retrieved {len(list_media)} media from {CONSTANTS.STORAGE_BUCKET_NAME}")

    id_list = []

    for media in list_media:
        remove_slash = media.split("/")[3]
        remove_extension = remove_slash.split(".")[0]

        id_list.append(remove_extension)

    # -----------------  START OF CHECKING LOCAL MEDIA ----------------- #

    for id in id_list:
        temp_Mediafile_path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "media", id)
        temp_Mediafile_path = temp_Mediafile_path + ".png"

        metadata = storage.blob_metadata(
            bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
            blob_name = decoded_jwt["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName",  data=True) + "/media/" + id + ".png"
        )

        TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Retrieved metadata for media {id} from {CONSTANTS.STORAGE_BUCKET_NAME}")

        if os.path.isfile(temp_Mediafile_path):
            return render_template('authorised_admin/media.html', media_id=media_id, id_list=id_list, media=list_media, metadata=metadata, role = decoded_jwt["role"],pic=decoded_jwt["picture"])

        else:
            storage.download_blob(
                bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
                source_blob_name = decoded_jwt["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/media/" + id + ".png",
                destination_file_name = temp_Mediafile_path
            )

            TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Downloaded media {id} from {CONSTANTS.STORAGE_BUCKET_NAME} to {temp_Mediafile_path}")

    # -----------------  END OF CHECKING LOCAL MEDIA ----------------- #
    
    # -----------------  END OF RETRIEVING MEDIA ----------------- #
        
    return render_template('authorised_admin/media.html', media_id=media_id, id_list=id_list, media=list_media, metadata=metadata,role = decoded_jwt["role"], pic=decoded_jwt["picture"])


@authorised_user.route("/media/<regex('[0-9a-f]{32}'):id>")
@check_signed_credential
@check_role_read
def media_id(id):
    media_id = id
    create_new_media_id = UniqueID()

    API_MEDIA_URL = CONSTANTS.API_MEDIA_URL + '/' + str(media_id)

    path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "media" , media_id)
    path = path + ".png"

    # -----------------  START OF RETRIEVING FROM GCS ----------------- #

    if ttlSession.verfiy_Ptoken("TTLAuthenticatedUserName"):

        metadata = storage.blob_metadata(
            bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
            blob_name = decoded_jwt["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/media/" + media_id + ".png"
        )

        TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Retrieved metadata for media {id} from {CONSTANTS.STORAGE_BUCKET_NAME}")

        # -----------------  START OF CHECK FILE EXIST ----------------- #

        if os.path.isfile(path):
            return render_template('authorised_admin/media_id.html', media_id=media_id, metadata=metadata, api=API_MEDIA_URL, new_id=create_new_media_id,role = decoded_jwt["role"], pic=decoded_jwt["picture"])

        storage.download_blob(
            bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
            source_blob_name = decoded_jwt["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/media/" + media_id + ".png",
            destination_file_name = path
        )

        TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Downloaded media {id} from {CONSTANTS.STORAGE_BUCKET_NAME} to {path}")

        # -----------------  END OF CHECK FILE EXIST ----------------- #
        
    else:

        TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. User is not authenticated")

        abort(403)

    # -----------------  END OF RETRIEVING FROM GCS ----------------- #

    return render_template('authorised_admin/media_id.html', media_id=media_id, metadata=metadata, new_id=create_new_media_id, api=API_MEDIA_URL,role = decoded_jwt["role"], pic=decoded_jwt["picture"])


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

            TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. File extension {file_extension} is not allowed")
            TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Redirected to {CONSTANTS.IDENTITY_PROXY_URL}")

            abort(415)

        # -----------------  END OF EXTENSION CHECKING ----------------- #


        # -----------------  START OF SAVING FILE LOCALLY ----------------- #

        temp_Mediafile_path = os.path.join(CONSTANTS.TTL_CONFIG_MEDIA_FOLDER, secure_filename(f.filename))
        f.save(os.path.join(CONSTANTS.TTL_CONFIG_MEDIA_FOLDER, secure_filename(f.filename)))

        # -----------------  END OF SAVING FILE LOCALLY ----------------- #

        # -----------------  START OF DATA LOSS PREVENTION ----------------- #

        TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Data Loss Prevention Initialised on {temp_Mediafile_path}")

        OCR = OpticalCharacterRecognition(temp_Mediafile_path)

        DLP = DataLossPrevention(OCR.ocr())

        if DLP.detect_sensitive_data():

            TomTomLoadLogging.warning(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Data Loss Prevention detected sensitive data in {temp_Mediafile_path}")

            abort(400)

        TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Data Loss Prevention completed on {temp_Mediafile_path}")

        # -----------------  END OF DATA LOSS PREVENTION ----------------- #

        # -----------------  START OF UPLOADING TO GCS ----------------- #
        
        if ttlSession.verfiy_Ptoken("TTLAuthenticatedUserName"):

            with open(temp_Mediafile_path, "rb") as fs:
                file_data = fs.read()

                # Create a new hash object
                hash_object = hashlib.sha256()

                TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Integrity Check Initialised on {temp_Mediafile_path} before uploading")

                # Update the hash object with the file's data
                hash_object.update(file_data)

                # Get the hexadecimal representation of the hash
                original_hash = hash_object.hexdigest()
                print("original:", original_hash)

            # -----------------  START OF MALWARE CHECKING ----------------- #

            TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Malware Check Initialised on {temp_Mediafile_path}")

            Decode(temp_Mediafile_path)
            if Decode(temp_Mediafile_path) == 0:
                print("steganography detected")

                TomTomLoadLogging.warning(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Steganography found in media {id}. Aborting upload.")
                abort(403)

            malwareAnalysis(original_hash)
            if malwareAnalysis(original_hash) == 0:
                # -----------------  START OF UPLOADING TO GCS ----------------- #

                storage.upload_blob(
                    bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
                    source_file_name = temp_Mediafile_path,
                    destination_blob_name = decoded_jwt["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/media/" + media_upload_id + "." + file_extension,
                )

                TomTomLoadLogging.info(f'{ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True)}. Uploaded media {id} to {CONSTANTS.STORAGE_BUCKET_NAME}')

                storage.set_blob_metadata(
                    bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
                    blob_name = decoded_jwt["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/media/" + media_upload_id + "." + file_extension,
                    metadata_dict = {"name": secure_filename(f.filename), "hash": original_hash}
                )

                TomTomLoadLogging.info(f'{ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True)}. Uploaded media {id} metadata to {CONSTANTS.STORAGE_BUCKET_NAME}')

                # -----------------  START OF REMOVING FILE LOCALLY ----------------- #

                os.remove(temp_Mediafile_path)

                # -----------------  END OF REMOVING FILE LOCALLY ----------------- #

                storage.download_blob(
                    bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
                    source_blob_name = decoded_jwt["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/media/" + id + ".png",
                    destination_file_name = temp_Mediafile_path
                )

                TomTomLoadLogging.info(f'{ttlSession.get_data_from_session("TTLAuthenticatedUserName")}. Downloaded media {id} from {CONSTANTS.STORAGE_BUCKET_NAME}')

                # -----------------  END OF UPLOADING TO GCS ----------------- #

                with open(temp_Mediafile_path, "rb") as fs:
                    file_data = fs.read()

                    TomTomLoadLogging.info(f'{ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True)}. Integrity Check Initialised on {temp_Mediafile_path} after uploading')

                    # Create a new hash object
                    hash_object = hashlib.sha256()

                    # Update the hash object with the file's data
                    hash_object.update(file_data)

                    # Get the hexadecimal representation of the hash
                    new_hash = hash_object.hexdigest()
                    print("new:", new_hash)

            else:
                print("malwarewareware")

                TomTomLoadLogging.warning(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Malware found in media {id}. Aborting upload.")

                abort(403)

            TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Malware Analysis completed on {temp_Mediafile_path}")

            if original_hash == new_hash:
                TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Integrity check of media {id} passed. {temp_Mediafile_path} has not been tampered with during upload. Hash matches.")
                print(f"{temp_Mediafile_path} has not been tampered with during upload. Hash matches.")

            else:

                TomTomLoadLogging.error(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Integrity check of media {id} failed. {temp_Mediafile_path} has been tampered with during upload. Hash does not match.")
                print(f"{temp_Mediafile_path} has been tampered with during upload. Hash does not match.")

            TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Integrity Check completed on {temp_Mediafile_path}")

        else:

            TomTomLoadLogging.error(f"User not logged in, aborting upload media {id}")
            TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Redirected to {CONSTANTS.IDENTITY_PROXY_URL}")

            abort(403)

        return redirect(url_for('authorised_user.media_id', id=media_upload_id))

    return render_template('authorised_admin/media_upload.html', upload_id=media_upload_id, name="k",role = decoded_jwt["role"], pic=decoded_jwt["picture"])


@authorised_user.route("/media/delete/<regex('[0-9a-f]{32}'):id>")
@check_signed_credential
@check_role_delete
def media_delete(id):
    media_delete_id = id

    # -----------------  START OF DELETING FROM GCS ----------------- #

    if ttlSession.verfiy_Ptoken("TTLAuthenticatedUserName"):
        storage.delete_blob(
            bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
            blob_name = decoded_jwt["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/media/" + media_delete_id + ".png"
        )

        TomTomLoadLogging.info(f'{ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True)}. Deleted media {id} from {CONSTANTS.STORAGE_BUCKET_NAME}')

    else:

        TomTomLoadLogging.error(f"User not logged in, aborting delete media {id}")

        abort(403)

    # -----------------  END OF DELETING FROM GCS ----------------- #

    return redirect(url_for('authorised_user.media'))


@authorised_user.route("/media/export")
@check_signed_credential
def media_export():
    if ttlSession.verfiy_Ptoken("TTLAuthenticatedUserName"):

        list_media = storage.list_blobs_with_prefix(
            bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
            prefix = decoded_jwt["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/media/",
            delimiter = "/"
        )

        TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Retrieved {len(list_media)} media from {CONSTANTS.STORAGE_BUCKET_NAME}")

        id_list = []

        for media in list_media:
            remove_slash = media.split("/")[3]
            remove_extension = remove_slash.split(".")[0]
            id_list.append(remove_extension)

        # -----------------  START OF CHECKING LOCAL MEDIA ----------------- #

        if not os.path.isdir(os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "downloads")):
            os.mkdir(os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "downloads"))

        for id in id_list:
            temp_Mediafile_path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "media", id)
            temp_Mediafile_path = temp_Mediafile_path + ".png"

            download_folder_path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "downloads", id)
            download_folder_path = download_folder_path + ".png"

            if not os.path.isfile(download_folder_path):
                storage.download_blob(
                    bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
                    source_blob_name = decoded_jwt["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/media/" + id + ".png",
                    destination_file_name = download_folder_path
                )
            
            TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Downloaded media {id} from {CONSTANTS.STORAGE_BUCKET_NAME} to {download_folder_path}")

        shutil.make_archive(os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "downloads"), 'zip', os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "downloads"))

        return send_file(os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "downloads.zip"), as_attachment=True)

        # -----------------  END OF CHECKING LOCAL MEDIA ----------------- #

    else:

        TomTomLoadLogging.error(f"User not logged in, aborting media export")
        
        abort(403)


@authorised_user.route("/posts")
@check_signed_credential
@check_role_read
def post():
    
    if ttlSession.verfiy_Ptoken("TTLAuthenticatedUserName"):
        post_id = UniqueID()

        # -----------------  START OF RETRIEVING MEDIA ----------------- #

        list_post = storage.list_blobs_with_prefix(
            bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
            prefix = decoded_jwt["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/post/",
            delimiter = "/"
        )

        TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Retrieved {len(list_post)} post from {CONSTANTS.STORAGE_BUCKET_NAME}")

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
                return render_template('authorised_admin/post.html', post_id=post_id, id_list=id_list, post=list_post, role = decoded_jwt["role"],pic=decoded_jwt["picture"])

            else:

                storage.download_blob(
                    bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
                    source_blob_name = "Admins/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/post/" + id + ".json",
                    destination_file_name = temp_Postfile_path
                )

                TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Downloaded post {id} from {CONSTANTS.STORAGE_BUCKET_NAME} to {temp_Postfile_path}")

                return redirect(url_for('authorised_user.post'))

        # -----------------  END OF CHECKING LOCAL MEDIA ----------------- #

        return render_template('authorised_admin/post.html', post_id=post_id, id_list=id_list, post=list_post, role = decoded_jwt["role"],pic=decoded_jwt["picture"])
   
    else:

        TomTomLoadLogging.error(f"User not logged in, aborting post")

        abort(403)


@authorised_user.route("/posts/<regex('[0-9a-f]{32}'):id>")
@check_signed_credential
@check_role_read
def post_id(id):
    if ttlSession.verfiy_Ptoken("TTLAuthenticatedUserName"):
        post_id = id
        create_new_post_id = UniqueID()

        API_POSTS_URL = CONSTANTS.API_POSTS_URL + "/" + post_id

        path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "post" , post_id)
        path = path + ".json"

        # -----------------  START OF RETRIEVING FROM GCS ----------------- #

        metadata = storage.blob_metadata(
            bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
            blob_name = decoded_jwt["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/post/" + post_id + ".json"
        )

        TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Retrieved metadata for post {id} from {CONSTANTS.STORAGE_BUCKET_NAME}")

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

                TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Decrypted post {id} from {CONSTANTS.STORAGE_BUCKET_NAME}")

                post_data = decrypted_content.plaintext.decode("utf-8")
                post_data = json.loads(post_data)

                # -----------------  END OF DECRYPTION ----------------- #

            return render_template('authorised_admin/post_id.html', post_id=post_id, metadata=metadata, post_data=post_data, create_new_post_id=create_new_post_id, API_POSTS_URL=API_POSTS_URL, role = decoded_jwt["role"],pic=decoded_jwt["picture"])

        # -----------------  END OF CHECK FILE EXIST ----------------- #

        storage.download_blob(
            bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
            source_blob_name = decoded_jwt["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/post/" + post_id + ".json",
            destination_file_name = path
        )

        TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Downloaded post {id} from {CONSTANTS.STORAGE_BUCKET_NAME} to {path}")

        return redirect(url_for('authorised_user.post_id'))

    else:

        TomTomLoadLogging.error(f"User not logged in, aborting post")

        abort(403)


@authorised_user.route("/posts/upload/<regex('[0-9a-f]{32}'):id>", methods=['GET', 'POST'])
@check_signed_credential
@check_role_write
def post_upload(id):
    if ttlSession.verfiy_Ptoken("TTLAuthenticatedUserName"):
        post_upload_id = id

        if request.method == 'POST':
            post_content = request.form['post_content']

            # -----------------  START OF SAVING FILE LOCALLY ----------------- #

            temp_post_path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "post", post_upload_id)
            temp_post_path = temp_post_path + ".json"

            post_data = {
                "post_content": post_content,
            }

            TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Data Loss Prevention Intialised on post {post_upload_id}")

            DLP = DataLossPrevention(post_data["post_content"])
            DLP.detect_sensitive_data()

            TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. detecting sensitive data on post {post_upload_id}")

            with open(temp_post_path, 'wb') as outfile:

                # -----------------  START OF ENCRYPTION ---------------- #

                encrypted_content = encryption.encrypt_symmetric(
                    project_id = CONSTANTS.GOOGLE_PROJECT_ID,
                    location_id = CONSTANTS.GOOGLE_LOCATION_ID,
                    key_ring_id = CONSTANTS.KMS_TTL_KEY_RING_ID,
                    key_id = CONSTANTS.KMS_KEY_ID,
                    plaintext = DLP.replace_sensitive_data()
                )

                TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. sensitive data redacted on post {post_upload_id}")
                TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Encrypted post {post_upload_id} to {temp_post_path}")
                TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Data Loss Prevention completed on post {post_upload_id}")

                # -----------------  END OF ENCRYPTION ---------------- #

                outfile.write(encrypted_content.ciphertext)

            # -----------------  END OF SAVING FILE LOCALLY ----------------- #

            # -----------------  START OF UPLOADING TO GCS ---------------- #

                storage.upload_blob(
                    bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
                    source_file_name = temp_post_path,
                    destination_blob_name = decoded_jwt["role"] + "/"  + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/post/" + post_upload_id + ".json",
                )

                TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Uploaded post {post_upload_id} to {CONSTANTS.STORAGE_BUCKET_NAME} from {temp_post_path}")

            # -----------------  END OF UPLOADING TO GCS ----------------- #

            return redirect(url_for('authorised_user.post_id', id=post_upload_id))
        
        return render_template('authorised_admin/post_upload.html', post_id=post_upload_id, role = decoded_jwt["role"],pic=decoded_jwt["picture"])

    else:

        TomTomLoadLogging.error(f"User not logged in, aborting post")

        abort(403)


@authorised_user.route("/posts/delete/<regex('[0-9a-f]{32}'):id>", methods=['GET', 'POST'])
@check_signed_credential
@check_role_delete
def post_delete(id):
    
    if ttlSession.verfiy_Ptoken("TTLAuthenticatedUserName"):
        post_delete_id = id

        storage.delete_blob(
            bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
            blob_name = decoded_jwt["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/post/" + post_delete_id + ".json",
        )

        TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Deleted post {post_delete_id} from {CONSTANTS.STORAGE_BUCKET_NAME}")

        # -----------------  START OF DELETING FILE LOCALLY ----------------- #

        temp_post_path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "post", post_delete_id)
        temp_post_path = temp_post_path + ".json"

        if os.path.isfile(temp_post_path):
            os.remove(temp_post_path)

        # -----------------  END OF DELETING FILE LOCALLY ----------------- #

    else:

        TomTomLoadLogging.error(f"User not logged in, aborting post")

        abort(403)

    return redirect(url_for('authorised_user.post'))


@authorised_user.route("/posts/update/<regex('[0-9a-f]{32}'):id>", methods=['GET', 'POST'])
@check_signed_credential
@check_role_write
def post_update(id):
    if ttlSession.verfiy_Ptoken("TTLAuthenticatedUserName"):
        post_update_id = id

        if request.method == 'POST':
            post_content = request.form['post_content']

            # -----------------  START OF SAVING FILE LOCALLY ----------------- #

            temp_post_path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "post", post_update_id)
            temp_post_path = temp_post_path + ".json"

            post_data = {
                "post_content": post_content,
            }

            TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Data Loss Prevention Intialised on post {post_update_id}")

            DLP = DataLossPrevention(post_data["post_content"])
            DLP.detect_sensitive_data()

            TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. detecting sensitive data on post {post_update_id}")

            with open(temp_post_path, 'wb') as outfile:

                # -----------------  START OF ENCRYPTION ---------------- #

                encrypted_content = encryption.encrypt_symmetric(
                    project_id = CONSTANTS.GOOGLE_PROJECT_ID,
                    location_id = CONSTANTS.GOOGLE_LOCATION_ID,
                    key_ring_id = CONSTANTS.KMS_TTL_KEY_RING_ID,
                    key_id = CONSTANTS.KMS_KEY_ID,
                    plaintext = DLP.replace_sensitive_data()
                )

                TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. sensitive data redacted on post {post_update_id}")
                TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Encrypted post {post_update_id} to {temp_post_path}")
                TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. End of Data Loss Prevention on post {post_update_id}")

                # -----------------  END OF ENCRYPTION ---------------- #

                outfile.write(encrypted_content.ciphertext)

            # -----------------  END OF SAVING FILE LOCALLY ----------------- #

            # -----------------  START OF UPLOADING TO GCS ---------------- #

                storage.upload_blob(
                    bucket_name = CONSTANTS.STORAGE_BUCKET_NAME,
                    source_file_name = temp_post_path,
                    destination_blob_name = decoded_jwt["role"] + "/" + ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) + "/post/" + post_update_id + ".json",
                )

                TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Uploaded post {post_update_id} to {CONSTANTS.STORAGE_BUCKET_NAME}")

            # -----------------  END OF UPLOADING TO GCS ----------------- #

            return redirect(url_for('authorised_user.post_id', id=post_update_id))

        return redirect(url_for('authorised_user.post_id', id=post_update_id))

    else:

        TomTomLoadLogging.error(f"User not logged in, aborting post")

        abort(403)


@authorised_user.route("/users")
@check_signed_credential
@check_role_read
def users():
    user_id = decoded_jwt["google_id"]
    role = decoded_jwt["role"]

    with open(CONSTANTS.TTL_CONFIG_FOLDER.joinpath("acl.json"), "r") as s:
        acl = json.load(s)

    Admins_list = []

    for user, value in acl['Admins'].items():
        if user not in Admins_list:
            acl['Admins'][user] = user, value[-2]
            Admins_list.append(acl['Admins'][user])

    # print(Admins_list)

    with open(CONSTANTS.TTL_CONFIG_FOLDER.joinpath("adminuser.json"), "r") as a:
        adminuser = json.load(a)

        adminuser_list = []

        for value in adminuser['Users']:
            print(value['email'])
            print(value['created_at'])
            if value['email'] not in adminuser_list:
                adminuser[value['email']] = value['email'], value['created_at']
                adminuser_list.append(adminuser[value['email']])

        # print(adminuser_list)

    return render_template('authorised_admin/users.html', user_id=user_id, email=decoded_jwt["email"], role=role, pic=decoded_jwt["picture"], Admins_list=Admins_list, adminuser_list=adminuser_list)


@authorised_user.route("/users/<regex('[0-9]{21}'):id>")
@check_signed_credential
@check_role_read
def users_id(id):
    user_id = id
    email = ''

    with open(CONSTANTS.TTL_CONFIG_FOLDER.joinpath("acl.json"), "r") as s:
        acl = json.load(s)

    for user, value in acl['Admins'].items():
        # print(user, value)
        if value[-2] == user_id:
            email = user
            # print(email)

    return render_template('authorised_admin/user_id.html', user_id=user_id, email=email, role = decoded_jwt["role"], pic=decoded_jwt["picture"])


@authorised_user.route("/users/create/<regex('[0-9]{21}'):id>")
@check_signed_credential
@check_role_write
def create_users(id):
    return render_template('authorised_admin/user_create.html',role = decoded_jwt["role"], pic=decoded_jwt["picture"])


@authorised_user.route("/account")
@check_signed_credential
@check_role_read
def profile():

    new_user = UniqueID()

    email = decoded_jwt["email"]

    if decoded_jwt["role"] == "Admins":
        id = decoded_jwt["google_id"]

    else:
        id = decoded_jwt["email"]

    return render_template('authorised_admin/profile.html', email=email, new_user=new_user, id=id, role = decoded_jwt["role"], pic=decoded_jwt["picture"])


@authorised_user.route("/users/edit_access/<regex('[0-9]{21}'):id>", methods=['GET', 'POST'])
@check_signed_credential
@check_role_write
def edit_access(id):
    user_id = id
    with open(CONSTANTS.TTL_CONFIG_FOLDER.joinpath("acl.json"), "r") as s:
        acl = json.load(s)

    email = ''
    for user, value in acl['Admins'].items():
        # print(user)
        if id == value[-2]:
            email = user

    access_list = []

    for user, value in acl['Admins'].items():
        if user == email:
            access_list = value

    # print('access_list:', access_list)

    if ttlSession.verfiy_Ptoken("TTLAuthenticatedUserName"):
        if request.method == 'POST':
            banned = request.form.get('ban')
            # print('banned?:', banned)
            if banned is not None:
                access_list_original = access_list
                access_list = ["None", "None", "None"] + access_list_original[3:4] + ['banned']
                TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Changed access for {email} to banned")

                server = smtplib.SMTP('smtp.gmail.com', 587)
                server.ehlo()
                server.starttls()
                server.login('tomtomloadcms@gmail.com', 'jixepnkykfebnkai')
                message = f"Subject: Account status\n\nYour account with {email} will be banned until further notice. \n\nPlease note that you will not be able to access tomtomload.com with this email during this period."
                server.sendmail('tomtomloadcms@gmail.com', email, message)
                server.quit()

            else:
                access_list = ["read", "None", "None"] + access_list[3:4] + ['unbanned']

                TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)}. Changed access for {email} to unbanned")

                write = request.form.get('writeAccess')
                delete = request.form.get('deleteAccess')

                if write is not None:
                    if 'write' in access_list:
                        pass
                    else:
                        access_list[1] = 'write'
                else:
                    if 'write' in access_list:
                        access_list[1] = 'None'
                    else:
                        pass

                if delete is not None:
                    if 'delete' in access_list:
                        pass
                    else:
                        access_list[2] = 'delete'
                else:
                    if 'delete' in access_list:
                        access_list[2] = 'None'
                    else:
                        pass

                # print('email',email)
                # print('access_list:', access_list)
                # print('acl: ', acl['Admins'][email])

            w = open(CONSTANTS.TTL_CONFIG_FOLDER.joinpath("acl.json"), "r")
            dict_acl = json.loads(w.read())
            dict_acl['Admins'][email] = access_list
            # print('dict_acl:', dict_acl)
            w.close()

            r = open(CONSTANTS.TTL_CONFIG_FOLDER.joinpath("acl.json"), "w")
            r.write(json.dumps(dict_acl))
            r.close()

            storage.upload_blob(
                bucket_name=CONSTANTS.STORAGE_BUCKET_NAME,
                source_file_name=CONSTANTS.TTL_CONFIG_FOLDER.joinpath("acl.json"),
                destination_blob_name="acl.json"
            )

            TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)} updated ACL file")

            return redirect(url_for('authorised_user.users'))

    else:

        TomTomLoadLogging.error(f"User not logged in, aborting post")

        abort(403)

    return render_template('authorised_admin/user_access.html', pic=decoded_jwt["picture"], email=email, role = decoded_jwt["role"], access_list=access_list, user_id=user_id)


@authorised_user.route("/logs/")
@check_signed_credential
@check_role_read
def logs():

    role = decoded_jwt["role"]

    with open(CONSTANTS.TTL_CONFIG_FOLDER.joinpath("tomtomload.log"), "r") as f:
        tomtomload_log = f.read()

        tomtomload_logs = []

        for line in tomtomload_log.splitlines():
            if ttlSession.get_data_from_session("TTLAuthenticatedUserName", data=True) in line:
                tomtomload_logs.append(line)

    with open(CONSTANTS.IP_CONFIG_FOLDER.joinpath("identity-proxy.log"), "r") as f:
        identityproxy_log = f.read()

        identityproxy_logs = []

        for line in identityproxy_log.splitlines():
            identityproxy_logs.append(line)

    return render_template('authorised_admin/logs.html', email=decoded_jwt["email"], role=role, tomtomloadlogs=tomtomload_logs, identityproxylogs=identityproxy_logs, pic=decoded_jwt["picture"])


@authorised_user.route("/users/addBlockIPAddresses", methods=['GET', 'POST'])
@check_signed_credential
@check_role_write
def addBlock_IPAddresses():
    with open(CONSTANTS.IP_CONFIG_FOLDER.joinpath("blacklisted.json"), "r") as f:
        blacklisted = json.load(f)

    if ttlSession.verfiy_Ptoken("TTLAuthenticatedUserName"):
        if request.method == 'POST':
            ipaddress = request.form.get('ipaddress')

            if ipaddress not in blacklisted["blacklisted_ip"]:
                w = open(CONSTANTS.IP_CONFIG_FOLDER.joinpath("blacklisted.json"), "r")
                dict_IPaddress = json.loads(w.read())
                dict_IPaddress["blacklisted_ip"].append(ipaddress)
                w.close()

                r = open(CONSTANTS.IP_CONFIG_FOLDER.joinpath("blacklisted.json"), "w")
                r.write(json.dumps(dict_IPaddress))
                r.close()

                storage.upload_blob(
                    bucket_name=CONSTANTS.STORAGE_BUCKET_NAME,
                    source_file_name=CONSTANTS.IP_CONFIG_FOLDER.joinpath("blacklisted.json"),
                    destination_blob_name="blacklisted.json"
                )
                TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)} updated Blacklisted file")

            return redirect(url_for('authorised_user.users'))

    else:

        TomTomLoadLogging.error(f"User not logged in, aborting post")

        abort(403)

    return render_template('authorised_admin/blockIPAddressesAdd.html', email=decoded_jwt["email"], role = decoded_jwt["role"], pic=decoded_jwt["picture"])


@authorised_user.route("/users/revoke_cert", methods=['GET', 'POST'])
@check_signed_credential
def revoke_cert():

    if ttlSession.verfiy_Ptoken("TTLAuthenticatedUserName"):

        # -----------------  START OF OVERWRITE ACL ---------------- #

        with open(CONSTANTS.TTL_CONFIG_FOLDER.joinpath("acl.json"), "r") as s:
            acl = json.load(s)

        used = 0

        w = open(CONSTANTS.TTL_CONFIG_FOLDER.joinpath("acl.json"), "r")
        dict_acl = json.loads(w.read())
        dict_acl[decoded_jwt["role"]][decoded_jwt["email"]][4] = used
        w.close()

        r = open(CONSTANTS.TTL_CONFIG_FOLDER.joinpath("acl.json"), "w")
        r.write(json.dumps(dict_acl))
        r.close()

        # -----------------  END OF OVERWRITE ACL ---------------- #

        # -----------------  START OF REMOVING REVOKE CERT ---------------- #

        super_admin_certificate = os.path.join(CONSTANTS.SUPER_CERTIFICATE_FOLDER,acl[decoded_jwt["role"]][decoded_jwt["email"]][3] + '_' + str(ttlSession.get_data_from_session('TTLContextAwareAccess', data=True)['TTL-Context-Aware-Access-Client-IP']['ip']).replace('.', '_'))
        super_admin = os.path.join(super_admin_certificate, "SUPER_ADMIN.crt")

        # print the full path
        print("super_admin_certificate: " + super_admin_certificate)
        print("super_admin: " + super_admin)

        # remove the directory
        shutil.rmtree(super_admin_certificate)

        TomTomLoadLogging.info(f"{ttlSession.get_data_from_session('TTLAuthenticatedUserName', data=True)} has revoked their certificate")

        # -----------------  END OF REMOVING REVOKE CERT ---------------- #

        # -----------------  START OF UPLOADING TO GCS ---------------- #

        storage.upload_blob(
            bucket_name=CONSTANTS.STORAGE_BUCKET_NAME,
            source_file_name=CONSTANTS.TTL_CONFIG_FOLDER.joinpath("acl.json"),
            destination_blob_name="acl.json"
        )

        # -----------------  END OF UPLOADING TO GCS ---------------- #


        return redirect(url_for('authorised_user.users'))

    return redirect(url_for('authorised_user.users'))

# -----------------  END OF AUTHENTICATED SIGNED TRAFFIC ----------------- #
