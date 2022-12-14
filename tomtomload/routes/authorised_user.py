import json
import base64
import jwt
import os

from static.classes.config import CONSTANTS, SECRET_CONSTANTS
from static.classes.unique_id import UniqueID
from static.security.storage import GoogleCloudStorage
from werkzeug.utils import secure_filename
from static.security.secure_data import AES_GCM

from flask import Blueprint, render_template, session, redirect, request, make_response, url_for, abort
from flask_reggie import Reggie
from flask_moment import Moment
from functools import wraps


authorised_user = Blueprint('authorised_user', __name__, url_prefix="/admin", template_folder="templates", static_folder='static')


# -----------------  START OF WRAPPER ----------------- #

def check_signed_credential(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if "TTLJWTAuthenticatedUser" not in session:
            return {"error": "User not authorized"}

        else:

            # -----------------  START OF DECODING  ----------------- #

            try:
                base64.b64decode(request.cookies.get('TTL-Authenticated-User-Name')).decode('utf-8')
                base64.b64decode(request.cookies.get('TTL-JWTAuthenticated-User')).decode('utf-8')
                base64.b64decode(request.cookies.get('TTL-Context-Aware-Access')).decode('utf-8')
            
            except TypeError:
                return abort(403)

            global decoded_jwt

            try:
                decoded_jwt = jwt.decode(
                    session["TTLJWTAuthenticatedUser"]["TTL-JWTAuthenticated-User"], 
                    algorithms="HS256", 
                    key=SECRET_CONSTANTS.JWT_SECRET_KEY
                )

            except jwt.ExpiredSignatureError:
                return abort(401)

            except jwt.InvalidTokenError:
                return abort(403)

            return func(*args, **kwargs)

            # -----------------  END OF DECODING  ----------------- #

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

    session["TTLAuthenticatedUserName"] = TTLAuthenticatedUserName
    session["TTLJWTAuthenticatedUser"] = TTLJWTAuthenticatedUser
    session["TTLContextAwareAccess"] = TTLContextAwareAccess

    # -----------------  END OF SESSION ----------------- #

    try:
        decoded_TTLJWTAuthenticatedUser = jwt.decode(
            TTLJWTAuthenticatedUser["TTL-JWTAuthenticated-User"], 
            algorithms="HS256", 
            key=SECRET_CONSTANTS.JWT_SECRET_KEY
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
def media():
    media_id = UniqueID()

    return render_template('authorised_admin/media.html', media_id=media_id, pic=decoded_jwt["picture"])


@authorised_user.route("/media/upload/<regex('[0-9a-f]{42}'):id>", methods=['GET', 'POST'])
@check_signed_credential
def media_upload(id):
    media_upload_id = id

    if request.method == 'POST':

        # -----------------  START OF PRE-PROCESSING DATA ----------------- #

        f = request.files['file']

        if f.filename == '':
            return redirect(request.url)

        file_extension = f.filename.rsplit('.', 1)[1].lower()
        if file_extension not in CONSTANTS.ALLOWED_MEDIA_EXTENSIONS:
            abort(415)

        f.save(os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, secure_filename(f.filename)))
        temp_file_path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, secure_filename(f.filename))

        # -----------------  END OF PRE-PROCESSING DATA ----------------- #

        # -----------------  START OF UPLOADING TO GCS ----------------- #

        # can compute hash here

        upload_media = GoogleCloudStorage()

        upload_media.upload_blob(
            bucket_name=CONSTANTS.STORAGE_BUCKET_NAME,
            source_file_name=temp_file_path,
            destination_blob_name="Admins/" + session["TTLAuthenticatedUserName"] + "/media/" + media_upload_id + "." + file_extension,
        )

        # -----------------  END OF UPLOADING TO GCS ----------------- #

        # -----------------  START OF REMOVING FILE FROM SERVER ----------------- #

        os.remove(temp_file_path)

        # -----------------  END OF REMOVING FILE FROM SERVER ----------------- #

        return redirect(url_for('authorised_user.media_id', id=media_upload_id))

    return render_template('authorised_admin/media_upload.html', upload_id=media_upload_id, name="k", pic=decoded_jwt["picture"])


@authorised_user.route("/media/<regex('[0-9a-f]{42}'):id>")
@check_signed_credential
def media_id(id):
    media_id = id

    path = os.path.join(CONSTANTS.TTL_CONFIG_FOLDER, "media" , media_id)
    path = path + ".png"

    # -----------------  START OF RETRIEVING FROM GCS ----------------- #

    get_media = GoogleCloudStorage()

    get_media.download_blob(
        bucket_name=CONSTANTS.STORAGE_BUCKET_NAME,
        source_blob_name="Admins/" + session["TTLAuthenticatedUserName"] + "/media/" + media_id + ".png",
        destination_file_name=path
    )

    # -----------------  END OF RETRIEVING FROM GCS ----------------- #

    return render_template('authorised_admin/media_id.html', media_id=media_id, pic=decoded_jwt["picture"])


@authorised_user.route("/posts")
@check_signed_credential
def post():
    post_id = UniqueID()

    return render_template('authorised_admin/post.html', post_id=post_id, pic=decoded_jwt["picture"])


@authorised_user.route("/posts/<string:id>")
@check_signed_credential
def post_id(id):
    post_id = id

    return render_template('authorised_admin/post_id.html', post_id=post_id, pic=decoded_jwt["picture"])


@authorised_user.route("/posts/upload/<string:id>")
@check_signed_credential
def post_upload(id):
    post_upload_id = id
    
    return render_template('authorised_admin/post_upload.html', post_id=post_upload_id, pic=decoded_jwt["picture"])


@authorised_user.route("/users")
@check_signed_credential
def users():
    user_id = decoded_jwt["google_id"]

    return render_template('authorised_admin/users.html', user_id=user_id, email=decoded_jwt["email"], pic=decoded_jwt["picture"])


@authorised_user.route("/users/<string:id>")
@check_signed_credential
def users_id(id):
    user_id = id

    return render_template('authorised_admin/user_id.html', user_id=user_id, email=decoded_jwt["email"], pic=decoded_jwt["picture"])


@authorised_user.route("/users/create/<string:id>")
@check_signed_credential
def create_users(id):
    return render_template('authorised_admin/user_create.html', pic=decoded_jwt["picture"])


@authorised_user.route("/account")
@check_signed_credential
def profile():
    return render_template('authorised_admin/profile.html', pic=decoded_jwt["picture"])

# -----------------  END OF AUTHENTICATED SIGNED TRAFFIC ----------------- #
