import os

from flask import Flask
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask_reggie import Reggie
from flask_moment import Moment

from apscheduler.schedulers.background import BackgroundScheduler

from routes.authorised_user import authorised_user, retention_policy
from routes.admin_user import admin_user
from routes.api import api
from routes.Errors import error

from static.classes.config import CONSTANTS, SECRET_CONSTANTS


# -----------------  START OF TOM TOM LOAD  ----------------- #

app = Flask(__name__)

# -----------------  START OF FLASK CONFIGURATION  ----------------- #

app.config["CONSTANTS"] = CONSTANTS
app.config["SECRET"] = SECRET_CONSTANTS

app.config["DEBUG_FLAG"] = app.config["CONSTANTS"].DEBUG_MODE

app.config['SESSION_TYPE'] = 'filesystem'
app.config["SESSION_FILE_DIR"] = os.path.join(app.config["CONSTANTS"].TTL_ROOT_FOLDER, "sessions")
app.config["SECRET_KEY"] = "SECRET.FLASK_SECRET_KEY"

# -----------------  END OF FLASK CONFIGURATION  ----------------- #


# -----------------  START OF CSRF CONFIGURATION  ----------------- #

csrf = CSRFProtect(app)

# -----------------  END OF CSRF CONFIGURATION  ----------------- #


# -----------------  START OF FLASK REGEX CONFIGURATION  ----------------- #

Reggie(app)

# -----------------  END OF FLASK REGEX CONFIGURATION  ----------------- #

moment = Moment(app)

# -----------------  START OF SESSION CONFIGURATION  ----------------- #

sess = Session(app)
if app.config["CONSTANTS"].DEBUG_MODE:
    app.config["SESSION_COOKIE_SECURE"] = True

# -----------------  END OF SESSION CONFIGURATION  ----------------- #


# -----------------  START OF HTST CONFIGURATION  ----------------- #

talisman = Talisman(
    app=app,

    content_security_policy=None,
    content_security_policy_nonce_in=["script-src", "style-src"],

    x_xss_protection=True,

    force_https=True,
    force_https_permanent=True,

    strict_transport_security=True,
    strict_transport_security_preload=True,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True,

    session_cookie_secure=True,
    session_cookie_http_only=True,
    session_cookie_samesite="Lax"
)

# -----------------  END OF HSTS CONFIGURATION  ----------------- #


# -----------------  START OF BLUEPRINT  ----------------- #

with app.app_context():
    app.register_blueprint(authorised_user)
    app.register_blueprint(admin_user)
    app.register_blueprint(api)
    app.register_blueprint(error)

# -----------------  END OF BLUEPRINT  ----------------- #


# -----------------  START OF SCHEDULER JOB  ----------------- #

def delete_sessions() -> None:
    for file in os.listdir(app.config["SESSION_FILE_DIR"]):
        file_path = os.path.join(app.config["SESSION_FILE_DIR"], file)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
                print("system deleted session file: " + file_path)

        except Exception as e:
            print(e)

def remove_media() -> None:
    for file in os.listdir(app.config["CONSTANTS"].TTL_CONFIG_MEDIA_FOLDER):
        file_path = os.path.join(app.config["CONSTANTS"].TTL_CONFIG_MEDIA_FOLDER, file)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
                print("system deleted media file: " + file_path)

        except Exception as e:
            print(e)

def remove_download() -> None:
    for file in os.listdir(app.config["CONSTANTS"].TTL_CONFIG_DOWNLOAD_FOLDER):
        file_path = os.path.join(app.config["CONSTANTS"].TTL_CONFIG_DOWNLOAD_FOLDER, file)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
                print("system deleted download file: " + file_path)

        except Exception as e:
            print(e)

def remove_post() -> None:
    for file in os.listdir(app.config["CONSTANTS"].TTL_CONFIG_POSTS_FOLDER):
        file_path = os.path.join(app.config["CONSTANTS"].TTL_CONFIG_POSTS_FOLDER, file)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
                print("system deleted post file: " + file_path)

        except Exception as e:
            print(e)

# -----------------  END OF SCHEDULER JOB  ----------------- #


if __name__ == "__main__":

    scheduler = BackgroundScheduler()
    scheduler.configure(timezone="Asia/Singapore")

    scheduler.add_job(
        delete_sessions,
        "interval", hours=23, minutes=58, seconds=0
    )

    scheduler.add_job(
        remove_media,
        "interval", minutes=10, seconds=0
    )

    scheduler.add_job(
        remove_download,
        "interval", minutes=1
    )

    scheduler.add_job(
        remove_post,
        "interval", hours=23, minutes=59, seconds=0
    )
    scheduler.add_job(
        retention_policy,
        "interval", hours=0, minutes=4, seconds=0
        # "interval", hours=23, minutes=59, seconds=59
)


    scheduler.start()

    if app.config["DEBUG_FLAG"]:
        SSL_CONTEXT = (
            CONSTANTS.TTL_CONFIG_FOLDER.joinpath("TOMTOMLOAD.crt"),
            CONSTANTS.TTL_CONFIG_FOLDER.joinpath("TOMTOMLOAD_key.pem")
        )
        host = None
    else:
        SSL_CONTEXT = None
        host = "0.0.0.0"

    app.run(
        debug = app.config["DEBUG_FLAG"],
        host = host,
        port = int(os.environ.get("PORT", 5000)),
        ssl_context = SSL_CONTEXT
    )

# -----------------  END OF TOM TOM LOAD  ----------------- #
