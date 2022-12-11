import os

from flask import Flask
from flask_session import Session
from flask_paranoid import Paranoid
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman

from routes.Errors import error
from routes.authorised_user import authorised_user
from routes.api import api

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

app.config["MAX_CONTENT_LENGTH"] = 75 * 1024 * 1024
app.config["ALLOWED_MEDIA_EXTENSIONS"] = app.config["CONSTANTS"].ALLOWED_MEDIA_EXTENSIONS
app.config["ALLOWED_POST_EXTENSIONS"] = app.config["CONSTANTS"].ALLOWED_POST_EXTENSIONS
app.config["MEDIA_FOLDER"] = app.config["CONSTANTS"].TTL_MEDIA_FOLDER
app.config["POST_FOLDER"] = app.config["CONSTANTS"].TTL_POST_FOLDER

# -----------------  END OF FLASK CONFIGURATION  ----------------- #


# -----------------  START OF CSRF CONFIGURATION  ----------------- #

csrf = CSRFProtect(app)

# -----------------  END OF CSRF CONFIGURATION  ----------------- #


# -----------------  START OF SESSION CONFIGURATION  ----------------- #

sess = Session(app)
if app.config["CONSTANTS"].DEBUG_MODE:
    app.config["SESSION_COOKIE_SECURE"] = True

paranoid = Paranoid(app)
paranoid.redirect_view = "/"

# -----------------  END OF SESSION CONFIGURATION  ----------------- #


# -----------------  START OF LIMITER CONFIGURATION  ----------------- #

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[app.config["CONSTANTS"].DEFAULT_REQUEST_LIMIT],
)

# -----------------  END OF LIMITER CONFIGURATION  ----------------- #


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
    app.register_blueprint(api)
    app.register_blueprint(error)

# -----------------  END OF BLUEPRINT  ----------------- #


if __name__ == "__main__":

    # maybe add scheduler here

    if app.config["DEBUG_FLAG"]:
        SSL_CONTEXT = (
            CONSTANTS.TTL_CONFIG_FOLDER.joinpath("certificate.pem"),
            CONSTANTS.TTL_CONFIG_FOLDER.joinpath("key.pem")
        )
        host = None
    else:
        SSL_CONTEXT = None
        host = "0.0.0.0"

    app.run(
        debug=app.config["DEBUG_FLAG"],
        host=host,
        port=int(os.environ.get("PORT", 5000)),
        ssl_context=SSL_CONTEXT
    )

# -----------------  END OF TOM TOM LOAD  ----------------- #
