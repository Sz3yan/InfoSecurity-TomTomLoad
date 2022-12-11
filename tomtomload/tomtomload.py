import os

from flask import Flask
from flask_session import Session
from flask_paranoid import Paranoid
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
# from flask_reggie import Reggie (regex in flask route)
# from flask_moment import Moment (moment.js)
from static.classes.config import CONSTANTS, SECRET_CONSTANTS

from routes.Errors import error
from routes.authorised_user import authorised_user
from routes.api import api

from static.security.session_management import TTLSession

app = Flask(__name__)

# print(app)
# TTLSession()

app.config["CONSTANTS"] = CONSTANTS
app.config["SECRET"] = SECRET_CONSTANTS
app.config["DEBUG_FLAG"] = app.config["CONSTANTS"].DEBUG_MODE
app.config['SESSION_TYPE'] = 'filesystem'
app.config["SESSION_FILE_DIR"] = os.path.join(app.config["CONSTANTS"].TTL_ROOT_FOLDER, "sessions")
app.config["SECRET_KEY"] = "SECRET.FLASK_SECRET_KEY"


csrf = CSRFProtect(app)

sess = Session(app)
if app.config["CONSTANTS"].DEBUG_MODE:
    app.config["SESSION_COOKIE_SECURE"] = True

paranoid = Paranoid(app)
paranoid.redirect_view = "/"


limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[app.config["CONSTANTS"].DEFAULT_REQUEST_LIMIT],
)


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

# prevent caching
@app.after_request
def add_header(response):
    response.cache_control.no_cache = True
    response.cache_control.no_store = True
    response.cache_control.must_revalidate = True
    response.cache_control.max_age = 0
    response.cache_control.public = False
    response.cache_control.proxy_revalidate = True
    response.cache_control.s_maxage = 0
    return response


with app.app_context():
    app.register_blueprint(authorised_user)
    app.register_blueprint(api)
    app.register_blueprint(error)


if __name__ == "__main__":
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
