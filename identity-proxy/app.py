import os

from flask import Flask
from flask_session import Session
from flask_paranoid import Paranoid
from flask_talisman import Talisman
from static.classes.config import CONSTANTS, SECRET_CONSTANTS

from routes.potential_user import potential_user


app = Flask(__name__)

app.config["CONSTANTS"] = CONSTANTS
app.config["SECRET"] = SECRET_CONSTANTS
app.config["DEBUG_FLAG"] = app.config["CONSTANTS"].DEBUG_MODE
app.config['SESSION_TYPE'] = 'filesystem'
app.config["SESSION_FILE_DIR"] = os.path.join(app.config["CONSTANTS"].IP_ROOT_FOLDER, "sessions")
app.config["SECRET_KEY"] = "SECRET.FLASK_SECRET_KEY"


sess = Session(app)
if app.config["CONSTANTS"].DEBUG_MODE:
    app.config["SESSION_COOKIE_SECURE"] = True


paranoid = Paranoid(app)
paranoid.redirect_view = "/"


talisman = Talisman(
    app=app,

    content_security_policy=None,
    content_security_policy_nonce_in=["script-src"],

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


app.register_blueprint(potential_user)


if __name__ == "__main__":
    if app.config["DEBUG_FLAG"]:
        SSL_CONTEXT = (
            CONSTANTS.IP_CONFIG_FOLDER.joinpath("certificate.pem"),
            CONSTANTS.IP_CONFIG_FOLDER.joinpath("key.pem")
        )
        host = None
    else:
        SSL_CONTEXT = None
        host = "0.0.0.0"

    app.run(
        debug=app.config["DEBUG_FLAG"],
        host=host,
        port=int(os.environ.get("PORT", 8080)),
        ssl_context=SSL_CONTEXT
    )
