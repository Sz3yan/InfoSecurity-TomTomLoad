import os

from flask import Flask
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from static.classes.constants import CONSTANTS, SECRET_CONSTANTS

from routes.Admin import admin
from routes.Errors import error
from routes.User import user

app = Flask(__name__)
app.config["CONSTANTS"] = CONSTANTS
app.config["SECRET"] = SECRET_CONSTANTS
app.config["DEBUG_FLAG"] = app.config["CONSTANTS"].DEBUG_MODE
# app.config['SESSION_TYPE'] = 'filesystem'
# app.config["SECRET_KEY"] = "SECRET.FLASK_SECRET_KEY"


csrf = CSRFProtect(app)

# sess = Session(app)
# if app.config["CONSTANTS"].DEBUG_MODE:
#     app.config["SESSION_COOKIE_SECURE"] = True

# limiter = Limiter(
#     app=app,
#     key_func=get_remote_address,
#     default_limits=[app.config["CONSTANTS"].DEFAULT_REQUEST_LIMIT],
# )


talisman = Talisman(
    app=app,

    content_security_policy=None,
    content_security_policy_nonce_in=["script-src", "style-src"],

    x_xss_protection=True,  # require nonce="{{ csp_nonce() }}" in script tags

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

with app.app_context():
    app.register_blueprint(admin)
    app.register_blueprint(error)
    app.register_blueprint(user)


if __name__ == "__main__":
    if app.config["DEBUG_FLAG"]:
        SSL_CONTEXT = (
            CONSTANTS.CONFIG_FOLDER.joinpath("certificate.pem"),
            CONSTANTS.CONFIG_FOLDER.joinpath("key.pem")
        )
        host = None
    else:
        SSL_CONTEXT = None
        host = "0.0.0.0"

    app.run(debug=app.config["DEBUG_FLAG"], host=host, port=int(os.environ.get("PORT", 8080)), ssl_context=SSL_CONTEXT)
