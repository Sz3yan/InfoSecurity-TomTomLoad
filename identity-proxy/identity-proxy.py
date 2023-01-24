import os
import pathlib

from flask import Flask
from flask_session import Session
from flask_paranoid import Paranoid

from routes.potential_user import potential_user
from routes.api import api
from routes.Errors import error

from apscheduler.schedulers.background import BackgroundScheduler

from static.classes.config import CONSTANTS, SECRET_CONSTANTS
from static.security.certificate_authority import CertificateAuthority, Certificates


# -----------------  START OF IDENTITY PROXY  ----------------- #

app = Flask(__name__)

# -----------------  START OF FLASK CONFIGURATION  ----------------- #

app.config["CONSTANTS"] = CONSTANTS
app.config["SECRET"] = SECRET_CONSTANTS
app.config["DEBUG_FLAG"] = app.config["CONSTANTS"].DEBUG_MODE
app.config['SESSION_TYPE'] = 'filesystem'
app.config["SESSION_FILE_DIR"] = os.path.join(app.config["CONSTANTS"].IP_ROOT_FOLDER, "sessions")
app.config["SECRET_KEY"] = "SECRET.FLASK_SECRET_KEY"

# -----------------  END OF FLASK CONFIGURATION  ----------------- #


# -----------------  START OF SESSION CONFIGURATION  ----------------- #

sess = Session(app)
if app.config["CONSTANTS"].DEBUG_MODE:
    app.config["SESSION_COOKIE_SECURE"] = True

paranoid = Paranoid(app)
paranoid.redirect_view = "/"

# -----------------  END OF SESSION CONFIGURATION  ----------------- #


# -----------------  START OF BLUEPRINT  ----------------- #

with app.app_context():
    app.register_blueprint(potential_user)
    app.register_blueprint(api)
    app.register_blueprint(error)

# -----------------  END OF BLUEPRINT  ----------------- #


# -----------------  START OF SCHEDULER JOB  ----------------- #

def auto_delete_sessions() -> None:
    for file in os.listdir(app.config["SESSION_FILE_DIR"]):
        file_path = os.path.join(app.config["SESSION_FILE_DIR"], file)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
                print("system delete session file:  ", file_path)

        except Exception as e:
            print(e)

# -----------------  END OF SCHEDULER JOB  ----------------- #


if __name__ == "__main__":

    scheduler = BackgroundScheduler()
    scheduler.configure(timezone="Asia/Singapore")

    scheduler.add_job(
        auto_delete_sessions,
        "interval", hours=23, minutes=58, seconds=0
    )

    scheduler.start()

    # -----------------  START OF CERTIFICATE AUTHORITY  ----------------- #

    # -----------------  START OF BASIC SETUP  ----------------- #

    # -----------------  START OF FILE DIRECTORY SETUP  ----------------- #

    certificate_directory = CONSTANTS.IP_CONFIG_FOLDER.joinpath("certificates")

    if not os.path.exists(certificate_directory):
        os.makedirs(certificate_directory)

    to_tomtomload_path = pathlib.Path(__file__).parent.parent.parent.parent.absolute()
    tomtomload_configfiles = os.path.join(to_tomtomload_path, "tomtomload/static/config_files/")

    # -----------------  END OF FILE DIRECTORY SETUP  ----------------- #

    # -----------------  START OF CERTIFICATE SETUP  ----------------- #

    ca_certificate = os.path.join(certificate_directory, "IDENTITY-PROXY.crt")
    ca_key = os.path.join(certificate_directory, "IDENTITY-PROXY.key")
    sub_certificate = os.path.join(certificate_directory, "SUBORDINATE_IDENTITY_PROXY.crt")
    sub_key = os.path.join(certificate_directory, "SUBORDINATE_IDENTITY_PROXY.key")
    identityproxy = os.path.join(certificate_directory, "IDENTITY-PROXY.crt")
    tomtomload = os.path.join(tomtomload_configfiles, "TOMTOMLOAD.crt")

    # -----------------  END OF CERTIFICATE SETUP  ----------------- #

    # -----------------  END OF BASIC SETUP  ----------------- #

    ca = CertificateAuthority()
    cert = Certificates()

    ttl_duration = 365 * 24 * 60 * 60

    if not os.path.exists(ca_certificate):
        ca.create_certificate_authority(ca_name="IDENTITYPROXY", ca_duration=ttl_duration)

    if not os.path.exists(sub_certificate):
        ca.create_subordinate_ca(subordinate_ca_name="SUBORDINATE_IDENTITY_PROXY", ca_duration=ttl_duration)
    
    if not os.path.exists(identityproxy):
        cert.create_certificate_csr(ca_name="IDENTITY-PROXY")
        ca.create_certificate_from_csr(csr_file="IDENTITY-PROXY", ca_name="SUBORDINATE_IDENTITY_PROXY", ca_duration=ttl_duration)

    if not os.path.exists(tomtomload):
        cert.create_certificate_csr(ca_name="TOMTOMLOAD")
        ca.create_certificate_from_csr(csr_file="TOMTOMLOAD", ca_name="SUBORDINATE_IDENTITY_PROXY", ca_duration=ttl_duration)

    # -----------------  END OF CERTIFICATE AUTHORITY  ----------------- #

    if app.config["DEBUG_FLAG"]:
        SSL_CONTEXT = (
            CONSTANTS.IP_CONFIG_FOLDER.joinpath("certificates/IDENTITY-PROXY.crt"),
            CONSTANTS.IP_CONFIG_FOLDER.joinpath("certificates/IDENTITY-PROXY_key.pem")
        )
        host = None
    else:
        SSL_CONTEXT = None
        host = "0.0.0.0"

    app.run(
        debug = app.config["DEBUG_FLAG"],
        host = host,
        port = int(os.environ.get("PORT", 8080)),
        ssl_context = SSL_CONTEXT
    )

# -----------------  END OF IDENTITY PROXY  ----------------- #
