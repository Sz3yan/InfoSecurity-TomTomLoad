import os

from flask import Flask
from flask_session import Session
from flask_paranoid import Paranoid

from routes.potential_user import potential_user
from routes.api import api
from routes.Errors import error

from apscheduler.schedulers.background import BackgroundScheduler

from static.classes.config import CONSTANTS, SECRET_CONSTANTS


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
        "interval", seconds=300
    )

    scheduler.start()

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
        debug = app.config["DEBUG_FLAG"],
        host = host,
        port = int(os.environ.get("PORT", 8080)),
        ssl_context = SSL_CONTEXT
    )

# -----------------  END OF IDENTITY PROXY  ----------------- #
