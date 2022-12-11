from flask_paranoid import Paranoid
from flask import session
import hashlib
from flask import Flask

class TTLSession(Paranoid):
    def __init__(self, app=None):
        app = Flask('tomtomload')
        print(app)
        super().__init__(app)
        # super().__init__(app)
    
    def get_token(self, jwtToken):
        if jwtToken != "":
            createdTTLtoken = str(jwtToken) + str(super().create_token())
            encoded_session = hashlib.sha384(createdTTLtoken.encode()).hexdigest()
            return encoded_session
        else:
            print("Please provide the JWT Token")

    def write_token_to_session(self, Ptoken):
        if "paranoid_session" not in session:
            session["paranoid_session"] = Ptoken
            return False
        elif Ptoken == session["paranoid_session"]:
            return True


    def get_token_from_session(self):
        return super().get_token_from_session()