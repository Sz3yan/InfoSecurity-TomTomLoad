from flask_paranoid import Paranoid
from flask import session, Flask
from datetime import datetime
import hashlib

class TTLSession(Paranoid):
    def __init__(self, location:str=None):

        self.__server = ""

        if location == "1":
            app = Flask('tomtomload')
            self.__server = 'tomtomload'
        elif location == "2":
            app = Flask('identity-proxy')
            self.__server = 'identity-proxy'
        else:
            print("Uknown location supplied")
        
        super().__init__(app)
    
    def get_token(self, jwtToken:str=""):
        if self.__server == "tomtomload" and jwtToken != "":
            createdTTLtoken = str(self.__server) + str(datetime.utcnow()) + str(super().create_token())
        elif self.__server == "identity-proxy":
            createdTTLtoken = str(self.__server) + str(datetime.utcnow()) + str(super().create_token())
        elif jwtToken == "":
            print("Please provide JWT token")
        else:
            print("Please provide server location")
        
        encoded_session = hashlib.sha384(createdTTLtoken.encode()).hexdigest()
        return encoded_session

    def write_token_to_session(self, Ptoken):
        if "paranoid_session" not in session or session["paranoid_session"] == "":
            session["paranoid_session"] = Ptoken
            return False

        elif Ptoken == session["paranoid_session"]:
            return True


    def get_token_from_session(self):
        return super().get_token_from_session()