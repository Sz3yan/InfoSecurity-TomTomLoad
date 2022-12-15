from flask_paranoid import Paranoid
from flask import session, Flask
from datetime import datetime
import hashlib
import json

class TTLSession(Paranoid):
    def __init__(self):

        app = Flask('identity-proxy')
        self.__server = 'identity-proxy'
        super().__init__(app)
    
    def get_token(self, jwtToken:str=""):

        createdTTLtoken = str(self.__server) + str(super().create_token())
        
        encoded_session = hashlib.sha384(createdTTLtoken.encode()).hexdigest()
        return encoded_session

    def write_data_to_session(self, session_name:str, Ptoken:str, data):
        value = {"Ptoken": Ptoken, "data": data}
        session[session_name] = json.dumps(value)

    def get_data_from_session(self, session_name:str, Ptoken:bool=False, data:bool = False):

        if session_name != "" and Ptoken:
            return json.loads(session[session_name])["Ptoken"]
        elif session_name != "" and data:
            return json.loads(session[session_name])["data"]
        else:
            return json.loads(session[session_name])

    def verfiy_Ptoken(self, current_token:str):
        return self.get_token() == current_token