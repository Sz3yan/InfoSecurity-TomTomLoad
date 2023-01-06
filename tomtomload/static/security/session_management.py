from flask_paranoid import Paranoid
from flask import session, Flask, request
from datetime import datetime
# import requests
import hashlib
import socket
import json

class TTLSession(Paranoid):
    def __init__(self):
        # session.pop("TTLAuthenticatedUserName")
        # session.pop("TTLJWTAuthenticatedUser")
        # print("ttlsession")
        app = Flask('tomtomload')
        self.__server = 'tomtomload'
        super().__init__(app)
    
    def get_token(self):
        # print(requests.get("https://api64.ipify.org?format=json").text)
        device_ip_addr = socket.gethostbyname(socket.gethostname())
        createdTTLtoken = str(self.__server) + str(super().create_token()) + str(device_ip_addr)
        
        encoded_session = hashlib.sha384(createdTTLtoken.encode("utf-8")).hexdigest()
        
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
        