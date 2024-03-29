from flask_paranoid import Paranoid
from flask import session, Flask, request
from datetime import datetime
from ast import literal_eval
from static.classes.config import CONSTANTS
import requests
import base64
import hashlib
import socket
import json


class TTLSession(Paranoid):
    def __init__(self):
        
        app = Flask(CONSTANTS.APP_NAME)
        self.__server = CONSTANTS.APP_NAME
        super().__init__(app)
    
    def __get_token(self):
        # print(requests.get("https://api64.ipify.org?format=json").text)
        device_ip_addr = requests.get("https://api64.ipify.org?format=json").text
        # device_ip_addr = socket.gethostbyname(socket.gethostname())
        createdTTLtoken = str(self.__server) + str(super().create_token()) + str(device_ip_addr)
        
        encoded_session = hashlib.sha384(createdTTLtoken.encode("utf-8")).hexdigest()
        
        return encoded_session

    def write_data_to_session(self, session_name:str, data:str):

        encoded_data = str(base64.b64encode(str(data).encode("utf-8")))
        
        value = {"Ptoken": self.__get_token(), "data": encoded_data[2:len(encoded_data)-1]}
        
        session[session_name] = json.dumps(value)


    def get_data_from_session(self, session_name:str, Ptoken:bool=False, data:bool = False):
        
        if session_name != "" and Ptoken and not data:
            return json.loads(session[session_name])["Ptoken"]
        elif session_name != "" and data and not Ptoken:
            str_value = json.loads(session[session_name])["data"]
            
            decoded_data = str(base64.b64decode(str_value).decode("utf-8"))
            
            try:
                return literal_eval(decoded_data)
            except:
                if ValueError:
                    # print(decoded_data)
                    return decoded_data
        else:
            return json.loads(session[session_name])
    
    def verfiy_Ptoken(self, session_name:str=None):
        return self.__get_token() == json.loads(session[session_name])["Ptoken"]
