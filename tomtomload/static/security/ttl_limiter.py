from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import Flask, request
from static.classes.config import CONSTANTS

class TTL_Limiter(Limiter):
    def __init__(self):
        app = Flask(CONSTANTS.APP_NAME)
        super().__init__(app=app, key_func=get_remote_address, default_limits=["60 per minute"])
    
    def limit_user(self, limit_value:str=None, exempt_when:str=None):
        if limit_value != None and exempt_when != None:
            return super().shared_limit(limit_value=limit_value,exempt_when=exempt_when)
        
        if limit_value != None and exempt_when == None:
            return super().shared_limit(limit_value=limit_value, scope=self.__host_scope)
        
        if limit_value == None and exempt_when != None:
            return super().shared_limit(exempt_when=exempt_when)


    def __host_scope(self, endpoint_name):
        return request.host