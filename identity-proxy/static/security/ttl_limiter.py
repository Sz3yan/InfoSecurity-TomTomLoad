from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import Flask

class TTL_Limiter(Limiter):
    def init_app(self):
        app = Flask('identity-proxy')
        self.__server = 'identity-proxy'
        super().__init__(app=app, key_func=get_remote_address, default_limits=[app.config["CONSTANTS"].DEFAULT_REQUEST_LIMIT])
    
    def limit_user(limit_value:str=None, exempt_when:str=None):
        if limit_value != None and exempt_when != None:
            super().shared_limit(limit_value=limit_value,exempt_when=exempt_when)
        
        if limit_value != None and exempt_when == None:
            super().shared_limit(limit_value=limit_value)
        
        if limit_value == None and exempt_when != None:
            super().shared_limit(exempt_when=exempt_when)
            
        else:
             super().shared_limit()