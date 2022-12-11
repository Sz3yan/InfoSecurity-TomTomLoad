from flask_paranoid import Paranoid
import hashlib

class TTLSession(Paranoid):
    def __init__(self, app=None):
        super().__init__(app)
    
    def write_token_to_session(self, Ptoken):
        pass
        # return super().write_token_to_session(token)
    
    def get_token(self, jwtToken):
        if jwtToken != "":
            super().create_token()
        else:
            print("Please provide the JWT Token")