from flask_paranoid import Paranoid
import jwt

class TTLSession(Paranoid):
    def __init__(self, app=None):
        super().__init__(app)
    
    def write_token_to_session(self, token):
        return super().write_token_to_session(token)
    
    def get_token(self, username, password):
        if username == "" and password == "":
            return 