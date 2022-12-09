from flask_paranoid import Paranoid

class TTLSession(Paranoid):
    def __init__(self, app=None):
        super().__init__(app)
    