import pyrebase

from .constants import SECRET_CONSTANTS


class Firebase:
    def  __init__(self):
        firebaseConfig = {
            "apiKey": SECRET_CONSTANTS.API_KEY,
            "authDomain": SECRET_CONSTANTS.AUTH_DOMAIN,
            "projectId": SECRET_CONSTANTS.PROJECT_ID,
            "storageBucket": SECRET_CONSTANTS.STORAGE_BUCKET,
            "messagingSenderId": SECRET_CONSTANTS.MESSAGING_SENDER_ID,
            "appId": SECRET_CONSTANTS.APP_ID,
            "measurementId": SECRET_CONSTANTS.MEASUREMENT_ID
        }

        self.__firebase = pyrebase.initialize_app(firebaseConfig)
        self.__database = self.__firebase.database()


    # --- article ---
    def create_article(self, article_dict):
        self.__database.child("article").push(article_dict.__dict__)


    def get_article(self):
        return self.__database.child("article").get()


    def update_article(self, article_id, article_dict):
        for i in self.__database.child("article").get().each():
            if i.val()["_Content__id"] == article_id:
                self.__database.child("article").child(i.key()).update(article_dict.__dict__)
                return "article updated"


    def delete_article(self, article_id):
        for i in self.__database.child("article").get().each():
            if i.val()["_Content__id"] == article_id:
                self.__database.child("article").child(i.key()).remove()
                return "article deleted"

    
    # --- CSP ---
    def set_csp(self, csp_dict):
        self.__database.child("Content_Security_Policy").set(csp_dict)


    def get_csp(self):
        csp_dict = {}
        for i in self.__database.child("Content_Security_Policy").get().each():
            csp_dict[i.key()] = i.val()

        return csp_dict


    def update_csp(self, csp_dict):
        self.__database.child("Content_Security_Policy").update(csp_dict)

