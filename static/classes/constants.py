import os
import pathlib

from dataclasses import dataclass
from ..security.secure_data import GoogleSecretManager


DEBUG_MODE = True


@dataclass(frozen=True, repr=False)
class Constants:
    DEBUG_MODE: bool = DEBUG_MODE 

    ROOT_FOLDER: pathlib.Path = pathlib.Path(__file__).parent.parent.parent.absolute()
    CONFIG_FOLDER: pathlib.Path = pathlib.Path(__file__).parent.parent.absolute() / "config_files"

    # --- GOOGLE CLOUD ---
    GOOGLE_PROJECT_ID: str = "infosec-62c05"

    # --- GOOGLE KEY MANAGEMENT SYSTEM ---
    # LOCATION_ID: str = ""
    # KEY_RING_ID: str = ""
    # AVAILABLE_KEY_RINGS: tuple = ()

    # --- GOOGLE SECRET MANAGER ---
    # FLASK_SECRET_KEY_NAME: str = ""

    # --- RATE LIMITING ---
    # DEFAULT_REQUEST_LIMIT: str = ""
    # SENSITIVE_PAGE_LIMIT: str = ""


CONSTANTS = Constants()


class SecretConstants:
    def __init__(self):
        # --- FIREBASE SDK ---
        service_account = os.path.join(Constants.CONFIG_FOLDER, "service_account.json")
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = service_account

        # --- RETRIEVING HSM SECRET KEY ---
        # self.__POST_SECRET_KEY = GoogleSecretManager.get_secret_payload(self, CONSTANTS.GOOGLE_PROJECT_ID, CONSTANTS.AVAILABLE_KEY_RINGS[0], "1")

        # --- RETRIEVING FIREBASE CREDENTIALS ---
        self.__API_KEY = GoogleSecretManager.get_secret_payload(self, CONSTANTS.GOOGLE_PROJECT_ID, "apiKey", "1")
        self.__AUTH_DOMAIN = GoogleSecretManager.get_secret_payload(self, CONSTANTS.GOOGLE_PROJECT_ID, "authDomain", "1")
        self.__PROJECT_ID = GoogleSecretManager.get_secret_payload(self, CONSTANTS.GOOGLE_PROJECT_ID, "projectId", "1")
        self.__STORAGE_BUCKET = GoogleSecretManager.get_secret_payload(self, CONSTANTS.GOOGLE_PROJECT_ID, "storageBucket", "1")
        self.__MESSAGING_SENDER_ID = GoogleSecretManager.get_secret_payload(self, CONSTANTS.GOOGLE_PROJECT_ID, "messagingSenderId", "1")
        self.__APP_ID = GoogleSecretManager.get_secret_payload(self, CONSTANTS.GOOGLE_PROJECT_ID, "appId", "1")
        self.__MEASUREMENT_ID = GoogleSecretManager.get_secret_payload(self, CONSTANTS.GOOGLE_PROJECT_ID, "measurementId", "1")

        # --- VIRUSTOTAL API ---
        self.__virus_total_api_key = GoogleSecretManager.get_secret_payload(self, CONSTANTS.GOOGLE_PROJECT_ID, "virustotal", "1")

        # --- RETRIEVING FLASK SECRET KEY ---
        # self.__FLASK_SECRET_KEY = GoogleSecretManager.get_secret_payload(self, CONSTANTS.GOOGLE_PROJECT_ID, CONSTANTS.FLASK_SECRET_KEY_NAME, "2")

    # @property
    # def POST_SECRET_KEY(self) -> str:
    #     return self.__POST_SECRET_KEY


    @property
    def API_KEY(self) -> str:
        return self.__API_KEY

    @property
    def AUTH_DOMAIN(self) -> str:
        return self.__AUTH_DOMAIN

    @property
    def PROJECT_ID(self) -> str:
        return self.__PROJECT_ID

    @property
    def STORAGE_BUCKET(self) -> str:
        return self.__STORAGE_BUCKET

    @property
    def MESSAGING_SENDER_ID(self) -> str:
        return self.__MESSAGING_SENDER_ID

    @property
    def APP_ID(self) -> str:
        return self.__APP_ID

    @property
    def MEASUREMENT_ID(self) -> str:
        return self.__MEASUREMENT_ID

    @property
    def virus_total_api_key(self) -> str:
        return self.__virus_total_api_key

    # @property
    # def FLASK_SECRET_KEY(self) -> str:
    #     return self.__FLASK_SECRET_KEY

SECRET_CONSTANTS = SecretConstants()

__all__ = [
    "CONSTANTS",
    "SECRET_CONSTANTS"
]
