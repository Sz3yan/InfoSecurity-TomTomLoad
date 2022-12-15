import os
import pathlib

from dataclasses import dataclass
from ..security.secure_data import GoogleSecretManager


DEBUG_MODE = True


@dataclass(frozen=True, repr=False)
class Constants:
    DEBUG_MODE: bool = DEBUG_MODE 

    TTL_ROOT_FOLDER: pathlib.Path = pathlib.Path(__file__).parent.parent.parent.absolute()
    TTL_CONFIG_FOLDER: pathlib.Path = pathlib.Path(__file__).parent.parent.absolute() / "config_files"

    # --- GOOGLE CLOUD ---
    GOOGLE_PROJECT_ID: str = "infosec-62c05"
    GOOGLE_LOCATION_ID: str = "global"

    # --- GOOGLE CLOUD STORAGE ---
    STORAGE_BUCKET_NAME: str = "ttl1234567890"
    BLACKLISTED_FILE_NAME: str = "blacklisted.json"
    ACL_FILE_NAME: str = "acl.json"

    # --- GOOGLE CLOUD KMS ---
    KMS_IP_KEY_RING_ID: str = "identity-proxy"
    KMS_TTL_KEY_RING_ID: str = "tomtomload"
    KMS_KEY_ID: str = "tomtomload-symmetric-key"

    # --- GOOGLE SECRET MANAGER ---
    # FLASK_SECRET_KEY_NAME: str = ""

    # --- JWT ACCESS TOKEN ---
    JWT_ACCESS_TOKEN_EXPIRATION_TIME: int = 10
    JWT_ACCESS_TOKEN_SKEW_TIME: int = 30
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_SECRET_KEY: str = "identity-proxy-jwt-key"

    # --- GOOGLE OAUTH ---
    GOOGLE_CLIENT_ID: str = "526204912239-9t2aptlchfeclmkcsegpp69cb690jre3.apps.googleusercontent.com"

    # --- RATE LIMITING ---
    DEFAULT_REQUEST_LIMIT: str = "60 per minute"
    SENSITIVE_PAGE_LIMIT: str = "9 per minute"

    # --- MEDIA UPLOAD ---
    ALLOWED_MEDIA_EXTENSIONS: dict = "png", "jpg", "jpeg","mp4", "mov", "quicktime","mpeg", "mp3", "wav", "pdf", "zip"
    ALLOWED_POST_EXTENSIONS: dict = "md", "txt"


CONSTANTS = Constants()


class SecretConstants:
    def __init__(self):
        service_account = os.path.join(Constants.TTL_CONFIG_FOLDER, "service_account.json")
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = service_account

        # self.__POST_SECRET_KEY = GoogleSecretManager.get_secret_payload(
        #     self, 
        #     CONSTANTS.GOOGLE_PROJECT_ID, 
        #     CONSTANTS.AVAILABLE_KEY_RINGS[0], 
        #     "1"
        # )

        self.__virus_total_api_key = GoogleSecretManager.get_secret_payload(
            self, 
            CONSTANTS.GOOGLE_PROJECT_ID, 
            "virustotal", 
            "1"
        )

    # @property
    # def POST_SECRET_KEY(self) -> str:
    #     return self.__POST_SECRET_KEY

    @property
    def virus_total_api_key(self) -> str:
        return self.__virus_total_api_key


SECRET_CONSTANTS = SecretConstants()


__all__ = [
    "CONSTANTS",
    "SECRET_CONSTANTS"
]
