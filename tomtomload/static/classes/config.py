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
    GOOGLE_KEY_RING_ID: str = "identity-proxy"

    # --- GOOGLE CLOUD STORAGE ---
    STORAGE_BUCKET_NAME: str = "ttl1234567890"
    BLACKLISTED_FILE_NAME: str = "blacklisted.json"

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
    DEFAULT_REQUEST_LIMIT: str = "600 per minute"
    SENSITIVE_PAGE_LIMIT: str = "9 per minute"


CONSTANTS = Constants()


class SecretConstants:
    def __init__(self):
        # --- FIREBASE SDK ---
        service_account = os.path.join(Constants.TTL_CONFIG_FOLDER, "service_account.json")
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = service_account

        # --- RETRIEVING HSM SECRET KEY ---
        # self.__POST_SECRET_KEY = GoogleSecretManager.get_secret_payload(self, CONSTANTS.GOOGLE_PROJECT_ID, CONSTANTS.AVAILABLE_KEY_RINGS[0], "1")

        # --- VIRUSTOTAL API ---
        self.__virus_total_api_key = GoogleSecretManager.get_secret_payload(self, CONSTANTS.GOOGLE_PROJECT_ID, "virustotal", "1")

        # --- RETRIEVING JWT ACCESS TOKEN SECRET KEY ---
        self.__JWT_SECRET_KEY = GoogleSecretManager.get_secret_payload(
            self,
            project_id=Constants.GOOGLE_PROJECT_ID,
            secret_id=Constants.JWT_ACCESS_TOKEN_SECRET_KEY,
            version_id="1"
        )

    # @property
    # def POST_SECRET_KEY(self) -> str:
    #     return self.__POST_SECRET_KEY

    @property
    def virus_total_api_key(self) -> str:
        return self.__virus_total_api_key

    @property
    def JWT_SECRET_KEY(self) -> str:
        return self.__JWT_SECRET_KEY


SECRET_CONSTANTS = SecretConstants()

__all__ = [
    "CONSTANTS",
    "SECRET_CONSTANTS"
]
