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

    # --- GOOGLE KEY MANAGEMENT SYSTEM ---
    # LOCATION_ID: str = ""
    # KEY_RING_ID: str = ""
    # AVAILABLE_KEY_RINGS: tuple = ()

    # --- GOOGLE SECRET MANAGER ---
    # FLASK_SECRET_KEY_NAME: str = ""

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
