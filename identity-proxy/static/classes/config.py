import os
import pathlib

from dataclasses import dataclass
from ..security.secret_manager import GoogleSecretManager


DEBUG_MODE = True


@dataclass(frozen=True, repr=False)
class Constants:
    DEBUG_MODE: bool = DEBUG_MODE 

    IP_ROOT_FOLDER: pathlib.Path = pathlib.Path(__file__).parent.parent.parent.absolute()
    IP_CONFIG_FOLDER: pathlib.Path = pathlib.Path(__file__).parent.parent.absolute() / "config_files"

    # --- GOOGLE CLOUD ---
    GOOGLE_PROJECT_ID: str = "infosec-62c05"

    # --- GOOGLE SECRET MANAGER ---
    # FLASK_SECRET_KEY_NAME: str = ""

    # --- JWT ACCESS TOKEN ---
    JWT_ACCESS_TOKEN_EXPIRATION_TIME: int = 3600  # 1 hour
    JWT_ACCESS_TOKEN_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_SECRET_KEY: str = "SECRET.JWT"

    # --- GOOGLE OAUTH ---
    GOOGLE_CLIENT_ID: str = "526204912239-9t2aptlchfeclmkcsegpp69cb690jre3.apps.googleusercontent.com"


CONSTANTS = Constants()


class SecretConstants:
    def __init__(self):
        service_account = os.path.join(Constants.IP_CONFIG_FOLDER, "service_account.json")
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = service_account

        # --- RETRIEVING FLASK SECRET KEY ---
        self.__FLASK_SECRET_KEY = "lll"

    @property
    def FLASK_SECRET_KEY(self) -> str:
        return self.__FLASK_SECRET_KEY

SECRET_CONSTANTS = SecretConstants()


__all__ = [
    "CONSTANTS",
    "SECRET_CONSTANTS"
]
