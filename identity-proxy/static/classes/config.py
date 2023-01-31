import os
import pathlib

from dataclasses import dataclass
from ..security.secure_data import GoogleSecretManager


DEBUG_MODE = True


@dataclass(frozen=True, repr=False)
class Constants:
    DEBUG_MODE: bool = DEBUG_MODE 

    CALLBACK_URL: str = "https://127.0.0.1:8080/callback" if DEBUG_MODE else "https://tomtomload.com/callback"
    API_ROUTE_URL: str = "https://127.0.0.1:5000/api" if DEBUG_MODE else "https://tomtomload.com/api"
    ADMIN_URL: str = "https://127.0.0.1:5000/admin" if DEBUG_MODE else "https://tomtomload.com/admin"

    IP_ROOT_FOLDER: pathlib.Path = pathlib.Path(__file__).parent.parent.parent.absolute()
    IP_CONFIG_FOLDER: pathlib.Path = pathlib.Path(__file__).parent.parent.absolute() / "config_files"

    # --- GOOGLE CLOUD ---
    GOOGLE_PROJECT_ID: str = "infosec-62c05"
    GOOGLE_LOCATION_ID: str = "global"
    GOOGLE_KEY_RING_ID: str = "identity-proxy"

    # --- GOOGLE CLOUD STORAGE ---
    STORAGE_BUCKET_NAME: str = "ttl1234567890"
    BLACKLISTED_FILE_NAME: str = "blacklisted.json"
    ACL_FILE_NAME: str = "acl.json"

    # --- GOOGLE CERTIFICATE AUTHORITY ---
    GOOGLE_CA_POOL_NAME: str = "identity-proxy-ca-pool"
    GOOGLE_CA_NAME: str = "identity-proxy-ca"
    GOOGLE_SUBORDINATE_CA_NAME: str = "identity-proxy-subordinate-ca"
    GOOGLE_COMMON_NAME: str = "identity-proxy-ca"
    GOOGLE_ORGANIZATION: str = "identity-proxy-ca"
    GOOGLE_CA_DURATION: str = "P10Y"

    # --- JWT ACCESS TOKEN ---
    JWT_ACCESS_TOKEN_EXPIRATION_TIME: int = 60 if DEBUG_MODE else 10
    JWT_ACCESS_TOKEN_SKEW_TIME: int = 30
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_SECRET_KEY: str = "identity-proxy-jwt-key"

    # --- GOOGLE OAUTH ---
    GOOGLE_CLIENT_ID: str = "526204912239-9t2aptlchfeclmkcsegpp69cb690jre3.apps.googleusercontent.com"
    GOOGLE_OAUTH_SKEW_TIME: int = 2

    # --- GOOGLE OAUTH API ---
    GOOGLE_CLIENT_ID2: str = "526204912239-ug33fg2dkq2jm55p0igbp7qc8v93gio4.apps.googleusercontent.com"

    # --- IPINFO ---
    IPINFO: str = "ipinfo"

    # --- RATE LIMITING ---
    DEFAULT_REQUEST_LIMIT: str = "60 per minute"
    SENSITIVE_PAGE_LIMIT: str = "9 per minute"


CONSTANTS = Constants()


class SecretConstants:
    def __init__(self):
        service_account = os.path.join(Constants.IP_CONFIG_FOLDER, "service_account.json")
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = service_account

        # --- RETRIEVING FLASK SECRET KEY ---
        self.__FLASK_SECRET_KEY = "lll"

        # --- RETRIEVING JWT ACCESS TOKEN SECRET KEY ---
        self.__JWT_SECRET_KEY = GoogleSecretManager.get_secret_payload(
            self,
            project_id=Constants.GOOGLE_PROJECT_ID,
            secret_id=Constants.JWT_ACCESS_TOKEN_SECRET_KEY,
            version_id="1"
        )

        # --- RETRIEVING IPINFO TOKEN KEY ---
        self.__IPINFO_TOKEN = GoogleSecretManager.get_secret_payload(
            self,
            project_id=Constants.GOOGLE_PROJECT_ID,
            secret_id=Constants.IPINFO,
            version_id="1"
        )

    @property
    def FLASK_SECRET_KEY(self) -> str:
        return self.__FLASK_SECRET_KEY

    @property
    def JWT_SECRET_KEY(self) -> str:
        return self.__JWT_SECRET_KEY

    @property
    def IPINFO_TOKEN(self) -> str:
        return self.__IPINFO_TOKEN


SECRET_CONSTANTS = SecretConstants()


__all__ = [
    "CONSTANTS",
    "SECRET_CONSTANTS"
]
