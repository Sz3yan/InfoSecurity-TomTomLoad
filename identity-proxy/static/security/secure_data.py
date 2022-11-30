import os
import time
import datetime
import google_crc32c
import pathlib

from google.cloud import kms
from google.cloud import secretmanager
from google.protobuf import duration_pb2


config_file = pathlib.Path(__file__).parent.parent.absolute()
join_sz3yan = os.path.join(config_file, "config_files/service_account.json")


class GoogleCloudKeyManagement:
    def __init__(self):
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = join_sz3yan
        
    # create once only when setup
    def create_key_ring(self, project_id, location_id, key_ring_id):
        client = kms.KeyManagementServiceClient()

        location_name = f'projects/{project_id}/locations/{location_id}'

        key_ring = {}

        created_key_ring = client.create_key_ring(request={'parent': location_name, 'key_ring_id': key_ring_id, 'key_ring': key_ring})
        print('Created key ring: {}'.format(created_key_ring.name))
        return created_key_ring

    # for key rotation. Google will automatically use the correct key version to encrypt and decrypt data (if key version is enabled)
    def create_key_rotation_schedule(self, project_id, location_id, key_ring_id, key_id):
        client = kms.KeyManagementServiceClient()

        key_ring_name = client.key_ring_path(project_id, location_id, key_ring_id)

        purpose = kms.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT
        algorithm = kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
        key = {
            'purpose': purpose,
            'version_template': {
                'algorithm': algorithm,
            },

            # Rotate the key every 30 days.
            'rotation_period': {
                'seconds': 60 * 60 * 24 * 30
            },

            'next_rotation_time': {
                'seconds': int(time.time()) + 60 * 60 * 24
            }
        }

        created_key = client.create_crypto_key(request={'parent': key_ring_name, 'crypto_key_id': key_id, 'crypto_key': key})
        print('Created labeled key: {}'.format(created_key.name))
        return created_key

    # creates key based on Hardware Security Module (HSM). To be use for encryption and decryption.
    def create_key_hsm(self, project_id, location_id, key_ring_id, key_id):
        client = kms.KeyManagementServiceClient()

        key_ring_name = client.key_ring_path(project_id, location_id, key_ring_id)

        purpose = kms.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT
        algorithm = kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
        protection_level = kms.ProtectionLevel.HSM
        key = {
            'purpose': purpose,
            'version_template': {
                'algorithm': algorithm,
                'protection_level': protection_level
            },

            # Optional: customize how long key versions should be kept before destroying.
            'destroy_scheduled_duration': duration_pb2.Duration().FromTimedelta(datetime.timedelta(days=1))
        }

        created_key = client.create_crypto_key(
            request={'parent': key_ring_name, 'crypto_key_id': key_id, 'crypto_key': key})
        print('Created hsm key: {}'.format(created_key.name))
        return created_key

    def retrieve_key(self, project_id, location_id, key_ring_id, key_id):
        client = kms.KeyManagementServiceClient()

        key_name = client.crypto_key_path(project_id, location_id, key_ring_id, key_id)
        retrieved_key = client.get_crypto_key(request={'name': key_name})
        return retrieved_key


class GoogleSecretManager:
    def __init__(self):
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = join_sz3yan

    def create_secret(self, project_id, secret_id):
        """
        Create a new secret with the given name. A secret is a logical wrapper
        around a collection of secret versions. Secret versions hold the actual
        secret material.
        """

        client = secretmanager.SecretManagerServiceClient()

        parent = f"projects/{project_id}"

        # Create the secret.
        response = client.create_secret(
            request={
                "parent": parent,
                "secret_id": secret_id,
                "secret": {"replication": {"automatic": {}}},
            }
        )

        # Print the new secret name.
        print("Created secret: {}".format(response.name))

    def add_secret_version(self, project_id, secret_id, payload):
        """
        Add a new secret version to the given secret with the provided payload.
        """
        client = secretmanager.SecretManagerServiceClient()

        parent = client.secret_path(project_id, secret_id)

        # Convert the string payload into a bytes. This step can be omitted if you
        # pass in bytes instead of a str for the payload argument.
        payload = payload.encode("UTF-8")

        # Calculate payload checksum. Passing a checksum in add-version request

        crc32c = google_crc32c.Checksum()
        crc32c.update(payload)

        # Add the secret version.
        response = client.add_secret_version(
            request={
                "parent": parent,
                "payload": {"data": payload, "data_crc32c": int(crc32c.hexdigest(), 16)},
            }
        )

        # Print the new secret version name.
        print("Added secret version: {}".format(response.name))

    def get_secret_payload(self, project_id, secret_id, version_id):
        """
        Get the payload of the given secret version.
        """
        client = secretmanager.SecretManagerServiceClient()

        name = client.secret_version_path(project_id, secret_id, version_id)
        response = client.access_secret_version(request={"name": name})
        payload = response.payload.data.decode("UTF-8")

        return payload

    def list_secrets(self, project_id):
        """
        List all secrets in the given project.
        """
        client = secretmanager.SecretManagerServiceClient()

        parent = f"projects/{project_id}"

        # List all secrets.
        for secret in client.list_secrets(request={"parent": parent}):
            print("Found secret: {}".format(secret.name))

    def delete_secret(self, project_id, secret_id):
        """
        Delete the secret with the given name and all of its versions.
        """
        client = secretmanager.SecretManagerServiceClient()

        name = client.secret_path(project_id, secret_id)

        # Delete the secret.
        client.delete_secret(request={"name": name})


# if __name__ == '__main__':
    # generate_JWTKEY = GoogleCloudKeyManagement()

    # generate_JWTKEY.create_key_ring('infosec-62c05', 'global', 'identity-proxy')

    # generate_JWTKEY.create_key_hsm(
    #     project_id="infosec-62c05",
    #     location_id="global",
    #     key_ring_id="identity-proxy",
    #     key_id="identity-proxy-jwt-key"
    # )

    # view_JWTKEY = generate_JWTKEY.retrieve_key(
    #     project_id="infosec-62c05",
    #     location_id="global",
    #     key_ring_id="identity-proxy",
    #     key_id="identity-proxy-jwt-key"
    # )

    # sm = GoogleSecretManager()

    # sm.create_secret(
    #     project_id="infosec-62c05",
    #     secret_id="identity-proxy-jwt-key"
    # )

    # sm.add_secret_version(
    #     project_id="infosec-62c05",
    #     secret_id="identity-proxy-jwt-key",
    #     payload=str(view_JWTKEY)
    # )

    # sm.list_secrets(
    #     project_id="infosec-62c05"
    # )

