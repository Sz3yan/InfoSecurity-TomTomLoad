import os
import time
import datetime
import base64
import google_crc32c
import pathlib
import crcmod
import six


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

        created_key_ring = client.create_key_ring(
            request={'parent': location_name, 'key_ring_id': key_ring_id, 'key_ring': key_ring})

        print('Created key ring: {}'.format(created_key_ring.name))

        return created_key_ring


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

        created_key = client.create_crypto_key(
            request={'parent': key_ring_name, 'crypto_key_id': key_id, 'crypto_key': key})

        print('Created labeled key: {}'.format(created_key.name))

        return created_key


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

        return str(retrieved_key)


class Encryption:

    def crc32c(self, data):
        """

        Calculates the CRC32C checksum of the provided data.

        Args:
            data: the bytes over which the checksum should be calculated.

        Returns:
            An int representing the CRC32C checksum of the provided bytes.

        """

        crc32c_fun = crcmod.predefined.mkPredefinedCrcFun('crc-32c')

        return crc32c_fun(six.ensure_binary(data))


    def encrypt_symmetric(self, project_id, location_id, key_ring_id, key_id, plaintext):
        """

        Encrypt plaintext using a symmetric key.

        Args:
            project_id (string): Google Cloud project ID (e.g. 'my-project').
            location_id (string): Cloud KMS location (e.g. 'us-east1').
            key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
            key_id (string): ID of the key to use (e.g. 'my-key').
            plaintext (string): message to encrypt

        Returns:
            bytes: Encrypted ciphertext.

        """

        # Convert the plaintext to bytes.
        plaintext_bytes = plaintext.encode('utf-8')

        # Optional, but recommended: compute plaintext's CRC32C.
        # See crc32c() function defined below.
        plaintext_crc32c = self.crc32c(plaintext_bytes)

        # Create the client.
        client = kms.KeyManagementServiceClient()

        # Build the key name.
        key_name = client.crypto_key_path(project_id, location_id, key_ring_id, key_id)

        # Call the API.
        encrypt_response = client.encrypt(
            request={'name': key_name, 'plaintext': plaintext_bytes, 'plaintext_crc32c': plaintext_crc32c})

        # Optional, but recommended: perform integrity verification on encrypt_response.
        # For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
        # https://cloud.google.com/kms/docs/data-integrity-guidelines
        if not encrypt_response.verified_plaintext_crc32c:
            raise Exception('The request sent to the server was corrupted in-transit.')

        if not encrypt_response.ciphertext_crc32c == self.crc32c(encrypt_response.ciphertext):
            raise Exception('The response received from the server was corrupted in-transit.')
        # End integrity verification

        print('Ciphertext: {}'.format(base64.b64encode(encrypt_response.ciphertext)))

        return encrypt_response


    def decrypt_symmetric(self, project_id, location_id, key_ring_id, key_id, ciphertext):
        """

        Decrypt the ciphertext using the symmetric key

        Args:
            project_id (string): Google Cloud project ID (e.g. 'my-project').
            location_id (string): Cloud KMS location (e.g. 'us-east1').
            key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
            key_id (string): ID of the key to use (e.g. 'my-key').
            ciphertext (bytes): Encrypted bytes to decrypt.

        Returns:
            DecryptResponse: Response including plaintext.

        """

        client = kms.KeyManagementServiceClient()

        key_name = client.crypto_key_path(project_id, location_id, key_ring_id, key_id)

        ciphertext_crc32c = self.crc32c(ciphertext)

        # Call the API.
        decrypt_response = client.decrypt(
            request={'name': key_name, 'ciphertext': ciphertext, 'ciphertext_crc32c': ciphertext_crc32c})

        # Optional, but recommended: perform integrity verification on decrypt_response.
        # For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
        # https://cloud.google.com/kms/docs/data-integrity-guidelines
        if not decrypt_response.plaintext_crc32c == self.crc32c(decrypt_response.plaintext):
            raise Exception('The response received from the server was corrupted in-transit.')
        # End integrity verification

        print('Plaintext: {}'.format(decrypt_response.plaintext))

        return decrypt_response


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
