import os
import google_crc32c
import pathlib

from google.cloud import secretmanager


config_file = pathlib.Path(__file__).parent.parent.absolute()
join_sz3yan = os.path.join(config_file, "config_files/service_account.json")


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
