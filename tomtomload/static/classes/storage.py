import os
import pathlib


from google.cloud import storage
from google.cloud import storage_transfer_v1


config_file = pathlib.Path(__file__).parent.parent.absolute()
join_sz3yan = os.path.join(config_file, "config_files/service_account.json")


class GoogleCloudStorage:
    def __init__(self):
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = join_sz3yan

    def create_bucket_class_location(self, bucket_name):
        """
        Create a new bucket in the US region with the coldline storage
        class
        """
        # bucket_name = "your-new-bucket-name"

        storage_client = storage.Client()

        bucket = storage_client.bucket(bucket_name)
        bucket.storage_class = "COLDLINE"
        new_bucket = storage_client.create_bucket(bucket, location="us")

        print(
            "Created bucket {} in {} with storage class {}".format(
                new_bucket.name, new_bucket.location, new_bucket.storage_class
            )
        )
        return new_bucket

    def download_blob(self, bucket_name, source_blob_name, destination_file_name):
        """Downloads a blob from the bucket."""
        # The ID of your GCS bucket
        # bucket_name = "your-bucket-name"

        # The ID of your GCS object
        # source_blob_name = "storage-object-name"

        # The path to which the file should be downloaded
        # destination_file_name = "local/path/to/file"

        storage_client = storage.Client()

        bucket = storage_client.bucket(bucket_name)

        # Construct a client side representation of a blob.
        # Note `Bucket.blob` differs from `Bucket.get_blob` as it doesn't retrieve
        # any content from Google Cloud Storage. As we don't need additional data,
        # using `Bucket.blob` is preferred here.
        blob = bucket.blob(source_blob_name)
        blob.download_to_filename(destination_file_name)

        print(
            "Downloaded storage object {} from bucket {} to local file {}.".format(
                source_blob_name, bucket_name, destination_file_name
            )
        )

    def upload_blob(self, bucket_name, source_file_name, destination_blob_name):
        """Uploads a file to the bucket."""
        # The ID of your GCS bucket
        # bucket_name = "your-bucket-name"
        # The path to your file to upload
        # source_file_name = "local/path/to/file"
        # The ID of your GCS object
        # destination_blob_name = "storage-object-name"


        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(destination_blob_name)

        blob.upload_from_filename(source_file_name)

        print(
            f"File {source_file_name} uploaded to {destination_blob_name}."
        )

    def delete_blob(self, bucket_name, blob_name):
        """Deletes a blob from the bucket."""
        # bucket_name = "your-bucket-name"
        # blob_name = "your-object-name"

        storage_client = storage.Client()

        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        blob.delete()

        print(f"Blob {blob_name} deleted.")

    def blob_metadata(self, bucket_name, blob_name):
        """Prints out a blob's metadata."""
        # bucket_name = 'your-bucket-name'
        # blob_name = 'your-object-name'

        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)

        # Retrieve a blob, and its metadata, from Google Cloud Storage.
        # Note that `get_blob` differs from `Bucket.blob`, which does not
        # make an HTTP request.
        blob = bucket.get_blob(blob_name)

        metadata_dict = {
            "blob_name": blob.name,
            "bucket_name": blob.bucket.name,
            "storage_class": blob.storage_class,    
            "id": blob.id,
            "size": blob.size,
            "updated": blob.updated,
            "generation": blob.generation,
            "metageneration": blob.metageneration,
            "etag": blob.etag,
            "owner": blob.owner,
            "component_count": blob.component_count,
            "crc32c": blob.crc32c,
            "md5_hash": blob.md5_hash,
            "cache_control": blob.cache_control,
            "content_type": blob.content_type,
            "content_disposition": blob.content_disposition,
            "content_encoding": blob.content_encoding,
            "content_language": blob.content_language,
            "custom_time": blob.custom_time,
            "temporary_hold": "enabled" if blob.temporary_hold else "disabled",
            "event_based_hold": "enabled" if blob.event_based_hold else "disabled",
            "retention_expiration_time": blob.retention_expiration_time,
            "time_created": blob.time_created,
            "time_deleted": blob.time_deleted,
            "updated": blob.updated,

            # get custom metadata
            "metadata": blob.metadata,


        }

        if blob.retention_expiration_time:
            print(
                f"retentionExpirationTime: {blob.retention_expiration_time}"
            )

        return metadata_dict

    def set_blob_metadata(self, bucket_name, blob_name, metadata_dict):
        """Set a blob's metadata."""
        # bucket_name = 'your-bucket-name'
        # blob_name = 'your-object-name'

        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.get_blob(blob_name)
        metadata = metadata_dict
        blob.metadata = metadata
        blob.patch()

        print(f"The metadata for the blob {blob.name} is {blob.metadata}")

    
    def list_blobs(self, bucket_name):
        """Lists all the blobs in the bucket."""
        # bucket_name = "your-bucket-name"

        storage_client = storage.Client()

        # Note: Client.list_blobs requires at least package version 1.17.0.
        blobs = storage_client.list_blobs(bucket_name)

        # Note: The call returns a response only when the iterator is consumed.
        for blob in blobs:
            print(blob.name)

    def list_blobs_with_prefix(self, bucket_name, prefix, delimiter=None):
        """Lists all the blobs in the bucket that begin with the prefix.

        This can be used to list all blobs in a "folder", e.g. "public/".

        The delimiter argument can be used to restrict the results to only the
        "files" in the given "folder". Without the delimiter, the entire tree under
        the prefix is returned. For example, given these blobs:

            a/1.txt
            a/b/2.txt

        If you specify prefix ='a/', without a delimiter, you'll get back:

            a/1.txt
            a/b/2.txt

        However, if you specify prefix='a/' and delimiter='/', you'll get back
        only the file directly under 'a/':

            a/1.txt

        As part of the response, you'll also get back a blobs.prefixes entity
        that lists the "subfolders" under `a/`:

            a/b/
        """

        storage_client = storage.Client()

        # Note: Client.list_blobs requires at least package version 1.17.0.
        blobs = storage_client.list_blobs(bucket_name, prefix=prefix, delimiter=delimiter)

        # Note: The call returns a response only when the iterator is consumed.
        blobs_array = []

        for blob in blobs:
            blobs_array.append(blob.name)

        return blobs_array

    def move_blob(self, bucket_name, blob_name, destination_bucket_name, destination_blob_name):
        """Moves a blob from one bucket to another with a new name."""
        # The ID of your GCS bucket
        # bucket_name = "your-bucket-name"
        # The ID of your GCS object
        # blob_name = "your-object-name"
        # The ID of the bucket to move the object to
        # destination_bucket_name = "destination-bucket-name"
        # The ID of your new GCS object (optional)
        # destination_blob_name = "destination-object-name"

        storage_client = storage.Client()

        source_bucket = storage_client.bucket(bucket_name)
        source_blob = source_bucket.blob(blob_name)
        destination_bucket = storage_client.bucket(destination_bucket_name)

        blob_copy = source_bucket.copy_blob(
            source_blob, destination_bucket, destination_blob_name
        )
        source_bucket.delete_blob(blob_name)

        print(
            "Blob {} in bucket {} moved to blob {} in bucket {}.".format(
                source_blob.name,
                source_bucket.name,
                blob_copy.name,
                destination_bucket.name,
            )
        )

    #scheduling le backup
    def sample_create_transfer_job(self):
        # Create a client
        client = storage_transfer_v1.StorageTransferServiceClient()

        # Initialize request argument(s)
        request = storage_transfer_v1.CreateTransferJobRequest(
        )

        # Make the request
        response = client.create_transfer_job(request=request)

        # Handle the response
        print(response)

    # Autoclass feature automatically transitions objects in your bucket to appropriate storage classes based on each object's access pattern
    def set_autoclass(self, bucket_name, toggle):
        """Disable Autoclass for a bucket.

        Note: Only patch requests that disable autoclass are currently supported.
        To enable autoclass, you must set it at bucket creation time.
        """
        # The ID of your GCS bucket
        # bucket_name = "my-bucket"
        # Boolean toggle - if true, enables Autoclass; if false, disables Autoclass
        # toggle = False

        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)

        bucket.autoclass_enabled = toggle
        bucket.patch()
        print(f"Autoclass enabled is set to {bucket.autoclass_enabled} for {bucket.name} at {bucket.autoclass_toggle_time}.")

        return bucket

    def get_autoclass(self, bucket_name):
        """Get the Autoclass setting for a bucket."""
        # The ID of your GCS bucket
        # bucket_name = "my-bucket"

        storage_client = storage.Client()
        bucket = storage_client.get_bucket(bucket_name)
        autoclass_enabled = bucket.autoclass_enabled
        autoclass_toggle_time = bucket.autoclass_toggle_time

        print(f"Autoclass enabled is set to {autoclass_enabled} for {bucket.name} at {autoclass_toggle_time}.")

        return bucket

    def enable_versioning(self, bucket_name):
        """Enable versioning for this bucket."""
        # bucket_name = "my-bucket"

        storage_client = storage.Client()

        bucket = storage_client.get_bucket(bucket_name)
        bucket.versioning_enabled = True
        bucket.patch()

        print(f"Versioning was enabled for bucket {bucket.name}")
        return bucket

    def disable_versioning(self, bucket_name):
        """Disable versioning for this bucket."""
        # bucket_name = "my-bucket"

        storage_client = storage.Client()

        bucket = storage_client.get_bucket(bucket_name)
        bucket.versioning_enabled = False
        bucket.patch()

        print(f"Versioning was disabled for bucket {bucket}")
        return bucket

    def list_file_archived_generations(self, bucket_name):
        """Lists all the blobs in the bucket with generation."""
        # bucket_name = "your-bucket-name"

        storage_client = storage.Client()

        blobs = storage_client.list_blobs(bucket_name, versions=True)

        for blob in blobs:
            print(f"{blob.name},{blob.generation}")

    def copy_file_archived_generation(
        self, bucket_name, blob_name, destination_bucket_name, destination_blob_name, generation
    ):
        """Copies a blob from one bucket to another with a new name with the same generation."""
        # bucket_name = "your-bucket-name"
        # blob_name = "your-object-name"
        # destination_bucket_name = "destination-bucket-name"
        # destination_blob_name = "destination-object-name"
        # generation = 1579287380533984

        storage_client = storage.Client()

        source_bucket = storage_client.bucket(bucket_name)
        source_blob = source_bucket.blob(blob_name)
        destination_bucket = storage_client.bucket(destination_bucket_name)

        # Optional: set a generation-match precondition to avoid potential race conditions
        # and data corruptions. The request to copy is aborted if the object's
        # generation number does not match your precondition. For a destination
        # object that does not yet exist, set the if_generation_match precondition to 0.
        # If the destination object already exists in your bucket, set instead a
        # generation-match precondition using its generation number.
        destination_generation_match_precondition = 0

        # source_generation selects a specific revision of the source object, as opposed to the latest version.
        blob_copy = source_bucket.copy_blob(
            source_blob, destination_bucket, destination_blob_name, source_generation=generation, if_generation_match=destination_generation_match_precondition
        )

        print(
            "Generation {} of the blob {} in bucket {} copied to blob {} in bucket {}.".format(
                generation,
                source_blob.name,
                source_bucket.name,
                blob_copy.name,
                destination_bucket.name,
            )
        )

    def delete_file_archived_generation(self, bucket_name, blob_name, generation):
        """Delete a blob in the bucket with the given generation."""
        # bucket_name = "your-bucket-name"
        # blob_name = "your-object-name"
        # generation = 1579287380533984

        storage_client = storage.Client()

        bucket = storage_client.get_bucket(bucket_name)
        bucket.delete_blob(blob_name, generation=generation)
        print(
            f"Generation {generation} of blob {blob_name} was deleted from {bucket_name}"
        )

    def create_key(self, project_id, service_account_email):
        """
        Create a new HMAC key using the given project and service account.
        """
        # project_id = 'Your Google Cloud project ID'
        # service_account_email = 'Service account used to generate the HMAC key'

        storage_client = storage.Client(project=project_id)

        hmac_key, secret = storage_client.create_hmac_key(
            service_account_email=service_account_email, project_id=project_id
        )

        print(f"The base64 encoded secret is {secret}")
        print("Do not miss that secret, there is no API to recover it.")
        print("The HMAC key metadata is:")
        print(f"Service Account Email: {hmac_key.service_account_email}")
        print(f"Key ID: {hmac_key.id}")
        print(f"Access ID: {hmac_key.access_id}")
        print(f"Project ID: {hmac_key.project}")
        print(f"State: {hmac_key.state}")
        print(f"Created At: {hmac_key.time_created}")
        print(f"Updated At: {hmac_key.updated}")
        print(f"Etag: {hmac_key.etag}")

        return hmac_key

    def list_keys(self, project_id):
        """
        List all HMAC keys associated with the project.
        """
        # project_id = "Your Google Cloud project ID"

        storage_client = storage.Client(project=project_id)
        hmac_keys = storage_client.list_hmac_keys(project_id=project_id)
        print("HMAC Keys:")
        for hmac_key in hmac_keys:
            print(
                f"Service Account Email: {hmac_key.service_account_email}"
            )
            print(f"Access ID: {hmac_key.access_id}")

        return hmac_keys

    def get_key(self, access_id, project_id):
        """
        Retrieve the HMACKeyMetadata with the given access id.
        """
        # project_id = "Your Google Cloud project ID"
        # access_id = "ID of an HMAC key"

        storage_client = storage.Client(project=project_id)

        hmac_key = storage_client.get_hmac_key_metadata(
            access_id, project_id=project_id
        )

        print("The HMAC key metadata is:")
        print(f"Service Account Email: {hmac_key.service_account_email}")
        print(f"Key ID: {hmac_key.id}")
        print(f"Access ID: {hmac_key.access_id}")
        print(f"Project ID: {hmac_key.project}")
        print(f"State: {hmac_key.state}")
        print(f"Created At: {hmac_key.time_created}")
        print(f"Updated At: {hmac_key.updated}")
        print(f"Etag: {hmac_key.etag}")
        
        return hmac_key

    def deactivate_key(self, access_id, project_id):
        """
        Deactivate the HMAC key with the given access ID.
        """
        # project_id = "Your Google Cloud project ID"
        # access_id = "ID of an active HMAC key"

        storage_client = storage.Client(project=project_id)

        hmac_key = storage_client.get_hmac_key_metadata(
            access_id, project_id=project_id
        )
        hmac_key.state = "INACTIVE"
        hmac_key.update()

        print("The HMAC key is now inactive.")
        print("The HMAC key metadata is:")
        print(f"Service Account Email: {hmac_key.service_account_email}")
        print(f"Key ID: {hmac_key.id}")
        print(f"Access ID: {hmac_key.access_id}")
        print(f"Project ID: {hmac_key.project}")
        print(f"State: {hmac_key.state}")
        print(f"Created At: {hmac_key.time_created}")
        print(f"Updated At: {hmac_key.updated}")
        print(f"Etag: {hmac_key.etag}")
        
        return hmac_key

    def activate_key(self, access_id, project_id):
        """
        Activate the HMAC key with the given access ID.
        """
        # project_id = "Your Google Cloud project ID"
        # access_id = "ID of an inactive HMAC key"

        storage_client = storage.Client(project=project_id)

        hmac_key = storage_client.get_hmac_key_metadata(
            access_id, project_id=project_id
        )
        hmac_key.state = "ACTIVE"
        hmac_key.update()

        print("The HMAC key metadata is:")
        print(f"Service Account Email: {hmac_key.service_account_email}")
        print(f"Key ID: {hmac_key.id}")
        print(f"Access ID: {hmac_key.access_id}")
        print(f"Project ID: {hmac_key.project}")
        print(f"State: {hmac_key.state}")
        print(f"Created At: {hmac_key.time_created}")
        print(f"Updated At: {hmac_key.updated}")
        print(f"Etag: {hmac_key.etag}")
        
        return hmac_key

    def delete_key(self, access_id, project_id):
        """
        Delete the HMAC key with the given access ID. Key must have state INACTIVE
        in order to succeed.
        """
        # project_id = "Your Google Cloud project ID"
        # access_id = "ID of an HMAC key (must be in INACTIVE state)"

        storage_client = storage.Client(project=project_id)

        hmac_key = storage_client.get_hmac_key_metadata(
            access_id, project_id=project_id
        )
        hmac_key.delete()

        print(
            "The key is deleted, though it may still appear in list_hmac_keys()"
            " results."
        )
        