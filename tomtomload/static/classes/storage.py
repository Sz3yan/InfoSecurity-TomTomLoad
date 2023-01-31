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
