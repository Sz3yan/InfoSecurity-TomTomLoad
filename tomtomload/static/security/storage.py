import os
import pathlib


from google.cloud import storage


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

        print(f"Blob: {blob.name}")
        print(f"Bucket: {blob.bucket.name}")
        print(f"Storage class: {blob.storage_class}")
        print(f"ID: {blob.id}")
        print(f"Size: {blob.size} bytes")
        print(f"Updated: {blob.updated}")
        print(f"Generation: {blob.generation}")
        print(f"Metageneration: {blob.metageneration}")
        print(f"Etag: {blob.etag}")
        print(f"Owner: {blob.owner}")
        print(f"Component count: {blob.component_count}")
        print(f"Crc32c: {blob.crc32c}")
        print(f"md5_hash: {blob.md5_hash}")
        print(f"Cache-control: {blob.cache_control}")
        print(f"Content-type: {blob.content_type}")
        print(f"Content-disposition: {blob.content_disposition}")
        print(f"Content-encoding: {blob.content_encoding}")
        print(f"Content-language: {blob.content_language}")
        print(f"Metadata: {blob.metadata}")
        print(f"Medialink: {blob.media_link}")
        print(f"Custom Time: {blob.custom_time}")
        print("Temporary hold: ", "enabled" if blob.temporary_hold else "disabled")
        print(
            "Event based hold: ",
            "enabled" if blob.event_based_hold else "disabled",
        )
        if blob.retention_expiration_time:
            print(
                f"retentionExpirationTime: {blob.retention_expiration_time}"
            )

    def set_blob_metadata(self, bucket_name, blob_name):
        """Set a blob's metadata."""
        # bucket_name = 'your-bucket-name'
        # blob_name = 'your-object-name'

        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.get_blob(blob_name)
        metadata = {'color': 'Red', 'name': 'Test'}
        blob.metadata = metadata
        blob.patch()

        print(f"The metadata for the blob {blob.name} is {blob.metadata}")


        