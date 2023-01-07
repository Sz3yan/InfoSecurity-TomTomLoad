import os
import pathlib


from google.cloud import storage


config_file = pathlib.Path(__file__).parent.parent.absolute()
join_sz3yan = os.path.join(config_file, "config_files/service_account.json")


class GoogleCloudStorage:
    def __init__(self):
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = join_sz3yan

    def create_bucket_class_location(self, bucket_name):

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

        storage_client = storage.Client()

        bucket = storage_client.bucket(bucket_name)

        blob = bucket.blob(source_blob_name)
        blob.download_to_filename(destination_file_name)

        print(
            "Downloaded storage object {} from bucket {} to local file {}.".format(
                source_blob_name, bucket_name, destination_file_name
            )
        )

    def upload_blob(self, bucket_name, source_file_name, destination_blob_name):

        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(destination_blob_name)

        blob.upload_from_filename(source_file_name)

        print(
            f"File {source_file_name} uploaded to {destination_blob_name}."
        )

    def delete_blob(self, bucket_name, blob_name):

        storage_client = storage.Client()

        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        blob.delete()

        print(f"Blob {blob_name} deleted.")
