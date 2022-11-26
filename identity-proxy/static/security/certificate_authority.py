import os
import pathlib

import google.cloud.security.privateca_v1 as privateca_v1
from google.protobuf import duration_pb2


config_file = pathlib.Path(__file__).parent.parent.absolute()
join_sz3yan = os.path.join(config_file, "config_files/service_account.json")


class GoogleCertificateAuthority:
    def __init__(self):
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = join_sz3yan

    # --- CERTIFICATION AUTHORITY ---
    def create_certificate_authority(
        self,
        project_id: str,
        location: str,
        ca_pool_name: str,
        ca_name: str,
        common_name: str,
        organization: str,
        ca_duration: int,
    ) -> None:
        """
        Create Certificate Authority which is the root CA in the given CA Pool. This CA will be
        responsible for signing certificates within this pool.

        Args:
            project_id: project ID or project number of the Cloud project you want to use.
            location: location you want to use. For a list of locations, see: https://cloud.google.com/certificate-authority-service/docs/locations.
            ca_pool_name: set it to the CA Pool under which the CA should be created.
            ca_name: unique name for the CA.
            common_name: a title for your certificate authority.
            organization: the name of your company for your certificate authority.
            ca_duration: the validity of the certificate authority in seconds.
        """

        caServiceClient = privateca_v1.CertificateAuthorityServiceClient()

        # Set the types of Algorithm used to create a cloud KMS key.
        key_version_spec = privateca_v1.CertificateAuthority.KeyVersionSpec(
            algorithm=privateca_v1.CertificateAuthority.SignHashAlgorithm.RSA_PKCS1_4096_SHA256
        )

        # Set CA subject config.
        subject_config = privateca_v1.CertificateConfig.SubjectConfig(
            subject=privateca_v1.Subject(common_name=common_name, organization=organization)
        )

        # Set the key usage options for X.509 fields.
        x509_parameters = privateca_v1.X509Parameters(
            key_usage=privateca_v1.KeyUsage(
                base_key_usage=privateca_v1.KeyUsage.KeyUsageOptions(
                    crl_sign=True,
                    cert_sign=True,
                )
            ),
            ca_options=privateca_v1.X509Parameters.CaOptions(
                is_ca=True,
            ),
        )

        # Set certificate authority settings.
        certificate_authority = privateca_v1.CertificateAuthority(
            # CertificateAuthority.Type.SELF_SIGNED denotes that this CA is a root CA.
            type_=privateca_v1.CertificateAuthority.Type.SELF_SIGNED,
            key_spec=key_version_spec,
            config=privateca_v1.CertificateConfig(
                subject_config=subject_config,
                x509_config=x509_parameters,
            ),
            lifetime=duration_pb2.Duration(seconds=ca_duration),
        )

        ca_pool_path = caServiceClient.ca_pool_path(project_id, location, ca_pool_name)

        # Create the CertificateAuthorityRequest.
        request = privateca_v1.CreateCertificateAuthorityRequest(
            parent=ca_pool_path,
            certificate_authority_id=ca_name,
            certificate_authority=certificate_authority,
        )

        operation = caServiceClient.create_certificate_authority(request=request)
        result = operation.result()

        print("Operation result:", result)

    # --- INTERMEDIATE CERTIFICATE AUTHORITY ---
    def create_subordinate_ca(
        self,
        project_id: str,
        location: str,
        ca_pool_name: str,
        subordinate_ca_name: str,
        common_name: str,
        organization: str,
        domain: str,
        ca_duration: int,
    ) -> None:
        """
        Create Certificate Authority (CA) which is the subordinate CA in the given CA Pool.
        Args:
            project_id: project ID or project number of the Cloud project you want to use.
            location: location you want to use. For a list of locations, see: https://cloud.google.com/certificate-authority-service/docs/locations.
            ca_pool_name: set it to the CA Pool under which the CA should be created.
            subordinate_ca_name: unique name for the Subordinate CA.
            common_name: a title for your certificate authority.
            organization: the name of your company for your certificate authority.
            domain: the name of your company for your certificate authority.
            ca_duration: the validity of the certificate authority in seconds.
        """

        ca_service_client = privateca_v1.CertificateAuthorityServiceClient()

        # Set the type of Algorithm
        key_version_spec = privateca_v1.CertificateAuthority.KeyVersionSpec(
            algorithm=privateca_v1.CertificateAuthority.SignHashAlgorithm.RSA_PKCS1_4096_SHA256
        )

        # Set CA subject config.
        subject_config = privateca_v1.CertificateConfig.SubjectConfig(
            subject=privateca_v1.Subject(
                common_name=common_name, organization=organization
            ),
            # Set the fully qualified domain name.
            subject_alt_name=privateca_v1.SubjectAltNames(dns_names=[domain]),
        )

        # Set the key usage options for X.509 fields.
        x509_parameters = privateca_v1.X509Parameters(
            key_usage=privateca_v1.KeyUsage(
                base_key_usage=privateca_v1.KeyUsage.KeyUsageOptions(
                    crl_sign=True,
                    cert_sign=True,
                )
            ),
            ca_options=privateca_v1.X509Parameters.CaOptions(
                is_ca=True,
            ),
        )

        # Set certificate authority settings.
        certificate_authority = privateca_v1.CertificateAuthority(
            type_=privateca_v1.CertificateAuthority.Type.SUBORDINATE,
            key_spec=key_version_spec,
            config=privateca_v1.CertificateConfig(
                subject_config=subject_config,
                x509_config=x509_parameters,
            ),
            # Set the CA validity duration.
            lifetime=duration_pb2.Duration(seconds=ca_duration),
        )

        ca_pool_path = ca_service_client.ca_pool_path(project_id, location, ca_pool_name)

        # Create the CertificateAuthorityRequest.
        request = privateca_v1.CreateCertificateAuthorityRequest(
            parent=ca_pool_path,
            certificate_authority_id=subordinate_ca_name,
            certificate_authority=certificate_authority,
        )

        operation = ca_service_client.create_certificate_authority(request=request)
        result = operation.result()

        print(f"Operation result: {result}")

    # --- DELETE CERTIFICATE AUTHORITY ---
    def delete_certificate_authority(
        self,
        project_id: str, location: str, ca_pool_name: str, ca_name: str
    ) -> None:
        """
        Delete the Certificate Authority from the specified CA pool.
        Before deletion, the CA must be disabled and must not contain any active certificates.

        Args:
            project_id: project ID or project number of the Cloud project you want to use.
            location: location you want to use. For a list of locations, see: https://cloud.google.com/certificate-authority-service/docs/locations.
            ca_pool_name: the name of the CA pool under which the CA is present.
            ca_name: the name of the CA to be deleted.
        """

        caServiceClient = privateca_v1.CertificateAuthorityServiceClient()
        ca_path = caServiceClient.certificate_authority_path(
            project_id, location, ca_pool_name, ca_name
        )

        # Check if the CA is enabled.
        ca_state = caServiceClient.get_certificate_authority(name=ca_path).state
        print(ca_state)
        if ca_state == privateca_v1.CertificateAuthority.State.ENABLED:
            print(
                "Please disable the Certificate Authority before deletion ! Current state:",
                ca_state,
            )

        # Create the DeleteCertificateAuthorityRequest.
        # Setting the ignore_active_certificates to True will delete the CA
        # even if it contains active certificates. Care should be taken to re-anchor
        # the certificates to new CA before deleting.
        request = privateca_v1.DeleteCertificateAuthorityRequest(
            name=ca_path, ignore_active_certificates=False
        )

        # Delete the Certificate Authority.
        operation = caServiceClient.delete_certificate_authority(request=request)
        result = operation.result()

        print("Operation result", result)

        # Get the current CA state.
        ca_state = caServiceClient.get_certificate_authority(name=ca_path).state

        # Check if the CA has been deleted.
        if ca_state == privateca_v1.CertificateAuthority.State.DELETED:
            print("Successfully deleted Certificate Authority:", ca_name)
        else:
            print(
                "Unable to delete Certificate Authority. Please try again ! Current state:",
                ca_state,
            )


    # --- DISABLE CERTIFICATE AUTHORITY ---
    def disable_certificate_authority(
        self,
        project_id: str, location: str, ca_pool_name: str, ca_name: str
    ) -> None:
        """
        Disable a Certificate Authority which is present in the given CA pool.

        Args:
            project_id: project ID or project number of the Cloud project you want to use.
            location: location you want to use. For a list of locations, see: https://cloud.google.com/certificate-authority-service/docs/locations.
            ca_pool_name: the name of the CA pool under which the CA is present.
            ca_name: the name of the CA to be disabled.
        """

        caServiceClient = privateca_v1.CertificateAuthorityServiceClient()
        ca_path = caServiceClient.certificate_authority_path(
            project_id, location, ca_pool_name, ca_name
        )

        # Create the Disable Certificate Authority Request.
        request = privateca_v1.DisableCertificateAuthorityRequest(name=ca_path)

        # Disable the Certificate Authority.
        operation = caServiceClient.disable_certificate_authority(request=request)
        result = operation.result()

        print("Operation result:", result)

        # Get the current CA state.
        ca_state = caServiceClient.get_certificate_authority(name=ca_path).state

        # Check if the CA is disabled.
        if ca_state == privateca_v1.CertificateAuthority.State.DISABLED:
            print("Disabled Certificate Authority:", ca_name)
        else:
            print("Cannot disable the Certificate Authority ! Current CA State:", ca_state)

    # --- ENABLE CERTIFICATE AUTHORITY ---
    def enable_certificate_authority(
        self,
        project_id: str, location: str, ca_pool_name: str, ca_name: str
    ) -> None:
        """
        Enable the Certificate Authority present in the given ca pool.
        CA cannot be enabled if it has been already deleted.

        Args:
            project_id: project ID or project number of the Cloud project you want to use.
            location: location you want to use. For a list of locations, see: https://cloud.google.com/certificate-authority-service/docs/locations.
            ca_pool_name: the name of the CA pool under which the CA is present.
            ca_name: the name of the CA to be enabled.
        """

        caServiceClient = privateca_v1.CertificateAuthorityServiceClient()
        ca_path = caServiceClient.certificate_authority_path(
            project_id, location, ca_pool_name, ca_name
        )

        # Create the Enable Certificate Authority Request.
        request = privateca_v1.EnableCertificateAuthorityRequest(
            name=ca_path,
        )

        # Enable the Certificate Authority.
        operation = caServiceClient.enable_certificate_authority(request=request)
        result = operation.result()

        print("Operation result:", result)

        # Get the current CA state.
        ca_state = caServiceClient.get_certificate_authority(name=ca_path).state

        # Check if the CA is enabled.
        if ca_state == privateca_v1.CertificateAuthority.State.ENABLED:
            print("Enabled Certificate Authority:", ca_name)
        else:
            print("Cannot enable the Certificate Authority ! Current CA State:", ca_state)

    # --- LIST CERTIFICATE AUTHORITY ---
    def list_certificate_authorities(
        self,
        project_id: str, location: str, ca_pool_name: str
    ) -> None:
        """
        List all Certificate authorities present in the given CA Pool.

        Args:
            project_id: project ID or project number of the Cloud project you want to use.
            location: location you want to use. For a list of locations, see: https://cloud.google.com/certificate-authority-service/docs/locations.
            ca_pool_name: the name of the CA pool under which the CAs to be listed are present.
        """

        caServiceClient = privateca_v1.CertificateAuthorityServiceClient()

        ca_pool_path = caServiceClient.ca_pool_path(project_id, location, ca_pool_name)

        # List the CA name and its corresponding state.
        for ca in caServiceClient.list_certificate_authorities(parent=ca_pool_path):
            print(ca.name, "is", ca.state)


class Certificates:
    def __init__(self):
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = join_sz3yan

    # --- CREATE CERTIFICATE SIGNING REQUEST ---
    def create_certificate_csr(
        self,
        project_id: str,
        location: str,
        ca_pool_name: str,
        ca_name: str,
        certificate_name: str,
        certificate_lifetime: int,
        pem_csr: str,
    ) -> None:
        """
        Create a Certificate which is issued by the specified Certificate Authority (CA).
        The certificate details and the public key is provided as a Certificate Signing Request (CSR).
        Args:
            project_id: project ID or project number of the Cloud project you want to use.
            location: location you want to use. For a list of locations, see: https://cloud.google.com/certificate-authority-service/docs/locations.
            ca_pool_name: set a unique name for the CA pool.
            ca_name: the name of the certificate authority to sign the CSR.
            certificate_name: set a unique name for the certificate.
            certificate_lifetime: the validity of the certificate in seconds.
            pem_csr: set the Certificate Issuing Request in the pem encoded format.
        """

        ca_service_client = privateca_v1.CertificateAuthorityServiceClient()

        # The public key used to sign the certificate can be generated using any crypto library/framework.
        # Also you can use Cloud KMS to retrieve an already created public key.
        # For more info, see: https://cloud.google.com/kms/docs/retrieve-public-key.

        # Create certificate with CSR.
        # The pem_csr contains the public key and the domain details required.
        certificate = privateca_v1.Certificate(
            pem_csr=pem_csr,
            lifetime=duration_pb2.Duration(seconds=certificate_lifetime),
        )

        # Create the Certificate Request.
        # Set the CA which is responsible for creating the certificate with the provided CSR.
        request = privateca_v1.CreateCertificateRequest(
            parent=ca_service_client.ca_pool_path(project_id, location, ca_pool_name),
            certificate_id=certificate_name,
            certificate=certificate,
            issuing_certificate_authority_id=ca_name,
        )
        response = ca_service_client.create_certificate(request=request)

        print(f"Certificate created successfully: {response.name}")

        # Get the signed certificate and the issuer chain list.
        print(f"Signed certificate: {response.pem_certificate}")
        print(f"Issuer chain list: {response.pem_certificate_chain}")

    # --- LIST CERTIFICATE ---
    def list_certificates(
        self,
        project_id: str,
        location: str,
        ca_pool_name: str,
    ) -> None:
        """
        List Certificates present in the given CA pool.

        Args:
            project_id: project ID or project number of the Cloud project you want to use.
            location: location you want to use. For a list of locations, see: https://cloud.google.com/certificate-authority-service/docs/locations.
            ca_pool_name: name of the CA pool which contains the certificates to be listed.
        """

        caServiceClient = privateca_v1.CertificateAuthorityServiceClient()

        ca_pool_path = caServiceClient.ca_pool_path(project_id, location, ca_pool_name)

        # Retrieve and print the certificate names.
        print(f"Available certificates in CA pool {ca_pool_name}:")
        for certificate in caServiceClient.list_certificates(parent=ca_pool_path):
            print(certificate.name)

    # --- REVOKE CERTIFICATE ---
    def revoke_certificate(
        self,
        project_id: str,
        location: str,
        ca_pool_name: str,
        certificate_name: str,
    ) -> None:
        """
        Revoke an issued certificate. Once revoked, the certificate will become invalid and will expire post its lifetime.

        Args:
            project_id: project ID or project number of the Cloud project you want to use.
            location: location you want to use. For a list of locations, see: https://cloud.google.com/certificate-authority-service/docs/locations.
            ca_pool_name: name for the CA pool which contains the certificate.
            certificate_name: name of the certificate to be revoked.
        """

        caServiceClient = privateca_v1.CertificateAuthorityServiceClient()

        # Create Certificate Path.
        certificate_path = caServiceClient.certificate_path(
            project_id, location, ca_pool_name, certificate_name
        )

        # Create Revoke Certificate Request and specify the appropriate revocation reason.
        request = privateca_v1.RevokeCertificateRequest(
            name=certificate_path, reason=privateca_v1.RevocationReason.PRIVILEGE_WITHDRAWN
        )
        result = caServiceClient.revoke_certificate(request=request)

        print("Certificate revoke result:", result)

    # --- GET CERTIFICATE ---
    def get_certificate(
        self,
        project_id: str,
        location: str,
        ca_pool_name: str,
        certificate_name: str,
    ) -> None:
        """
        Get the certificate details.

        Args:
            project_id: project ID or project number of the Cloud project you want to use.
            location: location you want to use. For a list of locations, see: https://cloud.google.com/certificate-authority-service/docs/locations.
            ca_pool_name: name for the CA pool which contains the certificate.
            certificate_name: name of the certificate to be revoked.
        """

        caServiceClient = privateca_v1.CertificateAuthorityServiceClient()

        # Create Certificate Path.
        certificate_path = caServiceClient.certificate_path(
            project_id, location, ca_pool_name, certificate_name
        )

        # Get the certificate details.
        certificate = caServiceClient.get_certificate(name=certificate_path)

        print("Certificate details:", certificate)


# import argparse
# import gzip
# import io
# import zipfile

# from cryptography import exceptions
# from cryptography import x509
# from cryptography.hazmat import backends
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import padding
# import pem
# import requests

# ATTESTATION_SIGNATURE_LEN = 256

# MANUFACTURER_CERT_URL = 'https://www.marvell.com/content/dam/marvell/en/public-collateral/security-solutions/liquid_security_certificate.zip'

# # <Name(C=US,ST=California,L=San Jose,O=Cavium\, Inc.,OU=LiquidSecurity,CN=localca.liquidsecurity.cavium.com)>
# MANUFACTURER_CERT_SUBJECT_BYTES = (
#     b'0\x81\x911\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08'
#     b'\x0c\nCalifornia1\x110\x0f\x06\x03U\x04\x07\x0c\x08San Jose1\x150\x13\x06'
#     b'\x03U\x04\n\x0c\x0cCavium, Inc.1\x170\x15\x06\x03U\x04\x0b\x0c\x0e'
#     b'LiquidSecurity1*0(\x06\x03U\x04\x03\x0c!localca.liquidsecurity.cavium.com'
# )

# # The owner root cert can be obtained from
# # 'https://www.gstatic.com/cloudhsm/roots/global_1498867200.pem'
# OWNER_ROOT_CERT_PEM = """Certificate:
#     Data:
#         Version: 3 (0x2)
#         Serial Number: 3 (0x3)
#         Signature Algorithm: sha256WithRSAEncryption
#         Issuer: C = US, ST = CA, L = Mountain View, O = Google Inc, CN = Hawksbill Root v1 prod
#         Validity
#             Not Before: Jul  1 00:00:00 2017 GMT
#             Not After : Jan  1 00:00:00 2030 GMT
#         Subject: C = US, ST = CA, L = Mountain View, O = Google Inc, CN = Hawksbill Root v1 prod
#         Subject Public Key Info:
#             Public Key Algorithm: rsaEncryption
#                 RSA Public-Key: (2048 bit)
#                 Modulus:
#                     00:ac:2e:a8:62:89:21:a0:70:92:df:b0:8e:c3:93:
#                     4d:26:38:db:a5:a2:5f:6b:1e:6d:a8:6c:2c:83:d6:
#                     5b:9a:f8:02:a0:f8:b0:16:fb:5c:da:b9:9b:b9:8b:
#                     4d:bc:15:26:e0:0e:4f:2f:b5:20:43:1c:31:7e:5e:
#                     c1:67:a9:36:c8:19:5e:c2:b5:a8:b6:96:76:90:7b:
#                     55:15:4d:53:16:10:f0:62:d5:d8:98:19:c7:9e:0e:
#                     b2:69:26:a3:f3:d9:a5:d3:70:88:21:ac:62:12:7b:
#                     2a:be:20:2e:33:db:9b:90:a7:b1:bf:0f:c0:11:7a:
#                     c2:98:a9:8c:4d:36:a7:1f:66:53:08:93:4b:3a:12:
#                     1e:1a:3f:2b:c2:5d:8b:4b:97:d4:17:0f:41:83:27:
#                     a9:f3:e0:d9:82:f8:5c:37:d4:1e:5d:e4:a8:3d:59:
#                     7c:43:64:e6:02:d7:35:39:f4:95:db:77:1c:73:78:
#                     2f:c4:26:8d:64:d4:01:e0:86:da:3f:27:c7:9d:bd:
#                     32:25:e4:d4:34:6a:13:87:2a:85:19:ce:18:43:46:
#                     c5:41:8a:81:66:ca:65:6e:c1:a1:ce:71:74:d4:b0:
#                     77:b7:35:39:0d:c9:e2:c8:7e:81:69:b1:04:38:5d:
#                     c1:fd:92:33:ba:ed:85:d3:91:d0:96:78:d6:30:fc:
#                     56:19
#                 Exponent: 65537 (0x10001)
#         X509v3 extensions:
#             X509v3 Basic Constraints: critical
#                 CA:TRUE
#             X509v3 Key Usage: critical
#                 Digital Signature, Certificate Sign, CRL Sign
#             X509v3 Subject Key Identifier:
#                 31:E8:52:DF:E1:49:F8:12:7B:7C:6E:E7:4E:91:7A:97:75:BC:A8:AE
#     Signature Algorithm: sha256WithRSAEncryption
#          8f:12:8e:8e:7a:fb:59:82:a8:0f:e6:be:b8:09:5d:17:c8:8e:
#          c1:3a:c7:a4:52:d4:0d:2e:ac:a8:5c:b1:f4:52:ee:b7:c4:25:
#          9a:2a:32:fc:91:3d:ba:29:9a:ed:c8:de:1f:75:39:54:16:d1:
#          72:74:e0:95:a0:e2:41:36:9c:f8:95:c2:21:10:29:12:5f:4d:
#          d1:b0:e1:a1:5b:c5:79:3c:d1:23:c9:c9:74:c2:42:58:fa:1b:
#          35:75:77:30:7a:58:b2:07:e0:cd:ec:21:e2:51:54:59:08:21:
#          be:c7:05:df:6e:55:81:21:0d:d1:ad:61:81:77:27:3e:bd:39:
#          81:df:bd:91:32:3d:cc:5d:eb:de:fc:a7:73:26:2f:cd:88:a7:
#          70:65:f4:35:06:b3:d6:02:56:e1:ba:e6:d5:6f:b0:4d:b5:95:
#          cb:c6:34:a3:a7:35:79:99:bb:bf:cb:07:a0:d4:a0:de:f2:2c:
#          e8:9b:27:43:c6:c0:5c:ae:62:da:a3:bf:01:76:50:bb:6e:70:
#          1f:56:8f:41:cb:7c:41:d1:b0:c7:62:41:b2:31:23:99:6a:47:
#          b8:10:c0:5c:f0:9e:b0:3e:5c:bb:d5:33:cc:38:1c:a5:dc:26:
#          8b:b5:e2:76:5e:f8:92:3d:df:fc:78:2b:39:e8:a6:45:d3:9b:
#          f2:51:b9:fc
# -----BEGIN CERTIFICATE-----
# MIIDjTCCAnWgAwIBAgIBAzANBgkqhkiG9w0BAQsFADBoMQswCQYDVQQGEwJVUzEL
# MAkGA1UECAwCQ0ExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxEzARBgNVBAoMCkdv
# b2dsZSBJbmMxHzAdBgNVBAMMFkhhd2tzYmlsbCBSb290IHYxIHByb2QwHhcNMTcw
# NzAxMDAwMDAwWhcNMzAwMTAxMDAwMDAwWjBoMQswCQYDVQQGEwJVUzELMAkGA1UE
# CAwCQ0ExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxEzARBgNVBAoMCkdvb2dsZSBJ
# bmMxHzAdBgNVBAMMFkhhd2tzYmlsbCBSb290IHYxIHByb2QwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCsLqhiiSGgcJLfsI7Dk00mONulol9rHm2obCyD
# 1lua+AKg+LAW+1zauZu5i028FSbgDk8vtSBDHDF+XsFnqTbIGV7Ctai2lnaQe1UV
# TVMWEPBi1diYGceeDrJpJqPz2aXTcIghrGISeyq+IC4z25uQp7G/D8AResKYqYxN
# NqcfZlMIk0s6Eh4aPyvCXYtLl9QXD0GDJ6nz4NmC+Fw31B5d5Kg9WXxDZOYC1zU5
# 9JXbdxxzeC/EJo1k1AHghto/J8edvTIl5NQ0ahOHKoUZzhhDRsVBioFmymVuwaHO
# cXTUsHe3NTkNyeLIfoFpsQQ4XcH9kjO67YXTkdCWeNYw/FYZAgMBAAGjQjBAMA8G
# A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBQx6FLf4Un4
# Ent8budOkXqXdbyorjANBgkqhkiG9w0BAQsFAAOCAQEAjxKOjnr7WYKoD+a+uAld
# F8iOwTrHpFLUDS6sqFyx9FLut8Qlmioy/JE9uima7cjeH3U5VBbRcnTglaDiQTac
# +JXCIRApEl9N0bDhoVvFeTzRI8nJdMJCWPobNXV3MHpYsgfgzewh4lFUWQghvscF
# 325VgSEN0a1hgXcnPr05gd+9kTI9zF3r3vyncyYvzYincGX0NQaz1gJW4brm1W+w
# TbWVy8Y0o6c1eZm7v8sHoNSg3vIs6JsnQ8bAXK5i2qO/AXZQu25wH1aPQct8QdGw
# x2JBsjEjmWpHuBDAXPCesD5cu9UzzDgcpdwmi7Xidl74kj3f/HgrOeimRdOb8lG5
# /A==
# -----END CERTIFICATE-----
# """


# def get_manufacturer_root_certificate():
#     """Gets the manufacturer root certificate."""
#     resp = requests.get(MANUFACTURER_CERT_URL)
#     tmp_file = io.BytesIO(resp.content)
#     zip_file = zipfile.ZipFile(tmp_file)
#     with zip_file.open('liquid_security_certificate.crt') as f:
#         return x509.load_pem_x509_certificate(f.read(), backends.default_backend())


# def get_owner_root_certificate():
#     """Gets the owner root certificate."""
#     return x509.load_pem_x509_certificate(
#         OWNER_ROOT_CERT_PEM.encode('utf-8'), backends.default_backend())


# def verify_certificate(signing_cert, issued_cert):
#     """Verifies the signing_cert issued the issued_cert.

#     Args:
#         signing_cert: The certificate used to verify the issued certificate's
#           signature.
#         issued_cert: The issued certificate.

#     Returns:
#         True if the signing_cert issued the issued_cert.
#     """
#     if signing_cert.subject != issued_cert.issuer:
#         return False
#     try:
#         signing_cert.public_key().verify(issued_cert.signature,
#                                          issued_cert.tbs_certificate_bytes,
#                                          padding.PKCS1v15(),
#                                          issued_cert.signature_hash_algorithm)
#         return True
#     except exceptions.InvalidSignature:
#         return False
#     return False


# def get_issued_certificate(issuer_cert,
#                            untrusted_certs,
#                            predicate=lambda _: True):
#     """Finds an issued certificates issued by an issuer certificate.

#     The issued certificate is removed from the set of untrusted certificates.

#     Args:
#         issuer_cert: The issuer certificate.
#         untrusted_certs: A set of untrusted certificates.
#         predicate: An additional condition for the issued certificate.

#     Returns:
#         A certificate within the set of untrusted certificates that was issued
#         by the issuer certificate and matches the predicate.
#     """
#     for cert in untrusted_certs:
#         if verify_certificate(issuer_cert, cert) and predicate(cert):
#             untrusted_certs.remove(cert)
#             return cert
#     return None


# def verify_attestation(cert, attestation):
#     """Verifies that the certificate signed the attestation.

#     Args:
#         cert: The certificate used to verify the attestation.
#         attestation: The attestation to verify.

#     Returns:
#     True if the certificate verified the attestation.
#     """
#     data = attestation[:-ATTESTATION_SIGNATURE_LEN]
#     signature = attestation[-ATTESTATION_SIGNATURE_LEN:]
#     try:
#         cert.public_key().verify(signature, data, padding.PKCS1v15(),
#                                  hashes.SHA256())
#         return True
#     except exceptions.InvalidSignature:
#         return False
#     return False


# def verify(certs_file, attestation_file):
#     """Verifies that the certificate chains are valid.

#     Args:
#         certs_file: The certificate chains filename.
#         attestation_file: The attestation filename.

#     Returns:
#         True if the certificate chains are valid.
#     """
#     mfr_root_cert = get_manufacturer_root_certificate()
#     if (mfr_root_cert.subject.public_bytes(backends.default_backend()) !=
#             MANUFACTURER_CERT_SUBJECT_BYTES):
#         return False

#     untrusted_certs_pem = pem.parse_file(certs_file)
#     untrusted_certs = {
#         x509.load_pem_x509_certificate(
#             str(cert_pem).encode('utf-8'), backends.default_backend())
#         for cert_pem in untrusted_certs_pem
#     }

#     # Build the manufacturer certificate chain.
#     mfr_card_cert = get_issued_certificate(mfr_root_cert, untrusted_certs)
#     mfr_partition_cert = get_issued_certificate(mfr_card_cert, untrusted_certs)
#     if not mfr_card_cert or not mfr_partition_cert:
#         print('Invalid HSM manufacturer certificate chain.')
#         return False
#     print('Successfully built HSM manufacturer certificate chain.')

#     owner_root_cert = get_owner_root_certificate()

#     # Build the owner card certificate chain.
#     def _check_card_pub_key(cert):
#         cert_pub_key_bytes = cert.public_key().public_bytes(
#             serialization.Encoding.DER,
#             serialization.PublicFormat.SubjectPublicKeyInfo)
#         mfr_card_pub_key_bytes = mfr_card_cert.public_key().public_bytes(
#             serialization.Encoding.DER,
#             serialization.PublicFormat.SubjectPublicKeyInfo)
#         return cert_pub_key_bytes == mfr_card_pub_key_bytes

#     owner_card_cert = get_issued_certificate(
#         owner_root_cert, untrusted_certs, predicate=_check_card_pub_key)

#     # Build the owner partition certificate chain.
#     def _check_partition_pub_key(cert):
#         cert_pub_key_bytes = cert.public_key().public_bytes(
#             serialization.Encoding.PEM,
#             serialization.PublicFormat.SubjectPublicKeyInfo)
#         mfr_partition_pub_key_bytes = mfr_partition_cert.public_key().public_bytes(
#             serialization.Encoding.PEM,
#             serialization.PublicFormat.SubjectPublicKeyInfo)
#         return cert_pub_key_bytes == mfr_partition_pub_key_bytes

#     owner_partition_cert = get_issued_certificate(
#         owner_root_cert, untrusted_certs, predicate=_check_partition_pub_key)

#     if not owner_card_cert or not owner_partition_cert or untrusted_certs:
#         print('Invalid HSM owner certificate chain.')
#         return False
#     print('Successfully built HSM owner certificate chain.')

#     with gzip.open(attestation_file, 'rb') as f:
#         attestation = f.read()
#         return (verify_attestation(mfr_partition_cert, attestation) and
#                 verify_attestation(owner_partition_cert, attestation))


# if __name__ == '__main__':
#     parser = argparse.ArgumentParser(
#         description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
#     parser.add_argument(
#         '--certificates', help='The certificate chains filename.')
#     parser.add_argument('--attestation', help='The attestation filename.')

#     args = parser.parse_args()

#     if verify(args.certificates, args.attestation):
#         print('The attestation has been verified.')
#     else:
#         print('The attestation could not be verified.')

