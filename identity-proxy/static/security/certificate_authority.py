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
