import os
import pathlib
import OpenSSL
from OpenSSL import crypto

config_file = pathlib.Path(__file__).parent.parent.absolute()
certificate_directory = os.path.join(config_file, "config_files/certificates")


class CertificateAuthority:
    def __post_init__(self) -> None:
        os.mkdir(certificate_directory)

    def create_certificate_authority(
            self,
            ca_name: str,
            ca_duration: int,
    ) -> None:
        """
        Create Certificate Authority which is the root CA in the given CA Pool. This CA will be
        responsible for signing certificates within this pool.

        Args:
            ca_name: unique name for the CA.
            ca_duration: the validity of the certificate authority in seconds.
        """

        # generate a CA private key
        CAkey = crypto.PKey()
        CAkey.generate_key(type=crypto.TYPE_RSA, bits=4096)

        # create a CA certificate
        ca = crypto.X509()
        ca.set_version(3)
        ca.set_serial_number(1000)
        ca.get_subject().CN = ca_name
        ca.gmtime_adj_notBefore(0)
        ca.gmtime_adj_notAfter(ca_duration)
        ca.set_issuer(ca.get_subject())
        ca.set_pubkey(key)
        ca.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
            crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca),
        ])
        ca.sign(key, "sha256")

        # save the CA private key and certificate to files
        # This will create a CA private key and certificate
        # that you can use to sign certificate requests.
        # You can then use the CA certificate to verify the authenticity
        # of signed certificates.
        with open("ca.key", "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        with open("ca.crt", "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca))

    def create_subordinate_ca(
            self,
            subordinate_ca_name: str,
            ca_duration: int,
    ) -> None:
        """
        Create Certificate Authority (CA) which is the subordinate CA in the given CA Pool.
        Args:
            subordinate_ca_name: unique name for the Subordinate CA.
            ca_duration: the validity of the certificate authority in seconds.
        """

        with open("parent_ca.key", "rb") as f:
            root_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

        with open("parent_ca.crt", "rb") as f:
            root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        # generate subordinate CA private key
        subordinate_key = crypto.PKey()
        subordinate_key.generate_key(type=crypto.TYPE_RSA, bits=4096)

        # Create a subordinate CA certificate request
        req = crypto.X509Req()
        subject = req.get_subject()
        subject.CN = subordinate_ca_name
        req.set_pubkey(key)
        req.sign(key, "sha256")

        # Create a certificate extension for the certificate request that indicates that it is a subordinate CA
        ext = crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0")
        req.add_extensions([ext])

        # Sign the subordinate CA certificate request with the parent CA
        cert = crypto.X509()
        cert.set_subject(req.get_subject())
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(ca_duration)
        cert.set_issuer(root_cert.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.add_extensions(req.get_extensions())
        cert.sign(root_key, "sha256")

        # Save the subordinate CA private key and certificate to files
        with open("sub_ca.key", "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        with open("sub_ca.crt", "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    def revoke_subordinate_ca(self) -> None:
        """
        Revoke the Certificate Authority.

        """

        # Load the subordinate CA certificate
        with open("sub_ca.crt", "rb") as f:
            sub_ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        # Load the parent CA private key and certificate
        with open("parent_ca.key", "rb") as f:
            parent_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

        with open("parent_ca.crt", "rb") as f:
            parent_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        # Create a certificate revocation list (CRL) with the revoked subordinate CA certificate
        crl = crypto.CRL()
        crl.set_lastUpdate(sub_ca_cert.get_notBefore())
        crl.set_nextUpdate(sub_ca_cert.get_notAfter())
        crl.add_revoked(sub_ca_cert)
        crl.sign(parent_key, "sha256")

        with open("crl.pem", "wb") as f:
            f.write(crypto.dump_crl(crypto.FILETYPE_PEM, crl))

    def load_crl(self) -> None:
        """
        Load the Certificate Revocation List (CRL) from the file system.
        """

        with open("crl.pem", "rb") as f:
            crl = crypto.load_crl(crypto.FILETYPE_PEM, f.read())

        # Verify the CRL
        store = crypto.X509Store()
        store.add_crl(crl)
        store.set_flags(crypto.X509StoreFlags.CRL_CHECK)
        store_ctx = crypto.X509StoreContext(store, crl)
        store_ctx.verify_certificate()

    def create_certificate_from_csr():
        """
        Create a certificate using the given CA.
        """

        # load the CSR and the CA private key and certificate
        with open("csr.pem", "rb") as f:
            req = crypto.load_certificate_request(crypto.FILETYPE_PEM, f.read())

        with open("ca.key", "rb") as f:
            ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

        with open("ca.crt", "rb") as f:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        # Create a certificate and sign it with the CA
        cert = crypto.X509()
        cert.set_subject(req.get_subject())
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        cert.set_issuer(ca_cert.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.sign(ca_key, "sha256")

        # Save the certificate to a file
        with open("cert.pem", "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    def verify_certificate(self) -> None:
        """
        Verify the certificate.
        """

        # Load the CA certificate
        with open("ca.crt", "rb") as f:
            ca = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        # Load the certificate
        with open("cert.pem", "rb") as f:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        # Verify the certificate
        store = crypto.X509Store()
        store.add_cert(ca)
        store_ctx = crypto.X509StoreContext(store, cert)
        store_ctx.verify_certificate()


class Certificates:
    def create_certificate_csr(
            self,
            ca_name: str,
            certificate_lifetime: int,
    ) -> None:
        """
        Create a Certificate which is issued by the specified Certificate Authority (CA).
        The certificate details and the public key is provided as a Certificate Signing Request (CSR).
        Args:
            ca_name: the name of the certificate authority to sign the CSR.
            certificate_lifetime: the validity of the certificate in seconds.
        """

        # generate private key
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)

        # create a certificate request
        req = crypto.X509Req()
        subject = req.get_subject()
        subject.CN = ca_name
        req.set_pubkey(key)
        req.gmtime_adj_notBefore(0)
        req.gmtime_adj_notAfter(certificate_lifetime)
        req.sign(key, "sha256")

        # Save the private key and request to files
        with open("key.pem", "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        with open("csr.pem", "wb") as f:
            f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))

    def revoke_certificate(self) -> None:
        """
        Revoke an issued certificate. Once revoked, the certificate will become invalid and will expire post its lifetime.

        """

        # Load the certificate and the Certificate Authority (CA) private key and certificate
        with open("cert.crt", "rb") as f:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        with open("ca.key", "rb") as f:
            ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

        with open("ca.crt", "rb") as f:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        # Create a certificate revocation list (CRL) with the revoked certificate
        crl = crypto.CRL()
        crl.set_lastUpdate(cert.get_notBefore())
        crl.set_nextUpdate(cert.get_notAfter())
        crl.add_revoked(cert)
        crl.sign(ca_key, "sha256")

        # Save the CRL to a file
        with open("crl.pem", "wb") as f:
            f.write(crypto.dump_crl(crypto.FILETYPE_PEM, crl))

    def get_certificates(self) -> None:
        """
        Get the certificate details.

        """

        # load the CA certificate
        with open("ca.crt", "rb") as f:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        # Enumerate all the certificate files in a directory
        cert_dir = "certs"
        cert_files = [os.path.join(cert_dir, f) for f in os.listdir(cert_dir) if f.endswith(".crt")]

        # iterate over the certificate files and check if they are signed by the CA
        for cert_file in cert_files:
            with open(cert_file, "rb") as f:
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
                if cert.verify(ca_cert.get_pubkey()):
                    print(f"{cert_file} is signed by {ca_cert.get_subject().CN}")
                else:
                    print(f"{cert_file} is not signed by {ca_cert.get_subject().CN}")
