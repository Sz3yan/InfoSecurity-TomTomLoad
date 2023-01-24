import os
import pathlib
import shutil
import uuid

from OpenSSL import crypto
from OpenSSL.crypto import PKey, X509, X509Extension, X509Req
from prettytable import PrettyTable


# -----------------  START OF BASIC SETUP  ----------------- #

# -----------------  START OF FILE DIRECTORY SETUP  ----------------- #

config_file = pathlib.Path(__file__).parent.parent.absolute()
certificate_directory = os.path.join(config_file, "config_files/certificates")

if not os.path.exists(certificate_directory):
    os.makedirs(certificate_directory)

to_tomtomload_path = pathlib.Path(__file__).parent.parent.parent.parent.absolute()
tomtomload_configfiles = os.path.join(to_tomtomload_path, "tomtomload/static/config_files/")

# -----------------  END OF FILE DIRECTORY SETUP  ----------------- #

# -----------------  START OF CERTIFICATE SETUP  ----------------- #

ca_certificate = os.path.join(certificate_directory, "IDENTITYPROXY.crt")
ca_key = os.path.join(certificate_directory, "IDENTITYPROXY.key")
sub_certificate = os.path.join(certificate_directory, "SUBORDINATE_IDENTITY_PROXY.crt")
sub_key = os.path.join(certificate_directory, "SUBORDINATE_IDENTITY_PROXY.key")

# -----------------  END OF CERTIFICATE SETUP  ----------------- #

# -----------------  END OF BASIC SETUP  ----------------- #


# -----------------  START OF CERTIFICATE AUTHORITY  ----------------- #
class CertificateAuthority:

    def create_certificate_authority(self, ca_name: str, ca_duration: int) -> None:
        """

        Create Certificate Authority which is the root CA who will be
        responsible for signing certificates for identity-proxy and tomtomload.

        Args:
            ca_name: unique name for the CA.
            ca_duration: the validity of the certificate authority in seconds.

        """

        CAkey = crypto.PKey()
        CAkey.generate_key(type=crypto.TYPE_RSA, bits=4096)

        ca = crypto.X509()
        ca.set_version(3)
        ca.set_serial_number(uuid.uuid4().int)
        ca.get_subject().CN = ca_name
        ca.gmtime_adj_notBefore(0)
        ca.gmtime_adj_notAfter(ca_duration)
        ca.set_issuer(ca.get_subject())
        ca.set_pubkey(CAkey)
        ca.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
            crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca),
        ])
        ca.sign(CAkey, "sha256")

        ca_certificate = os.path.join(certificate_directory, f"{ca_name}.crt")
        ca_key = os.path.join(certificate_directory, f"{ca_name}.key")

        with open(ca_key, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, CAkey))

        with open(ca_certificate, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca))

        print(f"Certificate Authority - {ca_key} created successfully.")


    def create_subordinate_ca(self, subordinate_ca_name: str, ca_duration: int) -> None:
        """

        Create a subordinate CA which will be responsible for signing certificates for
        the identity-proxy and tomtomload.

        Args:
            subordinate_ca_name: unique name for the subordinate CA.
            ca_duration: the validity of the certificate authority in seconds.

        """

        with open(ca_key, "rb") as f:
            root_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

        with open(ca_certificate, "rb") as f:
            root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        subordinate_key = crypto.PKey()
        subordinate_key.generate_key(type=crypto.TYPE_RSA, bits=4096)

        req = crypto.X509Req()
        subject = req.get_subject()
        subject.CN = subordinate_ca_name
        req.set_pubkey(subordinate_key)
        req.sign(subordinate_key, "sha256")

        ext = crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0")
        req.add_extensions([ext])

        cert = crypto.X509()
        cert.set_subject(req.get_subject())
        cert.set_serial_number(uuid.uuid4().int)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(ca_duration)
        cert.set_issuer(root_cert.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.add_extensions(req.get_extensions())
        cert.sign(root_key, "sha256")

        sub_certificate = os.path.join(certificate_directory, f"{subordinate_ca_name}.crt")
        sub_key = os.path.join(certificate_directory, f"{subordinate_ca_name}.key")

        with open(sub_key, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, subordinate_key))

        with open(sub_certificate, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

        print(f"Subordinate Certificate Authority - {subordinate_ca_name} created successfully.")


    def revoke_subordinate_ca(self, subordinate_ca_name: str) -> None:
        """

        Revoke the Certificate Authority.

        Args:
            name: name of the certificate authority to be revoked.

        """

        name = os.path.join(certificate_directory, f"{subordinate_ca_name}.crt")

        with open(name, "rb") as f:
            sub_ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        with open(ca_key, "rb") as f:
            parent_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

        crl = crypto.CRL()
        crl.set_lastUpdate(sub_ca_cert.get_notBefore())
        crl.set_nextUpdate(sub_ca_cert.get_notAfter())
        crl.add_revoked(sub_ca_cert)
        crl.sign(parent_key, "sha256")

        crl_pem = os.path.join(certificate_directory, "crl.pem")

        with open(crl_pem, "wb") as f:
            f.write(crypto.dump_crl(crypto.FILETYPE_PEM, crl))

        print(f"Subordinate Certificate Authority - {name} revoked successfully.")


    def create_certificate_from_csr(self, csr_file: str, ca_name: str, ca_duration: int) -> None:
        """

        Create a certificate using the given CA.

        Args:
            csr_file: name of the certificate signing request file.
            ca_name: name of the certificate authority to be used.
            ca_duration: the validity of the certificate authority in seconds.

        """

        csr_pem = os.path.join(certificate_directory, f"{csr_file}_csr.pem")
        sub_certificate = os.path.join(certificate_directory, f"{ca_name}.crt")
        sub_key = os.path.join(certificate_directory, f"{ca_name}.key")
        cert_crt = os.path.join(certificate_directory, f"{csr_file}.crt")

        with open(csr_pem, "rb") as f:
            req = crypto.load_certificate_request(crypto.FILETYPE_PEM, f.read())

        with open(sub_key, "rb") as f:
            root_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

        with open(sub_certificate, "rb") as f:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        cert = crypto.X509()
        cert.set_subject(req.get_subject())
        cert.set_serial_number(uuid.uuid4().int)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(ca_duration)
        cert.set_issuer(ca_cert.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.sign(root_key, "sha256")

        with open(cert_crt, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

        if "TOM" in cert_crt:
            shutil.copy(cert_crt, tomtomload_configfiles)

        print("Certificate created successfully.")


    def verify_certificate(self, cert_to_verify: str) -> None:
        """

        Verify the certificate.

        Args:
            cert_to_verify: name of the certificate to be verified.

        """

        cert_to_verify = os.path.join(certificate_directory, f"{cert_to_verify}.crt")

        with open(cert_to_verify, "rb") as f:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        with open(ca_certificate, "rb") as f:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        with open(sub_certificate, "rb") as f:
            sub_ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        store = crypto.X509Store()
        store.add_cert(ca_cert)
        store.add_cert(sub_ca_cert)
        store_ctx = crypto.X509StoreContext(store, cert)

        try:
            store_ctx.verify_certificate()
            print(f"Certificate - {cert_to_verify} verified successfully.")

        except crypto.X509StoreContextError as e:
            print("Certificate is invalid:", e)


# -----------------  END OF CERTIFICATE AUTHORITY  ----------------- #


# -----------------  START OF CERTIFICATE  ----------------- #
class Certificates:

    def create_certificate_csr(self, ca_name: str) -> None:
        """

        Create a Certificate which is issued by the specified Certificate Authority (CA).
        The certificate details and the public key is provided as a Certificate Signing Request (CSR).

        Args:
            ca_name: the name of the certificate authority to sign the CSR.

        """

        key = crypto.PKey()
        key.generate_key(type=crypto.TYPE_RSA, bits=4096)

        req = crypto.X509Req()
        subject = req.get_subject()
        subject.CN = ca_name
        req.set_pubkey(key)
        req.sign(key, "sha256")

        csr_pem = os.path.join(certificate_directory, f"{ca_name}_csr.pem")
        key_pem = os.path.join(certificate_directory, f"{ca_name}_key.pem")

        with open(key_pem, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        with open(csr_pem, "wb") as f:
            f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))

        if "TOM" in key_pem:
            shutil.copy(key_pem, tomtomload_configfiles)

        print(f"CSR - {ca_name} created successfully.")


    def revoke_certificate(self, cert: str) -> None:
        """

        Revoke an issued certificate. Once revoked, the certificate will become invalid and will expire post its lifetime.

        Args:
            cert: the name of the certificate to be revoked.

        """

        with open("cert.crt", "rb") as f:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        with open(sub_key, "rb") as f:
            root_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

        with open(sub_certificate, "rb") as f:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        crl = crypto.CRL()
        crl.set_lastUpdate(cert.get_notBefore())
        crl.set_nextUpdate(cert.get_notAfter())
        crl.add_revoked(cert)
        crl.sign(root_key, "sha256")

        crl_pem = os.path.join(certificate_directory, "cert.crl")

        with open(crl_pem, "wb") as f:
            f.write(crypto.dump_crl(crypto.FILETYPE_PEM, crl))

        print(f"Certificate - {cert} revoked successfully.")


    def get_certificates(self, name: str) -> None:
        """

        Get the certificate details.

        Args:
            name: the name of the certificate to get the details of.

        """

        cert_files = [
            os.path.join(certificate_directory, f) 
            for f in os.listdir(certificate_directory) if f.endswith(".crt")
        
        ]

        for cert_file in cert_files:
            if name in cert_file:
                with open(cert_file, "rb") as f:
                    cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

                table = PrettyTable()
                table.field_names =["Subject", "Issuer", "Serial Number", "Validity", "Signature Algorithm", "Public Key", "Version", "Revoked"]
                table.add_row([
                    str(cert.get_subject()),
                    str(cert.get_issuer()),
                    str(cert.get_serial_number()),
                    str(f"{cert.get_notBefore()} to {cert.get_notAfter()}"),
                    str(cert.get_signature_algorithm()),
                    str(cert.get_pubkey()),
                    str(cert.get_version()),
                    str(cert.has_expired())
                ])

                print(table)

        print(f"Certificate - {name} details retrieved successfully.")

# -----------------  END OF CERTIFICATE  ----------------- #

# if __name__ == "__main__":

#     ca = CertificateAuthority()
#     cert = Certificates()

#     ttl_duration = 365 * 24 * 60 * 60

#     if not os.path.exists(ca_certificate):
#         ca.create_certificate_authority(ca_name="IDENTITYPROXY", ca_duration=ttl_duration)
#         ca.create_subordinate_ca(subordinate_ca_name="SUBORDINATE_IDENTITY_PROXY", ca_duration=ttl_duration)

#     cert.create_certificate_csr(ca_name="TOMTOMLOAD")
#     ca.create_certificate_from_csr(csr_file="TOMTOMLOAD", ca_name="SUBORDINATE_IDENTITY_PROXY", ca_duration=ttl_duration)

#     cert.create_certificate_csr(ca_name="IDENTITYPROXY")
#     ca.create_certificate_from_csr(csr_file="IDENTITYPROXY", ca_name="SUBORDINATE_IDENTITY_PROXY", ca_duration=ttl_duration)

#     # ca.verify_certificate(cert_to_verify="IDENTITYPROXY")
#     # ca.verify_certificate(cert_to_verify="SUBORDINATE_IDENTITY_PROXY")
#     # ca.verify_certificate(cert_to_verify="TOMTOMLOAD")
    
