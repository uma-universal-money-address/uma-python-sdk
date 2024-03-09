from cryptography import x509
from cryptography.hazmat.primitives import serialization
from typing import List
from uma.exceptions import (
    InvalidRequestException,
)


def get_pubkey(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )[-65:]


def get_x509_certs(cert_chain: str) -> List[x509.Certificate]:
    try:
        return x509.load_pem_x509_certificates(cert_chain.encode())
    except ValueError:
        raise InvalidRequestException("Unable to parse certificate as valid X.509.")
