from typing import List
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from uma.exceptions import (
    InvalidRequestException,
)


def get_pubkey(cert: x509.Certificate) -> bytes:
    # The last 65 bytes of the DER-encoded public key are the uncompressed public key.
    pubkey = cert.public_key()

    if not isinstance(pubkey, ec.EllipticCurvePublicKey):
        raise InvalidRequestException("Public key is not an Elliptic Curve public key.")
    if pubkey.curve.name != "secp256k1":
        raise InvalidRequestException("Public key is not a valid SECP256K1 public key.")

    return pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )[-65:]


def get_x509_certs(cert_chain: str) -> List[x509.Certificate]:
    try:
        return x509.load_pem_x509_certificates(cert_chain.encode())
    except ValueError as exc:
        raise InvalidRequestException(
            "Unable to parse certificate as valid X.509."
        ) from exc
