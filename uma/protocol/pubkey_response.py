from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from uma.cert_utils import get_pubkey
from uma.exceptions import InvalidRequestException
from uma.JSONable import JSONable


@dataclass
class PubkeyResponse(JSONable):
    """
    PubkeyResponse is sent from a VASP to another VASP to provide its public keys.
    It is the response to GET requests at `/.well-known/lnurlpubkey`.
    """

    signing_cert_chain: Optional[List[x509.Certificate]]
    """The certificate chain used to verify signatures from a VASP."""

    encryption_cert_chain: Optional[List[x509.Certificate]]
    """The certificate chain used to encrypt TR info sent to a VASP."""

    signing_pubkey: Optional[bytes]
    """Used to verify signatures from a VASP."""

    encryption_pubkey: Optional[bytes]
    """Used to encrypt TR info sent to a VASP."""

    expiration_timestamp: Optional[datetime]
    """
    Optional expiration_timestamp in seconds since epoch at which these pub keys must be refreshed.
	It can be safely cached until this expiration (or forever if null).
    """

    def get_signing_pubkey(self) -> bytes:
        # the first cert in the chain is the leaf (sender's) cert
        if self.signing_cert_chain and self.signing_cert_chain[0]:
            return get_pubkey(self.signing_cert_chain[0])
        if self.signing_pubkey:
            return self.signing_pubkey
        raise InvalidRequestException("Signing pubkey is required for uma.")

    def get_encryption_pubkey(self) -> bytes:
        # the first cert in the chain is the leaf (sender's) cert
        if self.encryption_cert_chain and self.encryption_cert_chain[0]:
            return get_pubkey(self.encryption_cert_chain[0])
        if self.encryption_pubkey:
            return self.encryption_pubkey
        raise InvalidRequestException("Encryption pubkey is required for uma.")

    def to_dict(self) -> Dict[str, Any]:
        json_dict: Dict[str, Any] = {}
        signing_cert_chain = self.signing_cert_chain
        encryption_cert_chain = self.encryption_cert_chain
        if signing_cert_chain:
            json_dict["signingCertChain"] = [
                cert.public_bytes(encoding=serialization.Encoding.DER).hex()
                for cert in signing_cert_chain
            ]
            json_dict["signingPubKey"] = get_pubkey(signing_cert_chain[0]).hex()
        if encryption_cert_chain:
            json_dict["encryptionCertChain"] = [
                cert.public_bytes(encoding=serialization.Encoding.DER).hex()
                for cert in encryption_cert_chain
            ]
            json_dict["encryptionPubKey"] = get_pubkey(encryption_cert_chain[0]).hex()
        if self.signing_pubkey:
            json_dict["signingPubKey"] = self.signing_pubkey.hex()
        if self.encryption_pubkey:
            json_dict["encryptionPubKey"] = self.encryption_pubkey.hex()
        if self.expiration_timestamp:
            json_dict["expirationTimestamp"] = int(
                self.expiration_timestamp.timestamp()
            )
        return json_dict

    @classmethod
    def _from_dict(cls, json_dict: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "signing_cert_chain": (
                [
                    x509.load_der_x509_certificate(bytes.fromhex(cert))
                    for cert in json_dict["signingCertChain"]
                ]
                if "signingCertChain" in json_dict
                else None
            ),
            "encryption_cert_chain": (
                [
                    x509.load_der_x509_certificate(bytes.fromhex(cert))
                    for cert in json_dict["encryptionCertChain"]
                ]
                if "encryptionCertChain" in json_dict
                else None
            ),
            "signing_pubkey": (
                bytes.fromhex(json_dict["signingPubKey"])
                if "signingPubKey" in json_dict
                else None
            ),
            "encryption_pubkey": (
                bytes.fromhex(json_dict["encryptionPubKey"])
                if "encryptionPubKey" in json_dict
                else None
            ),
            "expiration_timestamp": (
                datetime.fromtimestamp(json_dict["expirationTimestamp"], timezone.utc)
                if "expirationTimestamp" in json_dict
                else None
            ),
        }
