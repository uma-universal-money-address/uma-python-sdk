from dataclasses import dataclass
from typing import List, Optional

from uma.JSONable import JSONable


@dataclass
class UtxoWithAmount(JSONable):
    utxo: str
    amount_msats: int


@dataclass
class PostTransactionCallback(JSONable):
    utxos: List[UtxoWithAmount]
    """List of utxo/amounts corresponding to the VASPs channels."""

    vasp_domain: Optional[str]
    """
    The domain of the VASP that is sending the callback. Used by the VASP to fetch the public keys of
    its counterparty.

    Note: This field is optional for UMA v0.X backwards-compatibility. It is required for UMA v1.X.
    """

    signature: Optional[str]
    """
    Signature is the base64-encoded signature of sha256(Nonce|Timestamp)

    Note: This field is optional for UMA v0.X backwards-compatibility. It is required for UMA v1.X.
    """

    signature_nonce: Optional[str]
    """
    Random string that is used to prevent replay attacks

    Note: This field is optional for UMA v0.X backwards-compatibility. It is required for UMA v1.X.
    """

    signature_timestamp: Optional[int]
    """
    Time stamp of the signature in seconds since epoch
    
    Note: This field is optional for UMA v0.X backwards-compatibility. It is required for UMA v1.X.
    """

    def signable_payload(self) -> bytes:
        if (
            not self.signature_nonce
            or not self.signature_timestamp
            or not self.vasp_domain
        ):
            raise ValueError(
                "Fields needed for signature are missing. Nonce, timestamp, and vasp_domain are required for UMA v1."
            )
        signable = "|".join([self.signature_nonce, str(self.signature_timestamp)])
        return signable.encode("utf8")
