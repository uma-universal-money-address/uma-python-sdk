from dataclasses import dataclass
from typing import List

from uma.JSONable import JSONable


@dataclass
class UtxoWithAmount(JSONable):
    utxo: str
    amount_msats: int


@dataclass
class PostTransactionCallback(JSONable):
    utxos: List[UtxoWithAmount]
    """List of utxo/amounts corresponding to the VASPs channels."""

    vasp_domain: str
    """
    The domain of the VASP that is sending the callback. Used by the VASP to fetch the public keys of
    its counterparty.
    """

    signature: str
    """Signature is the base64-encoded signature of sha256(Nonce|Timestamp)"""

    signature_nonce: str
    """Random string that is used to prevent replay attacks"""

    signature_timestamp: int
    """Time stamp of the signature in seconds since epoch"""

    def signable_payload(self) -> bytes:
        signable = "|".join([self.signature_nonce, str(self.signature_timestamp)])
        return signable.encode("utf8")
