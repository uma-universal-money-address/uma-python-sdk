from dataclasses import dataclass
from typing import List, Optional
from enum import Enum

from uma.JSONable import JSONable


class TransactionStatus(str, Enum):
    COMPLETED = "COMPLETED"
    """
    Recipient received the payment.
    """

    FAILED = "FAILED"
    """
    Payment failed due to a post-transaction error.
    """


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
    Timestamp of the signature in seconds since epoch
    
    Note: This field is optional for UMA v0.X backwards-compatibility. It is required for UMA v1.X.
    """

    transaction_status: Optional[TransactionStatus]
    """
    The status of the transaction.
    """

    error_code: Optional[str]
    """
    The error code if the transaction has failed. This should be one of the [ErrorCode] enum values.
    This should only be set if `transaction_status` is `FAILED`.
    """

    error_reason: Optional[str]
    """
    The reason for the transaction failure.
    Only set when transaction_status is `FAILED`.
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
        return signable.encode("utf-8")
