# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved

from dataclasses import dataclass
import json
from typing import Any, Dict, List, Optional

from uma.JSONable import JSONable


@dataclass
class CompliancePayeeData(JSONable):
    utxos: List[str]
    """List of UTXOs of channels over which the receiver will likely receive the payment"""

    utxo_callback: str
    """URL that the sender VASP will call to send UTXOs of the channel that the sender used to send the payment once it completes"""

    node_pubkey: Optional[str]
    """Public key of the receiver's node if known"""

    signature: str
    """Signature is the base64-encoded signature of sha256(ReceiverAddress|Nonce|Timestamp)"""

    signature_nonce: str
    """Random string that is used to prevent replay attacks"""

    signature_timestamp: int
    """Time stamp of the signature in seconds since epoch"""

    def signable_payload(self, sender_address: str, receiver_address: str) -> bytes:
        signable = "|".join(
            [sender_address, receiver_address, self.signature_nonce, str(int(self.signature_timestamp))]
        )
        return signable.encode("utf8")

    @classmethod
    def _get_field_name_overrides(cls) -> Dict[str, str]:
        return {"node_pubkey": "nodePubKey"}


PayeeData = Dict[str, Any]


def compliance_from_payee_data(payee_data: PayeeData) -> Optional[CompliancePayeeData]:
    compliance = payee_data.get("compliance")
    if not compliance or not isinstance(compliance, dict):
        return None

    return CompliancePayeeData.from_json(json.dumps(compliance))
