# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved

from dataclasses import dataclass
import json
from typing import Any, Dict, List, Optional, TypeAlias

from uma.JSONable import JSONable


@dataclass
class CompliancePayeeData(JSONable):
    utxos: List[str]
    """
    The list of UTXOs of the receiver's channels that might be used to forward the payment.
    """

    utxo_callback: str
    """
    The URL that the sender will call to send UTXOs of the channels that were used to
    receive the payment once it completes.
    """

    node_pubkey: Optional[str]
    """
    The public key of the receiver's Lightning node that will be used to receive the payment.
    """

    @classmethod
    def _get_field_name_overrides(cls) -> Dict[str, str]:
        return {"node_pubkey": "nodePubKey"}


PayeeData: TypeAlias = Dict[str, Any]


def compliance_from_payee_data(payee_data: PayeeData) -> Optional[CompliancePayeeData]:
    compliance = payee_data.get("compliance")
    if not compliance or not isinstance(compliance, dict):
        return None

    return CompliancePayeeData.from_json(json.dumps(compliance))
