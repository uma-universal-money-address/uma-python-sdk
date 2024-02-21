# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved

from dataclasses import dataclass
import json
from typing import Any, Dict, List, Optional

from uma.JSONable import JSONable


@dataclass
class CompliancePayeeData(JSONable):
    utxos: List[str]
    utxo_callback: str
    node_pubkey: Optional[str]

    @classmethod
    def _get_field_name_overrides(cls) -> Dict[str, str]:
        return {"node_pubkey": "nodePubKey"}


PayeeData = Dict[str, Any]


def compliance_from_payee_data(payee_data: PayeeData) -> Optional[CompliancePayeeData]:
    compliance = payee_data.get("compliance")
    if not compliance or not isinstance(compliance, dict):
        return None

    return CompliancePayeeData.from_json(json.dumps(compliance))
