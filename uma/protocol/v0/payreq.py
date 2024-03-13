# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved

from dataclasses import dataclass
from typing import Any, Dict, Optional

from uma.JSONable import JSONable
from uma.protocol.counterparty_data import CounterpartyDataOptions
from uma.protocol.payer_data import PayerData


@dataclass
class PayRequest(JSONable):
    currency_code: Optional[str]
    """
    The currency code for the currency that the receiver will receive for this payment.
    """

    amount: int
    """
    The amount of the payment in the currency specified by `currency_code`. This amount is
    in the smallest unit of the specified currency (e.g. cents for USD).
    """

    payer_data: Optional[PayerData]
    """
    The data about the payer that the sending VASP must provide in order to send a payment.
    This was requested by the receiver in the lnulp response. See LUD-18.
    """

    requested_payee_data: Optional[CounterpartyDataOptions] = None
    """
    The data about the receiver that the sending VASP would like to know from the receiver.
    See LUD-22.
    """

    comment: Optional[str] = None
    """
    A comment that the sender would like to include with the payment. This can only be included
    if the receiver included the `commentAllowed` field in the lnurlp response. The length of
    the comment must be less than or equal to the value of `commentAllowed`.
    """

    @classmethod
    def _get_field_name_overrides(cls) -> Dict[str, str]:
        return {"currency_code": "currency"}

    @classmethod
    def _from_dict(cls, json_dict: Dict[str, Any]) -> Dict[str, Any]:
        data = super()._from_dict(json_dict)
        amount = data.get("amount")
        if isinstance(amount, str):
            data["amount"] = int(amount)
        return data
