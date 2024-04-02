# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved

from dataclasses import dataclass
from typing import Any, Dict, Optional

from uma.protocol.counterparty_data import CounterpartyDataOptions
from uma.JSONable import JSONable
from uma.protocol.payer_data import PayerData


@dataclass
class PayRequest(JSONable):
    sending_amount_currency_code: Optional[str]
    """
    The currency code of the `amount` field. `None` indicates that `amount` is in millisatoshis
    as in LNURL without LUD-21. If this is not `None`, then `amount` is in the smallest unit of
    the specified currency (e.g. cents for USD). This currency code can be any currency which
    the receiver can quote. However, there are two most common scenarios for UMA:

    1. If the sender wants the receiver wants to receive a specific amount in their receiving
    currency, then this field should be the same as `receiving_currency_code`. This is useful
    for cases where the sender wants to ensure that the receiver receives a specific amount
    in that destination currency, regardless of the exchange rate, for example, when paying
    for some goods or services in a foreign currency.

    2. If the sender has a specific amount in their own currency that they would like to send,
    then this field should be left as `None` to indicate that the amount is in millisatoshis.
    This will lock the sent amount on the sender side, and the receiver will receive the
    equivalent amount in their receiving currency. NOTE: In this scenario, the sending VASP
    *should not* pass the sending currency code here, as it is not relevant to the receiver.
    Rather, by specifying an invoice amount in msats, the sending VASP can ensure that their
    user will be sending a fixed amount, regardless of the exchange rate on the receiving side.
    """

    receiving_currency_code: Optional[str]
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

    requested_payee_data: Optional[CounterpartyDataOptions]
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
        return {"requested_payee_data": "payeeData"}

    def to_dict(self) -> Dict[str, Any]:
        result_dict = super().to_dict()
        sending_currency = (
            result_dict.pop("sendingAmountCurrencyCode")
            if "sendingAmountCurrencyCode" in result_dict
            else None
        )
        if self.receiving_currency_code is not None:
            receiving_currency = result_dict.pop("receivingCurrencyCode")
            result_dict["convert"] = receiving_currency
        result_dict["amount"] = (
            f"{result_dict['amount']}.{sending_currency}"
            if sending_currency is not None
            else f"{result_dict['amount']}"
        )
        return result_dict

    @classmethod
    def _from_dict(cls, json_dict: Dict[str, Any]) -> Dict[str, Any]:
        data = super()._from_dict(json_dict)
        if "convert" in json_dict:
            data["receiving_currency_code"] = json_dict.pop("convert")
        if "amount" in data:
            amount = str(data.pop("amount"))
            if "." in amount:
                [amount, currency] = amount.split(".")
                data["amount"] = int(amount)
                data["sending_amount_currency_code"] = currency
            else:
                data["amount"] = int(amount)
        return data
