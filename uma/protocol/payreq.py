import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

from uma.exceptions import InvalidRequestException
from uma.JSONable import JSONable
from uma.protocol.counterparty_data import CounterpartyDataOptions
from uma.protocol.payer_data import PayerData, compliance_from_payer_data
from uma.protocol.v0.payreq import PayRequest as V0PayRequest
from uma.protocol.v1.payreq import PayRequest as V1PayRequest
from uma.type_utils import none_throws
from uma.version import MAJOR_VERSION


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

    uma_major_version: Optional[int] = MAJOR_VERSION
    """
    The major version of the UMA protocol that this currency adheres to. This is not serialized to JSON.
    """

    invoice_uuid: Optional[str] = None
    """
    The uma invoice UUID that the sender is paying.
    """

    def signable_payload(self) -> bytes:
        if not self.payer_data:
            raise InvalidRequestException("payer_data is required.")
        payer_identifier = self.payer_data.get("identifier")
        if not payer_identifier:
            raise InvalidRequestException(
                "identifier is required in payerdata for uma."
            )
        payloads = [payer_identifier]
        compliance = compliance_from_payer_data(none_throws(self.payer_data))
        if compliance:
            payloads += [
                compliance.signature_nonce,
                str(compliance.signature_timestamp),
            ]
        return "|".join(payloads).encode("utf8")

    def is_uma_request(self) -> bool:
        return self.payer_data is not None and "compliance" in self.payer_data

    def to_dict(self) -> Dict[str, Any]:
        version_payreq = (
            V0PayRequest(
                currency_code=self.receiving_currency_code,
                amount=self.amount,
                payer_data=self.payer_data,
                requested_payee_data=self.requested_payee_data,
                comment=self.comment,
            )
            if self.uma_major_version == 0
            else V1PayRequest(
                sending_amount_currency_code=self.sending_amount_currency_code,
                receiving_currency_code=self.receiving_currency_code,
                amount=self.amount,
                payer_data=self.payer_data,
                requested_payee_data=self.requested_payee_data,
                comment=self.comment,
            )
        )
        return version_payreq.to_dict()

    @classmethod
    def from_json(cls: "type[PayRequest]", json_encoded: str) -> "PayRequest":
        json_dict = json.loads(json_encoded)
        is_amount_string = "amount" in json_dict and isinstance(
            json_dict["amount"], str
        )
        is_uma = json_dict.get("payerData") and "compliance" in json_dict["payerData"]
        is_v1 = "convert" in json_dict and is_uma
        is_v0 = "currency" in json_dict and is_uma

        if is_v1 or is_amount_string:
            v1_payreq = V1PayRequest.from_json(json_encoded)
            return PayRequest(
                sending_amount_currency_code=v1_payreq.sending_amount_currency_code,
                receiving_currency_code=v1_payreq.receiving_currency_code,
                amount=v1_payreq.amount,
                payer_data=v1_payreq.payer_data,
                requested_payee_data=v1_payreq.requested_payee_data,
                comment=v1_payreq.comment,
                uma_major_version=1 if is_v1 else None,
            )
        v0_payreq = V0PayRequest.from_json(json_encoded)
        return PayRequest(
            sending_amount_currency_code=v0_payreq.currency_code,
            receiving_currency_code=v0_payreq.currency_code,
            amount=v0_payreq.amount,
            payer_data=v0_payreq.payer_data,
            requested_payee_data=None,
            uma_major_version=0 if is_v0 else None,
        )

    def to_request_params(self) -> Dict[str, str]:
        params = {}
        if self.sending_amount_currency_code:
            amount = f"{self.amount}.{self.sending_amount_currency_code}"
        else:
            amount = str(self.amount)
        params["amount"] = amount
        if self.receiving_currency_code:
            params["convert"] = self.receiving_currency_code
        if self.payer_data is not None:
            params["payerData"] = json.dumps(self.payer_data)
        if self.requested_payee_data is not None:
            params["payeeData"] = json.dumps(self.requested_payee_data)
        if self.comment:
            params["comment"] = self.comment
        return params

    @classmethod
    def from_request_params(
        cls: "type[PayRequest]", params: Dict[str, str]
    ) -> "PayRequest":
        if not params.get("amount"):
            raise InvalidRequestException("amount is required.")
        parts = params["amount"].split(".")
        sending_amount_currency_code = parts[1] if len(parts) == 2 else None
        amount = parts[0]
        payer_data_json = params.get("payerData")
        payer_data = None if payer_data_json is None else json.loads(payer_data_json)
        payee_data_json = params.get("payeeData")
        payee_data = None if payee_data_json is None else json.loads(payee_data_json)
        return PayRequest(
            sending_amount_currency_code=sending_amount_currency_code,
            receiving_currency_code=params.get("convert"),
            amount=int(amount),
            payer_data=payer_data,
            comment=params.get("comment"),
            requested_payee_data=payee_data,
        )
