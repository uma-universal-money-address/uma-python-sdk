from dataclasses import dataclass
import json
from typing import Any, Dict, List, Optional

from uma.JSONable import JSONable
from uma.protocol.payee_data import PayeeData
from uma.version import MAJOR_VERSION


@dataclass
class PayReqResponseCompliance(JSONable):
    utxos: List[str]
    """List of UTXOs of channels over which the receiver will likely receive the payment"""

    utxo_callback: str
    """URL that the sender VASP will call to send UTXOs of the channel that the sender used to send the payment once it completes"""

    node_pubkey: Optional[str]
    """Public key of the receiver's node if known"""

    signature: Optional[str]
    """
    Signature is the base64-encoded signature of sha256(ReceiverAddress|Nonce|Timestamp)

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

    def signable_payload(self, sender_address: str, receiver_address: str) -> bytes:
        if not self.signature_nonce or not self.signature_timestamp:
            raise ValueError(
                "Compliance data is missing signature nonce or timestamp fields. These are required for UMA v1."
            )
        signable = "|".join(
            [
                sender_address,
                receiver_address,
                self.signature_nonce,
                str(int(self.signature_timestamp)),
            ]
        )
        return signable.encode("utf8")

    @classmethod
    def _get_field_name_overrides(cls) -> Dict[str, str]:
        return {"node_pubkey": "nodePubKey"}

    @classmethod
    def from_payee_data(
        cls, payee_data: PayeeData
    ) -> Optional["PayReqResponseCompliance"]:
        compliance = payee_data.get("compliance")
        if not compliance or not isinstance(compliance, dict):
            return None
        return PayReqResponseCompliance.from_json(json.dumps(compliance))


@dataclass
class PayReqResponsePaymentInfo(JSONable):
    amount: Optional[int]
    """
    The amount that the receiver will receive in the receiving currency not including fees. The amount is specified
    in the smallest unit of the currency (eg. cents for USD).

    Note: This field is optional for UMA v0.X backwards-compatibility. It is required for UMA v1.X.
    """

    currency_code: str
    """
    The currency code that the receiver will receive for this payment.
    """

    decimals: int
    """
    Number of digits after the decimal point for the receiving currency. For example, in USD, by
    convention, there are 2 digits for cents - $5.95. In this case, `decimals` would be 2. This should align with
    the currency's `decimals` field in the LNURLP response. It is included here for convenience. See
    [UMAD-04](https://github.com/uma-universal-money-address/protocol/blob/main/umad-04-lnurlp-response.md) for
    details, edge cases, and examples.
    """

    multiplier: float
    """
    The conversion rate. It is the number of millisatoshis that the receiver will receive for 1
    unit of the specified currency (eg: cents in USD). In this context, this is just for convenience. The conversion
    rate is also baked into the invoice amount itself. Specifically:
    `invoiceAmount = amount * multiplier + exchange_fees_msats`
    """

    exchange_fees_msats: int
    """
    The fees charged (in millisats) by the receiving VASP for this transaction. This is separate from the `multiplier`.
    """

    @classmethod
    def _get_field_name_overrides(cls) -> Dict[str, str]:
        return {"exchange_fees_msats": "fee"}

    def to_dict(self) -> Dict[str, Any]:
        resp = super().to_dict()
        # For backwards-compatibility with UMA v0, duplicate the fee field
        # under both names:
        resp["exchangeFeesMillisatoshi"] = self.exchange_fees_msats
        return resp

    @classmethod
    def _from_dict(cls, json_dict: Dict[str, Any]) -> Dict[str, Any]:
        # For backwards-compatibility with UMA v0, pull fees from v0 name if
        # not present in v1 name:
        if "fee" not in json_dict:
            json_dict["fee"] = json_dict.pop("exchangeFeesMillisatoshi", 0)

        return super()._from_dict(json_dict)


@dataclass
class PayReqResponse(JSONable):
    encoded_invoice: str
    """
    The encoded BOLT11 invoice that the sender will use to pay the receiver.
    """

    routes: List[str]
    """
    Always just an empty array for legacy reasons.
    """

    payee_data: Optional[PayeeData]
    """
    The data about the receiver that the sending VASP requested in the payreq request.
    Required for UMA.
    """

    payment_info: Optional[PayReqResponsePaymentInfo]
    """
    Information about the payment that the receiver will receive. Includes
    Final currency-related information for the payment. Required for UMA.
    """

    disposable: Optional[bool] = None
    """
    This field may be used by a WALLET to decide whether the initial LNURL link will
    be stored locally for later reuse or erased. If disposable is null, it should be
    interpreted as true, so if SERVICE intends its LNURL links to be stored it must
    return `disposable: false`. UMA should never return `disposable: false` due to
    signature nonce checks, etc. See LUD-11.
    """

    success_action: Optional[Dict[str, str]] = None
    """
    Defines a struct which can be stored and shown to the user on payment success. See LUD-09.
    """

    uma_major_version: Optional[int] = MAJOR_VERSION
    """
    The major version of the UMA protocol that this currency adheres to. This is not serialized to JSON.
    """

    @classmethod
    def _get_field_name_overrides(cls) -> Dict[str, str]:
        return {"encoded_invoice": "pr", "payment_info": "converted"}

    def is_uma_response(self) -> bool:
        return (
            self.payee_data is not None
            and "compliance" in self.payee_data
            and self.payment_info is not None
        )

    def get_compliance(self) -> Optional[PayReqResponseCompliance]:
        if not self.payee_data:
            return None
        return PayReqResponseCompliance.from_payee_data(self.payee_data)

    def to_dict(self) -> Dict[str, Any]:
        resp = super().to_dict()
        # For backwards-compatibility with UMA v0, move the compliance data
        # and payment info to v0 names:
        if self.uma_major_version == 0:
            compliance = self.get_compliance()
            if compliance:
                resp["compliance"] = compliance.to_dict()
                resp["payeeData"].pop("compliance", None)
            if self.payment_info:
                resp["paymentInfo"] = self.payment_info.to_dict()
                resp.pop("converted", None)
        resp.pop("umaMajorVersion", None)

        return resp

    @classmethod
    def _from_dict(cls, json_dict: Dict[str, Any]) -> Dict[str, Any]:
        data = super()._from_dict(json_dict)

        # For backwards-compatibility with UMA v0, duplicate the compliance data
        # from the top-level response over to payee_data:
        is_uma_v0 = "compliance" in json_dict
        is_uma_v1 = "payeeData" in json_dict and "compliance" in json_dict["payeeData"]
        if is_uma_v0 and not is_uma_v1:
            if "payee_data" not in data or not data["payee_data"]:
                data["payee_data"] = {}
            data["payee_data"]["compliance"] = json_dict.pop("compliance")

        if "paymentInfo" in json_dict and "converted" not in json_dict:
            # pylint: disable=protected-access
            data["payment_info"] = PayReqResponsePaymentInfo(
                **PayReqResponsePaymentInfo._from_dict(json_dict.pop("paymentInfo"))
            )

        data["uma_major_version"] = 1 if is_uma_v1 else 0 if is_uma_v0 else None

        # Assert that v1 responses are properly signed.
        if is_uma_v1:
            compliance = PayReqResponseCompliance.from_payee_data(data["payee_data"])
            if not compliance:
                raise ValueError(
                    "UMA v1 responses must include compliance data in payee_data."
                )
            if (
                not compliance.signature
                or not compliance.signature_nonce
                or not compliance.signature_timestamp
            ):
                raise ValueError(
                    "UMA v1 responses must include signature data in compliance."
                )

        return data
