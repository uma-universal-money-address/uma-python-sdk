# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode
from uma.counterparty_data import CounterpartyDataOptions

from uma.currency import Currency
from uma.exceptions import InvalidRequestException
from uma.JSONable import JSONable
from uma.kyc_status import KycStatus
from uma.payee_data import PayeeData
from uma.payer_data import PayerData, compliance_from_payer_data
from uma.urls import is_domain_local


@dataclass
class LnurlpRequest:
    receiver_address: str
    """
    The UMA address of the receiver.
    """

    nonce: str
    """
    A random string included in the signature payload to prevent replay attacks.
    """

    signature: str
    """
    DER-encoded signature from the sending VASP.
    """

    is_subject_to_travel_rule: bool
    """
    Whether the sending VASP is subject to travel rule regulations.
    """

    vasp_domain: str
    """
    The domain of the sending VASP.
    """

    timestamp: datetime
    """
    The time at which the request was made.
    """

    uma_version: str
    """
    The version of the UMA protocol that the sender is using.
    """

    def encode_to_url(self) -> str:
        try:
            [identifier, host] = self.receiver_address.split("@")
        except ValueError as ex:
            raise InvalidRequestException(
                f"invalid receiver address {self.receiver_address}."
            ) from ex

        scheme = "http" if is_domain_local(host) else "https"
        base_url = f"{scheme}://{host}/.well-known/lnurlp/{identifier}?"
        params = {
            "signature": self.signature,
            "vaspDomain": self.vasp_domain,
            "nonce": self.nonce,
            "isSubjectToTravelRule": str(self.is_subject_to_travel_rule).lower(),
            "timestamp": int(self.timestamp.timestamp()),
            "umaVersion": self.uma_version,
        }
        return base_url + urlencode(params)

    def signable_payload(self) -> bytes:
        signable = "|".join(
            [self.receiver_address, self.nonce, str(int(self.timestamp.timestamp()))]
        )
        return signable.encode("utf8")


@dataclass
class LnurlComplianceResponse(JSONable):
    kyc_status: KycStatus
    """
    Whether the receiver is KYC verified by the receiving VASP.
    """

    signature: str
    """
    DER-encoded signature from the receiving VASP.
    """

    signature_nonce: str
    """
    A random string included in the signature payload to prevent replay attacks.
    """

    signature_timestamp: int
    """
    The time at which the request was made.
    """

    is_subject_to_travel_rule: bool
    """
    Whether the receiving VASP is subject to travel rule regulations.
    """

    receiver_identifier: str
    """
    The UMA address of the receiver.
    """


@dataclass
class LnurlpResponse(JSONable):
    tag: str
    callback: str
    """
    The URL that the sender will call for the payreq request.
    """

    min_sendable: int
    """
    The minimum amount that the sender can send in millisatoshis.
    """

    max_sendable: int
    """
    The maximum amount that the sender can send in millisatoshis.
    """

    encoded_metadata: str
    """
    JSON-encoded metadata that the sender can use to display information to the user.
    """

    currencies: List[Currency]
    """
    The list of currencies that the receiver accepts in order of preference.
    """

    required_payer_data: CounterpartyDataOptions
    """
    The data about the payer that the sending VASP must provide in order to send a payment.
    """

    compliance: LnurlComplianceResponse
    """
    Compliance-related data from the receiving VASP.
    """

    uma_version: str
    """
    The version of the UMA protocol that the receiver is using.
    """

    @classmethod
    def _get_field_name_overrides(cls) -> Dict[str, str]:
        return {"encoded_metadata": "metadata", "required_payer_data": "payerData"}

    def signable_payload(self) -> bytes:
        signable = "|".join(
            [
                self.compliance.receiver_identifier,
                self.compliance.signature_nonce,
                str(self.compliance.signature_timestamp),
            ]
        )
        return signable.encode("utf8")


@dataclass
class PayRequest(JSONable):
    currency_code: str
    """
    The currency code for the currency that the receiver will receive for this payment.
    """

    amount: int
    """
    The amount of the payment in the currency specified by `currency_code`. This amount is
    in the smallest unit of the specified currency (e.g. cents for USD).
    """

    payer_data: PayerData
    """
    The data about the payer that the sending VASP must provide in order to send a payment.
    This was requested by the receiver in the lnulp response. See LUD-18.
    """

    requested_payee_data: Optional[CounterpartyDataOptions]
    """
    The data about the receiver that the sending VASP would like to know from the receiver.
    See LUD-22.
    """

    def signable_payload(self) -> bytes:
        payloads = [self.payer_data.get("identifier", "")]
        compliance = compliance_from_payer_data(self.payer_data)
        if compliance:
            payloads += [
                compliance.signature_nonce,
                str(compliance.signature_timestamp),
            ]
        return "|".join(payloads).encode("utf8")

    @classmethod
    def _get_field_name_overrides(cls) -> Dict[str, str]:
        return {"currency_code": "currency", "requested_payee_data": "payeeData"}


@dataclass
class RoutePath(JSONable):
    pubkey: str
    fee: int
    msatoshi: int
    channel: str


@dataclass
class Route(JSONable):
    pubkey: str
    path: List[RoutePath]


@dataclass
class PayReqResponsePaymentInfo(JSONable):
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
    `invoiceAmount = amount * multiplier + exchangeFeesMillisatoshi`
    """

    exchange_fees_msats: int
    """
    The fees charged (in millisats) by the receiving VASP for this transaction. This is separate from the `multiplier`.
    """

    @classmethod
    def _get_field_name_overrides(cls) -> Dict[str, str]:
        return {"exchange_fees_msats": "exchangeFeesMillisatoshi"}


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

    payee_data: PayeeData
    """
    The data about the receiver that the sending VASP requested in the payreq request.
    """

    payment_info: PayReqResponsePaymentInfo
    """
    Information about the payment that the receiver will receive. Includes
    Final currency-related information for the payment.
    """

    @classmethod
    def _get_field_name_overrides(cls) -> Dict[str, str]:
        return {"encoded_invoice": "pr"}


@dataclass
class PubkeyResponse(JSONable):
    """
    PubkeyResponse is sent from a VASP to another VASP to provide its public keys.
    It is the response to GET requests at `/.well-known/lnurlpubkey`.
    """

    signing_pubkey: bytes
    """Used to verify signatures from a VASP."""

    encryption_pubkey: bytes
    """Used to encrypt TR info sent to a VASP."""

    expiration_timestamp: Optional[datetime]
    """
    Optional expiration_timestamp in seconds since epoch at which these pub keys must be refreshed.
	It can be safely cached until this expiration (or forever if null).
    """

    def to_dict(self) -> Dict[str, Any]:
        json_dict: Dict[str, Any] = {
            "signingPubKey": self.signing_pubkey.hex(),
            "encryptionPubKey": self.encryption_pubkey.hex(),
        }
        if self.expiration_timestamp:
            json_dict["expirationTimestamp"] = int(
                self.expiration_timestamp.timestamp()
            )
        return json_dict

    @classmethod
    def _from_dict(cls, json_dict: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "signing_pubkey": bytes.fromhex(json_dict["signingPubKey"]),
            "encryption_pubkey": bytes.fromhex(json_dict["encryptionPubKey"]),
            "expiration_timestamp": (
                datetime.fromtimestamp(json_dict["expirationTimestamp"], timezone.utc)
                if "expirationTimestamp" in json_dict
                and json_dict["expirationTimestamp"] is not None
                else None
            ),
        }


@dataclass
class UtxoWithAmount(JSONable):
    utxo: str
    amount_msats: int
