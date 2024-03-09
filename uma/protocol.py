# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode
from uma.counterparty_data import CounterpartyDataOptions

from uma.cert_utils import get_pubkey
from uma.currency import Currency
from uma.exceptions import InvalidRequestException
from uma.JSONable import JSONable
from uma.kyc_status import KycStatus
from uma.payee_data import PayeeData
from uma.payer_data import PayerData, compliance_from_payer_data
from uma.type_utils import none_throws
from uma.urls import is_domain_local


@dataclass
class LnurlpRequest:
    receiver_address: str
    """
    The UMA or Lightning address of the receiver.
    """

    nonce: Optional[str]
    """
    A random string included in the signature payload to prevent replay attacks.
    """

    signature: Optional[str]
    """
    DER-encoded signature from the sending VASP.
    """

    is_subject_to_travel_rule: Optional[bool]
    """
    Whether the sending VASP is subject to travel rule regulations.
    """

    vasp_domain: Optional[str]
    """
    The domain of the sending VASP.
    """

    timestamp: Optional[datetime]
    """
    The time at which the request was made.
    """

    uma_version: Optional[str]
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
        base_url = f"{scheme}://{host}/.well-known/lnurlp/{identifier}"
        if not self.is_uma_request():
            return base_url
        params = {
            "signature": self.signature,
            "vaspDomain": self.vasp_domain,
            "nonce": self.nonce,
            "isSubjectToTravelRule": str(self.is_subject_to_travel_rule).lower(),
            "timestamp": int(none_throws(self.timestamp).timestamp()),
            "umaVersion": self.uma_version,
        }
        return f"{base_url}?{urlencode(params)}"

    def signable_payload(self) -> bytes:
        if not self.nonce or not self.timestamp:
            raise InvalidRequestException(
                "nonce and timestamp are required for signing. This is not an UMA request."
            )
        signable = "|".join(
            [self.receiver_address, self.nonce, str(int(self.timestamp.timestamp()))]
        )
        return signable.encode("utf8")

    def is_uma_request(self) -> bool:
        return (
            self.uma_version is not None
            and self.signature is not None
            and self.nonce is not None
            and self.timestamp is not None
            and self.is_subject_to_travel_rule is not None
        )


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

    currencies: Optional[List[Currency]]
    """
    The list of currencies that the receiver accepts in order of preference.
    """

    required_payer_data: Optional[CounterpartyDataOptions]
    """
    The data about the payer that the sending VASP must provide in order to send a payment.
    """

    compliance: Optional[LnurlComplianceResponse]
    """
    Compliance-related data from the receiving VASP.
    """

    uma_version: Optional[str]
    """
    The version of the UMA protocol that the receiver is using.
    """

    comment_chars_allowed: Optional[int] = None
    """
    The number of characters that the sender can include in the comment field of the pay request.
    """

    nostr_pubkey: Optional[str] = None
    """
    An optional nostr pubkey used for nostr zaps (NIP-57). If set, it should be a valid
    BIP-340 public key in hex format.
    """

    allows_nostr: Optional[bool] = None
    """
    Should be set to true if the receiving VASP allows nostr zaps (NIP-57).
    """

    @classmethod
    def _get_field_name_overrides(cls) -> Dict[str, str]:
        return {
            "encoded_metadata": "metadata",
            "required_payer_data": "payerData",
            "comment_chars_allowed": "commentAllowed",
        }

    def is_uma_response(self) -> bool:
        return self.uma_version is not None and self.compliance is not None

    def signable_payload(self) -> bytes:
        if not self.compliance:
            raise InvalidRequestException(
                "compliance field is required for signing or verifying."
            )
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
            if sending_currency and sending_currency.upper() != "SAT"
            else str(result_dict["amount"])
        )
        return result_dict

    @classmethod
    def _from_dict(cls, json_dict: Dict[str, Any]) -> Dict[str, Any]:
        data = super()._from_dict(json_dict)
        if "convert" in json_dict:
            data["receiving_currency_code"] = json_dict.pop("convert")
        if "amount" in data:
            amount = data.pop("amount")
            if "." in amount:
                [amount, currency] = amount.split(".")
                data["amount"] = int(amount)
                data["sending_amount_currency_code"] = currency
            else:
                data["amount"] = int(amount)
        return data


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
    amount: int
    """
    The amount that the receiver will receive in the receiving currency not including fees. The amount is specified
    in the smallest unit of the currency (eg. cents for USD).
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
    """

    payment_info: Optional[PayReqResponsePaymentInfo]
    """
    Information about the payment that the receiver will receive. Includes
    Final currency-related information for the payment.
    """

    disposable: Optional[bool] = False
    """
    This field may be used by a WALLET to decide whether the initial LNURL link will
    be stored locally for later reuse or erased. If disposable is null, it should be
    interpreted as true, so if SERVICE intends its LNURL links to be stored it must
    return `disposable: false`. UMA should always return `disposable: false`. See LUD-11.
    """

    success_action: Optional[Dict[str, str]] = None
    """
    Defines a struct which can be stored and shown to the user on payment success. See LUD-09.
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


@dataclass
class PubkeyResponse(JSONable):
    """
    PubkeyResponse is sent from a VASP to another VASP to provide its public keys.
    It is the response to GET requests at `/.well-known/lnurlpubkey`.
    """

    signing_cert_chain: Optional[List[x509.Certificate]]
    """The certificate chain used to verify signatures from a VASP."""

    encryption_cert_chain: Optional[List[x509.Certificate]]
    """The certificate chain used to encrypt TR info sent to a VASP."""

    signing_pubkey: Optional[bytes]
    """Used to verify signatures from a VASP."""

    encryption_pubkey: Optional[bytes]
    """Used to encrypt TR info sent to a VASP."""

    expiration_timestamp: Optional[datetime]
    """
    Optional expiration_timestamp in seconds since epoch at which these pub keys must be refreshed.
	It can be safely cached until this expiration (or forever if null).
    """

    def get_signing_pubkey(self) -> bytes:
        # the first cert in the chain is the leaf (sender's) cert
        if self.signing_cert_chain and self.signing_cert_chain[0]:
            return get_pubkey(self.signing_cert_chain[0])
        if self.signing_pubkey:
            return self.signing_pubkey
        raise InvalidRequestException("Signing pubkey is required for uma.")

    def get_encryption_pubkey(self) -> bytes:
        # the first cert in the chain is the leaf (sender's) cert
        if self.encryption_cert_chain and self.encryption_cert_chain[0]:
            return get_pubkey(self.encryption_cert_chain[0])
        if self.encryption_pubkey:
            return self.encryption_pubkey
        raise InvalidRequestException("Encryption pubkey is required for uma.")

    def to_dict(self) -> Dict[str, Any]:
        json_dict: Dict[str, Any] = {}
        if self.signing_cert_chain:
            json_dict["signingCertChain"] = [
                cert.public_bytes(encoding=serialization.Encoding.PEM).hex()
                for cert in self.signing_cert_chain
            ]
        if self.encryption_cert_chain:
            json_dict["encryptionCertChain"] = [
                cert.public_bytes(encoding=serialization.Encoding.PEM).hex()
                for cert in self.encryption_cert_chain
            ]
        if self.signing_pubkey:
            json_dict["signingPubKey"] = self.signing_pubkey.hex()
        if self.encryption_pubkey:
            json_dict["encryptionPubKey"] = self.encryption_pubkey.hex()
        if self.expiration_timestamp:
            json_dict["expirationTimestamp"] = int(
                self.expiration_timestamp.timestamp()
            )
        return json_dict

    @classmethod
    def _from_dict(cls, json_dict: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "signing_cert_chain": (
                [
                    x509.load_pem_x509_certificate(bytes.fromhex(cert))
                    for cert in json_dict["signingCertChain"]
                ]
                if "signingCertChain" in json_dict
                and json_dict["signingCertChain"] is not None
                else None
            ),
            "encryption_cert_chain": (
                [
                    x509.load_pem_x509_certificate(bytes.fromhex(cert))
                    for cert in json_dict["encryptionCertChain"]
                ]
                if "encryptionCertChain" in json_dict
                and json_dict["encryptionCertChain"] is not None
                else None
            ),
            "signing_pubkey": (
                bytes.fromhex(json_dict["signingPubKey"])
                if "signingPubKey" in json_dict
                and json_dict["signingPubKey"] is not None
                else None
            ),
            "encryption_pubkey": (
                bytes.fromhex(json_dict["encryptionPubKey"])
                if "encryptionPubKey" in json_dict
                and json_dict["encryptionPubKey"] is not None
                else None
            ),
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
