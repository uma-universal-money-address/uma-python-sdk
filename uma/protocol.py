# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from uma.currency import Currency
from uma.exceptions import InvalidRequestException
from uma.JSONable import JSONable
from uma.kyc_status import KycStatus
from uma.payer_data import PayerData, PayerDataOptions


@dataclass
class LnurlpRequest:
    receiver_address: str
    nonce: str
    signature: str
    is_subject_to_travel_rule: bool
    vasp_domain: str
    timestamp: datetime
    uma_version: str

    def encode_to_url(self) -> str:
        try:
            [identifier, host] = self.receiver_address.split("@")
        except ValueError as ex:
            raise InvalidRequestException(
                f"invalid receiver address {self.receiver_address}."
            ) from ex

        scheme = "http" if host.startswith("localhost:") else "https"
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
    signature: str
    signature_nonce: str
    signature_timestamp: int
    is_subject_to_travel_rule: bool
    receiver_identifier: str


@dataclass
class LnurlpResponse(JSONable):
    tag: str
    callback: str
    min_sendable: int
    max_sendable: int
    encoded_metadata: str
    currencies: List[Currency]
    required_payer_data: PayerDataOptions
    compliance: LnurlComplianceResponse
    uma_version: str

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
    amount: int
    payer_data: PayerData

    def signable_payload(self) -> bytes:
        payloads = [self.payer_data.identifier]
        if self.payer_data.compliance:
            payloads += [
                self.payer_data.compliance.signature_nonce,
                str(self.payer_data.compliance.signature_timestamp),
            ]
        return "|".join(payloads).encode("utf8")

    @classmethod
    def _get_field_name_overrides(cls) -> Dict[str, str]:
        return {"currency_code": "currency"}


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
class PayReqResponseCompliance(JSONable):
    utxos: List[str]
    utxo_callback: str
    node_pubkey: Optional[str]

    @classmethod
    def _get_field_name_overrides(cls) -> Dict[str, str]:
        return {"node_pubkey": "nodePubKey"}


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
    routes: List[str]
    compliance: PayReqResponseCompliance
    payment_info: PayReqResponsePaymentInfo

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
            "expiration_timestamp": datetime.fromtimestamp(
                json_dict["expirationTimestamp"], timezone.utc
            )
            if "expirationTimestamp" in json_dict
            and json_dict["expirationTimestamp"] is not None
            else None,
        }


@dataclass
class UtxoWithAmount(JSONable):
    utxo: str
    amount_msats: int
