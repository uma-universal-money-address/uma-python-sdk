from dataclasses import dataclass
from typing import Dict, List, Optional
from uma.JSONable import JSONable

from uma.exceptions import InvalidRequestException
from uma.protocol.backing_signature import BackingSignature
from uma.protocol.counterparty_data import CounterpartyDataOptions
from uma.protocol.currency import Currency
from uma.protocol.kyc_status import KycStatus
from uma.signing_utils import sign_payload


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

    backing_signatures: Optional[List[BackingSignature]] = None
    """
    List of backing VASP signatures.
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

    def append_backing_signature(self, signing_private_key: bytes, domain: str) -> None:
        """
        Appends a backing signature to the lnurlp response.

        Args:
            signing_private_key: The private key of the backing VASP which is used to sign the payload.
            domain: The domain of the backing VASP that produced the signature. Public keys for this VASP
            will be fetched from this domain at /.well-known/lnurlpubkey and used to verify the signature.
        """
        if not self.is_uma_response():
            return
        compliance = self.compliance
        if not compliance:
            raise InvalidRequestException(
                "compliance field is required for adding backing signatures."
            )
        payload = self.signable_payload()
        backing_signature = sign_payload(payload, signing_private_key)
        if compliance.backing_signatures is None:
            compliance.backing_signatures = []
        compliance.backing_signatures.append(
            BackingSignature(domain=domain, signature=backing_signature)
        )
