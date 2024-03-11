from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from urllib.parse import urlencode

from uma.exceptions import InvalidRequestException
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
