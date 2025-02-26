from enum import Enum
from dataclasses import dataclass


@dataclass
class ErrorDetails:
    code: str
    http_status_code: int


class ErrorCode(Enum):
    COUNTERPARTY_PUBKEY_FETCH_ERROR = ErrorDetails(
        code="COUNTERPARTY_PUBKEY_FETCH_ERROR", http_status_code=424
    )
    """Error fetching counterparty public key for validating signatures or encrypting messages"""

    INVALID_PUBKEY_FORMAT = ErrorDetails(
        code="INVALID_PUBKEY_FORMAT", http_status_code=400
    )
    """Error parsing the counterparty public key response"""

    CERT_CHAIN_INVALID = ErrorDetails(code="CERT_CHAIN_INVALID", http_status_code=400)
    """The provided certificate chain is invalid"""

    CERT_CHAIN_EXPIRED = ErrorDetails(code="CERT_CHAIN_EXPIRED", http_status_code=400)
    """The provided certificate chain has expired"""

    INVALID_SIGNATURE = ErrorDetails(code="INVALID_SIGNATURE", http_status_code=401)
    """The provided signature is not valid"""

    INVALID_TIMESTAMP = ErrorDetails(code="INVALID_TIMESTAMP", http_status_code=400)
    """The provided timestamp is not valid"""

    INVALID_NONCE = ErrorDetails(code="INVALID_NONCE", http_status_code=400)
    """The provided nonce is not valid"""

    INTERNAL_ERROR = ErrorDetails(code="INTERNAL_ERROR", http_status_code=500)
    """An unexpected error occurred on the server"""

    NON_UMA_LNURL_NOT_SUPPORTED = ErrorDetails(
        code="NON_UMA_LNURL_NOT_SUPPORTED", http_status_code=403
    )
    """This party does not support non-UMA LNURLs"""

    MISSING_REQUIRED_UMA_PARAMETERS = ErrorDetails(
        code="MISSING_REQUIRED_UMA_PARAMETERS", http_status_code=400
    )
    """Missing required UMA parameters"""

    UNSUPPORTED_UMA_VERSION = ErrorDetails(
        code="UNSUPPORTED_UMA_VERSION", http_status_code=412
    )
    """The counterparty UMA version is not supported"""

    PARSE_LNURLP_REQUEST_ERROR = ErrorDetails(
        code="PARSE_LNURLP_REQUEST_ERROR", http_status_code=400
    )
    """Error parsing the LNURLP request"""

    VELOCITY_LIMIT_EXCEEDED = ErrorDetails(
        code="VELOCITY_LIMIT_EXCEEDED", http_status_code=403
    )
    """This user has exceeded the velocity limit and is unable to receive payments at this time"""

    USER_NOT_FOUND = ErrorDetails(code="USER_NOT_FOUND", http_status_code=404)
    """The user for this UMA was not found"""

    USER_NOT_READY = ErrorDetails(code="USER_NOT_READY", http_status_code=403)
    """The user for this UMA is not ready to receive payments at this time"""

    REQUEST_NOT_FOUND = ErrorDetails(code="REQUEST_NOT_FOUND", http_status_code=404)
    """The request corresponding to this callback URL was not found"""

    PARSE_PAYREQ_REQUEST_ERROR = ErrorDetails(
        code="PARSE_PAYREQ_REQUEST_ERROR", http_status_code=400
    )
    """Error parsing the payreq request"""

    AMOUNT_OUT_OF_RANGE = ErrorDetails(code="AMOUNT_OUT_OF_RANGE", http_status_code=400)
    """The amount provided is not within the min/max range"""

    UNSUPPORTED_CURRENCY = ErrorDetails(
        code="UNSUPPORTED_CURRENCY", http_status_code=400
    )
    """The currency provided is not supported"""

    SENDER_NOT_ACCEPTED = ErrorDetails(code="SENDER_NOT_ACCEPTED", http_status_code=400)
    """Payments from this sender are not accepted"""

    MISSING_MANDATORY_PAYER_DATA = ErrorDetails(
        code="MISSING_MANDATORY_PAYER_DATA", http_status_code=400
    )
    """Payer data is missing fields that are required by the receiver"""

    UNRECOGNIZED_MANDATORY_PAYEE_DATA_KEY = ErrorDetails(
        code="UNRECOGNIZED_MANDATORY_PAYEE_DATA_KEY", http_status_code=501
    )
    """Receiver does not recognize the mandatory payee data key"""

    PARSE_UTXO_CALLBACK_ERROR = ErrorDetails(
        code="PARSE_UTXO_CALLBACK_ERROR", http_status_code=500
    )
    """Error parsing the utxo callback"""

    SENDING_DOMAIN_NOT_ALLOWED = ErrorDetails(
        code="SENDING_DOMAIN_NOT_ALLOWED", http_status_code=403
    )
    """The receiving party does not accept payments from this sending domain"""
