from enum import Enum
from dataclasses import dataclass


@dataclass
class ErrorDetails:
    code: str
    http_status_code: int


class ErrorCode(Enum):
    # Error fetching counterparty public key for validating signatures or encrypting messages
    COUNTERPARTY_PUBKEY_FETCH_ERROR = ErrorDetails(
        code="COUNTERPARTY_PUBKEY_FETCH_ERROR", http_status_code=424
    )

    # Error parsing the counterparty public key response
    INVALID_PUBKEY_FORMAT = ErrorDetails(
        code="INVALID_PUBKEY_FORMAT", http_status_code=400
    )

    # The provided certificate chain is invalid
    CERT_CHAIN_INVALID = ErrorDetails(code="CERT_CHAIN_INVALID", http_status_code=400)

    # The provided certificate chain has expired
    CERT_CHAIN_EXPIRED = ErrorDetails(code="CERT_CHAIN_EXPIRED", http_status_code=400)

    # The provided signature is not valid
    INVALID_SIGNATURE = ErrorDetails(code="INVALID_SIGNATURE", http_status_code=401)

    # The provided timestamp is not valid
    INVALID_TIMESTAMP = ErrorDetails(code="INVALID_TIMESTAMP", http_status_code=400)

    # The provided nonce is not valid
    INVALID_NONCE = ErrorDetails(code="INVALID_NONCE", http_status_code=400)

    # An unexpected error occurred on the server
    SYSTEM_ERROR = ErrorDetails(code="SYSTEM_ERROR", http_status_code=500)

    # This party does not support non-UMA LNURLs
    NON_UMA_LNURL_NOT_SUPPORTED = ErrorDetails(
        code="NON_UMA_LNURL_NOT_SUPPORTED", http_status_code=403
    )

    # Missing required UMA parameters
    MISSING_REQD_UMA_PARAMETERS = ErrorDetails(
        code="MISSING_REQD_UMA_PARAMETERS", http_status_code=400
    )

    # The counterparty UMA version is not supported
    UNSUPPORTED_UMA_VERSION = ErrorDetails(
        code="UNSUPPORTED_UMA_VERSION", http_status_code=412
    )

    # Error parsing the LNURLP request
    PARSE_LNURLP_REQUEST_ERROR = ErrorDetails(
        code="PARSE_LNURLP_REQUEST_ERROR", http_status_code=400
    )

    # This user has exceeded the velocity limit and is unable to receive payments at this time
    VELOCITY_LIMIT_EXCEEDED = ErrorDetails(
        code="VELOCITY_LIMIT_EXCEEDED", http_status_code=403
    )

    # The user for this UMA was not found
    USER_NOT_FOUND = ErrorDetails(code="USER_NOT_FOUND", http_status_code=404)

    # The user for this UMA is not ready to receive payments at this time
    USER_NOT_READY = ErrorDetails(code="USER_NOT_READY", http_status_code=403)

    # The request corresponding to this callback URL was not found
    REQUEST_NOT_FOUND = ErrorDetails(code="REQUEST_NOT_FOUND", http_status_code=404)

    # Error parsing the payreq request
    PARSE_PAYREQ_REQUEST_ERROR = ErrorDetails(
        code="PARSE_PAYREQ_REQUEST_ERROR", http_status_code=400
    )

    # The amount provided is not within the min/max range
    AMOUNT_OUT_OF_RANGE = ErrorDetails(code="AMOUNT_OUT_OF_RANGE", http_status_code=400)

    # The currency provided is not supported
    UNSUPPORTED_CURRENCY = ErrorDetails(
        code="UNSUPPORTED_CURRENCY", http_status_code=400
    )

    # Payments from this sender are not accepted
    SENDER_NOT_ACCEPTED = ErrorDetails(code="SENDER_NOT_ACCEPTED", http_status_code=400)

    # Missing mandatory payer data fields
    MISSING_MANDATORY_PAYER_DATA = ErrorDetails(
        code="MISSING_MANDATORY_PAYER_DATA", http_status_code=400
    )

    # Unrecognized mandatory payee data key
    UNRECOGNIZED_MANDATORY_PAYEE_DATA_KEY = ErrorDetails(
        code="UNRECOGNIZED_MANDATORY_PAYEE_DATA_KEY", http_status_code=501
    )

    # Error parsing the utxo callback
    PARSE_UTXO_CALLBACK_ERROR = ErrorDetails(
        code="PARSE_UTXO_CALLBACK_ERROR", http_status_code=500
    )

    # This counterparty domain is not registered
    DOMAIN_REGISTRATION_REQUIRED = ErrorDetails(
        code="DOMAIN_REGISTRATION_REQUIRED", http_status_code=403
    )
