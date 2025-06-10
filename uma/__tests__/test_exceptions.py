import json
import pickle
import pytest
from uma.exceptions import (
    UmaException,
    UnsupportedVersionException,
    InvalidRequestException,
    InvalidCurrencyException,
    InvalidSignatureException,
    InvalidNonceException,
)
from uma.generated.errors import ErrorCode


def test_base_uma_exception():
    exc = UmaException("test reason", ErrorCode.INTERNAL_ERROR)
    json_output = json.loads(exc.to_json())

    assert json_output["status"] == "ERROR"
    assert json_output["reason"] == "test reason"
    assert json_output["code"] == "INTERNAL_ERROR"
    assert exc.to_http_status_code() == 500


def test_unsupported_version_exception():
    exc = UnsupportedVersionException("1.2", [0, 1])
    json_output = json.loads(exc.to_json())

    assert json_output["status"] == "ERROR"
    assert json_output["reason"] == "Version 1.2 not supported."
    assert json_output["code"] == "UNSUPPORTED_UMA_VERSION"
    assert json_output["supportedMajorVersions"] == [0, 1]


def test_invalid_request_exception():
    exc = InvalidRequestException("Signature is invalid", ErrorCode.INVALID_SIGNATURE)
    json_output = json.loads(exc.to_json())

    assert json_output["reason"] == "Signature is invalid"
    assert json_output["code"] == "INVALID_SIGNATURE"


def test_invalid_currency_exception():
    exc = InvalidCurrencyException("Invalid currency code")
    json_output = json.loads(exc.to_json())

    assert json_output["status"] == "ERROR"
    assert json_output["reason"] == "Invalid currency code"
    assert json_output["code"] == "INVALID_CURRENCY"
    assert exc.to_http_status_code() == 400


def test_invalid_signature_exception():
    exc = InvalidSignatureException("Bad signature format")
    json_output = json.loads(exc.to_json())

    assert json_output["status"] == "ERROR"
    assert json_output["reason"] == "Bad signature format"
    assert json_output["code"] == "INVALID_SIGNATURE"
    assert exc.to_http_status_code() == 401


def test_invalid_nonce_exception():
    exc = InvalidNonceException("Timestamp is too old")
    json_output = json.loads(exc.to_json())

    assert json_output["status"] == "ERROR"
    assert json_output["reason"] == "Timestamp is too old"
    assert json_output["code"] == "INVALID_NONCE"
    assert exc.to_http_status_code() == 400


def test_from_json():
    exc = UmaException("Amount out of range", ErrorCode.AMOUNT_OUT_OF_RANGE)
    json_str = exc.to_json()
    exc_from_json = UmaException.from_json(json_str)
    assert exc_from_json.reason == "Amount out of range"
    assert exc_from_json.error_code == ErrorCode.AMOUNT_OUT_OF_RANGE
    assert exc_from_json.to_http_status_code() == 400
    assert exc_from_json.code == "AMOUNT_OUT_OF_RANGE"


def test_pickle():
    exc = UmaException("Internal error", ErrorCode.INTERNAL_ERROR)
    exc_pickled = pickle.dumps(exc)
    exc_unpickled = pickle.loads(exc_pickled)
    assert exc_unpickled.reason == "Internal error"
    assert exc_unpickled.error_code == ErrorCode.INTERNAL_ERROR
    assert exc_unpickled.to_http_status_code() == 500
    assert exc_unpickled.code == "INTERNAL_ERROR"
