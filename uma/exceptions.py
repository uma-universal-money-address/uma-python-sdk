# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved

import json
from typing import List
from uma.generated.errors import ErrorCode


class UmaException(Exception):
    def __init__(self, reason: str, error_code: ErrorCode) -> None:
        super().__init__(reason)
        self.reason = reason
        self.code = error_code.value.code
        self.http_status_code = error_code.value.http_status_code
        self.error_code = error_code

    def get_additional_params(self) -> dict:
        """Override this method in child classes to add additional parameters to the JSON output"""
        return {}

    def to_json(self) -> str:
        result = {
            "status": "ERROR",
            "reason": self.reason,
            "code": self.code,
            **self.get_additional_params(),
        }
        return json.dumps(result)

    @classmethod
    def from_json(cls: type["UmaException"], json_str: str) -> "UmaException":
        try:
            data = json.loads(json_str)
            error_code = ErrorCode[data["code"]]
            return cls(data["reason"], error_code)
        except (json.JSONDecodeError, KeyError):
            return cls(
                f"Failed to parse error JSON: {json_str}", ErrorCode.INTERNAL_ERROR
            )

    def to_http_status_code(self) -> int:
        return self.http_status_code

    def __reduce__(self):
        return (self.__class__, (self.reason, self.error_code))


class UnsupportedVersionException(UmaException):
    def __init__(
        self, unsupported_version: str, supported_major_versions: List[int]
    ) -> None:
        super().__init__(
            f"Version {unsupported_version} not supported.",
            ErrorCode.UNSUPPORTED_UMA_VERSION,
        )
        self.unsupported_version = unsupported_version
        self.supported_major_versions = supported_major_versions

    def get_additional_params(self) -> dict:
        return {"supportedMajorVersions": self.supported_major_versions}


class InvalidRequestException(UmaException):
    def __init__(
        self,
        reason: str = "Invalid request",
        error_code: ErrorCode = ErrorCode.INVALID_REQUEST_FORMAT,
    ):
        super().__init__(reason, error_code)


class InvalidCurrencyException(UmaException):
    def __init__(self, reason: str = "Invalid currency"):
        super().__init__(reason, ErrorCode.INVALID_CURRENCY)


class InvalidSignatureException(UmaException):
    def __init__(self, reason: str = "Cannot verify signature"):
        super().__init__(reason, ErrorCode.INVALID_SIGNATURE)


class InvalidNonceException(UmaException):
    def __init__(self, reason: str = "Invalid nonce"):
        super().__init__(reason, ErrorCode.INVALID_NONCE)
