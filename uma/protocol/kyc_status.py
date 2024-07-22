# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved

from enum import Enum


class KycStatus(Enum):
    VERIFIED = "VERIFIED"
    NOT_VERIFIED = "NOT_VERIFIED"
    PENDING = "PENDING"
    UNKNOWN = "UNKNOWN"

    def to_bytes(self) -> bytes:
        return self.value.encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> "KycStatus":
        return cls(data.decode())
