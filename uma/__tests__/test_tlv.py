from typing import runtime_checkable
from uma.tlv_utils import ByteCodable, TLVCodable, implement_tlv_codable, tag


@implement_tlv_codable
class TLVImpl(TLVCodable):
    def __init__(self) -> None:
        self._string_field: str = ""
        self._int_field: int = 0
        self._float_field: float = 0.0
        self._bool_field: bool = False
        self._bytes_field: bytes = b""

    @tag(0)
    def string_field(self) -> str:
        return self._string_field

    @string_field.setter
    def string_field(self, value: str) -> None:
        self._string_field = value

    @tag(1)
    def int_field(self) -> int:
        return self._int_field

    @int_field.setter
    def int_field(self, value: int) -> None:
        self._int_field = value

    @tag(2)
    def float_field(self) -> float:
        return self._float_field

    @float_field.setter
    def float_field(self, value: float) -> None:
        self._float_field = value

    @tag(3)
    def bool_field(self) -> bool:
        return self._bool_field

    @bool_field.setter
    def bool_field(self, value: bool) -> None:
        self._bool_field = value

    @tag(4)
    def bytes_field(self) -> bytes:
        return self._bytes_field

    @bytes_field.setter
    def bytes_field(self, value: bytes) -> None:
        self._bytes_field = value


def test_tlv_coding() -> None:
    obj = TLVImpl()
    obj.string_field = "hello"
    obj.int_field = 42
    obj.float_field = 3.14
    obj.bool_field = True
    obj.bytes_field = b"world"

    data = obj.to_tlv()
    new_obj = TLVImpl.from_tlv(data)

    assert isinstance(new_obj, TLVImpl)
    assert new_obj.string_field == "hello"
    assert new_obj.int_field == 42
    assert new_obj.float_field == 3.14
    assert new_obj.bool_field == True
    assert new_obj.bytes_field == b"world"


@implement_tlv_codable
class NextedTestTLV(TLVCodable):
    def __init__(self) -> None:
        self._test_field: TLVImpl = TLVImpl()

    _test_field: TLVImpl

    @tag(0)
    def test_field(self) -> TLVImpl:
        return self._test_field

    @test_field.setter
    def test_field(self, value: TLVImpl) -> None:
        self._test_field = value


def test_nested_tlv_coding() -> None:
    obj = NextedTestTLV()
    obj.test_field = TLVImpl()
    obj.test_field.string_field = "hello"
    obj.test_field.int_field = 42
    obj.test_field.float_field = 3.14
    obj.test_field.bool_field = True
    obj.test_field.bytes_field = b"world"

    data = obj.to_tlv()
    new_obj = NextedTestTLV.from_tlv(data)

    assert isinstance(new_obj, NextedTestTLV)
    assert new_obj.test_field.string_field == "hello"
    assert new_obj.test_field.int_field == 42
    assert new_obj.test_field.float_field == 3.14
    assert new_obj.test_field.bool_field == True
    assert new_obj.test_field.bytes_field == b"world"


class BinaryClass:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def to_bytes(self) -> bytes:
        return self.data

    @classmethod
    def from_bytes(cls, data: bytes) -> "BinaryClass":
        return cls(data)


@implement_tlv_codable
class BinaryTestTLV(TLVCodable):
    def __init__(self) -> None:
        self._binary_field: BinaryClass = BinaryClass(b"")

    @tag(0)
    def binary_field(self) -> BinaryClass:
        return self._binary_field

    @binary_field.setter
    def binary_field(self, value: BinaryClass) -> None:
        self._binary_field = value


def test_binary_tlv_coding() -> None:
    obj = BinaryTestTLV()
    obj.binary_field = BinaryClass(b"hello")

    data = obj.to_tlv()
    new_obj = BinaryTestTLV.from_tlv(data)

    assert isinstance(new_obj, BinaryTestTLV)
    assert new_obj.binary_field.data == b"hello"
