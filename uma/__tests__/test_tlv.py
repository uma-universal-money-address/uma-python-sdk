from uma.tlv_utils import ByteCodable, TLVCodable


class TLVImpl(TLVCodable):
    def __init__(self) -> None:
        self.string_field: str = ""
        self.int_field: int = 0
        self.float_field: float = 0.0
        self.bool_field: bool = False
        self.bytes_field: bytes = b""

    @classmethod
    def tlv_map(cls) -> dict:
        return {
            "string_field": 0,
            "int_field": 1,
            "float_field": 2,
            "bool_field": 3,
            "bytes_field": 4,
        }


def test_tlv_coding() -> None:
    obj = TLVImpl()
    obj.string_field = "hello"
    obj.int_field = 42
    obj.float_field = 3.14
    obj.bool_field = True
    obj.bytes_field = b"world"

    data = obj.to_tlv()
    assert len(data) > 0
    new_obj = TLVImpl.from_tlv(data)

    assert isinstance(new_obj, TLVImpl)
    assert new_obj.string_field == "hello"
    assert new_obj.int_field == 42
    assert new_obj.float_field == 3.14
    assert new_obj.bool_field == True
    assert new_obj.bytes_field == b"world"


class NextedTestTLV(TLVCodable):
    def __init__(self) -> None:
        self.test_field: TLVImpl = TLVImpl()

    @classmethod
    def tlv_map(cls) -> dict:
        return {"test_field": 0}


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


class BinaryClass(ByteCodable):
    def __init__(self, data: bytes) -> None:
        self.data = data

    def to_bytes(self) -> bytes:
        return self.data

    @classmethod
    def from_bytes(cls, data: bytes) -> "BinaryClass":
        return cls(data)


class BinaryTestTLV(TLVCodable):
    def __init__(self) -> None:
        self.binary_field: BinaryClass = BinaryClass(b"")

    @classmethod
    def tlv_map(cls) -> dict:
        return {"binary_field": 0}


def test_binary_tlv_coding() -> None:
    obj = BinaryTestTLV()
    obj.binary_field = BinaryClass(b"hello")

    data = obj.to_tlv()
    new_obj = BinaryTestTLV.from_tlv(data)

    assert isinstance(new_obj, BinaryTestTLV)
    assert new_obj.binary_field.data == b"hello"
