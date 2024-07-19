from typing import Protocol, Any, Dict, Type, runtime_checkable
import struct


@runtime_checkable
class TLVCodable(Protocol):
    def to_tlv(self) -> bytes:
        ...

    @classmethod
    def from_tlv(cls, data: bytes) -> "TLVCodable":
        ...


def tag(number: int):
    def decorator(func):
        func.tag = number
        return property(func)

    return decorator


@runtime_checkable
class ByteCodable(Protocol):
    def to_bytes(self) -> bytes:
        ...

    @classmethod
    def from_bytes(cls, data: bytes) -> "ByteCodable":
        ...


def implement_tlv_codable(cls: Type[Any]) -> Type[TLVCodable]:
    def encode_value(value: Any) -> bytes:
        if isinstance(value, int):
            if -128 <= value <= 127:
                return struct.pack("!b", value)  # int8
            elif -32768 <= value <= 32767:
                return struct.pack("!h", value)  # int16
            elif -2147483648 <= value <= 2147483647:
                return struct.pack("!i", value)  # int32
            else:
                return struct.pack("!q", value)  # int64
        elif isinstance(value, float):
            return struct.pack("!d", value)  # 8-byte float
        elif isinstance(value, bytes):
            return value
        elif isinstance(value, bool):
            return struct.pack("!?", value)
        elif isinstance(value, str):
            return value.encode("utf-8")
        elif isinstance(value, TLVCodable):
            return value.to_tlv()
        elif isinstance(value, ByteCodable):
            return value.to_bytes()
        else:
            raise ValueError(f"Unsupported type: {type(value)}")

    def decode_value(value: bytes, attr_type: Type) -> Any:
        if attr_type == int:
            if len(value) == 1:
                return struct.unpack("!b", value)[0]
            elif len(value) == 2:
                return struct.unpack("!h", value)[0]
            elif len(value) == 4:
                return struct.unpack("!i", value)[0]
            elif len(value) == 8:
                return struct.unpack("!q", value)[0]
            else:
                raise ValueError(f"Invalid integer size: {len(value)} bytes")
        elif attr_type == float:
            return struct.unpack("!d", value)[0]
        elif attr_type == str:
            return value.decode("utf-8")
        elif attr_type == bytes:
            return value
        elif attr_type == bool:
            return struct.unpack("!?", value)[0]
        elif issubclass(attr_type, TLVCodable):
            return attr_type.from_tlv(value)
        elif issubclass(attr_type, ByteCodable):
            return attr_type.from_bytes(value)
        else:
            raise ValueError(f"Unsupported type: {attr_type}")

    def to_tlv(self) -> bytes:
        result = bytearray()
        for attr_name, attr in cls.__dict__.items():
            if isinstance(attr, property) and hasattr(attr.fget, "tag"):
                value = getattr(self, attr_name)
                tag = attr.fget.tag  # pyre-ignore[16]
                encoded_value = encode_value(value)
                length = len(encoded_value)
                result.extend(struct.pack("!BB", tag, length))
                result.extend(encoded_value)
        return bytes(result)

    @classmethod
    def from_tlv(cls, data: bytes) -> TLVCodable:
        obj = cls()
        index = 0
        tag_to_attr = {
            attr.fget.tag: attr_name
            for attr_name, attr in cls.__dict__.items()  # pyre-ignore[16]
            if isinstance(attr, property) and hasattr(attr.fget, "tag")
        }

        while index < len(data):
            tag, length = struct.unpack("!BB", data[index : index + 2])
            index += 2
            value_bytes = data[index : index + length]
            index += length

            if tag in tag_to_attr:
                attr_name = tag_to_attr[tag]
                attr = getattr(cls, attr_name)
                attr_type = get_property_type(attr)
                value = decode_value(value_bytes, attr_type)
                setattr(obj, attr_name, value)

        return obj

    cls.to_tlv = to_tlv
    cls.from_tlv = from_tlv
    return cls


def get_property_type(prop):
    # Try to infer the type from type hints
    if hasattr(prop.fget, "__annotations__") and "return" in prop.fget.__annotations__:
        return prop.fget.__annotations__["return"]

    # If no type hint, create a temporary instance and get the type of the property value
    temp_instance = prop.fget(object())  # This assumes the getter doesn't use self
    return type(temp_instance)
