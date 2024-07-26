from abc import ABC
from typing import (
    Optional,
    Protocol,
    Any,
    Dict,
    Type,
    TypeVar,
    Union,
    get_args,
    get_origin,
    get_type_hints,
    runtime_checkable,
)
import struct

T = TypeVar("T", bound="TLVCodable")


@runtime_checkable
class ByteCodable(Protocol):
    def to_bytes(self) -> bytes: ...

    @classmethod
    def from_bytes(cls, data: bytes) -> "ByteCodable": ...


class TLVCodable(ABC):
    def to_tlv(self) -> bytes:
        result = bytearray()
        tlv_map = self.tlv_map()
        for attr_name, _ in self.__dict__.items():
            value = getattr(self, attr_name)
            if value is not None:
                tag = tlv_map[attr_name]
                encoded_value = self._encode_value(value)
                length = len(encoded_value)
                result.extend(struct.pack("!BB", tag, length))
                result.extend(encoded_value)
        return bytes(result)

    @classmethod
    def from_tlv(cls: "type[T]", data: bytes) -> T:
        obj = cls()
        index = 0
        tag_to_data: Dict[int, bytes] = {}
        while index + 2 < len(data):
            tag, length = struct.unpack("!BB", data[index : index + 2])
            index += 2
            value_bytes = data[index : index + length]
            index += length
            tag_to_data[tag] = value_bytes

        tlv_map = cls.tlv_map()
        for attr_name, tag in tlv_map.items():
            value_bytes = tag_to_data.get(tag, None)
            if value_bytes is None:
                continue
            attr_type = cls._get_attribute_type(obj, attr_name)
            value = cls._decode_value(value_bytes, attr_type)
            setattr(obj, attr_name, value)

        return obj

    @classmethod
    def _get_attribute_type(cls, obj, attribute_name):
        # Get type hints for the object
        type_hints = get_type_hints(type(obj))

        # Check if the attribute exists in type hints
        if attribute_name in type_hints:
            attr_type = type_hints[attribute_name]

            # Check if it's an Optional type
            if hasattr(attr_type, "__origin__") and attr_type.__origin__ is Optional:
                return attr_type.__args__[0]
            return attr_type
        # Fallback to runtime type checking
        return type(getattr(obj, attribute_name))

    @classmethod
    def tlv_map(cls) -> Dict[str, int]:
        return {}

    @classmethod
    def _encode_value(cls, value: Any) -> bytes:
        if isinstance(value, int):
            if -128 <= value <= 127:
                result = struct.pack("!b", value)  # int8
            elif -32768 <= value <= 32767:
                result = struct.pack("!h", value)  # int16
            elif -2147483648 <= value <= 2147483647:
                result = struct.pack("!i", value)  # int32
            else:
                result = struct.pack("!q", value)  # int64
        elif isinstance(value, float):
            result = struct.pack("!d", value)  # 8-byte float
        elif isinstance(value, bytes):
            result = value
        elif isinstance(value, bool):
            result = struct.pack("!?", value)
        elif isinstance(value, str):
            result = value.encode("utf-8")
        elif isinstance(value, TLVCodable):
            result = value.to_tlv()
        elif isinstance(value, ByteCodable):
            result = value.to_bytes()
        else:
            raise ValueError(f"Unsupported type: {type(value)}")
        return result

    @classmethod
    def _decode_value(cls, value: bytes, attr_type: Type) -> Any:
        attr_type = unwrap_type(attr_type)
        if attr_type == int:
            result = int.from_bytes(value, byteorder="big")
        elif attr_type == float:
            result = struct.unpack("!d", value)[0]
        elif attr_type == str:
            result = value.decode("utf-8")
        elif attr_type == bytes:
            result = value
        elif attr_type == bool:
            result = struct.unpack("!?", value)[0]
        elif issubclass(attr_type, TLVCodable):
            result = attr_type.from_tlv(value)
        elif issubclass(attr_type, ByteCodable):
            result = attr_type.from_bytes(value)
        else:
            raise ValueError(f"Unsupported type: {attr_type}")
        return result


def unwrap_type(typ):
    origin = get_origin(typ)
    if origin is Union or origin is Optional:
        args = get_args(typ)
        return unwrap_type(args[0])  # Recursively unwrap
    return typ
