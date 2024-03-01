from typing import Optional, TypeVar


T = TypeVar("T")


def none_throws(value: Optional[T], error_message: Optional[str] = None) -> T:
    if value is None:
        raise RuntimeError(error_message or "Unexpected None")
    return value
