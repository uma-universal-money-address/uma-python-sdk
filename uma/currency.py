# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved

from dataclasses import dataclass
from typing import Any, Dict

from uma.JSONable import JSONable


@dataclass
class Currency(JSONable):
    code: str
    """
    ISO 4217 currency code (if applicable). For example, USD for US Dollars. For cryptocurrencies, this will
    be a ticker symbol, such as BTC for Bitcoin.
    """

    name: str
    """
    Full display name of the currency. For example, in USD, the name is "US Dollars".
    """

    symbol: str
    """
    Symbol for this currency. For example, in USD, the symbol is "$".
    """

    millisatoshi_per_unit: float
    """
    Estimated millisats per smallest "unit" of this currency (eg. 1 cent in USD).
    """

    min_sendable: int
    """
    Minimum amount that can be sent in this currency. This is in the smallest unit of the currency
    (eg. cents for USD).
    """

    max_sendable: int
    """
    Maximum amount that can be sent in this currency. This is in the smallest unit of the currency
    (eg. cents for USD).
    """

    decimals: int
    """
    The number of digits after the decimal point for display on the sender side, and to add clarity
	around what the "smallest unit" of the currency is. For example, in USD, by convention, there are 2 digits for
	cents - $5.95. In this case, `decimals` would be 2. Note that the multiplier is still always in the smallest
	unit (cents). In addition to display purposes, this field can be used to resolve ambiguity in what the multiplier
	means. For example, if the currency is "BTC" and the multiplier is 1000, really we're exchanging in SATs, so
	`decimals` would be 8.
	For details on edge cases and examples, see https://github.com/uma-universal-money-address/protocol/blob/main/umad-04-lnurlp-response.md.
    """

    @classmethod
    def _get_field_name_overrides(cls) -> Dict[str, str]:
        return {"millisatoshi_per_unit": "multiplier"}

    def to_dict(self) -> Dict[str, Any]:
        # The max and min sendable fields need to be moved into the convertible struct.
        result_dict = super().to_dict()
        result_dict.pop("maxSendable")
        result_dict.pop("minSendable")
        result_dict["convertible"] = {
            "max": self.max_sendable,
            "min": self.min_sendable,
        }
        return result_dict

    @classmethod
    def _from_dict(cls, json_dict: Dict[str, Any]) -> Dict[str, Any]:
        # pylint: disable=protected-access
        data = super()._from_dict(json_dict)
        convertible = json_dict.pop("convertible")
        data["max_sendable"] = convertible["max"]
        data["min_sendable"] = convertible["min"]
        return data
