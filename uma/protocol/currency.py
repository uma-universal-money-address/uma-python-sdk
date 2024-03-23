# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved

from dataclasses import dataclass
import json
from typing import Any, Dict

from uma.JSONable import JSONable
from uma.protocol.v0.currency import Currency as V0Currency
from uma.protocol.v1.currency import Currency as V1Currency
from uma.version import MAJOR_VERSION


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

    uma_major_version: int = MAJOR_VERSION
    """
    The major version of the UMA protocol that this currency adheres to. This is not serialized to JSON.
    """

    @classmethod
    def _get_field_name_overrides(cls) -> Dict[str, str]:
        return {"millisatoshi_per_unit": "multiplier"}

    def to_dict(self) -> Dict[str, Any]:
        if self.uma_major_version == 0:
            return V0Currency(
                code=self.code,
                name=self.name,
                symbol=self.symbol,
                millisatoshi_per_unit=self.millisatoshi_per_unit,
                min_sendable=self.min_sendable,
                max_sendable=self.max_sendable,
                decimals=self.decimals,
            ).to_dict()
        return V1Currency(
            code=self.code,
            name=self.name,
            symbol=self.symbol,
            millisatoshi_per_unit=self.millisatoshi_per_unit,
            min_sendable=self.min_sendable,
            max_sendable=self.max_sendable,
            decimals=self.decimals,
        ).to_dict()

    @classmethod
    def _from_dict(cls, json_dict: Dict[str, Any]) -> Dict[str, Any]:
        is_v0 = "minSendable" in json_dict
        # pylint: disable=protected-access
        currency_dict = (
            V0Currency._from_dict(json_dict)
            if is_v0
            else V1Currency._from_dict(json_dict)
        )
        currency_dict["uma_major_version"] = 0 if is_v0 else 1

        return currency_dict

    @classmethod
    def from_json(cls: "type[Currency]", json_encoded: str) -> "Currency":
        json_dict = json.loads(json_encoded)
        is_v0 = "minSendable" in json_dict
        if is_v0:
            v0_currency = V0Currency.from_json(json_encoded)
            return Currency(
                code=v0_currency.code,
                name=v0_currency.name,
                symbol=v0_currency.symbol,
                millisatoshi_per_unit=v0_currency.millisatoshi_per_unit,
                min_sendable=v0_currency.min_sendable,
                max_sendable=v0_currency.max_sendable,
                decimals=v0_currency.decimals,
                uma_major_version=0,
            )

        v1_currency = V1Currency.from_json(json_encoded)
        return Currency(
            code=v1_currency.code,
            name=v1_currency.name,
            symbol=v1_currency.symbol,
            millisatoshi_per_unit=v1_currency.millisatoshi_per_unit,
            min_sendable=v1_currency.min_sendable,
            max_sendable=v1_currency.max_sendable,
            decimals=v1_currency.decimals,
            uma_major_version=1,
        )
