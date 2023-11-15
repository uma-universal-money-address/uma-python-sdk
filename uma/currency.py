# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved

from dataclasses import dataclass
from typing import Dict, Optional

from uma.JSONable import JSONable


@dataclass
class Currency(JSONable):
    code: str
    """
    ISO 4217 currency code. For example, USD for US Dollars.
    """

    name: str
    """
    Full display name of the currency. For example, in USD, the name is "US Dollars".
    """

    symbol: str
    """
    Symbol for this currency. For example, in USD, the symbol is "$".
    """

    millisatoshi_per_unit: int
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

    display_decimals: Optional[int]
    """
    Number of digits after the decimal point for display on the sender side. For example,
    in USD, by convention, there are 2 digits for cents - $5.95. in this case, `display_decimals`
    would be 2. Note that the multiplier is still always in the smallest unit (cents). This field
    is only for display purposes. The sender should assume zero if this field is omitted, unless
    they know the proper display format of the target currency.
    """

    @classmethod
    def _get_field_name_overrides(cls) -> Dict[str, str]:
        return {"millisatoshi_per_unit": "multiplier"}
