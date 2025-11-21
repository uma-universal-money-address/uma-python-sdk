# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved

from dataclasses import dataclass

from uma.JSONable import JSONable


@dataclass
class SettlementInfo(JSONable):
    layer: str
    """
    The settlement layer chosen by the sender (e.g., "ln", "spark").
    """

    asset_identifier: str
    """
    The identifier of the settlement asset chosen by the sender.
    """

    @classmethod
    def _get_field_name_overrides(cls) -> dict[str, str]:
        return {
            "asset_identifier": "assetIdentifier",
        }


@dataclass
class SettlementAsset(JSONable):
    identifier: str
    """
    The identifier of the asset. For Lightning, this should be "BTC".
    For Spark, this is the token identifier.
    """

    multipliers: dict[str, float]
    """
    Estimated conversion rates from this asset to the currencies supported by
    the receiver. The key is the currency code and the value is the multiplier
    (how many of the smallest unit of this asset equals one unit of the
    currency).
    """


@dataclass
class SettlementOption(JSONable):
    settlement_layer: str
    """
    The name of the settlement layer (e.g., "spark", "ln").
    """

    assets: list[SettlementAsset]
    """
    List of accepted assets on this settlement layer with their conversion rates.
    """

    @classmethod
    def _get_field_name_overrides(cls) -> dict[str, str]:
        return {
            "settlement_layer": "settlementLayer",
        }
