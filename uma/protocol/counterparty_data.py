# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved

from dataclasses import dataclass
from typing import Dict

from uma.JSONable import JSONable


@dataclass
class CounterpartyDataOption(JSONable):
    mandatory: bool
    """Whether the field is mandatory or not"""


CounterpartyDataOptions = Dict[str, CounterpartyDataOption]


def create_counterparty_data_options(
    options: Dict[str, bool]
) -> CounterpartyDataOptions:
    return {
        key: CounterpartyDataOption(mandatory=value) for key, value in options.items()
    }
