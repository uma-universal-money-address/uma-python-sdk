# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved

from dataclasses import dataclass
from typing import Dict
from enum import Enum

from uma.JSONable import JSONable


@dataclass
class CounterpartyDataOption(JSONable):
    mandatory: bool
    """Whether the field is mandatory or not"""


CounterpartyDataOptions = Dict[str, CounterpartyDataOption]


class CounterpartyDataKeys(Enum):
    """Common keys used in counterparty data exchanges between VASPs."""

    IDENTIFIER = "identifier"
    """The UMA address of the counterparty"""

    NAME = "name"
    """The full name of the counterparty"""

    EMAIL = "email"
    """The email address of the counterparty"""

    COMPLIANCE = "compliance"
    """Compliance-related data including KYC status, UTXOs, and travel rule information"""

    BIRTH_DATE = "birthDate"
    """The counterparty's date of birth, in ISO 8601 format"""

    NATIONALITY = "nationality"
    """The counterparty's nationality, in ISO 3166-1 alpha-2 format"""

    COUNTRY_OF_RESIDENCE = "countryOfResidence"
    """The counterparty's country of residence, in ISO 3166-1 alpha-2 format"""

    PHONE_NUMBER = "phoneNumber"
    """The counterparty's phone number, in E.164 format"""

    FI_LEGAL_ENTITY_NAME = "fiLegalEntityName"
    """The counterparty financial institution's legal entity name"""


def create_counterparty_data_options(
    options: Dict[str, bool],
) -> CounterpartyDataOptions:
    return {
        key: CounterpartyDataOption(mandatory=value) for key, value in options.items()
    }
