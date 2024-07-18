# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved

from abc import ABC, abstractmethod
from typing import Optional


class IUmaInvoiceCreator(ABC):
    @abstractmethod
    def create_uma_invoice(
        self,
        amount_msats: int,
        metadata: str,
        receiver_identifier: Optional[str],
    ) -> str:
        pass
