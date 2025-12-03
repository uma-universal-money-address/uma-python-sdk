# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved

from abc import ABC, abstractmethod
from typing import Optional

from uma.protocol.settlement import SettlementInfo


class IUmaInvoiceCreator(ABC):
    @abstractmethod
    def create_uma_invoice(
        self,
        amount_msats: int,
        metadata: str,
        receiver_identifier: Optional[str],
    ) -> str:
        pass

    def create_invoice_for_settlement_layer(
        self,
        amount_units: int,
        metadata: str,
        receiver_identifier: Optional[str],
        settlement_info: Optional[SettlementInfo],
    ) -> str:
        """
        Creates a payment request with settlement-agnostic parameters.
        Default implementation delegates to create_uma_invoice for backward compatibility.
        Implementations can override this for settlement-layer specific behavior.

        Args:
            amount_units: Amount in smallest units of the settlement asset.
            metadata: Metadata to include.
            receiver_identifier: Receiver's UMA address.
            settlement_info: Settlement info including the layer and asset chosen by the sender.

        Returns:
            Payment request string.
        """
        # pylint: disable=unused-argument
        return self.create_uma_invoice(amount_units, metadata, receiver_identifier)
