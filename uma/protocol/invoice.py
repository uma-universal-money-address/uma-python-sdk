from dataclasses import dataclass
from typing import Optional

import bech32

from uma.protocol.counterparty_data import (
    CounterpartyDataOption,
    CounterpartyDataOptions,
)
from uma.protocol.kyc_status import KycStatus
from uma.tlv_utils import TLVCodable, ByteCodable


@dataclass
class InvoiceCurrency(TLVCodable):
    # code is the ISO 4217 (if applicable) currency code (eg. "USD"). For cryptocurrencies, this will  be a ticker
    # symbol, such as BTC for Bitcoin.
    code: str

    # name is the full display name of the currency (eg. US Dollars).
    name: str

    # symbol is the symbol used to represent the currency (eg. $).
    symbol: str

    # The number of digits after the decimal point for display on the sender side
    decimals: int

    def __init__(
        self, code: str = "", name: str = "", symbol: str = "", decimals: int = 0
    ) -> None:
        self.code = code
        self.name = name
        self.symbol = symbol
        self.decimals = decimals

    @classmethod
    def tlv_map(cls) -> dict:
        return {
            "code": 0,
            "name": 1,
            "symbol": 2,
            "decimals": 3,
        }


@dataclass
class InvoiceCounterpartyDataOptions(ByteCodable):
    options: CounterpartyDataOptions

    def to_bytes(self) -> bytes:
        pairs = []
        for key, value in self.options.items():
            result = key + ":"
            if value.mandatory:
                result += "1"
            else:
                result += "0"
            pairs.append(result)
        pairs.sort()
        return ",".join(pairs).encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> "InvoiceCounterpartyDataOptions":
        options = {}
        for pair in data.decode().split(","):
            key, value = pair.split(":")
            options[key] = CounterpartyDataOption(mandatory=value == "1")
        return cls(options)


@dataclass
class Invoice(TLVCodable):
    # Receiving UMA address
    receiver_uma: str

    # Invoice UUID Served as both the identifier of the UMA invoice, and the validation of proof of payment.
    invoice_uuid: str

    # The amount of invoice to be paid in the smalest unit of the ReceivingCurrency.
    amount: int

    # The currency of the invoice
    receving_currency: InvoiceCurrency

    # The unix timestamp the UMA invoice expires
    expiration: int

    # Indicates whether the VASP is a financial institution that requires travel rule information.
    is_subject_to_travel_rule: bool

    # RequiredPayerData the data about the payer that the sending VASP must provide in order to send a payment.
    required_payer_data: Optional[InvoiceCounterpartyDataOptions]

    # UmaVersion is a list of UMA versions that the VASP supports for this transaction. It should be
    # containing the lowest minor version of each major version it supported, separated by commas.
    uma_version: str

    # CommentCharsAllowed is the number of characters that the sender can include in the comment field of the pay request.
    comment_chars_allowed: Optional[int]

    # The sender's UMA address. If this field presents, the UMA invoice should directly go to the sending VASP instead of showing in other formats.
    sender_uma: Optional[str]

    # The maximum number of times the invoice can be paid
    invoice_limit: Optional[int]

    # KYC status of the receiver, default is verified.
    kyc_status: Optional[KycStatus]

    # The callback url that the sender should send the PayRequest to.
    callback: str

    # The signature of the UMA invoice
    signature: Optional[bytes]

    def __init__(
        self,
        receiver_uma: str = "",
        invoice_uuid: str = "",
        amount: int = 0,
        receving_currency: InvoiceCurrency = InvoiceCurrency(),
        expiration: int = 0,
        is_subject_to_travel_rule: bool = False,
        required_payer_data: Optional[InvoiceCounterpartyDataOptions] = None,
        uma_version: str = "",
        comment_chars_allowed: Optional[int] = None,
        sender_uma: Optional[str] = None,
        invoice_limit: Optional[int] = None,
        kyc_status: Optional[KycStatus] = None,
        callback: str = "",
        signature: Optional[bytes] = None,
    ) -> None:
        self.receiver_uma = receiver_uma
        self.invoice_uuid = invoice_uuid
        self.amount = amount
        self.receving_currency = receving_currency
        self.expiration = expiration
        self.is_subject_to_travel_rule = is_subject_to_travel_rule
        self.required_payer_data = required_payer_data
        self.uma_version = uma_version
        self.comment_chars_allowed = comment_chars_allowed
        self.sender_uma = sender_uma
        self.invoice_limit = invoice_limit
        self.kyc_status = kyc_status
        self.callback = callback
        self.signature = signature

    @classmethod
    def tlv_map(cls) -> dict:
        return {
            "receiver_uma": 0,
            "invoice_uuid": 1,
            "amount": 2,
            "receving_currency": 3,
            "expiration": 4,
            "is_subject_to_travel_rule": 5,
            "required_payer_data": 6,
            "uma_version": 7,
            "comment_chars_allowed": 8,
            "sender_uma": 9,
            "invoice_limit": 10,
            "kyc_status": 11,
            "callback": 12,
            "signature": 100,
        }

    def to_bech32_string(self) -> str:
        data = bech32.convertbits(self.to_tlv(), 8, 5)
        if data is None:
            raise ValueError("Failed to convert to bech32")
        return bech32.bech32_encode("uma", data)

    @classmethod
    def from_bech32_string(cls, bech32_str: str) -> "Invoice":
        _, data = bech32.bech32_decode(bech32_str)
        if data is None:
            raise ValueError("Failed to decode bech32")
        tlvs = bech32.convertbits(data, 5, 8)
        if tlvs is None:
            raise ValueError("Failed to convert bits")
        return cls.from_tlv(bytes(tlvs))
