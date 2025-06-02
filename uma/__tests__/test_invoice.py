from uma.protocol import invoice
from uma.protocol.counterparty_data import CounterpartyDataKeys
from uma.protocol.kyc_status import KycStatus


def test_invoice_tlv() -> None:
    i = invoice.Invoice(
        receiver_uma="$foo@bar.com",
        invoice_uuid="c7c07fec-cf00-431c-916f-6c13fc4b69f9",
        amount=1000,
        receving_currency=invoice.InvoiceCurrency(
            code="USD",
            name="US Dollar",
            symbol="$",
            decimals=2,
        ),
        expiration=1000000,
        is_subject_to_travel_rule=True,
        required_payer_data=invoice.InvoiceCounterpartyDataOptions(
            options={
                CounterpartyDataKeys.NAME.value: invoice.CounterpartyDataOption(
                    mandatory=False
                ),
                CounterpartyDataKeys.EMAIL.value: invoice.CounterpartyDataOption(
                    mandatory=False
                ),
                CounterpartyDataKeys.COMPLIANCE.value: invoice.CounterpartyDataOption(
                    mandatory=True
                ),
            }
        ),
        comment_chars_allowed=None,
        sender_uma=None,
        max_num_payments=None,
        uma_versions="0.3",
        kyc_status=KycStatus.VERIFIED,
        callback="https://example.com/callback",
        signature=b"signature",
    )

    str = i.to_bech32_string()
    assert (
        str
        == "uma1qqxzgen0daqxyctj9e3k7mgpy33nwcesxanx2cedvdnrqvpdxsenzced8ycnve3dxe3nzvmxvv6xyd3evcusyqsraqp3vqqr24f5gqgf24fjq3r0d3kxzuszqyjqxqgzqszqqr6zgqzszqgxrd3k7mtsd35kzmnrv5arztr9d4skjmp6xqkxuctdv5arqpcrxqhrxzcg2ez4yj2xf9z5grqudp68gurn8ghj7etcv9khqmr99e3k7mf0vdskcmrzv93kkeqfwd5kwmnpw36hyeg73rn40"
    )

    new_i = invoice.Invoice.from_bech32_string(str)
    assert new_i.receiver_uma == i.receiver_uma
    assert new_i.invoice_uuid == i.invoice_uuid
    assert new_i.amount == i.amount
    assert new_i.receving_currency.code == i.receving_currency.code
    assert new_i.receving_currency.name == i.receving_currency.name
    assert new_i.receving_currency.symbol == i.receving_currency.symbol
    assert new_i.expiration == i.expiration
    assert new_i.is_subject_to_travel_rule == i.is_subject_to_travel_rule
    assert new_i.required_payer_data == i.required_payer_data
    assert new_i.uma_versions == i.uma_versions
    assert new_i.kyc_status == i.kyc_status
    assert new_i.callback == i.callback
    assert new_i.signature == i.signature
    assert new_i.comment_chars_allowed == i.comment_chars_allowed
    assert new_i.sender_uma == i.sender_uma
    assert new_i.max_num_payments == i.max_num_payments
    assert new_i.kyc_status == i.kyc_status
    assert new_i.callback == i.callback
    assert new_i.signature == i.signature
