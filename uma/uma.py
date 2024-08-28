# Copyright ©, 2022-present, Lightspark Group, Inc. - All Rights Reserved
import json
import random
from dataclasses import replace
from datetime import datetime, timezone
from math import floor
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import requests
from coincurve.ecdsa import cdata_to_der, der_to_cdata, signature_normalize
from coincurve.keys import PrivateKey, PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from ecies import encrypt

from uma.cert_utils import get_pubkey, get_x509_certs
from uma.exceptions import (
    InvalidCurrencyException,
    InvalidRequestException,
    InvalidSignatureException,
    UnsupportedVersionException,
)
from uma.nonce_cache import INonceCache
from uma.protocol.counterparty_data import (
    CounterpartyDataOption,
    CounterpartyDataOptions,
)
from uma.protocol.currency import Currency
from uma.protocol.kyc_status import KycStatus
from uma.protocol.lnurlp_request import LnurlpRequest
from uma.protocol.lnurlp_response import LnurlComplianceResponse, LnurlpResponse
from uma.protocol.payer_data import (
    CompliancePayerData,
    PayerData,
    compliance_from_payer_data,
    create_payer_data,
)
from uma.protocol.payreq import PayRequest
from uma.protocol.payreq_response import (
    PayReqResponse,
    PayReqResponseCompliance,
    PayReqResponsePaymentInfo,
)
from uma.protocol.post_tx_callback import PostTransactionCallback, UtxoWithAmount
from uma.protocol.pubkey_response import PubkeyResponse
from uma.protocol.invoice import (
    Invoice,
    InvoiceCounterpartyDataOptions,
    InvoiceCurrency,
)
from uma.public_key_cache import IPublicKeyCache
from uma.type_utils import none_throws
from uma.uma_invoice_creator import IUmaInvoiceCreator
from uma.urls import is_domain_local
from uma.version import (
    UMA_PROTOCOL_VERSION,
    ParsedVersion,
    get_supported_major_versions,
    is_version_supported,
    select_lower_version,
)


def fetch_public_key_for_vasp(
    vasp_domain: str, cache: IPublicKeyCache
) -> PubkeyResponse:
    public_key = cache.fetch_public_key_for_vasp(vasp_domain)
    if public_key:
        return public_key

    scheme = "http://" if is_domain_local(vasp_domain) else "https://"
    url = scheme + vasp_domain + "/.well-known/lnurlpubkey"
    try:
        response = _run_http_get(url)
    except Exception as ex:  # pylint: disable=broad-except
        raise InvalidRequestException(
            f"Unable to fetch pubkey from {vasp_domain}. Make sure the vasp domain is correct."
        ) from ex
    public_key = PubkeyResponse.from_json(response)
    cache.add_public_key_for_vasp(vasp_domain, public_key)
    return public_key


def create_pubkey_response(
    signing_cert_chain: str,
    encryption_cert_chain: str,
    expiration_timestamp: Optional[datetime] = None,
) -> PubkeyResponse:
    """
    Creates a pubkey response.

    Args:
        signing_cert_chain: the chain of signing certificates in PEM format.
            The order of the certificates should be from the leaf to the root.
        encryption_cert_chain: the chain of encryption certificates in PEM format.
            The order of the certificates should be from the leaf to the root.
        expiration_timestamp: the expiration timestamp of the public keys.
    """
    signing_certs = get_x509_certs(signing_cert_chain)
    encryption_certs = get_x509_certs(encryption_cert_chain)
    return PubkeyResponse(
        signing_certs,
        encryption_certs,
        get_pubkey(signing_certs[0]),
        get_pubkey(encryption_certs[0]),
        expiration_timestamp,
    )


def parse_pubkey_response(response: str) -> PubkeyResponse:
    return PubkeyResponse.from_json(response)


def _run_http_get(url: str) -> str:
    session = requests.session()
    response = session.get(url=url)
    response.raise_for_status()
    session.close()
    return response.text


def generate_nonce() -> str:
    return str(random.randint(0, 0xFFFFFFFF))


def _sign_payload(payload: bytes, private_key: bytes) -> str:
    key = _load_private_key(private_key)
    signature = key.sign(payload)
    return signature.hex()


def verify_pay_request_signature(
    request: PayRequest, other_vasp_pubkeys: PubkeyResponse, nonce_cache: INonceCache
) -> None:
    if not request.payer_data:
        raise InvalidRequestException(
            "UMA requires payer data in request. For regular LNURL requests, "
            + "payer data is optional and signatures should not be checked."
        )
    compliance_data = compliance_from_payer_data(request.payer_data)
    if not compliance_data:
        raise InvalidRequestException("Missing compliance data in request")

    nonce_cache.check_and_save_nonce(
        compliance_data.signature_nonce,
        _parse_timestamp(compliance_data.signature_timestamp),
    )
    _verify_signature(
        request.signable_payload(),
        compliance_data.signature,
        other_vasp_pubkeys.get_signing_pubkey(),
    )


def _verify_signature(payload: bytes, signature: str, signing_pubkey: bytes) -> None:
    """
    Verifies the signature of the uma request.

    Args:
        payload: the raw payload.
        signature: the hex-encoded signature.
        other_vasp_pubkey: the bytes of the signing public key of the VASP who signed the payload.
    """
    key = _load_public_key(signing_pubkey)
    try:
        _, normalized_signature = signature_normalize(
            der_to_cdata(bytes.fromhex(signature))
        )
        did_verify = key.verify(
            signature=cdata_to_der(normalized_signature),
            message=payload,
        )
        if not did_verify:
            raise InvalidSignature()
    except (ValueError, InvalidSignature) as ex:
        raise InvalidSignatureException() from ex


def _load_public_key(key: bytes) -> PublicKey:
    try:
        return PublicKey(key)
    except ValueError:
        der_key = serialization.load_der_public_key(key)
        return PublicKey(
            der_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )
        )


def _load_private_key(key: bytes) -> PrivateKey:
    try:
        return PrivateKey(key)
    except ValueError:
        return PrivateKey.from_der(key)


def _encrypt_travel_rule_info(
    travel_rule_info: str, receiver_encryption_pubkey: bytes
) -> str:
    public_key = _load_public_key(receiver_encryption_pubkey)
    return encrypt(
        receiver_pk=public_key.format(),
        msg=travel_rule_info.encode(),
    ).hex()


def create_compliance_payer_data(
    receiver_encryption_pubkey: bytes,
    signing_private_key: bytes,
    payer_identifier: str,
    travel_rule_info: Optional[str],
    payer_kyc_status: KycStatus,
    payer_utxos: List[str],
    payer_node_pubkey: Optional[str],
    utxo_callback: str,
    travel_rule_format: Optional[str] = None,
) -> CompliancePayerData:
    timestamp = int(datetime.now(timezone.utc).timestamp())
    nonce = generate_nonce()
    encrypted_travel_rule_info = (
        _encrypt_travel_rule_info(travel_rule_info, receiver_encryption_pubkey)
        if travel_rule_info
        else None
    )
    payload = "|".join([payer_identifier, nonce, str(timestamp)])
    signature = _sign_payload(payload.encode(), signing_private_key)
    return CompliancePayerData(
        kyc_status=payer_kyc_status,
        utxos=payer_utxos,
        node_pubkey=payer_node_pubkey,
        encrypted_travel_rule_info=encrypted_travel_rule_info,
        travel_rule_format=travel_rule_format,
        signature=signature,
        signature_nonce=nonce,
        signature_timestamp=timestamp,
        utxo_callback=utxo_callback,
    )


def create_pay_request(
    receiving_currency_code: str,
    amount: int,
    is_amount_in_receiving_currency: bool,
    payer_identifier: str,
    uma_major_version: int,
    payer_name: Optional[str],
    payer_email: Optional[str],
    payer_compliance: Optional[CompliancePayerData],
    requested_payee_data: Optional[CounterpartyDataOptions] = None,
    comment: Optional[str] = None,
    invoice_uuid: Optional[str] = None,
) -> PayRequest:
    """
    Creates a payreq request object.

    Args:
        receiving_currency_code: The code of the currency that the receiver will receive for this
            payment.
        amount: The amount that the receiver will receive in either the smallest unit of the
            receiving currency (if is_amount_in_receiving_currency is True), or in msats (if false).
        is_amount_in_receiving_currency: Whether the amount field is specified in the smallest unit
            of the receiving currency or in msats (if false).
        payer_identifier: The UMA address of the sender. For example, $alice@vasp.com.
        uma_major_version: The major version of the UMA protocol that this currency adheres to.
            If non-UMA, this version is still relevant for which LUD-21 spec to follow. For the older
            LUD-21 spec, this should be 0. For the newer LUD-21 spec, this should be 1.
        payer_name: The name of the sender if requested by the receiver.
        payer_email: The email of the sender if requested by the receiver.
        payer_compliance: The compliance data of the sender. This is REQUIRED for UMA payments,
            but not for regular LNURL payments.
        requested_payee_data: the additional data about the payee which is requested by the sending
            VASP, if any.
        comment: A comment that the sender wants to add to the payment. This can only be included
            if the receiver included the `commentAllowed` field in the lnurlp response. The length of
            the comment must be less than or equal to the value of `commentAllowed`.
        invoice_uuid: if the PayRequest is for an UMA invoice, this should be the UUID of the invoice.
    """
    if uma_major_version == 0 and not is_amount_in_receiving_currency:
        raise InvalidRequestException(
            "UMA v0 does not support sending amounts in msats. Please set is_amount_in_receiving_currency to True."
        )

    sending_currency_code = (
        receiving_currency_code if is_amount_in_receiving_currency else None
    )
    return PayRequest(
        receiving_currency_code=receiving_currency_code,
        sending_amount_currency_code=sending_currency_code,
        amount=amount,
        payer_data=create_payer_data(
            identifier=payer_identifier,
            name=payer_name,
            email=payer_email,
            compliance=payer_compliance,
        ),
        requested_payee_data=requested_payee_data,
        comment=comment,
        uma_major_version=uma_major_version,
        invoice_uuid=invoice_uuid,
    )


def parse_pay_request(payload: str) -> PayRequest:
    return PayRequest.from_json(payload)


def create_uma_lnurlp_request_url(
    signing_private_key: bytes,
    receiver_address: str,
    sender_vasp_domain: str,
    is_subject_to_travel_rule: bool,
    uma_version_override: Optional[str] = None,
) -> str:
    """
    Creates a signed uma request URL.

    Args:
        signing_private_key: the private key of the VASP that is sending the payment. This will be used to sign the request.
        receiver_address: the address of the receiver of the payment (i.e. $bob@vasp2).
        sender_vasp_domain: the domain of the VASP that is sending the payment. It will be used by the receiver to fetch the public keys of the sender.
        is_subject_to_travel_rule: whether the sending VASP is a financial institution that requires travel rule information.
    """

    nonce = generate_nonce()
    request = LnurlpRequest(
        receiver_address=receiver_address,
        nonce=nonce,
        signature="",
        is_subject_to_travel_rule=is_subject_to_travel_rule,
        vasp_domain=sender_vasp_domain,
        timestamp=datetime.now(timezone.utc),
        uma_version=uma_version_override or UMA_PROTOCOL_VERSION,
    )
    request.signature = _sign_payload(request.signable_payload(), signing_private_key)
    return request.encode_to_url()


def parse_lnurlp_request(url: str) -> LnurlpRequest:
    parsed_url = urlparse(url)
    query = parse_qs(parsed_url.query, keep_blank_values=True)
    signature = query.get("signature", [""])[0] if query.get("signature") else None
    vasp_domain = query.get("vaspDomain", [""])[0] if query.get("vaspDomain") else None
    nonce = query.get("nonce", [""])[0] if query.get("nonce") else None
    timestamp = query.get("timestamp", [""])[0] if query.get("timestamp") else None
    uma_version = query.get("umaVersion", [""])[0] if query.get("umaVersion") else None

    if uma_version and not is_version_supported(uma_version):
        raise UnsupportedVersionException(
            unsupported_version=uma_version,
            supported_major_versions=get_supported_major_versions(),
        )

    required_uma_fields = {
        "signature": signature,
        "vasp_domain": vasp_domain,
        "nonce": nonce,
        "timestamp": timestamp,
        "uma_version": uma_version,
    }
    # UMA fields are all or nothing. If any are present, all must be present.
    has_an_uma_field = any(required_uma_fields.values())
    has_all_uma_fields = all(required_uma_fields.values())
    if has_an_uma_field and not has_all_uma_fields:
        raise InvalidRequestException(
            "Missing uma query parameters: vaspDomain, signature, nonce, uma_version, and timestamp are required."
        )

    paths = parsed_url.path.split("/")
    if len(paths) != 4 or paths[1] != ".well-known" or paths[2] != "lnurlp":
        raise InvalidRequestException("Invalid request path.")

    receiver_address = paths[3] + "@" + parsed_url.netloc
    is_subject_to_travel_rule = (
        query.get("isSubjectToTravelRule", [""])[0].lower() == "true"
    )

    return LnurlpRequest(
        receiver_address=receiver_address,
        nonce=nonce,
        signature=signature,
        is_subject_to_travel_rule=is_subject_to_travel_rule,
        vasp_domain=vasp_domain,
        timestamp=(_parse_timestamp(int(timestamp)) if timestamp else None),
        uma_version=uma_version,
    )


def is_uma_lnurlp_query(url: str) -> bool:
    try:
        request = parse_lnurlp_request(url)
        return request.is_uma_request()
    except UnsupportedVersionException:
        # Unsupported versions are still UMA requests. The version negotiation
        # should be handled by the VASP when parsing the request.
        return True
    except Exception:  # pylint: disable=broad-except
        return False


def verify_uma_lnurlp_query_signature(
    request: LnurlpRequest, other_vasp_pubkeys: PubkeyResponse, nonce_cache: INonceCache
) -> None:
    """
    Verifies the signature on an uma Lnurlp query based on the public key of the VASP making the request.

    Args:
        request: the signed request to verify.
        other_vasp_signing_pubkey: the public key of the VASP making this request in bytes.
    """
    if not request.signature or not request.nonce or not request.timestamp:
        raise InvalidRequestException(
            "Missing uma query parameters: signature, nonce and timestamp are required."
        )

    nonce_cache.check_and_save_nonce(request.nonce, request.timestamp)
    _verify_signature(
        request.signable_payload(),
        none_throws(request.signature),
        other_vasp_pubkeys.get_signing_pubkey(),
    )


def _add_invoice_uuid_to_metadata(metadata: str, invoice_uuid: str) -> str:
    try:
        data = json.loads(metadata)
        data.append(["text/plain", invoice_uuid])
        return json.dumps(data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}") from e


def create_pay_req_response(
    request: PayRequest,
    invoice_creator: IUmaInvoiceCreator,
    metadata: str,
    receiving_currency_code: Optional[str],
    receiving_currency_decimals: Optional[int],
    msats_per_currency_unit: Optional[float],
    receiver_fees_msats: Optional[int],
    receiver_node_pubkey: Optional[str],
    utxo_callback: Optional[str],
    payee_identifier: Optional[str],
    signing_private_key: Optional[bytes],
    receiver_utxos: Optional[List[str]] = None,
    payee_data: Optional[PayerData] = None,
    disposable: bool = True,
    success_action: Optional[Dict[str, str]] = None,
) -> PayReqResponse:
    """
    Creates an uma pay request response with an encoded invoice.

    Args:
        request: the uma pay request.This will be used to sign the request.
        invoice_creator: the object that will create the invoice. In practice, this is usually a `services.LightsparkClient`.
        metadata: the metadata that will be added to the invoice's metadata hash field.
        receiving_currency_code: the code of the currency that the receiver will receive for this payment. Required for UMA transactions.
        receiving_currency_decimals: the number of decimal places in the specified currency. For example, USD has 2 decimal
            places. This should align with the decimals field returned for the chosen currency in the LNURLP response. Required for UMA transactions.
        msats_per_currency_unit: milli-satoshis per the smallest unit of the specified currency. This rate is committed to by the receiving VASP until the
            invoice expires. Required for UMA transactions.
        receiver_fees_msats: the fees charged (in millisats) by the receiving VASP to convert to the target currency. This is separate from the
            conversion rate. Required for UMA transactions.
        receiver_node_pubkey: the public key of the receiver node.
        utxo_callback: the URL that the receiving VASP will call to send UTXOs of the channel that the receiver used to receive the payment once it completes.
        payee_identifier: the identifier of the receiver. For example, $bob@vasp2.com. Required for UMA transactions.
        signing_private_key: the private key of the VASP that is receiving the payment. This will be used to sign the request. Required for UMA transactions.
        receiver_utxos: the list of UTXOs of the receiver's channels that might be used to fund the payment.
        payee_data: the additional data about the payee which was requested in the pay request by the sending VASP, if any.
        disposable: This field may be used by a WALLET to decide whether the initial LNURL link will be stored locally for later reuse or erased.
            If disposable is null, it should be interpreted as true, so if SERVICE intends its LNURL links to be stored it must return
            `disposable: false`. UMA should never return `disposable: false`. See LUD-11.
        success_action: an action that the wallet should take once the payment is complete. See LUD-09
    """
    if (
        request.sending_amount_currency_code
        and request.sending_amount_currency_code != receiving_currency_code
    ):
        raise InvalidCurrencyException(
            "The sending currency code in the pay request does not match the receiving currency code."
        )
    required_uma_fields = {
        "receiving_currency_code": receiving_currency_code,
        "receiving_currency_decimals": receiving_currency_decimals,
        "msats_per_currency_unit": msats_per_currency_unit,
        "receiver_fees_msats": receiver_fees_msats,
        "payee_identifier": payee_identifier,
        "signing_private_key": signing_private_key,
    }
    if request.is_uma_request():
        for field, value in required_uma_fields.items():
            if value is None:
                raise InvalidRequestException(
                    f"Missing required field {field} for UMA request."
                )

    sending_currency = request.sending_amount_currency_code
    amount_msats = (
        request.amount
        if sending_currency is None
        or msats_per_currency_unit is None
        or receiver_fees_msats is None
        else request.amount * msats_per_currency_unit + receiver_fees_msats
    )
    receiving_amount = (
        request.amount
        if sending_currency is not None
        or msats_per_currency_unit is None
        or receiver_fees_msats is None
        else floor((request.amount - receiver_fees_msats) / msats_per_currency_unit)
    )
    if request.payer_data:
        metadata += json.dumps(request.payer_data)

    if request.invoice_uuid:
        metadata = _add_invoice_uuid_to_metadata(metadata, request.invoice_uuid)

    encoded_invoice = invoice_creator.create_uma_invoice(
        amount_msats=round(amount_msats),
        metadata=metadata,
        receiver_identifier=payee_identifier,
    )
    payer_identifier = request.payer_data["identifier"] if request.payer_data else None
    if not payer_identifier and request.is_uma_request():
        raise InvalidRequestException("Missing payer identifier in request")
    if request.is_uma_request():
        payee_data = payee_data or {}
        payee_data["compliance"] = _create_compliance_payee_data(
            signing_private_key=none_throws(signing_private_key),
            payer_identifier=none_throws(payer_identifier),
            payee_identifier=none_throws(payee_identifier),
            receiver_utxos=receiver_utxos or [],
            receiver_node_pubkey=receiver_node_pubkey,
            utxo_callback=utxo_callback or "",
        ).to_dict()
        payee_data["identifier"] = payee_identifier
    return PayReqResponse(
        encoded_invoice=encoded_invoice,
        routes=[],
        payee_data=payee_data,
        payment_info=(
            PayReqResponsePaymentInfo(
                amount=receiving_amount,
                currency_code=none_throws(receiving_currency_code),
                decimals=none_throws(receiving_currency_decimals),
                multiplier=none_throws(msats_per_currency_unit),
                exchange_fees_msats=none_throws(receiver_fees_msats),
            )
            if receiving_currency_code is not None
            and msats_per_currency_unit is not None
            else None
        ),
        disposable=disposable,
        success_action=success_action,
        uma_major_version=request.uma_major_version,
    )


def _create_compliance_payee_data(
    signing_private_key: bytes,
    payer_identifier: str,
    payee_identifier: str,
    receiver_utxos: List[str],
    receiver_node_pubkey: Optional[str],
    utxo_callback: str,
) -> PayReqResponseCompliance:
    timestamp = int(datetime.now(timezone.utc).timestamp())
    nonce = generate_nonce()
    compliance_payee_data = PayReqResponseCompliance(
        utxos=receiver_utxos,
        utxo_callback=utxo_callback,
        node_pubkey=receiver_node_pubkey,
        signature="",
        signature_nonce=nonce,
        signature_timestamp=timestamp,
    )
    payload = compliance_payee_data.signable_payload(payer_identifier, payee_identifier)
    signature = _sign_payload(payload, signing_private_key)
    compliance_payee_data.signature = signature
    return compliance_payee_data


def parse_pay_req_response(payload: str) -> PayReqResponse:
    return PayReqResponse.from_json(payload)


def verify_pay_req_response_signature(
    sender_address: str,
    receiver_address: str,
    response: PayReqResponse,
    other_vasp_pubkeys: PubkeyResponse,
    nonce_cache: INonceCache,
) -> None:
    payee_data = response.payee_data
    if not payee_data:
        raise InvalidRequestException(
            "Missing payee data in response. Cannot verify signature."
        )
    compliance_data = response.get_compliance()
    if not compliance_data:
        raise InvalidRequestException("Missing compliance data in response")

    if response.uma_major_version != 1:
        raise InvalidRequestException(
            "Signatures were added to payreq responses in UMA v1. This response is from an UMA v0 receiving VASP."
        )

    payee_data_identifier = payee_data.get("identifier")
    if (
        payee_data_identifier is not None
        and payee_data_identifier.lower() != receiver_address.lower()
    ):
        raise InvalidRequestException(
            f"Payee data identifier {payee_data_identifier} does not match receiver address {receiver_address}."
        )
    if payee_data_identifier is None:
        payee_data_identifier = receiver_address

    nonce_cache.check_and_save_nonce(
        none_throws(compliance_data.signature_nonce),
        _parse_timestamp(none_throws(compliance_data.signature_timestamp)),
    )
    _verify_signature(
        compliance_data.signable_payload(sender_address, payee_data_identifier),
        none_throws(compliance_data.signature),
        other_vasp_pubkeys.get_signing_pubkey(),
    )


def create_uma_lnurlp_response(
    request: LnurlpRequest,
    signing_private_key: bytes,
    requires_travel_rule_info: bool,
    callback: str,
    encoded_metadata: str,
    min_sendable_sats: int,
    max_sendable_sats: int,
    payer_data_options: CounterpartyDataOptions,
    currency_options: List[Currency],
    receiver_kyc_status: KycStatus,
    comment_chars_allowed: Optional[int] = None,
    nostr_pubkey: Optional[str] = None,
) -> LnurlpResponse:
    if not request.is_uma_request():
        raise InvalidRequestException(
            "The request is not a UMA request. Cannot create an UMA response. "
            + "Just create an LnurlpResponse directly instead."
        )
    uma_version = select_lower_version(
        none_throws(request.uma_version), UMA_PROTOCOL_VERSION
    )
    compliance = _create_signed_lnurlp_compliance_response(
        request=request,
        signing_private_key=signing_private_key,
        is_subject_to_travel_rule=requires_travel_rule_info,
        receiver_kyc_status=receiver_kyc_status,
    )
    _validate_currency_options(currency_options)
    # Ensure correct serializing for UMA V0:
    if ParsedVersion.load(uma_version).major == 0:
        for currency in currency_options:
            currency.uma_major_version = 0

    # compliance and identifier are mandatory fields for UMA
    if "compliance" not in payer_data_options:
        payer_data_options["compliance"] = CounterpartyDataOption(mandatory=True)
    if "identifier" not in payer_data_options:
        payer_data_options["identifier"] = CounterpartyDataOption(mandatory=True)

    return LnurlpResponse(
        tag="payRequest",
        callback=callback,
        min_sendable=min_sendable_sats * 1000,
        max_sendable=max_sendable_sats * 1000,
        encoded_metadata=encoded_metadata,
        currencies=currency_options,
        required_payer_data=payer_data_options,
        compliance=compliance,
        uma_version=uma_version,
        comment_chars_allowed=comment_chars_allowed,
        nostr_pubkey=nostr_pubkey,
        allows_nostr=nostr_pubkey is not None,
    )


def _create_signed_lnurlp_compliance_response(
    request: LnurlpRequest,
    signing_private_key: bytes,
    is_subject_to_travel_rule: bool,
    receiver_kyc_status: KycStatus,
) -> LnurlComplianceResponse:
    timestamp = int(datetime.now(timezone.utc).timestamp())
    nonce = generate_nonce()
    payload = "|".join([request.receiver_address, nonce, str(timestamp)])
    signature = _sign_payload(payload.encode(), signing_private_key)
    return LnurlComplianceResponse(
        kyc_status=receiver_kyc_status,
        signature=signature,
        signature_nonce=nonce,
        signature_timestamp=timestamp,
        is_subject_to_travel_rule=is_subject_to_travel_rule,
        receiver_identifier=request.receiver_address,
    )


def parse_lnurlp_response(payload: str) -> LnurlpResponse:
    return LnurlpResponse.from_json(payload)


def verify_uma_lnurlp_response_signature(
    response: LnurlpResponse,
    other_vasp_pubkeys: PubkeyResponse,
    nonce_cache: INonceCache,
) -> None:
    if not response.compliance:
        raise InvalidRequestException("Missing compliance data in response")

    nonce_cache.check_and_save_nonce(
        response.compliance.signature_nonce,
        _parse_timestamp(response.compliance.signature_timestamp),
    )
    _verify_signature(
        response.signable_payload(),
        none_throws(response.compliance).signature,
        other_vasp_pubkeys.get_signing_pubkey(),
    )


def _validate_currency_options(currency_options: List[Currency]) -> None:
    for currency in currency_options:
        if currency.millisatoshi_per_unit <= 0:
            raise InvalidCurrencyException(
                f"Invalid currency option {currency.code}. The multiplier must be greater than 0."
            )
        if currency.min_sendable < 0 or currency.max_sendable < 0:
            raise InvalidCurrencyException(
                f"Invalid currency option {currency.code}. The min and max sendable amounts must be greater than 0."
            )
        if currency.min_sendable > currency.max_sendable:
            raise InvalidCurrencyException(
                f"Invalid currency option {currency.code}. The min sendable amount must be less than or equal to the max sendable amount."
            )
        if currency.decimals < 0 or currency.decimals > 8:
            raise InvalidCurrencyException(
                f"Invalid currency option {currency.code}. The number of decimals must be between 0 and 8."
            )


def get_vasp_domain_from_uma_address(uma_address: str) -> str:
    # Gets the domain of the VASP from an uma address.

    [_, domain] = uma_address.split("@")
    return domain


def create_post_transaction_callback(
    utxos: List[UtxoWithAmount],
    vasp_domain: str,
    signing_private_key: bytes,
) -> PostTransactionCallback:
    """
    Creates a signed post transaction callback.

    Args:
        utxos: UTXOs of the channels of the VASP initiating the callback.
        vasp_domain: the domain of the VASP initiating the callback.
        signing_private_key: the private key of the VASP initiating the callback. This will be used to sign the request.
    """
    timestamp = int(datetime.now(timezone.utc).timestamp())
    nonce = generate_nonce()
    post_transaction_callback = PostTransactionCallback(
        utxos=utxos,
        vasp_domain=vasp_domain,
        signature="",
        signature_nonce=nonce,
        signature_timestamp=timestamp,
    )
    payload = post_transaction_callback.signable_payload()
    signature = _sign_payload(payload, signing_private_key)
    post_transaction_callback.signature = signature
    return post_transaction_callback


def parse_post_transaction_callback(payload: str) -> PostTransactionCallback:
    return PostTransactionCallback.from_json(payload)


def verify_post_transaction_callback_signature(
    callback: PostTransactionCallback,
    other_vasp_pubkeys: PubkeyResponse,
    nonce_cache: INonceCache,
) -> None:
    """
    Verifies the signature on a post transaction callback based on the public key of the counterparty

    Args:
        callback: the signed callback to verify.
        other_vasp_signing_pubkey: the public key of the counterparty VASP.
        nonce_cache: the nonce cache used to prevent replay attacks.
    """
    if (
        not callback.signature
        or not callback.signature_nonce
        or not callback.signature_timestamp
    ):
        raise InvalidRequestException(
            "Missing post transaction callback signature, nonce, or timestamp. Is this an UMA v0 callback? If so, don't verify the signature."
        )
    nonce_cache.check_and_save_nonce(
        callback.signature_nonce,
        _parse_timestamp(callback.signature_timestamp),
    )
    _verify_signature(
        callback.signable_payload(),
        none_throws(callback.signature),
        other_vasp_pubkeys.get_signing_pubkey(),
    )


def _parse_timestamp(
    timestamp: float,
) -> datetime:
    try:
        return datetime.fromtimestamp(timestamp, timezone.utc)
    except ValueError as ex:
        raise InvalidRequestException("Invalid timestamp in request.") from ex


def create_uma_invoice(
    receiver_uma: str,
    receiving_currency_amount: int,
    receiving_currency: InvoiceCurrency,
    expiration: datetime,
    callback: str,
    is_subject_to_travel_rule: bool,
    signing_private_key: bytes,
    required_payer_data: Optional[CounterpartyDataOptions] = None,
    comment_chars_allowed: Optional[int] = None,
    receiver_kyc_status: Optional[KycStatus] = None,
    invoice_limit: Optional[int] = None,
    sender_uma: Optional[str] = None,
) -> Invoice:
    """
    Creates a UMA invoice.

    Args:
        receiver_uma: the UMA address of the receiver.
        receiving_currency_amount: the amount that the receiver will receive in either the smallest unit of the receiving currency.
        receiving_currency: the currency that the receiver will receive for this payment.
        expiration: the expiration time of the invoice in seconds.
        callback: the URL that the receiver will call to send UTXOs of the channel that the receiver used to receive the payment once it completes.
        is_subject_to_travel_rule: whether the receiver is a financial institution that requires travel rule information.
        signing_private_key: the private key of the VASP that is creating the invoice. This will be used to sign the request.
        required_payer_data: RequiredPayerData the data about the payer that the sending VASP must provide in order to send a payment.
        comment_chars_allowed: the number of characters that the receiver allows in the comment field.
        receiver_kyc_status: the KYC status of the receiver.
        invoice_limit: the maximum times of the invoice can be paid.
        sender_uma: the UMA address of the sender.
    """
    uuid = str(uuid4())
    invoice_required_payer_data = (
        InvoiceCounterpartyDataOptions(options=required_payer_data)
        if required_payer_data
        else None
    )
    invoice = Invoice(
        receiver_uma=receiver_uma,
        invoice_uuid=uuid,
        amount=receiving_currency_amount,
        receving_currency=receiving_currency,
        expiration=int(expiration.timestamp()),
        is_subject_to_travel_rule=is_subject_to_travel_rule,
        required_payer_data=invoice_required_payer_data,
        uma_version=UMA_PROTOCOL_VERSION,
        comment_chars_allowed=comment_chars_allowed,
        sender_uma=sender_uma,
        invoice_limit=invoice_limit,
        kyc_status=receiver_kyc_status,
        callback=callback,
    )

    payload = invoice.to_tlv()
    signature = _sign_payload(payload, signing_private_key)
    invoice.signature = bytes.fromhex(signature)
    return invoice


def verify_uma_invoice_signature(
    invoice: Invoice,
    other_vasp_pubkeys: PubkeyResponse,
) -> None:
    new_invoice = replace(invoice, signature=None)
    signature = invoice.signature
    if not signature:
        print("No signature in invoice")
    _verify_signature(
        new_invoice.to_tlv(),
        none_throws(signature).hex(),
        other_vasp_pubkeys.get_signing_pubkey(),
    )
