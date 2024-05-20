# Changelog

## 1.0.6

- Raise InvalidRequestException for invalid request timestamps

## 1.0.5

- Add conversion utils for request params to/from PayRequest
- Fix PayRequest parsing bug

## 1.0.4

- Ensure that compliance and identifier are required in payerdata
- Don't allow sending in msats for UMA v0

## 1.0.3

- Always use a string for the amount in v1 to match the v1 spec.

## 1.0.2

- Avoid defaulting to SAT for empty sending currency to fix msats conversion.

## 1.0.1

- Export the `create_post_transaction_callback` function.

## 1.0.0

- Upgrading to UMA protocol v1.0!
  - Using X.509 Certificates for PKI
  - Adding a signature to the payreq response
  - Add a signature to post-tx hook callback requests
  - Using the new Currency LUD-21 spec to allow locking the sending currency amount.
  - Adding optional Payee Data (LUD-22)
- SDK Improvements
  - Version fallback support. Fully compatible with UMA v0.3 counterparties.
  - Better raw LNURL interoperability.

## 0.6.1

- Export the NonceCache types.

## 0.6.0

- Check and cache nonces when verifying signatures.
- Fix forward compatibility with the `isUmaLnurlpQuery` function.
- Fix setup.cfg paths for README and LICENSE.
- Improve some code documentation.

## 0.5.2

- Use HTTP for more localhost formats to help with local tests.

## 0.5.1

- Fix a typo: s/UtxoWitAmount/UtxoWithAmount/

## 0.5.0

- Add the decimals field to payreq paymentinfo for convenience.
- Make the multiplier here a float to match the Currency object in the lnurlp response.
- Bump version to 0.3 since these are breaking changes. Protocol change: uma-universal-money-address/protocol#14

## v0.4.1

- Fix the top-level min/maxSendable fields on the lnurlpResponse field. They were being set in sats, when they should have been in millisats.

## v0.4.0

- Make the `decimals` field on `Currency` required and change its description to include more details about its use.
- Change the `multiplier` field from int to float to allow for very small unit currencies. See [UMAD-04](https://github.com/uma-universal-money-address/protocol/blob/main/umad-04-lnurlp-response.md) for details on why this is needed.

## v0.3.1

- Normalize signatures before verifying them to allow for high S-values.

## v0.3.0

- Switch `display_decimals` to `decimals` to better match a LUD-21 proposal after discussions with the author.

## v0.2.2

- IMPORTANT: Fix a bug with signature validation to actually ensure the signature matches the pubkey.

## v0.2.1

- Handle null expiration correctly when parsing pubkey responses.

## v0.2.0

- Add the display_decimals field to the currency object in the lnurlp response.

## v0.1.6

- Missed one other mismatched serialized field name.

## v0.1.5

- Fix the serialized names of several fields.

## v0.1.4

- Fix a bug in loading key.

## v0.1.3

- Fix a typo in the pubkey JSON seriailzation.

## v0.1.2

- Support both der and compressed key.

## v0.1.1

- Add optional travel_rule_format to the payreq request.

## v0.1.0

- First version of UMA.
