# Changelog

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
