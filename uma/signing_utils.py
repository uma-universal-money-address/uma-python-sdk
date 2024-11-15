from coincurve.keys import PrivateKey


def sign_payload(payload: bytes, private_key: bytes) -> str:
    key = _load_private_key(private_key)
    signature = key.sign(payload)
    return signature.hex()


def _load_private_key(key: bytes) -> PrivateKey:
    try:
        return PrivateKey(key)
    except ValueError:
        return PrivateKey.from_der(key)
