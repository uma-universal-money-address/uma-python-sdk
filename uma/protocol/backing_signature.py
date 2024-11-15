from dataclasses import dataclass

from uma.JSONable import JSONable


@dataclass
class BackingSignature(JSONable):
    domain: str
    """
    The domain of the backing VASP that produced the signature. Public keys for this VASP will be fetched
	from this domain at /.well-known/lnurlpubkey and used to verify the signature.
    """

    signature: str
    """
    Signature of the payload by a backing VASP that can attest to the authenticity of the message.
    """
