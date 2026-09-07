import hashlib

from ecdsa import BadSignatureError

from app import _key, sign


def test_sign_and_verify():
    payload = b"hello"
    sig = bytes.fromhex(sign(payload))
    assert _key.verifying_key.verify(sig, payload, hashfunc=hashlib.sha256)


def test_bad_signature_rejected():
    try:
        _key.verifying_key.verify(b"\x00" * 64, b"hello", hashfunc=hashlib.sha256)
        raised = False
    except BadSignatureError:
        raised = True
    assert raised
