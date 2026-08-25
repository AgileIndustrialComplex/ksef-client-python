"""Unit tests: crypto primitives (RSA-OAEP token encryption, AES-CBC invoices)."""

from __future__ import annotations

import hashlib
from base64 import b64decode

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from ksef.crypto import decrypt_invoice, encrypt_invoice, encrypt_token, new_session_encryption
from tests.helpers import generate_rsa_keypair


@pytest.fixture(scope="module")
def keypair() -> tuple[str, str]:
    return generate_rsa_keypair()


def test_encrypt_token_roundtrip(keypair):
    priv_pem, pub_pem = keypair
    encrypted_b64 = encrypt_token("my-secret-token", "20260825-CR-XXXX", pub_pem)
    raw = b64decode(encrypted_b64)
    # decrypt with the private key to prove OAEP-SHA256 shape
    from cryptography.hazmat.primitives import serialization

    priv = serialization.load_pem_private_key(priv_pem.encode(), password=None)
    plain = priv.decrypt(
        raw,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    assert plain == b"my-secret-token|20260825-CR-XXXX"


def test_encrypt_token_rejects_non_rsa():
    with pytest.raises((ValueError, TypeError)):
        encrypt_token("t", "ts", "not a pem")


def test_new_session_encryption_shape(keypair):
    _, pub = keypair
    enc = new_session_encryption(pub)
    assert len(enc.aes_key) == 32
    assert len(enc.iv) == 16
    api = enc.api_view
    assert len(b64decode(api.encrypted_symmetric_key)) == 256  # RSA-2048 block


def test_invoice_encrypt_decrypt_roundtrip(keypair):
    _, pub = keypair
    enc = new_session_encryption(pub)
    xml = "<Faktura>zażółć gęślą jaźń</Faktura>".encode()
    out = encrypt_invoice(xml, enc)
    assert b64decode(out.sha256_base64) == hashlib.sha256(xml).digest()
    assert decrypt_invoice(out.encrypted_body_b64, enc) == xml


def test_invoice_padding_variants(keypair):
    _, pub = keypair
    for size in (0, 15, 16, 17, 100):
        enc = new_session_encryption(pub)
        data = bytes(range(256))[:size]
        out = encrypt_invoice(data, enc) if size else encrypt_invoice(b"", enc)
        assert decrypt_invoice(out.encrypted_body_b64, enc) == data


def test_decrypt_invalid_padding_raises(keypair):
    _, pub = keypair
    enc = new_session_encryption(pub)
    bad = "AAAAAAAAAAAAAAAAAAAAAA=="
    with pytest.raises(ValueError):
        decrypt_invoice(bad, enc)
