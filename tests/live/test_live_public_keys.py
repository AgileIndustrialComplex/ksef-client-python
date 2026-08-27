"""LIVE tests for KSeF public-key discovery (no credentials required).

Exercises ``/security/public-key-certificates`` and the encryption-key
extraction. These run with just ``KSEF_LIVE=1``.
"""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.live]

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402


def test_fetch_public_key_certificates_live(live_client):
    certs = live_client.fetch_public_key_certificates()

    assert certs, "no public-key certificates returned"
    # At least one cert must be usable for challenge / session encryption.
    # Live usage tags are compound (e.g. "KsefTokenEncryption") — substring match.
    usable = [
        c
        for c in certs
        if any(t in u for u in (c.get("usage") or []) for t in ("KsefToken", "Encryption"))
    ]
    assert usable, f"no KsefToken/Encryption-capable cert: {certs}"


def test_fetch_public_encryption_key_live(live_client):
    pem = live_client.fetch_public_encryption_key()

    assert "-----BEGIN PUBLIC KEY-----" in pem, f"unexpected key format: {pem[:40]!r}"
    key = serialization.load_pem_public_key(pem.encode())
    assert isinstance(key, rsa.RSAPublicKey)
    assert key.key_size >= 2048