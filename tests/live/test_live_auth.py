"""LIVE tests for the KSeF token + X.509 (XAdES) authentication flows.

Requires ``KSEF_LIVE=1 KSEF_TEST_TOKEN=<token> KSEF_TEST_NIP=<NIP>``.

The XAdES certificate path is **fully passwordless and self-contained**: it
generates a fresh self-signed X.509 certificate on the fly with
``LoadedCertificate.generate_self_signed_test`` (no private-key password,
serial ``TINPL-<NIP>`` binding the cert to the authenticated subject), signs
the ``AuthTokenRequest`` with it, and submits via ``/auth/xades-signature``.
"""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.live, pytest.mark.live_token]

from ksef import KSeFClient, KSeFConfig  # noqa: E402
from ksef.xades import (  # noqa: E402
    LoadedCertificate,
    SubjectIdentifierType,
)


@pytest.fixture(scope="module")
def self_signed_cert(live_nip: str) -> LoadedCertificate:
    """A freshly generated self-signed certificate (no password).

    KSeF's test environment accepts self-signed certificates; the serial
    number attribute carries ``TINPL-<NIP>`` so the cert is bound to the
    authenticated taxpayer NIP.
    """
    pytest.importorskip("signxml", reason="ksef-client[xades] not installed")
    return LoadedCertificate.generate_self_signed_test(
        serial_number=f"TINPL-{live_nip}"
    )


def test_token_auth_handshake_live(
    live_config: KSeFConfig, live_token: str, live_nip: str
) -> None:
    """Full KSeF token flow: challenge -> RSA-OAEP token -> poll -> redeem."""
    client = KSeFClient(live_config)
    tokens = client.authenticate_with_token(live_token, nip=live_nip)

    assert tokens.access_token, "no access token returned"
    assert tokens.refresh_token, "no refresh token returned"
    assert client.is_authenticated
    # An access token must be a real Bearer credential, not an obvious stub.
    assert len(tokens.access_token) >= 20


def test_refresh_access_token_live(authed_client) -> None:
    """POST /auth/token/refresh must rotate the access token in place."""
    before = authed_client._tokens
    assert before is not None

    refreshed = authed_client.refresh_access_token()

    assert refreshed.access_token
    assert refreshed.refresh_token
    assert refreshed.access_token != before.access_token


def test_certificate_xades_auth_live(
    live_config: KSeFConfig, live_nip: str, self_signed_cert: LoadedCertificate
) -> None:
    """XAdES cert auth with an auto-generated self-signed cert (passwordless)."""
    client = KSeFClient(live_config)
    tokens = client.authenticate_with_certificate(
        self_signed_cert,
        nip=live_nip,
        subject_identifier_type=SubjectIdentifierType.CERTIFICATE_SUBJECT,
    )

    assert tokens.access_token
    assert tokens.refresh_token
    assert client.is_authenticated