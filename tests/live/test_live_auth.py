"""LIVE tests for the KSeF token + certificate (XAdES) authentication flows.

Requires ``KSEF_LIVE=1 KSEF_TEST_TOKEN=<token> KSEF_TEST_NIP=<NIP>``.
"""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.live, pytest.mark.live_token]

from ksef import KSeFClient, KSeFConfig  # noqa: E402
from ksef.xades import LoadedCertificate, SubjectIdentifierType  # noqa: E402


def test_token_auth_handshake_live(
    live_config: KSeFConfig, live_token: str, live_nip: str
):
    """Full KSeF-token flow: challenge -> RSA-OAEP token -> poll -> redeem."""
    client = KSeFClient(live_config)
    tokens = client.authenticate_with_token(live_token, nip=live_nip)

    assert tokens.access_token, "no access token returned"
    assert tokens.refresh_token, "no refresh token returned"
    assert client.is_authenticated
    # Access token must be a real Bearer credential (not an obvious stub).
    assert len(tokens.access_token) >= 20


def test_refresh_access_token_live(authed_client):
    """POST /auth/token/refresh must rotate the access token in place."""
    before = authed_client._tokens
    assert before is not None

    refreshed = authed_client.refresh_access_token()

    assert refreshed.access_token
    assert refreshed.refresh_token
    assert refreshed.access_token != before.access_token


def test_certificate_xades_auth_live(live_config: KSeFConfig, live_nip: str):
    """XAdES certificate auth with a self-signed test cert (test env accepts).

    The certificate's serial number carries ``TINPL-<NIP>`` matching the
    authenticated subject, mirroring how CIRFMF's reference clients generate
    test certificates.
    """
    signxml = pytest.importorskip("signxml", reason="ksef-client[xades] not installed")

    cert = signxml_self_signed(live_nip)
    client = KSeFClient(live_config)
    tokens = client.authenticate_with_certificate(
        cert,
        nip=live_nip,
        subject_identifier_type=SubjectIdentifierType.CERTIFICATE_SUBJECT,
    )

    assert tokens.access_token
    assert tokens.refresh_token
    assert client.is_authenticated


def signxml_self_signed(nip: str):
    from ksef.xades import LoadedCertificate

    return LoadedCertificate.generate_self_signed_test(serial_number=f"TINPL-{nip}")