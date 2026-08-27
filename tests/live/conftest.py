"""Gating, fixtures and helpers for the LIVE KSeF integration suite.

These tests hit the **real Polish KSeF test environment**
(``https://api-test.ksef.mf.gov.pl/v2``), not a mock. They are gated off by
default so that a plain ``pytest`` run stays hermetic and network-free.

To run them:

    # Latarnia + public-key tests need no credentials:
    KSEF_LIVE=1 pytest tests/live

    # Certificate (XADES/passwordless) auth needs only a NIP:
    KSEF_LIVE=1 KSEF_TEST_NIP=<NIP> pytest tests/live -k xades

    # Token-auth + session-flow + rate-limits need a KSeF test token too:
    KSEF_LIVE=1 KSEF_TEST_TOKEN=<token> KSEF_TEST_NIP=<NIP> pytest tests/live

Environment variables
---------------------
``KSEF_LIVE``            set to ``1`` to enable *any* live test
``KSEF_TEST_TOKEN``      the KSeF token used for the challenge -> redeem auth
``KSEF_TEST_NIP``        the taxpayer NIP owned by ``KSEF_TEST_TOKEN``
``KSEF_TEST_BUYER_NIP``  optional; invoice buyer NIP (defaults to the seller NIP)
``KSEF_TEST_BASE_URL``   optional; API base URL (defaults to the test env)
``KSEF_TEST_TIMEOUT``    optional per-request timeout, seconds (default 30)
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

from ksef import Environment, KSeFClient, KSeFConfig

if TYPE_CHECKING:
    from ksef.xades import LoadedCertificate

__all__ = [
    "authed_client",
    "buyer_nip",
    "cert_authed_client",
    "env",
    "live_client",
    "live_config",
    "live_nip",
    "self_signed_cert",
]


def env(name: str) -> str:
    return os.environ.get(name, "").strip()


def _truthy(name: str) -> bool:
    return env(name).lower() in {"1", "true", "yes", "on"}


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Apply per-test skips so the suite stays offline unless opted in.

    * Every ``@pytest.mark.live`` test skips unless ``KSEF_LIVE=1``.
    * ``@pytest.mark.live_token`` tests additionally require a token + NIP.
    * ``@pytest.mark.live_nip``  tests additionally require just a NIP.
        Latarnia / public-key tests run with only ``KSEF_LIVE=1``.
    """
    live = _truthy("KSEF_LIVE")
    token = env("KSEF_TEST_TOKEN")
    nip = env("KSEF_TEST_NIP")

    for item in items:
        if not item.get_closest_marker("live"):
            continue

        if not live:
            item.add_marker(
                pytest.mark.skip(reason="Live KSeF tests disabled: set KSEF_LIVE=1")
            )
            continue

        if item.get_closest_marker("live_token"):
            missing = []
            if not token:
                missing.append("KSEF_TEST_TOKEN")
            if not nip:
                missing.append("KSEF_TEST_NIP")
            if missing:
                item.add_marker(
                    pytest.mark.skip(
                        reason="Token-dependent live test needs env: "
                        + ", ".join(missing)
                    )
                )
            continue

        if item.get_closest_marker("live_nip"):
            if not nip:
                item.add_marker(
                    pytest.mark.skip(
                        reason="This live test needs env: KSEF_TEST_NIP"
                    )
                )


# --------------------------------------------------------------------------- #
# fixtures                                                                    #
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def live_nip() -> str:
    return env("KSEF_TEST_NIP")


@pytest.fixture(scope="module")
def live_token() -> str:
    return env("KSEF_TEST_TOKEN")


@pytest.fixture(scope="module")
def buyer_nip() -> str:
    return env("KSEF_TEST_BUYER_NIP") or env("KSEF_TEST_NIP")


@pytest.fixture(scope="module")
def live_config() -> KSeFConfig:
    base = env("KSEF_TEST_BASE_URL") or Environment.TEST.value
    timeout = float(env("KSEF_TEST_TIMEOUT") or 30.0)
    return KSeFConfig(
        base_url=base,
        nip=env("KSEF_TEST_NIP"),
        timeout=timeout,
    )


@pytest.fixture
def live_client(live_config: KSeFConfig) -> KSeFClient:
    return KSeFClient(live_config)


@pytest.fixture(scope="module")
def authed_client(
    live_config: KSeFConfig, live_token: str, live_nip: str
) -> KSeFClient:
    """An ``KSeFClient`` authenticated with the challenge -> redeem handshake."""
    client = KSeFClient(live_config)
    client.authenticate_with_token(live_token, nip=live_nip)
    assert client.is_authenticated
    return client


@pytest.fixture(scope="module")
def self_signed_cert(live_nip: str) -> "LoadedCertificate":
    """A freshly generated self-signed certificate (no password, test env only).

    The serial number ``TINPL-<NIP>`` binds the cert to the authenticated
    taxpayer, so this certificate can only be used to authenticate as ``NIP``.
    """
    pytest.importorskip("signxml", reason="ksef-client[xades] not installed")
    from ksef.xades import LoadedCertificate

    return LoadedCertificate.generate_self_signed_test(
        serial_number=f"TINPL-{live_nip}"
    )


@pytest.fixture(scope="module")
def cert_authed_client(
    live_config: KSeFConfig, live_nip: str, self_signed_cert
) -> KSeFClient:
    """A ``KSeFClient`` authenticated with the XAdES certificate flow.

    Unlike ``authed_client`` (token auth), this needs **only ** ``KSEF_TEST_NIP``
    - no ``KSEF_TEST_TOKEN`` - so the full online-session flow can be exercised
    on the test env with just a NIP.
    """
    from ksef.xades import SubjectIdentifierType

    client = KSeFClient(live_config)
    client.authenticate_with_certificate(
        self_signed_cert,
        nip=live_nip,
        subject_identifier_type=SubjectIdentifierType.CERTIFICATE_SUBJECT,
    )
    assert client.is_authenticated
    return client