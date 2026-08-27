"""Gating, fixtures and helpers for the LIVE KSeF integration suite.

These tests hit the **real Polish KSeF test environment**
(``https://api-test.ksef.mf.gov.pl/v2``), not a mock. They are gated off by
default so that a plain ``pytest`` run stays hermetic and network-free.

To run them:

    # Latarnia + public-key tests need no credentials:
    KSEF_LIVE=1 pytest tests/live

    # Token-auth + session-flow + rate-limits need a KSeF test token:
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

import pytest

from ksef import Environment, KSeFClient, KSeFConfig

__all__ = [
    "authed_client",
    "buyer_nip",
    "env",
    "live_client",
    "live_config",
    "live_nip",
]


def env(name: str) -> str:
    return os.environ.get(name, "").strip()


def _truthy(name: str) -> bool:
    return env(name).lower() in {"1", "true", "yes", "on"}


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Apply per-test skips so the suite stays offline unless opted in.

    * Every ``@pytest.mark.live`` test skips unless ``KSEF_LIVE=1``.
    * ``@pytest.mark.live_token`` tests additionally require a token + NIP.
        Latarnia / public-key tests run with just ``KSEF_LIVE=1``.
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