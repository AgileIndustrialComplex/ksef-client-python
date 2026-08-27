"""LIVE tests for the Latarnia (public availability-status) API.

These are unauthenticated end-to-end checks against the real test Latarnia
endpoint, so they only need ``KSEF_LIVE=1``.
"""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.live]

from ksef import Environment, LatarniaClient  # noqa: E402
from ksef.config import default_transport  # noqa: E402


@pytest.fixture(scope="module")
def latarnia() -> LatarniaClient:
    transport = default_transport()
    return LatarniaClient(
        transport,
        base_url=Environment.LATARNIA_TEST.value,
    )


def test_latarnia_status_live(latarnia: LatarniaClient):
    availability = latarnia.status()

    assert availability.status
    assert availability.status in {"AVAILABLE", "MAINTENANCE", "FAILURE", "TOTAL_FAILURE"}
    assert isinstance(availability.messages, tuple)


def test_latarnia_messages_live(latarnia: LatarniaClient):
    messages = latarnia.messages()

    assert isinstance(messages, tuple)
    for msg in messages:
        assert msg.id
        assert msg.title or msg.text  # message has some body