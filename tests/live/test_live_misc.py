"""LIVE tests for transactional endpoints that need only an authenticated client.

Currently exercises ``GET /rate-limits``. Requires
``KSEF_LIVE=1 KSEF_TEST_TOKEN=<token> KSEF_TEST_NIP=<NIP>``.
"""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.live, pytest.mark.live_token]


def test_rate_limits_live(authed_client):
    limits = authed_client.rate_limits()

    # The endpoint returns a structured object; on the test env it is normally
    # the per-TIN / per-IP limits. Don't assert exact values — just that a
    # serialisable body came back.
    assert limits.raw, "empty rate-limits payload"
    assert isinstance(limits.raw, dict)