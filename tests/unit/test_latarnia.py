"""Unit tests: Latarnia availability client."""

from __future__ import annotations

import pytest

from ksef.latarnia import LatarniaClient
from tests.helpers import FakeTransport, json_response


def test_status_available():
    t = FakeTransport()
    t.route("GET", "/status", lambda req: json_response({"status": "AVAILABLE"}))
    client = LatarniaClient(t, base_url="https://latarnia.test")
    st = client.status()
    assert st.status == "AVAILABLE"
    assert st.messages == ()


def test_status_with_maintenance_messages():
    t = FakeTransport()
    msg = {
        "id": "K/2026/NI/01",
        "category": "MAINTENANCE",
        "type": "MAINTENANCE_ANNOUNCEMENT",
        "title": "Przerwa",
        "text": "W dniu ... niedostępność",
        "start": "2026-08-30T22:00:00+00:00",
        "end": "2026-08-31T02:00:00+00:00",
        "published": "2026-08-25T08:00:00+00:00",
    }
    t.route("GET", "/status", lambda req: json_response({"status": "MAINTENANCE", "messages": [msg]}))
    t.route("GET", "/messages", lambda req: json_response([msg]))
    client = LatarniaClient(t, base_url="https://latarnia.test")
    st = client.status()
    assert st.status == "MAINTENANCE"
    assert st.messages[0].id == "K/2026/NI/01"
    msgs = client.messages()
    assert len(msgs) == 1 and msgs[0].category == "MAINTENANCE"


def test_http_error_propagates():
    t = FakeTransport()
    t.route("GET", "/status", lambda req: json_response({"detail": "boom"}, status=500))
    client = LatarniaClient(t, base_url="https://latarnia.test")
    with pytest.raises(RuntimeError, match="500"):
        client.status()
