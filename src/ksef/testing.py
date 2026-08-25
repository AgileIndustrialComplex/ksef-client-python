"""Test-support transport for consumers exercising the KSeF client hermetically.

This module ships with the library so downstream test suites (e.g. a Django
app that wires ksef-client into its invoice pipeline) can simulate the KSeF
API without hitting the network or re-implementing the transport seam.

Example
-------
.. code-block:: python

    from ksef.testing import FakeTransport

    t = FakeTransport()
    t.route("POST", "/auth/challenge", lambda req: json_response({...}))
    client = KSeFClient(config, transport=t)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

from ksef.config import HTTPTransport


@dataclass
class RecordedRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes | None

    @property
    def path(self) -> str:
        return urlparse(self.url).path or "/"

    @property
    def json(self) -> Any:
        return json.loads(self.body) if self.body else None


def json_response(payload: Any, *, status: int = 200) -> tuple[int, dict[str, str], bytes]:
    return status, {"Content-Type": "application/json"}, json.dumps(payload).encode()


def xml_response(text: str, *, status: int = 200) -> tuple[int, dict[str, str], bytes]:
    return status, {"Content-Type": "application/xml"}, text.encode()


class FakeTransport(HTTPTransport):
    """Route-based fake implementing the :class:`HTTPTransport` protocol.

    Routes are keyed by ``(method, path_prefix)``; the longest matching prefix
    wins. Unmatched requests return 404. Every request is recorded on
    :attr:`requests` for assertions.
    """

    def __init__(self) -> None:
        self.requests: list[RecordedRequest] = []
        self.routes: dict[tuple[str, str], Callable[[RecordedRequest], tuple[int, dict[str, str], bytes]]] = {}

    def route(
        self,
        method: str,
        path_prefix: str,
        handler: Callable[[RecordedRequest], tuple[int, dict[str, str], bytes]],
    ) -> None:
        self.routes[(method, path_prefix)] = handler

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        timeout: float = 30.0,
    ) -> tuple[int, dict[str, str], bytes]:
        req = RecordedRequest(method, url, dict(headers or {}), body)
        self.requests.append(req)
        for (r_method, r_prefix), handler in sorted(self.routes.items(), key=lambda kv: -len(kv[0][1])):
            if method == r_method and req.path.startswith(r_prefix):
                return self._call(handler, req)
        return 404, {"Content-Type": "application/json"}, b'{"detail": "no route"}'

    @staticmethod
    def _call(handler, req: RecordedRequest) -> tuple[int, dict[str, str], bytes]:
        status, headers, body = handler(req)
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        return status, {k.lower(): v for k, v in headers.items()}, body


__all__ = ["FakeTransport", "RecordedRequest", "json_response", "xml_response"]