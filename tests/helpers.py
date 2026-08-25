"""Shared fake HTTP transport used by both unit and e2e tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass
class RecordedRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes | None


def generate_rsa_keypair() -> tuple[str, str]:
    """Return (private_pem, public_pem) for a fresh RSA-2048 key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub


class FakeTransport:
    """Route-based fake transport.

    Routes map ``(method, path)`` to a handler receiving the request and
    returning ``(status, headers, body)``.
    """

    def __init__(self) -> None:
        self.requests: list[RecordedRequest] = []
        self.routes: dict[tuple[str, str], Callable[[RecordedRequest], tuple[int, dict[str, str], bytes]]] = {}
        self.default_public_key_pem = generate_rsa_keypair()[1]

    def route(
        self,
        method: str,
        path_prefix: str,
        handler: Callable[[RecordedRequest], tuple[int, dict[str, str], bytes]],
    ) -> None:
        self.routes[(method, path_prefix)] = handler

    def request(self, method, url, *, headers=None, body=None, timeout=30.0):
        req = RecordedRequest(method, url, dict(headers or {}), body)
        self.requests.append(req)
        path = urlparse(url).path or "/"
        for prefix in sorted(self.routes, key=lambda k: -len(k[1])):
            if method == prefix[0] and path.startswith(prefix[1]):
                return handler_wrap(self.routes[prefix])(req)
        return 404, {"Content-Type": "application/json"}, b'{"detail": "no route"}'


def handler_wrap(fn):
    def inner(req):
        status, headers, body = fn(req)
        if isinstance(body, (dict, list)):
            import json

            body = json.dumps(body).encode()
        return status, {k.lower(): v for k, v in headers.items()}, body

    return inner


def json_response(payload: Any, status: int = 200) -> tuple[int, dict[str, str], bytes]:
    import json

    return status, {"Content-Type": "application/json"}, json.dumps(payload).encode()


def xml_response(text: str, status: int = 200) -> tuple[int, dict[str, str], bytes]:
    return status, {"Content-Type": "application/xml"}, text.encode()
