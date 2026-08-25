"""Configuration for the KSeF client."""

from __future__ import annotations

import ssl
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol

from ksef.models import Environment


class HTTPTransport(Protocol):
    """Minimal transport seam so tests can stub the network layer."""

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        timeout: float = 30.0,
    ) -> tuple[int, dict[str, str], bytes]:
        """Return (status_code, response_headers, response_body)."""
        ...  # pragma: no cover


class UrllibTransport:
    """Default stdlib-only transport."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context())
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        timeout: float = 30.0,
    ) -> tuple[int, dict[str, str], bytes]:
        req = urllib.request.Request(url, data=body, method=method)
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                return resp.status, dict(resp.headers.items()), resp.read()
        except urllib.error.HTTPError as exc:  # 4xx/5xx
            return exc.code, dict(exc.headers.items()), exc.read()


@dataclass(frozen=True, slots=True)
class KSeFConfig:
    """Client configuration.

    Attributes:
        environment: API base URL source.
        base_url: Explicit base URL override (e.g. a mock server in tests).
        nip: Default taxpayer NIP used as authentication context.
        timeout: Per-request timeout in seconds.
        max_retries: Retries on transient failures (429 / 5xx).
        extra_headers: Headers merged into every request.
    """

    base_url: str = field(default_factory=lambda: Environment.TEST.value)
    nip: str | None = None
    timeout: float = 30.0
    max_retries: int = 2
    extra_headers: dict[str, str] = field(default_factory=dict)

    @staticmethod
    def for_environment(environment: Environment) -> KSeFConfig:
        return KSeFConfig(base_url=environment.value)

    def with_nip(self, nip: str) -> KSeFConfig:
        return KSeFConfig(
            base_url=self.base_url,
            nip=nip,
            timeout=self.timeout,
            max_retries=self.max_retries,
            extra_headers=dict(self.extra_headers),
        )


def default_transport() -> HTTPTransport:
    return UrllibTransport()
