"""Exception hierarchy for the KSeF client."""

from __future__ import annotations


class KSeFClientError(Exception):
    """Base error for all ksef-client failures."""


class KSeFHTTPError(KSeFClientError):
    """Non-2xx HTTP response from the KSeF API."""

    def __init__(self, status_code: int, message: str, details: dict[str, object] | None = None) -> None:
        self.status_code = status_code
        self.details = details or {}
        super().__init__(f"HTTP {status_code}: {message}")


class KSeFAuthenticationError(KSeFClientError):
    """Authentication flow failed or was rejected."""


class KSeFPollingTimeoutError(KSeFClientError):
    """Polling an async operation exceeded the allowed time."""
