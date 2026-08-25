"""Latarnia KSeF — public availability-status API (no authentication)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from ksef._http_json import loads
from ksef.models import Environment


class LatarniaCategory(StrEnum):
    MAINTENANCE = "MAINTENANCE"
    FAILURE = "FAILURE"
    TOTAL_FAILURE = "TOTAL_FAILURE"


class LatarniaMessageType(StrEnum):
    FAILURE_START = "FAILURE_START"
    FAILURE_END = "FAILURE_END"
    MAINTENANCE_ANNOUNCEMENT = "MAINTENANCE_ANNOUNCEMENT"


@dataclass(frozen=True, slots=True)
class LatarniaMessage:
    id: str
    category: str
    type: str
    title: str
    text: str
    start: datetime | None
    end: datetime | None
    published: datetime | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> LatarniaMessage:
        return cls(
            id=data["id"],
            category=data["category"],
            type=data["type"],
            title=data.get("title", ""),
            text=data.get("text", ""),
            start=_dt(data.get("start")),
            end=_dt(data.get("end")),
            published=_dt(data.get("published")),
        )


@dataclass(frozen=True, slots=True)
class KSeFAvailability:
    status: str  # AVAILABLE / MAINTENANCE / FAILURE / TOTAL_FAILURE
    messages: tuple[LatarniaMessage, ...]


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class LatarniaClient:
    """Unauthenticated client for the Latarnia status API.

    Endpoints (per CIRFMF/ksef-latarnia open-api.json):
      GET /messages   — current messages
      GET /status     — overall KSeF availability
    """

    def __init__(self, transport: Any, base_url: str = Environment.LATARNIA_PRODUCTION.value) -> None:
        self._transport = transport
        self._base_url = base_url.rstrip("/")

    def _get(self, path: str) -> Any:
        url = f"{self._base_url}{path}"
        status, headers, body = self._transport.request("GET", url, timeout=30.0)
        if status >= 400:
            raise RuntimeError(f"Latarnia HTTP {status}")
        return loads(body)

    def messages(self) -> tuple[LatarniaMessage, ...]:
        data = self._get("/messages")
        return tuple(LatarniaMessage.from_api(item) for item in data)

    def status(self) -> KSeFAvailability:
        data = self._get("/status")
        return KSeFAvailability(
            status=data["status"],
            messages=tuple(
                LatarniaMessage.from_api(m) for m in (data.get("messages") or [])
            ),
        )


__all__ = [
    "KSeFAvailability",
    "LatarniaCategory",
    "LatarniaClient",
    "LatarniaMessage",
    "LatarniaMessageType",
]
