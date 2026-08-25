"""JSON helpers over :mod:`json` with stable error reporting."""

from __future__ import annotations

import json
from typing import Any


def dumps(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=False).encode("utf-8")


def loads(body: bytes) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid JSON payload: {exc}") from exc
