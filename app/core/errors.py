"""Typed service errors surfaced through API envelopes."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ServiceError(Exception):
    """Typed domain/application error."""

    code: str
    message: str
    status_code: int
    details: list[dict[str, Any]] = field(default_factory=list)
