"""Logging setup and redaction utilities."""
from __future__ import annotations

import hashlib
import logging
from typing import Any


def configure_logging() -> None:
    """Configure structured-ish process logging once at startup."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def redact_text(value: str | None, max_preview: int = 64) -> dict[str, Any]:
    """Return hash + preview metadata instead of raw potentially sensitive content."""
    if not value:
        return {"preview": "", "sha256": "", "length": 0}

    digest = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()
    preview = value[:max_preview].replace("\n", " ")
    return {"preview": preview, "sha256": digest, "length": len(value)}
