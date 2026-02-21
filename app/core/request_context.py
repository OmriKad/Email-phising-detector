"""Request context helpers."""
from __future__ import annotations

import uuid
from contextvars import ContextVar

from fastapi import Request

_REQUEST_ID: ContextVar[str] = ContextVar("request_id", default="")


def get_request_id() -> str:
    """Return the active request ID if available."""
    return _REQUEST_ID.get() or "unknown"


async def request_id_middleware(request: Request, call_next):
    """Attach a request ID to each incoming HTTP request."""
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    token = _REQUEST_ID.set(request_id)
    try:
        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        return response
    finally:
        _REQUEST_ID.reset(token)
