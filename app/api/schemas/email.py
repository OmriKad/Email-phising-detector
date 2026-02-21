"""Gmail-compatible request schemas."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Header(BaseModel):
    """RFC5322-style header entry."""

    name: str | None = None
    value: str | None = None


class MessagePartBody(BaseModel):
    """Gmail message part body data."""

    data: str | None = None
    size: int | None = None
    attachmentId: str | None = None


class MessagePart(BaseModel):
    """Gmail message MIME part."""

    partId: str | None = None
    mimeType: str | None = None
    filename: str | None = None
    headers: list[Header] | None = None
    body: MessagePartBody | None = None
    parts: list["MessagePart"] | None = None


class GmailMessage(BaseModel):
    """Input message shape compatible with Gmail API payloads."""

    model_config = ConfigDict(extra="ignore")

    id: str | None = None
    threadId: str | None = None
    snippet: str | None = None
    payload: MessagePart | None = None
    raw: str | None = None


class DetectRequest(BaseModel):
    """Detect phishing request."""

    message: GmailMessage
    source: Literal["gmail_addon", "streamlit", "api", "unknown"] = Field(default="unknown")


MessagePart.model_rebuild()
