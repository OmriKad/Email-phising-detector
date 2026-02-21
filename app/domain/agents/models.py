"""Domain models for normalized email input and LLM output."""
from __future__ import annotations

from enum import Enum
from ipaddress import ip_address
from urllib.parse import urlparse

from pydantic import BaseModel, Field, model_validator


class AgentVerdict(str, Enum):
    safe = "safe"
    suspicious = "suspicious"
    likely_phishing = "likely_phishing"


class AgentTriggerKind(str, Enum):
    keyword = "keyword"
    link = "link"
    header_field = "header_field"
    sender = "sender"
    attachment = "attachment"
    other = "other"


class AgentSeverity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class AgentSourceField(str, Enum):
    subject_text = "subject_text"
    body_text = "body_text"
    body_html = "body_html"
    sender_email = "sender_email"
    reply_to_email = "reply_to_email"
    urls = "urls"
    attachment_names = "attachment_names"


class NormalizedEmail(BaseModel):
    """Minimal, deterministic normalized input passed into the agent."""

    sender_email: str | None = None
    reply_to_email: str | None = None
    subject_text: str = ""
    body_text: str = ""
    body_html: str = ""
    urls: list[str] = Field(default_factory=list)
    attachment_names: list[str] = Field(default_factory=list)


class AgentTrigger(BaseModel):
    """Model-selected structured reason for a verdict."""

    kind: AgentTriggerKind
    source_field: AgentSourceField
    value: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    severity: AgentSeverity

    @model_validator(mode="after")
    def validate_semantics(self) -> "AgentTrigger":
        """Enforce semantic consistency between trigger fields."""
        value = self.value.strip()
        reason = self.reason.lower()
        is_url = _is_http_url(value)

        if self.kind == AgentTriggerKind.link and not is_url:
            raise ValueError("link trigger must use an http(s) URL value")

        if self.kind == AgentTriggerKind.keyword and is_url:
            raise ValueError("keyword trigger cannot use a URL value")

        if self.kind == AgentTriggerKind.sender and self.source_field not in {
            AgentSourceField.sender_email,
            AgentSourceField.reply_to_email,
        }:
            raise ValueError("sender trigger must use sender_email or reply_to_email source_field")

        if self.kind == AgentTriggerKind.attachment and self.source_field != AgentSourceField.attachment_names:
            raise ValueError("attachment trigger must use attachment_names source_field")

        if self.source_field == AgentSourceField.urls and not is_url:
            raise ValueError("urls source_field requires a URL value")

        if self.source_field in {AgentSourceField.sender_email, AgentSourceField.reply_to_email} and "@" not in value:
            raise ValueError("sender_email/reply_to_email trigger values must look like email addresses")

        if "ip address" in reason or "raw ip" in reason:
            if not is_url:
                raise ValueError("IP-address reason requires a URL value")
            host = urlparse(value).hostname
            if not host or not _is_ip_address(host):
                raise ValueError("IP-address reason requires URL host to be an IP address")

        return self


class AgentOutput(BaseModel):
    """Strict LLM output contract consumed by API layer."""

    verdict: AgentVerdict
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(min_length=1)
    triggers: list[AgentTrigger] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_no_conflicting_evidence(self) -> "AgentOutput":
        """Prevent conflicting kind assignments for the same evidence value."""
        evidence_kinds: dict[tuple[str, str], set[AgentTriggerKind]] = {}

        for trigger in self.triggers:
            key = (trigger.source_field.value, trigger.value.strip().lower())
            evidence_kinds.setdefault(key, set()).add(trigger.kind)

        for (source_field, value), kinds in evidence_kinds.items():
            if AgentTriggerKind.keyword in kinds and AgentTriggerKind.link in kinds and _is_http_url(value):
                raise ValueError(
                    f"same evidence cannot be both keyword and link (source_field={source_field}, value={value})"
                )

        return self


def _is_http_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _is_ip_address(hostname: str) -> bool:
    try:
        ip_address(hostname)
        return True
    except ValueError:
        return False
