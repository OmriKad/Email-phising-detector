"""API response envelope schemas."""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    safe = "safe"
    suspicious = "suspicious"
    likely_phishing = "likely_phishing"


class TriggerKind(str, Enum):
    keyword = "keyword"
    link = "link"
    header_field = "header_field"
    sender = "sender"
    attachment = "attachment"
    other = "other"


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class SourceField(str, Enum):
    subject_text = "subject_text"
    body_text = "body_text"
    body_html = "body_html"
    sender_email = "sender_email"
    reply_to_email = "reply_to_email"
    urls = "urls"
    attachment_names = "attachment_names"


class ErrorCode(str, Enum):
    validation_error = "VALIDATION_ERROR"
    payload_too_large = "PAYLOAD_TOO_LARGE"
    model_timeout = "MODEL_TIMEOUT"
    model_provider_error = "MODEL_PROVIDER_ERROR"
    model_contract_violation = "MODEL_CONTRACT_VIOLATION"
    internal_error = "INTERNAL_ERROR"


class Trigger(BaseModel):
    """Structured reason that contributed to the model verdict."""

    kind: TriggerKind
    source_field: SourceField
    value: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    severity: Severity


class DetectionResult(BaseModel):
    """Detection payload inside the response envelope."""

    verdict: Verdict
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(min_length=1)
    triggers: list[Trigger] = Field(default_factory=list)


class ApiError(BaseModel):
    """Typed API error."""

    code: ErrorCode
    message: str
    details: list[dict] = Field(default_factory=list)


class DetectResponse(BaseModel):
    """Versioned envelope returned by all detection responses."""

    schema_version: str = "v1"
    request_id: str
    result: DetectionResult | None
    error: ApiError | None
