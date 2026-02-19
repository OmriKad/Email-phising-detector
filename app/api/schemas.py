"""Pydantic models for Gmail API format and detection responses."""
from typing import Any, List, Literal, Optional
from pydantic import BaseModel, Field


class Header(BaseModel):
    """Email header following RFC 5322 format."""
    # Using Optional[str] because some malformed headers might have null values
    name: Optional[str] = None 
    value: Optional[str] = None


class MessagePartBody(BaseModel):
    """Message part body content."""
    data: Optional[str] = None
    size: Optional[int] = None
    attachmentId: Optional[str] = None # Added this as it's common in Gmail API


class MessagePart(BaseModel):
    """Gmail MessagePart structure (MIME part)."""
    partId: Optional[str] = None
    mimeType: Optional[str] = None
    filename: Optional[str] = None
    headers: Optional[List[Header]] = None
    body: Optional[MessagePartBody] = None
    parts: Optional[List["MessagePart"]] = None

# CRITICAL: This line is required for recursive models in Pydantic v2
MessagePart.model_rebuild()


class GmailMessage(BaseModel):
    """Gmail message structure for phishing detection."""
    id: Optional[str] = None
    threadId: Optional[str] = None
    snippet: Optional[str] = None
    # Change to Optional to avoid 422 if payload is missing in metadata-only calls
    payload: Optional[MessagePart] = None 
    raw: Optional[str] = None
    # Allow extra fields from the Gmail API that aren't in our model
    class Config:
        extra = "ignore"


class DetectedIndicator(BaseModel):
    """Individual phishing indicator found."""
    type: str = Field(
        ...,
        description="Type of indicator: suspicious_link, spoofed_sender, urgent_language, young_domain"
    )
    description: str = Field(..., description="Human-readable description of what was detected")
    severity: str = Field(..., description="Severity level: high, medium, low")
    details: Optional[dict] = Field(default=None, description="Additional details about the indicator")
    contribution: Optional[float] = Field(
        default=None,
        description="Model contribution score for this indicator (higher means stronger phishing signal)",
    )
    evidence: Optional[List[str]] = Field(
        default=None,
        description="Short evidence strings for why this indicator was raised",
    )
    source: Optional[Literal["ml_feature", "ml_text"]] = Field(
        default=None,
        description="Detection source that produced this indicator",
    )


class PhishingDetectionResponse(BaseModel):
    """Response from phishing detection analysis."""
    risk_score: float = Field(..., ge=0, le=1, description="Risk score from 0 to 1")
    classification: str = Field(..., description="Risk classification: Seems safe, Few indicators found, Major indicators found")
    indicators: List[DetectedIndicator] = Field(default_factory=list, description="List of detected phishing indicators")
    message: str = Field(..., description="Summary message about the detection results")
    model_version: Optional[str] = Field(default=None, description="Model artifact version used for this detection")
    decision_threshold: Optional[float] = Field(default=None, description="Decision threshold used by the detector")
    raw_probability: Optional[float] = Field(default=None, description="Uncalibrated probability before post-processing")
    guardrail_applied: Optional[bool] = Field(
        default=None,
        description="Whether deterministic guardrail policy escalated the final risk score",
    )
    guardrail_reasons: Optional[List[str]] = Field(
        default=None,
        description="Human-readable reasons for guardrail escalation",
    )
