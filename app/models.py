"""Pydantic models for Gmail API format and detection responses."""
from typing import Optional, List, Any
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


class PhishingDetectionResponse(BaseModel):
    """Response from phishing detection analysis."""
    risk_score: float = Field(..., ge=0, le=1, description="Risk score from 0 to 1")
    classification: str = Field(..., description="Risk classification: Seems safe, Few indicators found, Major indicators found")
    indicators: List[DetectedIndicator] = Field(default_factory=list, description="List of detected phishing indicators")
    message: str = Field(..., description="Summary message about the detection results")
