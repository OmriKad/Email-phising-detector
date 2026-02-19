"""Unit tests for cache-free ML feature extraction."""
import base64

from app.api.schemas import GmailMessage, Header, MessagePart, MessagePartBody
from app.features.email_feature_extractor import EmailFeatureExtractor


def create_test_message(from_email: str, subject: str, body: str, reply_to: str = "") -> GmailMessage:
    """Helper to create test Gmail message."""
    body_b64 = base64.urlsafe_b64encode(body.encode("utf-8")).decode("utf-8").rstrip("=")
    headers = [
        Header(name="From", value=from_email),
        Header(name="Subject", value=subject),
    ]
    if reply_to:
        headers.append(Header(name="Reply-To", value=reply_to))
    return GmailMessage(
        payload=MessagePart(
            headers=headers,
            body=MessagePartBody(data=body_b64),
            mimeType="text/plain",
        )
    )


def test_feature_extraction_is_deterministic():
    extractor = EmailFeatureExtractor()
    message = create_test_message(
        from_email="Security Team <alerts1234@paypa1-security.com>",
        subject="URGENT: Verify your account immediately!!!",
        body="Click here now: http://192.168.1.20/login",
        reply_to="support@different-domain.com",
    )

    first = extractor.extract(message)
    second = extractor.extract(message)

    assert first.features == second.features
    assert first.evidence == second.evidence


def test_feature_extraction_captures_url_and_language_risk():
    extractor = EmailFeatureExtractor()
    message = create_test_message(
        from_email="Security Team <alerts1234@paypa1-security.com>",
        subject="URGENT: Verify your account immediately!!!",
        body=(
            "Your account is suspended. Act now and confirm your password: "
            "http://192.168.1.20/login"
        ),
        reply_to="support@different-domain.com",
    )
    result = extractor.extract(message)

    assert result.features["url_count"] >= 1
    assert result.features["url_ip_count"] >= 1
    assert result.features["language_urgent_terms_count"] >= 1
    assert result.features["language_credential_terms_count"] >= 1
    assert result.features["credential_plus_link_flag"] == 1
    assert result.features["reply_to_mismatch"] == 1
    assert "url_ip_count" in result.evidence


def test_feature_extraction_detects_brand_typosquat():
    extractor = EmailFeatureExtractor()
    message = create_test_message(
        from_email="security@gogle.com",
        subject="Account Verification Required",
        body="Please verify your account: https://gogle.com/verify",
    )
    result = extractor.extract(message)

    assert result.features["sender_brand_typosquat_flag"] == 1
    assert result.features["url_brand_typosquat_flag"] == 1
    assert result.features["sender_brand_min_distance"] < 0.5
    assert result.features["url_brand_min_distance"] < 0.5
    assert "sender_brand_typosquat_flag" in result.evidence
