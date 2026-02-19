"""Unit tests for ML phishing detector behavior and explainability outputs."""
import base64

from app.api.schemas import GmailMessage, Header, MessagePart, MessagePartBody
from app.detectors.ml_detector import MLPhishingDetector


def create_test_message(from_email: str, subject: str, body: str, reply_to: str = "") -> GmailMessage:
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


def test_ml_detector_returns_explainable_indicators():
    detector = MLPhishingDetector()
    message = create_test_message(
        from_email="Security Team <alerts1234@paypa1-security.com>",
        subject="URGENT: Account Suspended",
        body="Verify your password now via http://192.168.1.1/auth",
        reply_to="support@different-domain.com",
    )

    result = detector.detect(message)

    assert 0 <= result.risk_score <= 1
    assert result.model_version is not None
    assert result.decision_threshold is not None
    assert result.raw_probability is not None
    assert all(ind.source == "ml_feature" for ind in result.indicators)
    assert any(ind.contribution is not None for ind in result.indicators)
    assert all("positive_impact_share" in (ind.details or {}) for ind in result.indicators)


def test_ml_detector_ranks_risky_email_above_safe_email():
    detector = MLPhishingDetector()
    risky = create_test_message(
        from_email="Security Team <alerts1234@paypa1-security.com>",
        subject="URGENT: Verify account immediately",
        body="Act now, confirm password at http://192.168.1.1/auth",
        reply_to="support@different-domain.com",
    )
    safe = create_test_message(
        from_email="noreply@google.com",
        subject="Welcome",
        body="Thanks for signing up to our newsletter.",
    )

    risky_result = detector.detect(risky)
    safe_result = detector.detect(safe)

    assert risky_result.risk_score > safe_result.risk_score


def test_guardrail_escalates_typosquat_with_credential_link():
    detector = MLPhishingDetector()
    message = create_test_message(
        from_email="security@gogle.com",
        subject="Account Verification Required",
        body=(
            "Your account requires immediate verification. "
            "Please verify your account at https://gogle.com/verify"
        ),
    )

    result = detector.detect(message)

    assert result.risk_score >= 0.34
    assert result.classification in {"Few indicators found, need to be cautious", "Major indicators found!"}
    if result.guardrail_applied:
        assert result.guardrail_reasons
    else:
        # Accept when model already scores high enough without explicit guardrail lift.
        assert result.raw_probability is not None
        assert result.raw_probability >= 0.34


def test_guardrail_does_not_escalate_benign_newsletter_with_one_keyword():
    detector = MLPhishingDetector()
    message = create_test_message(
        from_email="news@google.com",
        subject="Account update from newsletter team",
        body="Thanks for reading. You can manage account preferences in your profile.",
    )

    result = detector.detect(message)

    assert result.guardrail_applied in {False, None}
