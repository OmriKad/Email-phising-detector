"""Tests for phishing detection logic."""
import pytest
from app.models import GmailMessage, MessagePart, Header, MessagePartBody, DetectedIndicator
from app.phishing_detector import PhishingDetector
from app.domain_fetcher import domain_cache


@pytest.fixture
def setup_domains():
    """Initialize domain cache with test data."""
    if not domain_cache.is_initialized():
        # Use fallback domains for testing
        domain_cache.domains = {
            "google.com", "facebook.com", "amazon.com", "microsoft.com", "apple.com",
            "github.com", "twitter.com", "linkedin.com", "netflix.com", "paypal.com"
        }
        domain_cache._initialized = True
    yield


@pytest.fixture(autouse=True)
def disable_whois(monkeypatch):
    """Disable WHOIS lookups during tests."""
    monkeypatch.setattr(domain_cache, "get_domain_age", lambda domain: None)
    

@pytest.fixture
def detector():
    """Create a PhishingDetector instance."""
    return PhishingDetector()


def create_test_message(from_email: str, subject: str, body: str) -> GmailMessage:
    """Helper to create a test Gmail message."""
    import base64
    
    # Encode body as base64url
    body_bytes = body.encode('utf-8')
    body_b64 = base64.urlsafe_b64encode(body_bytes).decode('utf-8').rstrip('=')
    
    return GmailMessage(
        id="test123",
        payload=MessagePart(
            headers=[
                Header(name="From", value=from_email),
                Header(name="Subject", value=subject),
            ],
            body=MessagePartBody(data=body_b64),
            mimeType="text/plain"
        )
    )


def test_safe_email(setup_domains, detector):
    """Test detection of a safe email from known domain."""
    message = create_test_message(
        from_email="noreply@google.com",
        subject="Welcome to Google",
        body="Thank you for signing up."
    )
    
    result = detector.detect(message)
    
    assert result.risk_score < 0.33
    assert result.classification == "Seems safe"
    assert len(result.indicators) == 0


def test_typosquatting_sender(setup_domains, detector):
    """Test detection of typosquatting in sender domain."""
    message = create_test_message(
        from_email="security@gogle.com",  # Typo of google
        subject="Account Alert",
        body="Please verify your account."
    )
    
    result = detector.detect(message)
    
    assert result.risk_score >= 0.4
    assert result.classification in [
        "Few indicators found, need to be cautious",
        "Major indicators found!"
    ]
    assert any(i.type == "spoofed_sender" for i in result.indicators)
    
    # Check details
    spoofed_indicator = next(i for i in result.indicators if i.type == "spoofed_sender")
    assert spoofed_indicator.severity == "high"
    assert "gogle" in spoofed_indicator.description.lower()


def test_suspicious_link(setup_domains, detector):
    """Test detection of suspicious links."""
    message = create_test_message(
        from_email="noreply@google.com",
        subject="Update Required",
        body="Please click here: https://gogle.com/verify to update your account."
    )
    
    result = detector.detect(message)
    
    assert result.risk_score >= 0.3
    assert any(i.type == "suspicious_link" for i in result.indicators)
    
    link_indicator = next(i for i in result.indicators if i.type == "suspicious_link")
    assert "gogle" in link_indicator.description.lower()


def test_ip_address_url(setup_domains, detector):
    """Test detection of IP address in URL."""
    message = create_test_message(
        from_email="noreply@google.com",
        subject="Security Alert",
        body="Click here: http://192.168.1.1/login"
    )
    
    result = detector.detect(message)
    
    assert result.risk_score > 0.3
    assert any(i.type == "suspicious_link" for i in result.indicators)
    
    link_indicator = next(i for i in result.indicators if i.type == "suspicious_link")
    assert "IP address" in link_indicator.description


def test_urgent_language(setup_domains, detector):
    """Test detection of urgent language patterns."""
    message = create_test_message(
        from_email="security@google.com",
        subject="URGENT: Action Required",
        body="Your account will be suspended immediately unless you verify your identity now!"
    )
    
    result = detector.detect(message)
    
    assert any(i.type == "urgent_language" for i in result.indicators)
    
    language_indicator = next(i for i in result.indicators if i.type == "urgent_language")
    assert language_indicator.severity == "low"


def test_multiple_indicators(setup_domains, detector):
    """Test email with multiple phishing indicators."""
    message = create_test_message(
        from_email="alert@paypa1.com",  # Typosquatting (paypal -> paypa1)
        subject="URGENT: Account Suspended",
        body="Your account has been suspended! Click here immediately: https://192.168.1.1/verify"
    )
    
    result = detector.detect(message)
    
    assert result.risk_score > 0.5
    assert result.classification == "Major indicators found!"
    assert len(result.indicators) >= 2  # Should have multiple indicators


def test_unknown_domain_moderate_score(setup_domains, detector):
    """Test that unknown (but not typosquatting) domains get moderate score."""
    message = create_test_message(
        from_email="info@randomcompany.com",
        subject="Newsletter",
        body="Check out our website: https://randomcompany.com"
    )
    
    result = detector.detect(message)
    
    # Should have some score but not maximum
    assert 0.3 < result.risk_score < 0.6
    assert result.classification in [
        "Seems safe",
        "Few indicators found, need to be cautious"
    ]


def test_levenshtein_threshold(setup_domains, detector):
    """Test that Levenshtein distance threshold is enforced."""
    # Distance of 3 should NOT trigger (threshold is 2)
    message = create_test_message(
        from_email="info@goooooogle.com",  # Distance 3 from google
        subject="Test",
        body="Test message"
    )
    
    result = detector.detect(message)
    
    # Should detect as unknown domain, not typosquatting
    if any(i.type == "spoofed_sender" for i in result.indicators):
        spoofed = next(i for i in result.indicators if i.type == "spoofed_sender")
        assert spoofed.severity != "high"  # Not high severity for distance > 2

