"""Tests for the FastAPI endpoints."""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.domain_fetcher import domain_cache
import base64


@pytest.fixture(scope="module")
def client():
    """Create a test client."""
    # Initialize domain cache with test data
    domain_cache.domains = {
        "google.com", "facebook.com", "amazon.com", "microsoft.com", "apple.com",
        "github.com", "twitter.com", "linkedin.com", "netflix.com", "paypal.com"
    }
    domain_cache._initialized = True
    
    return TestClient(app)


@pytest.fixture(autouse=True)
def disable_whois(monkeypatch):
    """Disable WHOIS lookups during tests."""
    monkeypatch.setattr(domain_cache, "get_domain_age", lambda domain: None)


def create_test_payload(from_email: str, subject: str, body: str) -> dict:
    """Helper to create test Gmail message payload."""
    body_b64 = base64.urlsafe_b64encode(body.encode()).decode().rstrip('=')
    
    return {
        "id": "test123",
        "payload": {
            "headers": [
                {"name": "From", "value": from_email},
                {"name": "Subject", "value": subject}
            ],
            "body": {"data": body_b64},
            "mimeType": "text/plain"
        }
    }


def test_root_endpoint(client):
    """Test root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "running"
    assert data["domain_cache_initialized"] is True


def test_health_check(client):
    """Test health check endpoint."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["cached_domains"] > 0


def test_detect_safe_email(client):
    """Test detection of safe email."""
    payload = create_test_payload(
        from_email="noreply@google.com",
        subject="Welcome",
        body="Thank you for signing up."
    )
    
    response = client.post("/api/v1/detect", json=payload)
    assert response.status_code == 200
    
    data = response.json()
    assert data["risk_score"] < 0.33
    assert data["classification"] == "Seems safe"


def test_detect_typosquatting(client):
    """Test detection of typosquatting."""
    payload = create_test_payload(
        from_email="security@gogle.com",
        subject="Security Alert",
        body="Please verify your account immediately."
    )
    
    response = client.post("/api/v1/detect", json=payload)
    assert response.status_code == 200
    
    data = response.json()
    assert data["risk_score"] > 0.5
    assert data["classification"] == "Major indicators found!"
    assert len(data["indicators"]) > 0


def test_detect_multiple_indicators(client):
    """Test email with multiple phishing indicators."""
    payload = create_test_payload(
        from_email="alert@paypa1.com",
        subject="URGENT: Account Suspended",
        body="Your account will be suspended! Click: http://192.168.1.1/verify"
    )
    
    response = client.post("/api/v1/detect", json=payload)
    assert response.status_code == 200
    
    data = response.json()
    assert data["risk_score"] > 0.5
    assert len(data["indicators"]) >= 2


def test_invalid_payload(client):
    """Test with invalid payload."""
    response = client.post("/api/v1/detect", json={"invalid": "data"})
    assert response.status_code == 422  # Validation error
