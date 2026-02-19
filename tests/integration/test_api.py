"""Integration tests for FastAPI endpoints (ML-only runtime)."""
import base64

import pytest
from fastapi.testclient import TestClient

from app.api.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    """Create API test client."""
    return TestClient(app)


def create_test_payload(
    from_email: str,
    subject: str,
    body: str,
    reply_to: str = "",
    auth_results: str = "",
) -> dict:
    """Helper to create test Gmail message payload."""
    body_b64 = base64.urlsafe_b64encode(body.encode()).decode().rstrip("=")

    headers = [
        {"name": "From", "value": from_email},
        {"name": "Subject", "value": subject},
    ]
    if reply_to:
        headers.append({"name": "Reply-To", "value": reply_to})
    if auth_results:
        headers.append({"name": "Authentication-Results", "value": auth_results})

    return {
        "id": "test123",
        "payload": {
            "headers": headers,
            "body": {"data": body_b64},
            "mimeType": "text/plain",
        },
    }


def test_root_endpoint(client: TestClient):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "running"
    assert data["engine"] == "ml"


def test_health_check(client: TestClient):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["engine"] == "ml"
    assert "runtime" in data
    assert "artifacts" in data


def test_detect_safe_email(client: TestClient):
    payload = create_test_payload(
        from_email="noreply@google.com",
        subject="Welcome",
        body="Thank you for signing up.",
    )

    response = client.post("/api/v1/detect", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["risk_score"] < 0.33
    assert data["classification"] == "Seems safe"


def test_detect_typosquatting_hard_case_is_at_least_caution(client: TestClient):
    payload = create_test_payload(
        from_email="security@gogle.com",
        subject="Account Verification Required",
        body=(
            "Your account requires immediate verification. "
            "Please click the link below to verify: https://gogle.com/verify"
        ),
    )

    response = client.post("/api/v1/detect", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["risk_score"] >= 0.34
    assert data["classification"] in {
        "Few indicators found, need to be cautious",
        "Major indicators found!",
    }
    assert data["model_version"] is not None
    assert data["decision_threshold"] is not None
    assert data["raw_probability"] is not None
    assert "guardrail_applied" in data


def test_detect_multiple_indicators(client: TestClient):
    payload = create_test_payload(
        from_email="alert@paypa1.com",
        subject="URGENT: Account Suspended",
        body="Your account is suspended. Verify now: http://192.168.1.1/login",
        reply_to="support@different-domain.com",
        auth_results="spf=fail dkim=fail dmarc=fail",
    )

    response = client.post("/api/v1/detect", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["risk_score"] > 0.5
    assert len(data["indicators"]) >= 2


def test_invalid_payload(client: TestClient):
    response = client.post("/api/v1/detect", json={"invalid": "data"})
    assert response.status_code == 422
