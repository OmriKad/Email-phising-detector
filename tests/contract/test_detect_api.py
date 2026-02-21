"""Contract tests for /api/v1/detect response envelope."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.api.routes.detect import get_phishing_service
from app.api.schemas.response import DetectionResult, Severity, Trigger, TriggerKind, Verdict
from app.main import app


class FakeService:
    async def analyze(self, message, source):  # noqa: ANN001
        return DetectionResult(
            verdict=Verdict.likely_phishing,
            risk_score=0.91,
            confidence=0.82,
            summary="Credential phishing indicators detected.",
            triggers=[
                Trigger(
                    kind=TriggerKind.link,
                    source_field="body_text",
                    value="http://login-check.example/reset",
                    reason="Impersonation style URL",
                    severity=Severity.high,
                )
            ],
        )


def _valid_request() -> dict:
    return {
        "source": "api",
        "message": {
            "id": "msg1",
            "payload": {
                "headers": [
                    {"name": "From", "value": "sender@example.com"},
                    {"name": "Subject", "value": "Hello"},
                ],
                "mimeType": "text/plain",
                "body": {"data": "SGVsbG8"},
            },
        },
    }


def test_detect_success_envelope_contract() -> None:
    app.dependency_overrides[get_phishing_service] = lambda: FakeService()
    client = TestClient(app)

    response = client.post("/api/v1/detect", json=_valid_request())

    assert response.status_code == 200
    data = response.json()
    assert data["schema_version"] == "v1"
    assert data["request_id"]
    assert data["error"] is None
    assert data["result"]["verdict"] in {"safe", "suspicious", "likely_phishing"}
    assert isinstance(data["result"]["triggers"], list)

    app.dependency_overrides.clear()


def test_detect_validation_error_envelope() -> None:
    client = TestClient(app)

    response = client.post("/api/v1/detect", json={})

    assert response.status_code == 422
    data = response.json()
    assert data["schema_version"] == "v1"
    assert data["result"] is None
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert isinstance(data["error"]["details"], list)
