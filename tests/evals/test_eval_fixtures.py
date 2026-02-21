"""Evaluation fixture checks and optional live eval run."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.schemas.email import DetectRequest
from app.main import app

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _fixtures() -> list[dict]:
    files = sorted(FIXTURES_DIR.glob("*.json"))
    return [json.loads(file.read_text(encoding="utf-8")) for file in files]


def test_eval_fixture_schema() -> None:
    for fixture in _fixtures():
        DetectRequest.model_validate(fixture["request"])
        assert fixture["expectations"]["verdict_any_of"]
        assert fixture["expectations"]["min_triggers"] >= 0


@pytest.mark.skipif(os.getenv("RUN_EVALS") != "1", reason="Set RUN_EVALS=1 to run live eval fixtures")
def test_eval_fixture_live_expectations() -> None:
    client = TestClient(app)

    for fixture in _fixtures():
        response = client.post("/api/v1/detect", json=fixture["request"])
        assert response.status_code == 200

        payload = response.json()["result"]
        assert payload["verdict"] in fixture["expectations"]["verdict_any_of"]
        assert len(payload["triggers"]) >= fixture["expectations"]["min_triggers"]
