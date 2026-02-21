"""Optional integration test against live model runner."""
from __future__ import annotations

import os

import pytest

from app.api.schemas.email import GmailMessage, Header, MessagePart, MessagePartBody
from app.core.config import get_settings
from app.domain.agents.phishing_agent import PhishingLLMAgent
from app.domain.services.phishing_service import PhishingService


@pytest.mark.skipif(os.getenv("RUN_MODEL_INTEGRATION") != "1", reason="Set RUN_MODEL_INTEGRATION=1 to run")
@pytest.mark.asyncio
async def test_live_model_runner_detection() -> None:
    settings = get_settings()
    service = PhishingService(agent=PhishingLLMAgent(settings))

    message = GmailMessage(
        payload=MessagePart(
            headers=[
                Header(name="From", value="billing@example.com"),
                Header(name="Subject", value="Urgent account verification"),
            ],
            mimeType="text/plain",
            body=MessagePartBody(data="Q2xpY2sgaHR0cDovL2xvZ2luLWNoZWNrLmV4YW1wbGUvdmVyaWZ5"),
        )
    )

    result = await service.analyze(message, source="api")
    assert 0.0 <= result.risk_score <= 1.0
    assert result.verdict.value in {"safe", "suspicious", "likely_phishing"}
    if result.verdict.value != "safe":
        assert result.triggers
