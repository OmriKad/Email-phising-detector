"""Unit tests for strict semantic trigger schema validation."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.domain.agents.models import AgentOutput


def _base_output() -> dict:
    return {
        "verdict": "suspicious",
        "risk_score": 0.8,
        "confidence": 0.8,
        "summary": "Suspicious patterns detected",
        "triggers": [],
    }


def test_link_trigger_requires_url_value() -> None:
    payload = _base_output()
    payload["triggers"] = [
        {
            "kind": "link",
            "source_field": "body_html",
            "value": "verify account now",
            "reason": "Suspicious URL",
            "severity": "high",
        }
    ]

    with pytest.raises(ValidationError):
        AgentOutput.model_validate(payload)


def test_keyword_trigger_cannot_be_url() -> None:
    payload = _base_output()
    payload["triggers"] = [
        {
            "kind": "keyword",
            "source_field": "body_text",
            "value": "https://secure-login-portal-amz.net/verify",
            "reason": "Urgency language",
            "severity": "high",
        }
    ]

    with pytest.raises(ValidationError):
        AgentOutput.model_validate(payload)


def test_ip_reason_requires_ip_host() -> None:
    payload = _base_output()
    payload["triggers"] = [
        {
            "kind": "link",
            "source_field": "urls",
            "value": "https://secure-login-portal-amz.net/verify",
            "reason": "Suspicious link with raw IP address",
            "severity": "high",
        }
    ]

    with pytest.raises(ValidationError):
        AgentOutput.model_validate(payload)


def test_reject_conflicting_link_and_keyword_for_same_url() -> None:
    payload = _base_output()
    payload["triggers"] = [
        {
            "kind": "keyword",
            "source_field": "body_html",
            "value": "https://secure-login-portal-amz.net/verify",
            "reason": "Suspicious",
            "severity": "high",
        },
        {
            "kind": "link",
            "source_field": "body_html",
            "value": "https://secure-login-portal-amz.net/verify",
            "reason": "Uncommon domain",
            "severity": "high",
        },
    ]

    with pytest.raises(ValidationError):
        AgentOutput.model_validate(payload)


def test_valid_link_and_keyword_triggers_pass() -> None:
    payload = _base_output()
    payload["triggers"] = [
        {
            "kind": "keyword",
            "source_field": "body_text",
            "value": "verify account now",
            "reason": "Urgent credential action request",
            "severity": "high",
        },
        {
            "kind": "link",
            "source_field": "urls",
            "value": "http://192.168.10.2/verify",
            "reason": "Suspicious link using IP address",
            "severity": "high",
        },
    ]

    result = AgentOutput.model_validate(payload)
    assert len(result.triggers) == 2


def test_attachment_trigger_requires_attachment_source_field() -> None:
    payload = _base_output()
    payload["triggers"] = [
        {
            "kind": "attachment",
            "source_field": "body_text",
            "value": "invoice.pdf",
            "reason": "Unexpected executable-looking attachment name",
            "severity": "medium",
        }
    ]

    with pytest.raises(ValidationError):
        AgentOutput.model_validate(payload)
