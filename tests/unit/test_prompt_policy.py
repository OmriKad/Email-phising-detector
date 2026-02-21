"""Regression checks for phishing prompt policy priorities."""
from app.domain.agents.phishing_agent import SYSTEM_PROMPT_V1


def test_prompt_covers_requested_detection_priorities() -> None:
    prompt = SYSTEM_PROMPT_V1.lower()

    assert "urgency" in prompt
    assert "financial" in prompt or "payment" in prompt
    assert "credential" in prompt or "password" in prompt

    assert "typosquatting" in prompt
    assert "tld" in prompt
    assert "microsoft.net" in prompt

    assert "ip addresses" in prompt or "raw ip" in prompt
    assert "suspicious links" in prompt
    assert "same exact value as both keyword and link" in prompt
    assert "kind=link" in prompt
    assert "kind=keyword" in prompt
    assert "kind=attachment" in prompt
    assert "attachment_names" in prompt
