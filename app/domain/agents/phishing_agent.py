"""PydanticAI-powered phishing analysis agent."""
from __future__ import annotations

import asyncio
import json
import logging

from pydantic import ValidationError

from app.core.config import Settings
from app.domain.agents.models import AgentOutput, NormalizedEmail
from app.infrastructure.model_runner.ollama_adapter import build_ollama_model

logger = logging.getLogger(__name__)

SYSTEM_PROMPT_V1 = """
You are a phishing detection assistant.
Return only the requested structured JSON schema.
Evaluate whether this email is safe, suspicious, or likely phishing.
Always include concrete triggers when verdict is suspicious or likely_phishing.
Use triggers only from observable evidence in headers/body/links/attachment names.
Prioritize the following phishing patterns:
1) Urgency language tied to financial or credential actions.
   Examples: "verify account now", "payment failed", "update banking details", "password reset immediately".
2) Brand impersonation and typosquatting, including suspicious TLD mismatches for well-known brands.
   Example: microsoft.net pretending to be Microsoft instead of expected microsoft.com context.
3) Suspicious links, including uncommon or deceptive domains and URLs using raw IP addresses.

Trigger typing rules (strict):
- kind=link: value MUST be a full http/https URL, not a phrase.
- kind=keyword: value MUST be a non-URL phrase/snippet from subject/body text.
- kind=sender: value MUST be an email address from sender_email or reply_to_email.
- kind=attachment: value MUST be an attachment filename from attachment_names.
- source_field MUST be one of: subject_text, body_text, body_html, sender_email, reply_to_email, urls, attachment_names.
- Never emit the same exact value as both keyword and link.
- Only mention "IP address" in reason when the URL host is actually an IP.

When a pattern is found, return a specific trigger with:
- source_field set to the relevant field (subject_text, body_text, body_html, sender_email, reply_to_email, urls, attachment_names)
- value set to the exact suspicious token/text/URL/email
- reason explaining why that value is suspicious

Do not include markdown, prose outside schema, or hidden reasoning.
""".strip()


class AgentTimeoutError(Exception):
    """Raised when the model call times out."""


class AgentProviderError(Exception):
    """Raised when model provider call fails."""


class AgentContractError(Exception):
    """Raised when model output does not satisfy the strict schema."""


class PhishingLLMAgent:
    """Wrap PydanticAI with strict output validation and timeouts."""

    def __init__(self, settings: Settings):
        self._settings = settings

        from pydantic_ai import Agent

        self._agent = Agent(
            model=build_ollama_model(settings),
            output_type=AgentOutput,
            system_prompt=SYSTEM_PROMPT_V1,
            retries=settings.model_retries,
        )

    async def analyze(self, normalized: NormalizedEmail) -> AgentOutput:
        """Analyze normalized email and return typed output."""
        user_prompt = self._build_user_prompt(normalized)

        try:
            run_result = await asyncio.wait_for(
                self._agent.run(user_prompt),
                timeout=self._settings.request_timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            raise AgentTimeoutError("Model request timed out") from exc
        except Exception as exc:
            raise AgentProviderError(str(exc)) from exc

        try:
            data = getattr(run_result, "output", run_result)
            return AgentOutput.model_validate(data)
        except ValidationError as exc:
            raise AgentContractError(f"Structured output validation failed: {exc}") from exc

    def _build_user_prompt(self, normalized: NormalizedEmail) -> str:
        payload = normalized.model_dump()
        return (
            "Analyze this normalized email for phishing risk and respond only with the structured result.\n"
            f"Input JSON:\n{json.dumps(payload, indent=2)}"
        )
