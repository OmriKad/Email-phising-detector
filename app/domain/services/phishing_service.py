"""Domain orchestration service for phishing detection."""
from __future__ import annotations

import logging

from app.api.schemas.email import GmailMessage
from app.api.schemas.response import (
    DetectionResult,
    ErrorCode,
    Severity,
    SourceField,
    Trigger,
    TriggerKind,
    Verdict,
)
from app.core.errors import ServiceError
from app.domain.agents.models import AgentOutput, AgentTrigger
from app.domain.agents.phishing_agent import (
    AgentContractError,
    AgentProviderError,
    AgentTimeoutError,
    PhishingLLMAgent,
)
from app.domain.email.normalize import normalize_email

logger = logging.getLogger(__name__)


class PhishingService:
    """Coordinates normalization + model inference + post-validation guards."""

    def __init__(self, agent: PhishingLLMAgent):
        self._agent = agent

    async def analyze(self, message: GmailMessage, source: str) -> DetectionResult:
        normalized = normalize_email(message)

        logger.info(
            "normalized_email source=%s sender=%s urls=%d subject_len=%d",
            source,
            normalized.sender_email,
            len(normalized.urls),
            len(normalized.subject_text),
        )

        try:
            output = await self._agent.analyze(normalized)
        except AgentTimeoutError as exc:
            raise ServiceError(
                code=ErrorCode.model_timeout.value,
                message="Model request timed out.",
                status_code=504,
            ) from exc
        except AgentProviderError as exc:
            raise ServiceError(
                code=ErrorCode.model_provider_error.value,
                message="Model provider error.",
                status_code=502,
                details=[{"reason": str(exc)}],
            ) from exc
        except AgentContractError as exc:
            raise ServiceError(
                code=ErrorCode.model_contract_violation.value,
                message="Model returned invalid structured output.",
                status_code=502,
                details=[{"reason": str(exc)}],
            ) from exc

        self._validate_output(output)
        return self._to_detection_result(output)

    def _validate_output(self, output: AgentOutput) -> None:
        if output.verdict.value != Verdict.safe.value and not output.triggers:
            raise ServiceError(
                code=ErrorCode.model_contract_violation.value,
                message="Non-safe verdict must include at least one trigger.",
                status_code=502,
            )

    def _to_detection_result(self, output: AgentOutput) -> DetectionResult:
        return DetectionResult(
            verdict=Verdict(output.verdict.value),
            risk_score=output.risk_score,
            confidence=output.confidence,
            summary=output.summary,
            triggers=[self._to_trigger(trigger) for trigger in output.triggers],
        )

    @staticmethod
    def _to_trigger(trigger: AgentTrigger) -> Trigger:
        return Trigger(
            kind=TriggerKind(trigger.kind.value),
            source_field=SourceField(trigger.source_field.value),
            value=trigger.value,
            reason=trigger.reason,
            severity=Severity(trigger.severity.value),
        )
