"""Detection API routes."""
from __future__ import annotations

from functools import lru_cache

from fastapi import APIRouter, Depends, Request

from app.api.schemas.email import DetectRequest
from app.api.schemas.response import ApiError, DetectResponse, ErrorCode
from app.core.config import Settings, get_settings
from app.core.errors import ServiceError
from app.core.request_context import get_request_id
from app.domain.agents.phishing_agent import PhishingLLMAgent
from app.domain.services.phishing_service import PhishingService

router = APIRouter(tags=["detection"])


@lru_cache(maxsize=1)
def get_phishing_service() -> PhishingService:
    settings = get_settings()
    return PhishingService(agent=PhishingLLMAgent(settings=settings))


@router.post("/detect", response_model=DetectResponse)
async def detect_phishing(
    request_payload: DetectRequest,
    request: Request,
    service: PhishingService = Depends(get_phishing_service),
    settings: Settings = Depends(get_settings),
) -> DetectResponse:
    request_id = get_request_id()

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.max_payload_bytes:
                raise ServiceError(
                    code=ErrorCode.payload_too_large.value,
                    message="Payload exceeds maximum allowed size.",
                    status_code=413,
                )
        except ValueError:
            pass

    result = await service.analyze(request_payload.message, request_payload.source)
    return DetectResponse(
        schema_version=settings.schema_version,
        request_id=request_id,
        result=result,
        error=None,
    )


@router.get("/health")
async def health(settings: Settings = Depends(get_settings)) -> dict:
    return {
        "status": "ok",
        "schema_version": settings.schema_version,
        "model_endpoint": settings.model_endpoint(),
        "openai_base_url": settings.openai_base_url(),
        "model": settings.model_name(),
    }


def error_envelope(
    *,
    code: ErrorCode,
    message: str,
    details: list[dict] | None = None,
) -> DetectResponse:
    return DetectResponse(
        schema_version=get_settings().schema_version,
        request_id=get_request_id(),
        result=None,
        error=ApiError(code=code, message=message, details=details or []),
    )
