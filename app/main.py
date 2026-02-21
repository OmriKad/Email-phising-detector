"""FastAPI application entrypoint."""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.routes.detect import error_envelope, router as detect_router
from app.api.schemas.response import ErrorCode
from app.core.config import get_settings
from app.core.errors import ServiceError
from app.core.logging import configure_logging
from app.core.request_context import request_id_middleware

configure_logging()
logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create FastAPI application with middleware and exception handlers."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
    )
    app.middleware("http")(request_id_middleware)

    @app.exception_handler(RequestValidationError)
    async def on_validation_error(_: Request, exc: RequestValidationError):
        logger.warning("validation_error errors=%s", exc.errors())
        envelope = error_envelope(
            code=ErrorCode.validation_error,
            message="Invalid request payload.",
            details=[{"errors": exc.errors()}],
        )
        return JSONResponse(status_code=422, content=envelope.model_dump())

    @app.exception_handler(ServiceError)
    async def on_service_error(_: Request, exc: ServiceError):
        envelope = error_envelope(
            code=ErrorCode(exc.code),
            message=exc.message,
            details=exc.details,
        )
        return JSONResponse(status_code=exc.status_code, content=envelope.model_dump())

    @app.exception_handler(Exception)
    async def on_unhandled_error(_: Request, exc: Exception):
        logger.exception("unhandled_error")
        envelope = error_envelope(
            code=ErrorCode.internal_error,
            message="Unexpected server error.",
            details=[{"reason": str(exc)}],
        )
        return JSONResponse(status_code=500, content=envelope.model_dump())

    @app.get("/")
    async def root() -> dict:
        return {
            "name": settings.app_name,
            "status": "running",
            "schema_version": settings.schema_version,
        }

    app.include_router(detect_router, prefix="/api/v1")
    return app


app = create_app()
