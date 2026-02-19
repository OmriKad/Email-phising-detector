"""FastAPI application for ML-only phishing detection."""
from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.schemas import GmailMessage, PhishingDetectionResponse
from app.detectors.ml_detector import MLPhishingDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

_ml_detector = MLPhishingDetector()


app = FastAPI(
    title="Email Phishing Detector",
    description="Detect phishing attempts in email content using local ML inference",
    version="1.0.0",
)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Logs the exact validation error to your terminal."""
    logger.error(f"Validation Error: {exc.errors()}")
    logger.error(f"Body: {await request.body()}")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "body": str(await request.body())},
    )

@app.get("/")
async def root():
    """Health check endpoint."""
    return {
        "message": "Email Phishing Detector API",
        "status": "running",
        "engine": "ml",
    }


@app.post("/api/v1/detect", response_model=PhishingDetectionResponse)
async def detect_phishing(message: GmailMessage) -> PhishingDetectionResponse:
    """
    Analyze Gmail message for phishing indicators.
    
    Accepts a Gmail message in the standard Gmail API format and returns
    a phishing detection analysis with risk score, classification, and
    detailed indicators.
    """
    try:
        if message.payload is None:
            raise HTTPException(status_code=422, detail="Invalid Gmail message: payload is required")

        result = _ml_detector.detect(message)

        logger.info(
            "Detection completed: engine=ml score=%.3f classification=%s",
            result.risk_score,
            result.classification,
        )
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during phishing detection: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error during phishing detection: {str(e)}"
        )


@app.get("/api/v1/health")
async def health_check():
    """Detailed ML runtime health check endpoint."""
    runtime = _ml_detector.runtime
    return {
        "status": "healthy",
        "engine": "ml",
        "runtime": {
            "model_version": runtime.model_version,
            "default_threshold": runtime.default_threshold,
            "model_loaded": runtime.booster is not None,
            "calibrator_loaded": runtime.calibrator is not None,
        },
        "artifacts": {
            "model_path": str(runtime.model_path),
            "calibrator_path": str(runtime.calibrator_path),
            "schema_path": str(runtime.schema_path),
            "model_exists": runtime.model_path.exists(),
            "calibrator_exists": runtime.calibrator_path.exists(),
            "schema_exists": runtime.schema_path.exists(),
        },
    }
