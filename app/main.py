"""FastAPI application for email phishing detection."""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi import Request
from .models import GmailMessage, PhishingDetectionResponse
from .phishing_detector import PhishingDetector
from .domain_fetcher import domain_cache

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize domain cache on startup."""
    logger.info("Starting up: initializing domain cache...")
    await domain_cache.initialize()
    logger.info("Domain cache initialized successfully")
    yield
    logger.info("Shutting down...")


app = FastAPI(
    title="Email Phishing Detector",
    description="Detect phishing attempts in email content using Gmail API format",
    version="1.0.0",
    lifespan=lifespan
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
        "domain_cache_initialized": domain_cache.is_initialized()
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
        # Ensure domain cache is initialized
        if not domain_cache.is_initialized():
            await domain_cache.initialize()
        
        # Create detector and analyze message
        detector = PhishingDetector()
        result = detector.detect(message)
        
        logger.info(f"Detection completed: score={result.risk_score}, classification={result.classification}")
        return result
        
    except Exception as e:
        logger.error(f"Error during phishing detection: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error during phishing detection: {str(e)}"
        )


@app.get("/api/v1/health")
async def health_check():
    """Detailed health check endpoint."""
    return {
        "status": "healthy",
        "domain_cache_initialized": domain_cache.is_initialized(),
        "cached_domains": len(domain_cache.get_domains())
    }
