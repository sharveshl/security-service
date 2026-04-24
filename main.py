"""
Security Service — Production-grade message analysis microservice.

Detects scam, fraud messages, phishing links for chat applications.
"""

import asyncio
import logging
import sys
import time

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from config import settings
from risk_engine import analyze_message

# ── Logging Setup ──────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("security-service")

# ── Rate Limiter ───────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── FastAPI App ────────────────────────────────────────────────────
app = FastAPI(
    title="Security Service",
    description="Microservice for detecting scam, fraud, and phishing in chat messages.",
    version="2.0.0",
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)



# ── Request / Response Models ──────────────────────────────────────
class MessageRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000, description="Message text to analyze")
    user_id: str = Field(..., min_length=1, max_length=128, description="ID of the user who sent the message")


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    uptime_seconds: float


# ── Keep-Alive Configuration ───────────────────────────────────────
KEEP_ALIVE_URL = "https://chatnow-backend-j17m.onrender.com"
KEEP_ALIVE_INTERVAL = 45  # seconds

_start_time: float = 0.0
_keep_alive_task: asyncio.Task | None = None


async def _keep_alive_loop():
    """Periodically ping the main backend to prevent Render from spinning it down."""
    logger.info("Keep-alive task started — pinging %s every %ds", KEEP_ALIVE_URL, KEEP_ALIVE_INTERVAL)
    async with httpx.AsyncClient(timeout=10) as client:
        while True:
            await asyncio.sleep(KEEP_ALIVE_INTERVAL)
            try:
                response = await client.get(KEEP_ALIVE_URL)
                logger.info("Keep-alive ping → %s (HTTP %d)", KEEP_ALIVE_URL, response.status_code)
            except Exception as exc:
                logger.warning("Keep-alive ping failed → %s: %s", KEEP_ALIVE_URL, exc)


# ── Startup / Shutdown ─────────────────────────────────────────────


@app.on_event("startup")
async def on_startup():
    global _start_time, _keep_alive_task
    _start_time = time.time()
    logger.info(
        "Security Service started — env=%s, log_level=%s",
        settings.ENVIRONMENT,
        settings.LOG_LEVEL,
    )
    if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
        logger.warning("GOOGLE_SAFE_BROWSING_API_KEY is not set — URL scanning will be limited")
    # Start keep-alive background task
    _keep_alive_task = asyncio.create_task(_keep_alive_loop())


@app.on_event("shutdown")
async def on_shutdown():
    global _keep_alive_task
    if _keep_alive_task and not _keep_alive_task.done():
        _keep_alive_task.cancel()
        try:
            await _keep_alive_task
        except asyncio.CancelledError:
            pass
    logger.info("Keep-alive task stopped.")



# ── Middleware: Request Logging ────────────────────────────────────
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response: Response = await call_next(request)
    duration_ms = (time.time() - start) * 1000
    logger.info(
        "%s %s — %d (%.1fms)",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


# ── Global Exception Handler ──────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


# ── Endpoints ──────────────────────────────────────────────────────
@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint for Render and monitoring."""
    return HealthResponse(
        status="healthy",
        version="2.0.0",
        environment=settings.ENVIRONMENT,
        uptime_seconds=round(time.time() - _start_time, 2),
    )


@app.post("/analyze")
@limiter.limit(settings.RATE_LIMIT)
async def analyze(request: Request, message: MessageRequest):
    """
    Analyze a chat message for scam, fraud, and phishing indicators.

    Returns risk score, action (allow/warn/block), risk level,
    reasons, and detailed match information.
    """
    logger.debug("Analyzing message from user_id=%s (length=%d)", message.user_id, len(message.text))

    result = analyze_message(message.text)
    result["user_id"] = message.user_id

    return result