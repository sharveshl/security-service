"""Risk engine — orchestrates all detection modules and produces a final verdict.

Uses keyword-based detection and URL analysis only (no LLM dependency).
This makes the service fast, dependency-free, and fully deterministic.
"""

import logging
from datetime import datetime, timezone

from config import settings
from google_safe_browsing import check_url_with_google
from keyword_detector import keyword_risk
from url_checker import extract_urls, is_suspicious_url

logger = logging.getLogger(__name__)


def _determine_risk_level(score: int) -> str:
    """Map numeric score to a human-readable risk level."""
    if score == 0:
        return "none"
    if score < settings.WARN_THRESHOLD:
        return "low"
    if score < settings.BLOCK_THRESHOLD:
        return "medium"
    if score < settings.BLOCK_THRESHOLD * 2:
        return "high"
    return "critical"


def _determine_action(score: int) -> str:
    """Decide action based on score thresholds."""
    if score >= settings.BLOCK_THRESHOLD:
        return "block"
    if score >= settings.WARN_THRESHOLD:
        return "warn"
    return "allow"


def analyze_message(text: str) -> dict:
    """
    Analyze a chat message for scam, fraud, and phishing indicators.

    Uses keyword matching and URL analysis (Google Safe Browsing + local patterns).

    Returns a structured result dict with score, action, risk level,
    reasons, matched details, and metadata.
    """
    risk_score = 0
    reasons: list[str] = []
    flagged_urls: list[str] = []
    details: dict = {}

    # ── URL Analysis ───────────────────────────────────────────────
    urls = extract_urls(text)

    for url in urls:
        # Google Safe Browsing check
        if check_url_with_google(url):
            risk_score += 10
            reasons.append(f"Google Safe Browsing flagged malicious URL: {url}")
            flagged_urls.append(url)

        # Local suspicious URL patterns
        url_result = is_suspicious_url(url)
        if url_result["score"] > 0:
            risk_score += url_result["score"]
            reasons.extend(url_result["flags"])
            if url not in flagged_urls:
                flagged_urls.append(url)

    # ── Content Analysis (keyword matching) ───────────────────────
    kw_result = keyword_risk(text)
    risk_score += kw_result["score"]
    details["detection_method"] = "keyword"

    if kw_result["matched_keywords"]:
        reasons.append(
            f"Suspicious keywords detected: {', '.join(kw_result['matched_keywords'])}"
        )
        details["matched_keywords"] = kw_result["matched_keywords"]
        details["matched_categories"] = kw_result["matched_categories"]
        details["risk_categories"] = kw_result["matched_categories"]

    logger.info(
        "Keyword analysis complete — score=%d keywords=%s",
        kw_result["score"],
        kw_result["matched_keywords"],
    )

    # ── Final Verdict ──────────────────────────────────────────────
    action = _determine_action(risk_score)
    risk_level = _determine_risk_level(risk_score)

    result = {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "action": action,
        "reasons": reasons,
        "flagged_urls": flagged_urls,
        "details": details,
        "urls_scanned": len(urls),
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }

    if action != "allow":
        logger.info(
            "Message flagged — action=%s score=%d level=%s reasons=%s",
            action, risk_score, risk_level, reasons,
        )

    return result