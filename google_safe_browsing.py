"""Google Safe Browsing API integration with caching, timeouts, and error handling."""

import logging
import time

import requests

from config import settings

logger = logging.getLogger(__name__)

SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)

# Simple in-memory cache: {url: {"result": bool, "expires": timestamp}}
_cache: dict[str, dict] = {}


def _get_cached(url: str) -> bool | None:
    """Return cached result if still valid, else None."""
    entry = _cache.get(url)
    if entry and entry["expires"] > time.time():
        return entry["result"]
    # Expired — remove it
    _cache.pop(url, None)
    return None


def _set_cache(url: str, result: bool) -> None:
    """Cache a result with TTL from settings."""
    _cache[url] = {
        "result": result,
        "expires": time.time() + settings.CACHE_TTL,
    }


def check_url_with_google(url: str) -> bool:
    """
    Check a URL against Google Safe Browsing API.

    Returns True if the URL is flagged as malicious, False otherwise.
    On errors, logs the issue and returns False (fail-open).
    """
    # Check cache first
    cached = _get_cached(url)
    if cached is not None:
        logger.debug("Cache hit for URL: %s → %s", url, cached)
        return cached

    api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
    if not api_key:
        logger.warning("Google Safe Browsing API key not configured — skipping check")
        return False

    payload = {
        "client": {
            "clientId": "security-service",
            "clientVersion": "2.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "POTENTIALLY_HARMFUL_APPLICATION",
                "UNWANTED_SOFTWARE",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(
            SAFE_BROWSING_URL,
            params={"key": api_key},
            json=payload,
            timeout=5,
        )
        response.raise_for_status()

        data = response.json()
        is_malicious = "matches" in data

        _set_cache(url, is_malicious)

        if is_malicious:
            logger.warning("Google Safe Browsing flagged URL as malicious: %s", url)

        return is_malicious

    except requests.exceptions.Timeout:
        logger.error("Google Safe Browsing API timeout for URL: %s", url)
        return False
    except requests.exceptions.RequestException as exc:
        logger.error("Google Safe Browsing API error: %s", exc)
        return False
    except Exception as exc:
        logger.exception("Unexpected error checking URL %s: %s", url, exc)
        return False