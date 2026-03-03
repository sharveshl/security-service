import re


def extract_urls(text: str) -> list[str]:
    """Extract URLs from message text, including ones without http:// prefix."""
    # Match URLs with protocol
    url_with_protocol = r"https?://[^\s<>\"\']+"
    # Match common domains without protocol (e.g., example.com/path)
    url_without_protocol = r"(?<!\S)(?:www\.)[^\s<>\"\']+"

    urls = re.findall(url_with_protocol, text)
    urls += [f"http://{u}" for u in re.findall(url_without_protocol, text)]

    return urls


def is_suspicious_url(url: str) -> dict:
    """Check a URL against known suspicious patterns. Returns details."""
    url_lower = url.lower()
    flags = []
    score = 0

    # URL shortener detection
    shorteners = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "short.io",
    ]
    for shortener in shorteners:
        if shortener in url_lower:
            flags.append(f"URL shortener detected: {shortener}")
            score += 3
            break

    # IP-based URL (common phishing tactic)
    ip_pattern = r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    if re.match(ip_pattern, url_lower):
        flags.append("IP-based URL detected (common phishing indicator)")
        score += 4

    # Suspicious keywords in URL
    suspicious_url_words = [
        "free-money", "win-prize", "claim-reward", "account-verify",
        "login-secure", "update-billing", "confirm-identity",
        "password-reset", "suspended", "locked-account",
    ]
    for word in suspicious_url_words:
        if word in url_lower:
            flags.append(f"Suspicious keyword in URL: {word}")
            score += 3

    # Excessive subdomains (e.g., secure.login.bank.evil.com)
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        subdomain_count = hostname.count(".")
        if subdomain_count >= 3:
            flags.append(f"Excessive subdomains ({subdomain_count} dots) — possible impersonation")
            score += 2
    except Exception:
        pass

    # Homograph / lookalike characters
    lookalikes = {"0": "o", "1": "l", "rn": "m"}
    for fake, real in lookalikes.items():
        if fake in url_lower:
            # Only flag if it looks like a common domain spoof
            pass  # Reserved for future ML-based detection

    return {"score": score, "flags": flags}