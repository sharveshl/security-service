from url_checker import extract_urls
from keyword_detector import keyword_risk
from google_safe_browsing import check_url_with_google

BLOCK_THRESHOLD = 5

def analyze_message(text):
    risk_score = 0
    reasons = []

    urls = extract_urls(text)

    for url in urls:
        if check_url_with_google(url):
            risk_score += 10
            reasons.append(f"Google flagged malicious URL: {url}")

    keyword_score = keyword_risk(text)
    risk_score += keyword_score

    if keyword_score > 0:
        reasons.append("Suspicious language detected")

    action = "allow"
    if risk_score >= BLOCK_THRESHOLD:
        action = "block"

    return {
        "risk_score": risk_score,
        "action": action,
        "reasons": reasons
    }