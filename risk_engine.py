from url_checker import extract_urls, basic_url_check
from keyword_detector import keyword_risk

BLOCK_THRESHOLD = 5

def analyze_message(text):
    risk_score = 0
    reasons = []

    urls = extract_urls(text)

    for url in urls:
        if basic_url_check(url):
            risk_score += 5
            reasons.append(f"Suspicious URL detected: {url}")

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