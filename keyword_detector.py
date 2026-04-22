"""Keyword-based risk detection with categorized, weighted scoring.

Since this is the primary content-analysis method (no LLM), the keyword
lists are comprehensive to ensure high detection coverage.
"""


# Each category has a weight and a list of keywords/phrases
KEYWORD_CATEGORIES: dict[str, dict] = {
    "financial_scam": {
        "weight": 3,
        "keywords": [
            "free money", "lottery", "you won", "prize winner",
            "cash prize", "inheritance", "million dollars",
            "wire transfer", "western union", "bitcoin payment",
            "investment opportunity", "guaranteed returns",
            "double your money", "work from home", "no experience needed",
            "you have won", "unclaimed funds", "lottery winner",
            "claim your prize", "claim your reward", "jackpot",
            "send money", "money transfer", "financial assistance",
            "crypto investment", "forex trading", "high returns",
            "risk free investment", "passive income", "mlm",
            "ponzi", "pyramid scheme", "get rich quick",
            "100% profit", "zero risk", "guaranteed profit",
            "binary options", "stock tips", "insider trading",
        ],
    },
    "urgency_pressure": {
        "weight": 2,
        "keywords": [
            "urgent", "act now", "immediately", "expires today",
            "last chance", "don't miss", "limited time",
            "hurry", "right away", "asap",
            "respond now", "time sensitive", "deadline today",
            "offer expires", "act fast", "limited offer",
            "within 24 hours", "within the next hour", "before it's too late",
            "don't delay", "final notice", "last warning",
            "expiring soon", "do it now", "today only",
        ],
    },
    "phishing": {
        "weight": 4,
        "keywords": [
            "verify your account", "confirm your identity",
            "account suspended", "unusual activity",
            "update your payment", "security alert",
            "click here to verify", "reset your password",
            "verify your email", "confirm your details",
            "your account has been", "account will be closed",
            "suspended account", "reactivate your account",
            "validate your information", "your profile is restricted",
            "login attempt detected", "sign in to verify",
            "important account notice", "action required",
            "account at risk", "your account is compromised",
            "failed login attempt", "suspicious login",
        ],
    },
    "credential_harvesting": {
        "weight": 5,
        "keywords": [
            "send otp", "share otp", "otp", "send your password",
            "share your pin", "credit card number",
            "social security", "bank details", "cvv",
            "enter your credentials", "provide your password",
            "share your password", "send your pin",
            "tell me your otp", "what is your otp",
            "enter your otp", "provide otp",
            "share account details", "account number",
            "routing number", "mother's maiden name",
            "security question", "date of birth",
            "share your card", "card number", "expiry date",
        ],
    },
    "impersonation": {
        "weight": 3,
        "keywords": [
            "i am from bank", "customer support",
            "technical support", "irs", "tax refund",
            "government agency", "official notice",
            "from microsoft", "from apple", "from google",
            "i am calling from", "this is the bank",
            "bank representative", "from your bank",
            "rbi", "federal reserve", "social security administration",
            "medicare", "internal revenue", "tax department",
            "police department", "fbi", "interpol",
            "from amazon", "from paypal", "from netflix",
            "helpdesk", "it support", "system administrator",
        ],
    },
    "click_bait": {
        "weight": 2,
        "keywords": [
            "click now", "click here", "click this link",
            "tap here", "open this", "download now",
            "install now", "open the link", "follow the link",
            "visit this link", "go to this link", "open link",
            "check this out", "see here", "watch this",
            "access here", "get it here", "grab it now",
        ],
    },
    "malware_threat": {
        "weight": 4,
        "keywords": [
            "download this file", "run this program",
            "install this app", "execute this",
            "open attachment", "open the file",
            "download the attachment", "apk download",
            "install apk", "update required", "mandatory update",
            "your device is infected", "virus detected",
            "remove the virus", "scan your phone",
        ],
    },
    "romance_scam": {
        "weight": 3,
        "keywords": [
            "i love you already", "send me money",
            "i need your help financially", "emergency money",
            "military officer", "deployed overseas",
            "stuck at customs", "customs fee",
            "send gift card", "itunes card", "google play card",
            "steam card", "vanilla gift card",
            "money gram", "moneygram",
        ],
    },
}


def keyword_risk(text: str) -> dict:
    """
    Analyze text for risky keywords across multiple categories.

    Returns:
        dict with score, matched_keywords list, and matched_categories list.
    """
    text_lower = text.lower()
    score = 0
    matched_keywords: list[str] = []
    matched_categories: list[str] = []

    for category, data in KEYWORD_CATEGORIES.items():
        weight = data["weight"]
        for keyword in data["keywords"]:
            if keyword in text_lower:
                score += weight
                matched_keywords.append(keyword)
                if category not in matched_categories:
                    matched_categories.append(category)

    return {
        "score": score,
        "matched_keywords": matched_keywords,
        "matched_categories": matched_categories,
    }