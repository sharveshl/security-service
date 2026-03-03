"""Keyword-based risk detection with categorized, weighted scoring."""


# Each category has a weight and a list of keywords/phrases
KEYWORD_CATEGORIES: dict[str, dict] = {
    "financial_scam": {
        "weight": 3,
        "keywords": [
            "free money", "lottery", "you won", "prize winner",
            "cash prize", "inheritance", "million dollars",
            "wire transfer", "western union", "bitcoin payment",
            "investment opportunity", "guaranteed returns",
            "double your money",
        ],
    },
    "urgency_pressure": {
        "weight": 2,
        "keywords": [
            "urgent", "act now", "immediately", "expires today",
            "last chance", "don't miss", "limited time",
            "hurry", "right away", "asap",
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
        ],
    },
    "credential_harvesting": {
        "weight": 5,
        "keywords": [
            "send otp", "share otp", "otp", "send your password",
            "share your pin", "credit card number",
            "social security", "bank details", "cvv",
            "enter your credentials",
        ],
    },
    "impersonation": {
        "weight": 3,
        "keywords": [
            "i am from bank", "customer support",
            "technical support", "irs", "tax refund",
            "government agency", "official notice",
            "from microsoft", "from apple", "from google",
        ],
    },
    "click_bait": {
        "weight": 2,
        "keywords": [
            "click now", "click here", "click this link",
            "tap here", "open this", "download now",
            "install now",
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