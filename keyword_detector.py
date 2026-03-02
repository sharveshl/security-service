def keyword_risk(text):
    risky_keywords = [
        "urgent",
        "verify",
        "lottery",
        "click now",
        "free money",
        "account suspended",
        "otp"
    ]

    score = 0

    for word in risky_keywords:
        if word in text.lower():
            score += 2

    return score