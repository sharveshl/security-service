import re

def extract_urls(text):
    url_pattern = r"(https?://[^\s]+)"
    return re.findall(url_pattern, text)

def basic_url_check(url):
    suspicious_patterns = ["bit.ly", "tinyurl", "free-money", "win-prize"]

    for pattern in suspicious_patterns:
        if pattern in url.lower():
            return True
    
    return False