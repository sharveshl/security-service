import requests
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

def check_url_with_google(url):
    payload = {
        "client": {
            "clientId": "your-chat-app",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "POTENTIALLY_HARMFUL_APPLICATION",
                "UNWANTED_SOFTWARE"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    response = requests.post(SAFE_BROWSING_URL, json=payload)

    if response.status_code == 200:
        data = response.json()
        if "matches" in data:
            return True  # URL is malicious
        else:
            return False  # URL is safe
    else:
        return False  # Fail open (or log error)