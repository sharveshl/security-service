# 🛡️ Security Service

Production-grade microservice for detecting **scam, fraud, and phishing** in chat messages. Built with FastAPI, integrates Google Safe Browsing API.

## Features

- **Google Safe Browsing** — real-time URL threat detection with caching
- **Keyword Detection** — 6 weighted categories (financial scam, urgency, phishing, credential harvesting, impersonation, clickbait)
- **URL Analysis** — shortener detection, IP-based URL flagging, suspicious pattern matching
- **Risk Scoring** — tiered actions: `allow` / `warn` / `block`
- **Rate Limiting** — configurable per-IP rate limits
- **API Key Auth** — optional header-based authentication
- **Health Check** — `/health` endpoint for monitoring

## API Endpoints

| Method | Path       | Description                              |
| ------ | ---------- | ---------------------------------------- |
| POST   | `/analyze` | Analyze a message for threats            |
| GET    | `/health`  | Health check (used by Render)            |
| GET    | `/docs`    | Swagger UI (development only)            |

### POST `/analyze`

**Request:**
```json
{
  "text": "URGENT! Click here to verify your account http://bit.ly/xyz",
  "user_id": "user123"
}
```

**Response:**
```json
{
  "risk_score": 15,
  "risk_level": "critical",
  "action": "block",
  "reasons": [
    "URL shortener detected: bit.ly",
    "Suspicious keywords detected: urgent, click here, verify your account"
  ],
  "flagged_urls": ["http://bit.ly/xyz"],
  "details": {
    "matched_keywords": ["urgent", "click here", "verify your account"],
    "matched_categories": ["urgency_pressure", "click_bait", "phishing"]
  },
  "urls_scanned": 1,
  "analyzed_at": "2026-03-03T06:10:00+00:00",
  "user_id": "user123"
}
```

## Local Setup

```bash
# 1. Clone and enter the project
cd security-service

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env and set your GOOGLE_SAFE_BROWSING_API_KEY

# 5. Run the server
uvicorn main:app --reload --port 8000
```

## Environment Variables

| Variable                        | Required | Default      | Description                        |
| ------------------------------- | -------- | ------------ | ---------------------------------- |
| `GOOGLE_SAFE_BROWSING_API_KEY`  | Yes      | —            | Google Safe Browsing API key       |
| `ENVIRONMENT`                   | No       | development  | `development` or `production`      |
| `LOG_LEVEL`                     | No       | INFO         | Python log level                   |
| `ALLOWED_ORIGINS`               | No       | *            | Comma-separated CORS origins       |
| `API_KEY`                       | No       | —            | API key for service authentication |
| `RATE_LIMIT`                    | No       | 30/minute    | Rate limit per IP                  |
| `BLOCK_THRESHOLD`               | No       | 5            | Score threshold to block messages  |
| `WARN_THRESHOLD`                | No       | 3            | Score threshold to warn            |
| `CACHE_TTL`                     | No       | 3600         | URL cache TTL in seconds           |

## Deploy to Render

1. Push this repo to GitHub
2. Go to [Render Dashboard](https://dashboard.render.com)
3. Click **New → Blueprint** and connect your repo
4. Render reads `render.yaml` automatically
5. Set the environment variables marked `sync: false` in the Render dashboard:
   - `GOOGLE_SAFE_BROWSING_API_KEY`
   - `ALLOWED_ORIGINS` (your chat app domain, e.g. `https://your-chat-app.onrender.com`)
   - `API_KEY` (optional, for service-to-service auth)
6. Deploy!

## Integration

Call from your chat app backend before delivering messages:

```javascript
const response = await fetch('https://your-security-service.onrender.com/analyze', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': process.env.SECURITY_SERVICE_API_KEY  // if API_KEY is set
  },
  body: JSON.stringify({ text: messageText, user_id: senderId })
});

const result = await response.json();

if (result.action === 'block') {
  // Reject the message
} else if (result.action === 'warn') {
  // Flag with warning
} else {
  // Allow through
}
```