import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Centralized application settings loaded from environment variables."""

    # Environment
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # Google Safe Browsing
    GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

    # CORS
    ALLOWED_ORIGINS: list[str] = [
        origin.strip()
        for origin in os.getenv("ALLOWED_ORIGINS", "*").split(",")
    ]

    # Rate Limiting
    RATE_LIMIT: str = os.getenv("RATE_LIMIT", "300/minute")

    # Risk Engine Thresholds
    BLOCK_THRESHOLD: int = int(os.getenv("BLOCK_THRESHOLD", "5"))
    WARN_THRESHOLD: int = int(os.getenv("WARN_THRESHOLD", "3"))

    # API Authentication (optional, for service-to-service calls)
    API_KEY: str = os.getenv("API_KEY", "")

    # Safe Browsing Cache TTL (seconds)
    CACHE_TTL: int = int(os.getenv("CACHE_TTL", "3600"))

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"


settings = Settings()
