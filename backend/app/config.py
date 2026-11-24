
import os
from pathlib import Path
from datetime import timedelta

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BACKEND_DIR / ".env")


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", SECRET_KEY)

    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }
    BLOCKCHAIN_RPC_URL = os.getenv(
        "BLOCKCHAIN_RPC_URL",
        "http://host.docker.internal:8545",
    )

    BLOCKCHAIN_PRIVATE_KEY = os.getenv(
        "BLOCKCHAIN_PRIVATE_KEY",
    )

    BLOCKCHAIN_CONTRACT_ADDRESS = os.getenv(
        "BLOCKCHAIN_CONTRACT_ADDRESS",
    )

    BLOCKCHAIN_CHAIN_ID = int(
        os.getenv("BLOCKCHAIN_CHAIN_ID", "31337")
    )

    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_TOKEN_LOCATION = ["headers"]
    JWT_HEADER_TYPE = "Bearer"

    FRONTEND_ORIGIN = os.getenv(
        "FRONTEND_ORIGIN",
        "http://localhost:5173",
    )

    DEBUG = os.getenv("FLASK_DEBUG", "false").lower() in {
        "1", "true", "yes"
    }

    AUTH_DEBUG_OTP = os.getenv(
        "AUTH_DEBUG_OTP", "false"
    ).lower() in {
        "1", "true", "yes"
    }

    IDENTITY_HMAC_KEY = os.getenv("IDENTITY_HMAC_KEY")

    IDENTITY_STORAGE_PATH = os.getenv(
        "IDENTITY_STORAGE_PATH",
        str(BACKEND_DIR / "storage" / "identity_documents"),
    )

    OCR_ENCRYPTION_KEY = os.getenv("OCR_ENCRYPTION_KEY")

    MAX_DOCUMENT_SIZE = 5 * 1024 * 1024
    MAX_CONTENT_LENGTH = 6 * 1024 * 1024

    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # Rate Limiting Configuration
    # RQ uses DB 0 (e.g. redis://.../0). Limiter uses DB 1 by default.
    RATELIMIT_STORAGE_URI = os.getenv(
        "RATELIMIT_STORAGE_URI",
        os.getenv("REDIS_URL", "redis://localhost:6379/0").rsplit("/", 1)[0] + "/1"
        if "/" in os.getenv("REDIS_URL", "redis://localhost:6379/0")
        else "redis://localhost:6379/1"
    )
    RATELIMIT_STRATEGY = os.getenv("RATELIMIT_STRATEGY", "moving-window")
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "200 per minute")
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_IN_MEMORY_FALLBACK = os.getenv("RATELIMIT_DEFAULT", "200 per minute")

    RATELIMIT_ENABLED = os.getenv("RATELIMIT_ENABLED", "false" if (os.getenv("TESTING") == "true") else "true").lower() in {
        "1", "true", "yes"
    }

    RATELIMIT_FALLBACK_ENABLED = os.getenv(
        "RATELIMIT_FALLBACK_ENABLED",
        "true"
        if (
            os.getenv("FLASK_DEBUG", "false").lower() in {"1", "true", "yes"}
            or os.getenv("FLASK_ENV") == "development"
            or os.getenv("TESTING", "false").lower() in {"1", "true", "yes"}
        )
        else "false",
    ).lower() in {"1", "true", "yes"}
    RATELIMIT_IN_MEMORY_FALLBACK_ENABLED = RATELIMIT_FALLBACK_ENABLED
    TRUSTED_PROXY_COUNT = int(os.getenv("TRUSTED_PROXY_COUNT", "0"))


    # Configurable endpoint limits
    RATELIMIT_REGISTER = os.getenv("RATELIMIT_REGISTER", "5 per hour; 15 per day")
    RATELIMIT_LOGIN_IP = os.getenv("RATELIMIT_LOGIN_IP", "10 per minute; 30 per hour")
    RATELIMIT_LOGIN_ACCOUNT = os.getenv("RATELIMIT_LOGIN_ACCOUNT", "5 per 15 minutes")
    RATELIMIT_VERIFY_EMAIL = os.getenv("RATELIMIT_VERIFY_EMAIL", "10 per 15 minutes")
    RATELIMIT_RESEND_OTP = os.getenv("RATELIMIT_RESEND_OTP", "3 per hour")
    RATELIMIT_FORGOT_PASSWORD = os.getenv("RATELIMIT_FORGOT_PASSWORD", "3 per hour")
    RATELIMIT_RESET_PASSWORD = os.getenv("RATELIMIT_RESET_PASSWORD", "5 per hour")
    RATELIMIT_REFRESH_TOKEN = os.getenv("RATELIMIT_REFRESH_TOKEN", "30 per minute")
    RATELIMIT_PROFILE_UPDATE = os.getenv("RATELIMIT_PROFILE_UPDATE", "15 per minute")
    RATELIMIT_DOCUMENT_UPLOAD_USER = os.getenv("RATELIMIT_DOCUMENT_UPLOAD_USER", "10 per hour")
    RATELIMIT_DOCUMENT_UPLOAD_IP = os.getenv("RATELIMIT_DOCUMENT_UPLOAD_IP", "20 per hour")
    RATELIMIT_ADMIN_ACTIONS = os.getenv("RATELIMIT_ADMIN_ACTIONS", "60 per minute")
    RATELIMIT_ADMIN_QUEUE = os.getenv("RATELIMIT_ADMIN_QUEUE", "30 per minute")
    RATELIMIT_ADMIN_DOCUMENT_STREAM = os.getenv("RATELIMIT_ADMIN_DOCUMENT_STREAM", "30 per minute")


    EMAIL_PROVIDER = os.getenv("EMAIL_PROVIDER", "console").lower()
    EMAIL_SYNC_FALLBACK = os.getenv(
        "EMAIL_SYNC_FALLBACK",
        "true" if (os.getenv("FLASK_DEBUG", "false").lower() in {"1", "true", "yes"} or os.getenv("FLASK_ENV") == "development") else "false",
    ).lower() in {"1", "true", "yes"}

    EMAIL_FROM_ADDRESS = os.getenv(
        "EMAIL_FROM_ADDRESS", "no-reply@creatorxdr.local"
    )
    EMAIL_FROM_NAME = os.getenv(
        "EMAIL_FROM_NAME", "CreatorXDR Security"
    )
    SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() in {
        "1", "true", "yes"
    }
    SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").lower() in {
        "1", "true", "yes"
    }

