
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

