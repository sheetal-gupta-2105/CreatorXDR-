import logging
from flask import request
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logger = logging.getLogger(__name__)


def get_request_ip() -> str:
    """Safe IP address extraction respecting ProxyFix if configured."""
    return get_remote_address()


def get_user_or_ip() -> str:
    """
    Returns authenticated user ID if JWT is present in request,
    otherwise falls back to remote IP.
    Safe for endpoints that may or may not be authenticated.
    """
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
        if user_id:
            return f"user:{user_id}"
    except Exception:
        pass
    return f"ip:{get_remote_address()}"


def get_email_or_ip() -> str:
    """
    Extracts normalized email from JSON payload for email-targeted limits
    (e.g. login failed attempts, forgot password, resend OTP).
    Safely handles missing or malformed JSON payloads.
    """
    try:
        data = request.get_json(silent=True)
        if isinstance(data, dict):
            email = str(data.get("email", "")).strip().lower()
            if email and "@" in email:
                return f"email:{email}"
    except Exception:
        pass
    return f"ip:{get_remote_address()}"


def is_401_response(response) -> bool:
    """Predicate function to deduct limit only when response is HTTP 401."""
    return getattr(response, "status_code", None) == 401


# Global limiter instance initialized with key_func and default configs from Flask app
limiter = Limiter(
    key_func=get_request_ip,
    default_limits_per_method=False,
    headers_enabled=True,
    strategy="moving-window",
)

