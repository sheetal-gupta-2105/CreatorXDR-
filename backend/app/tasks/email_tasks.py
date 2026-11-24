import logging
from typing import Optional
from redis import Redis
from rq import Queue
from flask import current_app

logger = logging.getLogger(__name__)

_redis_conn: Optional[Redis] = None
_email_queue: Optional[Queue] = None


def get_redis_connection() -> Optional[Redis]:
    """Get or initialize a Redis connection from current application config."""
    global _redis_conn
    if _redis_conn is not None:
        return _redis_conn

    redis_url = current_app.config.get("REDIS_URL")
    if not redis_url:
        return None

    try:
        conn = Redis.from_url(redis_url, socket_connect_timeout=2)
        conn.ping()
        _redis_conn = conn
        return _redis_conn
    except Exception as e:
        logger.warning("Redis is not available (%s). Background jobs will run synchronously.", str(e))
        return None


def get_email_queue() -> Optional[Queue]:
    """Get the RQ queue for email tasks, or None if Redis is unreachable."""
    conn = get_redis_connection()
    if conn:
        return Queue("email_queue", connection=conn)
    return None


def execute_email_job(
    to_email: str,
    subject: str,
    html_body: str,
    text_body: str,
    provider_name: str,
    config_dict: dict,
):
    """
    Worker function executed by RQ worker (or directly when run synchronously).
    Never logs OTP codes, passwords or sensitive user payloads.
    """
    from app.services.email.provider import ConsoleEmailProvider, SMTPEmailProvider

    logger.info("Executing email job for recipient '%s' with subject '%s'", to_email, subject)

    if provider_name == "smtp":
        provider = SMTPEmailProvider(
            host=config_dict.get("SMTP_HOST", "localhost"),
            port=config_dict.get("SMTP_PORT", 587),
            username=config_dict.get("SMTP_USER", ""),
            password=config_dict.get("SMTP_PASSWORD", ""),
            use_tls=config_dict.get("SMTP_USE_TLS", True),
            use_ssl=config_dict.get("SMTP_USE_SSL", False),
            default_from_email=config_dict.get("EMAIL_FROM_ADDRESS", "no-reply@creatorxdr.local"),
            default_from_name=config_dict.get("EMAIL_FROM_NAME", "CreatorXDR Security"),
        )
    else:
        provider = ConsoleEmailProvider()

    provider.send_email(
        to_email=to_email,
        subject=subject,
        html_body=html_body,
        text_body=text_body,
        from_email=config_dict.get("EMAIL_FROM_ADDRESS"),
        from_name=config_dict.get("EMAIL_FROM_NAME"),
    )
