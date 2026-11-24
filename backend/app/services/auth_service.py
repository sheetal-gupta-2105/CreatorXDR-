import hashlib
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from flask import current_app
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    decode_token,
)
import redis

from app.extensions import db
from app.models.user import (
    EmailVerification,
    PasswordResetToken,
    RefreshToken,
    User,
)

logger = logging.getLogger(__name__)

password_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
)

# Precomputed once at import time to equalize login timing for unknown emails.
DUMMY_PASSWORD_HASH = password_hasher.hash("creatorxdr-dummy-timing-password")

# Dev/test-only fallback when Redis is unavailable.
_DEV_REVOKED_JTIS: set[str] = set()


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError):
        return False


def verify_dummy_password(password: str) -> None:
    """Run Argon2 verification against a dummy hash to equalize timing."""
    verify_password(DUMMY_PASSWORD_HASH, password)


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_verification_challenge(user: User) -> str:
    """Invalidate any prior unused OTPs for this user and create a fresh 6-digit OTP."""
    now = datetime.now(timezone.utc)
    EmailVerification.query.filter_by(user_id=user.id, used_at=None).update(
        {"used_at": now},
        synchronize_session=False,
    )

    code = f"{secrets.randbelow(1_000_000):06d}"

    challenge = EmailVerification(
        user_id=user.id,
        code_hash=password_hasher.hash(code),
        expires_at=now + timedelta(minutes=10),
    )

    db.session.add(challenge)
    db.session.commit()

    return code


def check_otp_resend_allowed(
    user: User,
    cooldown_seconds: int = 60,
    max_per_hour: int = 5,
) -> bool:
    """Return True if user is outside the cooldown window and under the hourly cap."""
    now = datetime.now(timezone.utc)

    latest = (
        EmailVerification.query
        .filter_by(user_id=user.id)
        .order_by(EmailVerification.created_at.desc())
        .first()
    )
    if latest:
        created_at = _ensure_utc(latest.created_at)
        if created_at and (now - created_at).total_seconds() < cooldown_seconds:
            return False

    one_hour_ago = now - timedelta(hours=1)
    recent_count = (
        EmailVerification.query
        .filter(
            EmailVerification.user_id == user.id,
            EmailVerification.created_at >= one_hour_ago,
        )
        .count()
    )
    if recent_count >= max_per_hour:
        return False

    return True


def verify_email_code(challenge: EmailVerification, code: str):
    if challenge.used_at is not None:
        return False, "Verification code already used."

    now = datetime.now(timezone.utc)
    expires_at = _ensure_utc(challenge.expires_at)

    if expires_at is not None and expires_at <= now:
        return False, "Verification code expired."

    if challenge.attempts >= 5:
        return False, "Maximum verification attempts exceeded."

    challenge.attempts += 1

    try:
        valid = password_hasher.verify(
            challenge.code_hash,
            code,
        )
    except (VerifyMismatchError, VerificationError):
        valid = False

    if not valid:
        db.session.commit()
        return False, "Invalid verification code."

    challenge.used_at = now
    db.session.commit()

    return True, None


def create_password_reset_token(user: User, expiry_minutes: int = 15) -> str:
    """Invalidate older unused reset tokens and issue a new 15-minute single-use token."""
    now = datetime.now(timezone.utc)
    PasswordResetToken.query.filter_by(user_id=user.id, used_at=None).update(
        {"used_at": now},
        synchronize_session=False,
    )

    raw_token = secrets.token_urlsafe(32)
    token_row = PasswordResetToken(
        user_id=user.id,
        token_hash=hash_token(raw_token),
        expires_at=now + timedelta(minutes=expiry_minutes),
    )
    db.session.add(token_row)
    db.session.commit()

    return raw_token


def consume_password_reset_token(
    raw_token: str,
    new_password: str,
) -> tuple[bool, Optional[User], Optional[str]]:
    """
    Validate and consume a single-use password reset token with row locking.
    Updates password, sets tokens_valid_after, and revokes all refresh tokens.
    """
    now = datetime.now(timezone.utc)
    token_digest = hash_token(raw_token)

    token_row = (
        PasswordResetToken.query
        .filter_by(token_hash=token_digest)
        .with_for_update()
        .first()
    )

    if not token_row or token_row.used_at is not None:
        return False, None, "Invalid or expired password reset token."

    expires_at = _ensure_utc(token_row.expires_at)
    if expires_at is not None and expires_at <= now:
        return False, None, "Invalid or expired password reset token."

    user = db.session.get(User, token_row.user_id)
    if not user or user.account_status != "ACTIVE":
        return False, None, "Account is unavailable."

    token_row.used_at = now
    user.password_hash = hash_password(new_password)
    user.tokens_valid_after = now

    RefreshToken.query.filter_by(user_id=user.id, revoked_at=None).update(
        {"revoked_at": now},
        synchronize_session=False,
    )

    db.session.commit()
    return True, user, None


def issue_token_pair(
    user: User,
    family_id: Optional[str] = None,
    replaced_token: Optional[RefreshToken] = None,
) -> tuple[str, str, RefreshToken]:
    """Issue a new access + refresh token pair and persist the refresh token row."""
    now = datetime.now(timezone.utc)
    family = family_id or str(uuid4())
    issued_at_ms = time.time_ns() // 1_000_000

    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={
            "role": user.role,
            "issued_at_ms": issued_at_ms,
        },
    )
    refresh_token = create_refresh_token(
        identity=str(user.id),
        additional_claims={
            "role": user.role,
            "family_id": family,
            "issued_at_ms": issued_at_ms,
        },
    )

    decoded = decode_token(refresh_token)
    jti = decoded["jti"]
    exp = datetime.fromtimestamp(decoded["exp"], tz=timezone.utc)

    new_row = RefreshToken(
        user_id=user.id,
        family_id=family,
        jti=jti,
        expires_at=exp,
    )
    db.session.add(new_row)
    db.session.flush()

    if replaced_token is not None:
        replaced_token.revoked_at = now
        replaced_token.replaced_by_id = new_row.id

    db.session.commit()
    return access_token, refresh_token, new_row


def rotate_refresh_token(jti: str) -> tuple[bool, Optional[str], Optional[str], Optional[str], int]:
    """
    Rotate a refresh token with row-level locking.
    Detects reuse of a revoked token and commits family-wide revocation before returning 401.
    Note: No retry grace window is implemented (known limitation). Pre-migration refresh
    tokens without a DB row are rejected (one-time logout).
    """
    now = datetime.now(timezone.utc)

    token_row = (
        RefreshToken.query
        .filter_by(jti=jti)
        .with_for_update()
        .first()
    )

    if not token_row:
        return False, None, None, "Invalid refresh token.", 401

    if token_row.revoked_at is not None:
        logger.warning(
            "Refresh token reuse detected for family_id=%s; revoking family.",
            token_row.family_id,
        )
        RefreshToken.query.filter_by(
            family_id=token_row.family_id,
            revoked_at=None,
        ).update({"revoked_at": now}, synchronize_session=False)
        db.session.commit()
        return False, None, None, "Refresh token reuse detected.", 401

    expires_at = _ensure_utc(token_row.expires_at)
    if expires_at is not None and expires_at <= now:
        token_row.revoked_at = now
        db.session.commit()
        return False, None, None, "Refresh token expired.", 401

    user = db.session.get(User, token_row.user_id)
    if not user or user.account_status != "ACTIVE":
        RefreshToken.query.filter_by(
            family_id=token_row.family_id,
            revoked_at=None,
        ).update({"revoked_at": now}, synchronize_session=False)
        db.session.commit()
        return False, None, None, "Account is unavailable.", 401

    if not user.email_verified:
        return False, None, None, "Email verification required.", 403

    access_token, refresh_token, _ = issue_token_pair(
        user,
        family_id=token_row.family_id,
        replaced_token=token_row,
    )
    return True, access_token, refresh_token, None, 200


def revoke_refresh_family(family_id: str) -> None:
    """Revoke all active refresh tokens belonging to family_id."""
    now = datetime.now(timezone.utc)
    RefreshToken.query.filter_by(family_id=family_id, revoked_at=None).update(
        {"revoked_at": now},
        synchronize_session=False,
    )
    db.session.commit()


def _get_redis_client() -> Optional[redis.Redis]:
    redis_url = current_app.config.get("REDIS_URL")
    if not redis_url:
        return None
    return redis.from_url(redis_url, socket_connect_timeout=1, socket_timeout=1)


def _is_dev_or_test() -> bool:
    return bool(current_app.config.get("DEBUG") or current_app.config.get("TESTING"))


def revoke_access_jti(jti: str, exp_timestamp: Optional[int] = None) -> None:
    """Add an access token JTI to the Redis blocklist (or dev/test in-memory fallback)."""
    ttl = 900
    if exp_timestamp is not None:
        ttl = max(1, int(exp_timestamp - time.time()))

    try:
        client = _get_redis_client()
        if client is not None:
            client.setex(f"revoked_jti:{jti}", ttl, "1")
            return
    except Exception as exc:
        if not _is_dev_or_test():
            logger.error("Failed to record revoked JTI in Redis in production: %s", exc)
            raise
        logger.warning("Redis unavailable for JTI revocation; using dev/test in-memory fallback: %s", exc)

    if _is_dev_or_test():
        _DEV_REVOKED_JTIS.add(jti)


def is_access_jti_revoked(jti: str) -> bool:
    """
    Check whether an access token JTI is blocklisted.
    Uses dev/test-only in-memory fallback when Redis is unavailable; fails closed in production.
    """
    if _is_dev_or_test() and jti in _DEV_REVOKED_JTIS:
        return True

    try:
        client = _get_redis_client()
        if client is not None:
            return bool(client.exists(f"revoked_jti:{jti}"))
    except Exception as exc:
        if _is_dev_or_test():
            logger.warning("Redis unavailable checking JTI blocklist; using dev/test fallback: %s", exc)
            return jti in _DEV_REVOKED_JTIS
        logger.error("Redis unavailable checking JTI blocklist in production; failing closed: %s", exc)
        return True

    if _is_dev_or_test():
        return jti in _DEV_REVOKED_JTIS
    return True
