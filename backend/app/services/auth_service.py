import secrets
from datetime import timedelta, timezone, datetime

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

from app.extensions import db
from app.models.user import EmailVerification


password_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
)


def hash_password(password):
    return password_hasher.hash(password)


def verify_password(password_hash, password):
    try:
        return password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError):
        return False


def create_verification_challenge(user):
    code = f"{secrets.randbelow(1_000_000):06d}"

    challenge = EmailVerification(
        user_id=user.id,
        code_hash=password_hasher.hash(code),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )

    db.session.add(challenge)
    db.session.commit()

    return code


def verify_email_code(challenge, code):
    if challenge.used_at is not None:
        return False, "Verification code already used."

    now = datetime.now(timezone.utc)

    if challenge.expires_at <= now:
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