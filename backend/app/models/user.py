from datetime import datetime, timezone
from uuid import uuid4

from app.extensions import db


def utc_now():
    return datetime.now(timezone.utc)



class User(db.Model):
    __tablename__ = "users"

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    email = db.Column(
        db.String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    full_name = db.Column(
        db.String(120),
        nullable=True,
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False,
    )

    role = db.Column(
        db.String(20),
        nullable=False,
        default="CREATOR",
    )

    email_verified = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
    )

    account_status = db.Column(
        db.String(20),
        nullable=False,
        default="ACTIVE",
    )

    tokens_valid_after = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    verification_challenges = db.relationship(
        "EmailVerification",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    password_reset_tokens = db.relationship(
        "PasswordResetToken",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    refresh_tokens = db.relationship(
        "RefreshToken",
        back_populates="user",
        cascade="all, delete-orphan",
    )


class EmailVerification(db.Model):
    __tablename__ = "email_verifications"

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    code_hash = db.Column(
        db.String(255),
        nullable=False,
    )

    expires_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
    )

    attempts = db.Column(
        db.Integer,
        nullable=False,
        default=0,
    )

    used_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    user = db.relationship(
        "User",
        back_populates="verification_challenges",
    )


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    token_hash = db.Column(
        db.String(64),
        unique=True,
        nullable=False,
        index=True,
    )

    expires_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
    )

    used_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    user = db.relationship(
        "User",
        back_populates="password_reset_tokens",
    )


class RefreshToken(db.Model):
    __tablename__ = "refresh_tokens"

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    family_id = db.Column(
        db.String(36),
        nullable=False,
        index=True,
    )

    jti = db.Column(
        db.String(36),
        unique=True,
        nullable=False,
        index=True,
    )

    expires_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
    )

    revoked_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
    )

    replaced_by_id = db.Column(
        db.String(36),
        nullable=True,
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    user = db.relationship(
        "User",
        back_populates="refresh_tokens",
    )