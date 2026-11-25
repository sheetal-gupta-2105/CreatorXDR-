
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, CheckConstraint, Index, text

from app.extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class VerificationSubmission(db.Model):
    __tablename__ = "verification_submissions"

    __table_args__ = (
        CheckConstraint(
            "status IN ("
            "'AWAITING_CONFIRMATION', 'PENDING_REVIEW', 'UNDER_REVIEW', "
            "'NEEDS_RESUBMISSION', 'REJECTED', "
            "'APPROVED', 'PENDING_CHAIN', "
            "'CHAIN_FAILED', 'VERIFIED', 'QUARANTINED'"
            ")",
            name="ck_verification_submission_status",
        ),
        CheckConstraint(
            "ocr_status IN ('PENDING', 'COMPLETED', 'FAILED')",
            name="ck_verification_ocr_status",
        ),
        Index("ix_verification_user_status", "user_id", "status"),
    )

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Examples: PASSPORT, DRIVING_LICENSE, NATIONAL_ID,
    # PAN_CARD, AADHAAR, OTHER.
    document_type = db.Column(
        db.String(40),
        nullable=False,
    )

    issuing_country = db.Column(
        db.String(2),
        nullable=False,
    )

    # Random storage identifier, never the original filename.
    storage_key = db.Column(
        db.String(100),
        unique=True,
        nullable=False,
    )

    mime_type = db.Column(
        db.String(100),
        nullable=False,
    )

    file_size_bytes = db.Column(
        db.Integer,
        nullable=False,
    )

    # HMAC of uploaded file contents, not a raw identity number.
    document_hmac = db.Column(
        db.String(64),
        nullable=False,
    )

    status = db.Column(
        db.String(30),
        nullable=False,
        default="PENDING_REVIEW",
    )

    ocr_status = db.Column(
        db.String(20),
        nullable=False,
        default="PENDING",
    )

    # Internal duplicate signal. Never expose another user's identity.
    duplicate_detected = db.Column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )

    ocr_confidence = db.Column(
        db.Float,
        nullable=True,
    )

    submitted_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    reviewed_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
    )

    document_deleted_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
    )

    deletion_reason = db.Column(
        db.String(255),
        nullable=True,
    )

    quarantined = db.Column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )

    quarantine_reason = db.Column(
        db.String(255),
        nullable=True,
    )

    confirmed_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
    )

    correction_mismatch = db.Column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
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

    user = db.relationship(
        "User",
        backref=db.backref(
            "verification_submissions",
            lazy="dynamic",
        ),
    )

    reviews = db.relationship(
        "VerificationReview",
        back_populates="submission",
        cascade="all, delete-orphan",
        order_by="VerificationReview.created_at",
    )

    def to_dict(self):
        return {
            "id": self.id,
            "document_type": self.document_type,
            "issuing_country": self.issuing_country,
            "status": self.status,
            "ocr_status": self.ocr_status,
            "ocr_confidence": self.ocr_confidence,
            "quarantined": self.quarantined,
            "confirmed_at": (
                self.confirmed_at.isoformat()
                if self.confirmed_at else None
            ),
            "submitted_at": self.submitted_at.isoformat(),
            "reviewed_at": (
                self.reviewed_at.isoformat()
                if self.reviewed_at else None
            ),
        }


class VerificationReview(db.Model):
    __tablename__ = "verification_reviews"

    __table_args__ = (
        CheckConstraint(
            "decision IN ("
            "'APPROVED', 'REJECTED', 'NEEDS_RESUBMISSION'"
            ")",
            name="ck_verification_review_decision",
        ),
        Index(
            "ix_verification_review_submission",
            "submission_id",
            "created_at",
        ),
    )

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    submission_id = db.Column(
        db.String(36),
        db.ForeignKey(
            "verification_submissions.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    reviewer_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=False,
    )

    decision = db.Column(
        db.String(30),
        nullable=False,
    )

    reason_code = db.Column(
        db.String(50),
        nullable=True,
    )

    reviewer_notes = db.Column(
        db.Text,
        nullable=True,
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    submission = db.relationship(
        "VerificationSubmission",
        back_populates="reviews",
    )

    reviewer = db.relationship(
        "User",
        foreign_keys=[reviewer_id],
    )

    def to_dict(self):
        return {
            "id": self.id,
            "decision": self.decision,
            "reason_code": self.reason_code,
            "reviewer_notes": self.reviewer_notes,
            "created_at": self.created_at.isoformat(),
        }


class IdentityFingerprint(db.Model):
    __tablename__ = "identity_fingerprints"

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    # Keyed HMAC of normalized identity information.
    # Never store the raw government ID number here.
    fingerprint = db.Column(
        db.String(64),
        unique=True,
        nullable=False,
        index=True,
    )

    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    submission_id = db.Column(
        db.String(36),
        db.ForeignKey(
            "verification_submissions.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    user = db.relationship("User")
    submission = db.relationship("VerificationSubmission")
