
from datetime import datetime, timezone
from uuid import uuid4

from app.extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class OCRResult(db.Model):
    __tablename__ = "ocr_results"

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
        unique=True,
        index=True,
    )

    # Encrypted OCR text. Never return this through creator APIs.
    encrypted_text = db.Column(
        db.Text,
        nullable=False,
    )

    # Encrypted structured extraction.
    # This may contain sensitive identity information.
    encrypted_identity_data = db.Column(
        db.Text,
        nullable=True,
    )

    # EXTRACTED, NOT_FOUND, AMBIGUOUS, or UNSUPPORTED.
    extraction_status = db.Column(
        db.String(20),
        nullable=False,
        default="UNSUPPORTED",
    )

    average_confidence = db.Column(
        db.Float,
        nullable=True,
    )

    language = db.Column(
        db.String(30),
        nullable=False,
        default="eng+hin",
    )

    page_count = db.Column(
        db.Integer,
        nullable=False,
        default=1,
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    submission = db.relationship(
        "VerificationSubmission",
        backref=db.backref(
            "ocr_result",
            uselist=False,
            cascade="all, delete-orphan",
        ),
    )
