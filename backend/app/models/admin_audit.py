
from datetime import datetime, timezone
from uuid import uuid4

from app.extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class AdminAuditLog(db.Model):
    __tablename__ = "admin_audit_logs"

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    admin_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    submission_id = db.Column(
        db.String(36),
        db.ForeignKey(
            "verification_submissions.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    event_type = db.Column(
        db.String(50),
        nullable=False,
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        index=True,
    )

    admin = db.relationship("User")

    submission = db.relationship(
        "VerificationSubmission",
    )

    def to_dict(self):
        return {
            "id": self.id,
            "admin_id": self.admin_id,
            "submission_id": self.submission_id,
            "event_type": self.event_type,
            "created_at": self.created_at.isoformat(),
        }
