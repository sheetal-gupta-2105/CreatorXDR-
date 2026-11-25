
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import CheckConstraint, Index

from app.extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class ThreatDetection(db.Model):
    __tablename__ = "threat_detections"

    __table_args__ = (
        CheckConstraint(
            "risk_score >= 0 AND risk_score <= 100",
            name="ck_threat_detection_risk_score",
        ),
        CheckConstraint(
            "risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_threat_detection_risk_level",
        ),
        CheckConstraint(
            "investigation_status IN "
            "('NEW', 'REVIEWING', 'CONFIRMED', 'SAFE', 'DISMISSED')",
            name="ck_threat_detection_status",
        ),
        Index(
            "ix_threat_detection_risk_created",
            "risk_level",
            "created_at",
        ),
    )

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    reference_profile_id = db.Column(
        db.String(36),
        db.ForeignKey(
            "creator_social_profiles.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    monitored_profile_id = db.Column(
        db.String(36),
        db.ForeignKey(
            "monitored_profiles.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    risk_score = db.Column(
        db.Float,
        nullable=False,
    )

    risk_level = db.Column(
        db.String(20),
        nullable=False,
    )

    feature_scores = db.Column(
        db.JSON,
        nullable=False,
    )

    evidence = db.Column(
        db.JSON,
        nullable=False,
    )

    available_signals = db.Column(
        db.JSON,
        nullable=False,
    )

    missing_signals = db.Column(
        db.JSON,
        nullable=False,
    )

    scoring_note = db.Column(
        db.Text,
        nullable=True,
    )

    investigation_status = db.Column(
        db.String(20),
        nullable=False,
        default="NEW",
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    reference_profile = db.relationship(
        "CreatorSocialProfile",
    )

    monitored_profile = db.relationship(
        "MonitoredProfile",
    )

    def to_dict(self):
        return {
            "id": self.id,
            "reference_profile_id": self.reference_profile_id,
            "monitored_profile_id": self.monitored_profile_id,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "feature_scores": self.feature_scores,
            "evidence": self.evidence,
            "available_signals": self.available_signals,
            "missing_signals": self.missing_signals,
            "scoring_note": self.scoring_note,
            "investigation_status": self.investigation_status,
            "created_at": self.created_at.isoformat(),
        }
