
from datetime import datetime, timezone
from uuid import uuid4

from app.extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class MonitoredProfile(db.Model):
    __tablename__ = "monitored_profiles"

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    submitted_by = db.Column(
        db.String(36),
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    platform = db.Column(
        db.String(30),
        nullable=False,
    )

    username = db.Column(
        db.String(100),
        nullable=False,
    )

    display_name = db.Column(
        db.String(150),
        nullable=True,
    )

    bio = db.Column(
        db.Text,
        nullable=True,
    )

    profile_image_path = db.Column(
        db.String(500),
        nullable=True,
    )

    source = db.Column(
        db.String(30),
        nullable=False,
        default="MANUAL",
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    submitted_by_user = db.relationship("User")

    def to_dict(self):
        return {
            "id": self.id,
            "platform": self.platform,
            "username": self.username,
            "display_name": self.display_name,
            "bio": self.bio,
            "source": self.source,
            "created_at": self.created_at.isoformat(),
        }
