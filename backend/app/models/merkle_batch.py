
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import CheckConstraint, UniqueConstraint

from app.extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class MerkleBatch(db.Model):
    __tablename__ = "merkle_batches"

    __table_args__ = (
        CheckConstraint(
            "leaf_count > 0",
            name="ck_merkle_batch_leaf_count",
        ),
        CheckConstraint(
            "status IN ('PENDING_ANCHOR', 'ANCHORED', 'FAILED')",
            name="ck_merkle_batch_status",
        ),
    )

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    merkle_root = db.Column(
        db.String(64),
        nullable=False,
        index=True,
    )

    leaf_count = db.Column(
        db.Integer,
        nullable=False,
    )

    hash_version = db.Column(
        db.String(32),
        nullable=False,
        default="creatorxdr-audit-v1",
    )

    status = db.Column(
        db.String(30),
        nullable=False,
        default="PENDING_ANCHOR",
        index=True,
    )

    # Ethereum anchoring fields, populated later.
    chain_id = db.Column(
        db.BigInteger,
        nullable=True,
    )

    contract_address = db.Column(
        db.String(42),
        nullable=True,
    )

    transaction_hash = db.Column(
        db.String(66),
        nullable=True,
    )

    block_number = db.Column(
        db.BigInteger,
        nullable=True,
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        index=True,
    )

    anchored_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
    )

    leaves = db.relationship(
        "MerkleBatchLeaf",
        back_populates="batch",
        cascade="all, delete-orphan",
        order_by="MerkleBatchLeaf.leaf_index",
    )

    def to_dict(self):
        return {
            "id": self.id,
            "merkle_root": self.merkle_root,
            "leaf_count": self.leaf_count,
            "hash_version": self.hash_version,
            "status": self.status,
            "chain_id": self.chain_id,
            "contract_address": self.contract_address,
            "transaction_hash": self.transaction_hash,
            "block_number": self.block_number,
            "created_at": self.created_at.isoformat(),
            "anchored_at": (
                self.anchored_at.isoformat()
                if self.anchored_at else None
            ),
        }


class MerkleBatchLeaf(db.Model):
    __tablename__ = "merkle_batch_leaves"

    __table_args__ = (
        UniqueConstraint(
            "audit_log_id",
            name="uq_merkle_leaf_audit_log",
        ),
        UniqueConstraint(
            "batch_id",
            "leaf_index",
            name="uq_merkle_batch_leaf_position",
        ),
        CheckConstraint(
            "leaf_index >= 0",
            name="ck_merkle_leaf_index",
        ),
    )

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    batch_id = db.Column(
        db.String(36),
        db.ForeignKey(
            "merkle_batches.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    audit_log_id = db.Column(
        db.String(36),
        db.ForeignKey(
            "admin_audit_logs.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    # Snapshot of the event hash at batch creation.
    event_hash = db.Column(
        db.String(64),
        nullable=False,
    )

    leaf_index = db.Column(
        db.Integer,
        nullable=False,
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    batch = db.relationship(
        "MerkleBatch",
        back_populates="leaves",
    )

    audit_log = db.relationship(
        "AdminAuditLog",
    )

    def to_dict(self):
        return {
            "id": self.id,
            "batch_id": self.batch_id,
            "audit_log_id": self.audit_log_id,
            "event_hash": self.event_hash,
            "leaf_index": self.leaf_index,
            "created_at": self.created_at.isoformat(),
        }

