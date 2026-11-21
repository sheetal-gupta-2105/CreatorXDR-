
from typing import Optional

from sqlalchemy.orm import joinedload

from app.extensions import db
from app.models import (
    AdminAuditLog,
    MerkleBatch,
    MerkleBatchLeaf,
)
from app.blockchain.hashing import (
    HASH_VERSION,
    hash_audit_event,
)
from app.blockchain.merkle_tree import (
    build_merkle_tree,
    verify_merkle_root,
)


DEFAULT_BATCH_SIZE = 100
MAX_BATCH_SIZE = 1000


class MerkleBatchError(Exception):
    """Raised when a Merkle batch cannot be created or verified."""


def create_merkle_batch(
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> Optional[MerkleBatch]:
    """
    Create a Merkle batch from eligible audit events.

    Eligible events:
    - Have a stored event hash.
    - Use the current hash version.
    - Have not already been assigned to a batch.

    The batch and its leaves are persisted atomically.
    Returns None if no eligible events are available.
    """

    if (
        isinstance(batch_size, bool)
        or not isinstance(batch_size, int)
        or not 1 <= batch_size <= MAX_BATCH_SIZE
    ):
        raise ValueError(
            f"batch_size must be between 1 and {MAX_BATCH_SIZE}"
        )

    try:
        query = (
            AdminAuditLog.query
            .outerjoin(
                MerkleBatchLeaf,
                MerkleBatchLeaf.audit_log_id == AdminAuditLog.id,
            )
            .filter(
                AdminAuditLog.event_hash.isnot(None),
                AdminAuditLog.hash_version == HASH_VERSION,
                MerkleBatchLeaf.id.is_(None),
            )
            .order_by(
                AdminAuditLog.created_at.asc(),
                AdminAuditLog.id.asc(),
            )
            .limit(batch_size)
            .with_for_update(
                skip_locked=True,
                of=AdminAuditLog,
            )
        )

        audit_logs = query.all()

        if not audit_logs:
            return None

        event_hashes = []

        for audit_log in audit_logs:
            stored_hash = audit_log.event_hash

            # Validate the stored hash format.
            if (
                not isinstance(stored_hash, str)
                or len(stored_hash) != 64
            ):
                raise MerkleBatchError(
                    f"Invalid event hash for audit event {audit_log.id}"
                )

            try:
                bytes.fromhex(stored_hash)
            except ValueError as exc:
                raise MerkleBatchError(
                    f"Malformed event hash for audit event {audit_log.id}"
                ) from exc

            # Ensure the stored hash still matches the event.
            actual_hash = hash_audit_event(audit_log)

            if actual_hash != stored_hash.lower():
                raise MerkleBatchError(
                    f"Audit integrity check failed for event {audit_log.id}"
                )

            event_hashes.append(stored_hash.lower())

        merkle_root, _ = build_merkle_tree(event_hashes)

        batch = MerkleBatch(
            merkle_root=merkle_root,
            leaf_count=len(audit_logs),
            hash_version=HASH_VERSION,
            status="PENDING_ANCHOR",
        )

        db.session.add(batch)
        db.session.flush()

        leaves = []

        for index, audit_log in enumerate(audit_logs):
            leaf = MerkleBatchLeaf(
                batch_id=batch.id,
                audit_log_id=audit_log.id,
                event_hash=audit_log.event_hash.lower(),
                leaf_index=index,
            )

            leaves.append(leaf)

        db.session.add_all(leaves)
        db.session.commit()

        return batch

    except Exception:
        db.session.rollback()
        raise


def verify_merkle_batch(batch_id: str) -> bool:
    """
    Verify a stored Merkle batch.

    Checks:
    - Batch exists.
    - Leaf count matches the stored count.
    - Leaf positions are contiguous.
    - Each snapshot matches its audit record.
    - Each audit record still matches its canonical hash.
    - Recomputed root matches the stored root.
    """

    if not isinstance(batch_id, str) or not batch_id.strip():
        return False

    batch = (
        MerkleBatch.query
        .options(
            joinedload(MerkleBatch.leaves).joinedload(
                MerkleBatchLeaf.audit_log
            )
        )
        .filter_by(id=batch_id)
        .first()
    )

    if batch is None:
        return False

    if batch.hash_version != HASH_VERSION:
        return False

    leaves = sorted(
        batch.leaves,
        key=lambda leaf: leaf.leaf_index,
    )

    if len(leaves) != batch.leaf_count:
        return False

    if not leaves:
        return False

    event_hashes = []

    for expected_index, leaf in enumerate(leaves):
        if leaf.leaf_index != expected_index:
            return False

        audit_log = leaf.audit_log

        if audit_log is None:
            return False

        if audit_log.hash_version != batch.hash_version:
            return False

        if audit_log.event_hash != leaf.event_hash:
            return False

        try:
            actual_hash = hash_audit_event(audit_log)
        except (TypeError, ValueError, AttributeError):
            return False

        if actual_hash != leaf.event_hash:
            return False

        event_hashes.append(leaf.event_hash)

    return verify_merkle_root(
        event_hashes,
        batch.merkle_root,
    )

