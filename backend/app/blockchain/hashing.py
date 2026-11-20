
import hashlib
import json
from datetime import datetime, timezone
from typing import Any


HASH_ALGORITHM = "sha256"
HASH_VERSION = "creatorxdr-audit-v1"


def _normalize_timestamp(value: datetime) -> str:
    """Convert timestamps into a consistent UTC ISO-8601 representation."""
    if not isinstance(value, datetime):
        raise TypeError("created_at must be a datetime object")

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def canonicalize_audit_event(audit_log: Any) -> bytes:
    """
    Create deterministic bytes from an audit log record.

    Deliberately excludes admin_id and submission_id.
    Personal identifiers and document-related data must not enter
    the public blockchain commitment.
    """
    payload = {
        "version": HASH_VERSION,
        "event_id": str(audit_log.id),
        "event_type": str(audit_log.event_type),
        "created_at": _normalize_timestamp(audit_log.created_at),
    }

    canonical_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    return canonical_json.encode("utf-8")


def hash_audit_event(audit_log: Any) -> str:
    """Return the SHA-256 hash of a canonical audit event."""
    event_bytes = canonicalize_audit_event(audit_log)

    return hashlib.sha256(event_bytes).hexdigest()


def verify_audit_event(audit_log: Any, expected_hash: str) -> bool:
    """Verify an audit event against its previously stored hash."""
    if not isinstance(expected_hash, str):
        return False

    if len(expected_hash) != 64:
        return False

    try:
        actual_hash = hash_audit_event(audit_log)
    except (TypeError, ValueError, AttributeError):
        return False

    return actual_hash == expected_hash.lower()
