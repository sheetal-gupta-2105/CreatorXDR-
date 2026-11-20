
from datetime import datetime, timezone
from types import SimpleNamespace

from app.blockchain.hashing import (
    hash_audit_event,
    verify_audit_event,
)


def make_event():
    return SimpleNamespace(
        id="test-event-001",
        admin_id="admin-123",
        submission_id="submission-456",
        event_type="DOCUMENT_ACCESSED",
        created_at=datetime(2026, 11, 21, 10, 30, tzinfo=timezone.utc),
    )


def test_hash_is_deterministic():
    event = make_event()

    assert hash_audit_event(event) == hash_audit_event(event)


def test_hash_is_sha256_length():
    assert len(hash_audit_event(make_event())) == 64


def test_modified_event_fails_verification():
    event = make_event()
    original_hash = hash_audit_event(event)

    event.event_type = "DOCUMENT_DELETED"

    assert not verify_audit_event(event, original_hash)


def test_verification_succeeds_for_unchanged_event():
    event = make_event()
    expected_hash = hash_audit_event(event)

    assert verify_audit_event(event, expected_hash)


def test_identifiers_are_not_part_of_hash():
    event = make_event()
    original_hash = hash_audit_event(event)

    event.admin_id = "different-admin"
    event.submission_id = "different-submission"

    assert hash_audit_event(event) == original_hash
