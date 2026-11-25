from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile

from flask import current_app, has_app_context

from app.extensions import db
from app.models.monitored_profile import MonitoredProfile
from app.models.social_profile import CreatorSocialProfile
from app.models.threat_detection import ThreatDetection

ACTIVE_DETECTION_STATUSES = {"NEW", "REVIEWING", "CONFIRMED"}
RESOLVED_DETECTION_STATUSES = {"SAFE", "DISMISSED"}


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _validate_storage_dir(
    storage_path: str | Path,
    allowed_base_dir: str | Path | None = None,
) -> Path:
    """Validate and resolve the threat profile image storage directory."""
    if not storage_path or not str(storage_path).strip():
        raise ValueError("Storage path must not be empty.")

    raw_path = Path(storage_path)
    if raw_path.is_symlink():
        raise ValueError("Storage path must not be a symlink.")

    storage_dir = raw_path.resolve()

    if storage_dir == storage_dir.parent:
        raise ValueError("Storage path must not be a filesystem root.")

    if storage_dir.exists() and not storage_dir.is_dir():
        raise ValueError("Storage path must be a directory.")

    if has_app_context():
        for protected_key in ("IDENTITY_STORAGE_PATH", "QUARANTINE_STORAGE_PATH"):
            protected_val = current_app.config.get(protected_key)
            if protected_val:
                protected_dir = Path(protected_val).resolve()
                if (
                    storage_dir == protected_dir
                    or storage_dir.is_relative_to(protected_dir)
                    or protected_dir.is_relative_to(storage_dir)
                ):
                    raise ValueError(
                        f"Storage path must not overlap with {protected_key}."
                    )

    allowed_bases: list[Path] = []
    if allowed_base_dir is not None:
        base_raw = Path(allowed_base_dir)
        if base_raw.is_symlink():
            raise ValueError("Allowed base directory must not be a symlink.")
        allowed_bases.append(base_raw.resolve())
    elif has_app_context():
        configured_base = current_app.config.get("PROFILE_IMAGE_STORAGE_BASE")
        if configured_base:
            allowed_bases.append(Path(configured_base).resolve())
        else:
            app_storage_base = (
                Path(current_app.root_path).parent / "storage"
            ).resolve()
            allowed_bases.append(app_storage_base)
            if current_app.config.get("TESTING"):
                allowed_bases.append(Path(tempfile.gettempdir()).resolve())

    if allowed_bases and not any(
        storage_dir != base and storage_dir.is_relative_to(base)
        for base in allowed_bases
    ):
        raise ValueError(
            "Storage path is outside the allowed storage boundary."
        )

    return storage_dir


def _is_monitored_profile_eligible(
    monitored: MonitoredProfile,
    cutoff: datetime,
) -> bool:
    """Return True only when all detections are resolved and past cutoff."""
    detections = (
        ThreatDetection.query
        .filter_by(monitored_profile_id=monitored.id)
        .all()
    )

    if any(
        d.investigation_status in ACTIVE_DETECTION_STATUSES
        or _ensure_utc(d.created_at) >= cutoff
        for d in detections
    ):
        return False

    if not detections and _ensure_utc(monitored.created_at) >= cutoff:
        return False

    if any(
        d.investigation_status not in RESOLVED_DETECTION_STATUSES
        for d in detections
    ):
        return False

    return True


def _is_filename_referenced(
    filename: str,
    exclude_monitored_id: str | None = None,
) -> bool:
    """Return True if any active reference or monitored profile uses filename."""
    ref_exists = (
        db.session.query(CreatorSocialProfile.id)
        .filter(CreatorSocialProfile.profile_image_path == filename)
        .first()
        is not None
    )
    if ref_exists:
        return True

    monitored_query = db.session.query(MonitoredProfile.id).filter(
        MonitoredProfile.profile_image_path == filename
    )
    if exclude_monitored_id is not None:
        monitored_query = monitored_query.filter(
            MonitoredProfile.id != exclude_monitored_id
        )

    return monitored_query.first() is not None


def _safe_resolve_storage_file(storage_dir: Path, filename: str) -> Path | None:
    """Resolve a stored profile image filename strictly inside storage_dir."""
    if not filename or Path(filename).name != filename:
        return None

    candidate = storage_dir / filename
    if candidate.is_symlink():
        return None

    resolved = candidate.resolve()
    if resolved.parent != storage_dir:
        return None

    return resolved


def cleanup_threat_images(
    storage_path: str | Path,
    retention_days: int = 90,
    orphan_grace_seconds: int = 3600,
    dry_run: bool = False,
    now: datetime | None = None,
    allowed_base_dir: str | Path | None = None,
) -> dict:
    """
    Safely clean up expired resolved monitored-profile images and orphaned files.

    Policy:
    - Active reference profile images (CreatorSocialProfile) are NEVER deleted.
    - MonitoredProfile images are NEVER deleted if any referencing ThreatDetection
      is active (NEW, REVIEWING, CONFIRMED) or newer than retention_days.
    - When a MonitoredProfile image expires, its DB reference is cleared to NULL
      while preserving DB detection history, and then its file is deleted.
    - Orphaned files in storage_path not referenced by any profile and older
      than orphan_grace_seconds are deleted after a pre-delete reference recheck.
    """
    if retention_days < 0:
        raise ValueError("retention_days must be non-negative.")
    if orphan_grace_seconds < 0:
        raise ValueError("orphan_grace_seconds must be non-negative.")

    storage_dir = _validate_storage_dir(
        storage_path,
        allowed_base_dir=allowed_base_dir,
    )
    current_time = _ensure_utc(now) if now else datetime.now(timezone.utc)
    cutoff = current_time - timedelta(days=retention_days)

    summary = {
        "dry_run": dry_run,
        "retention_days": retention_days,
        "expired_cleared": 0,
        "orphans_deleted": 0,
        "missing_files": 0,
        "skipped": 0,
    }

    # 1. Identify expired resolved MonitoredProfile images.
    monitored_ids = [
        row[0]
        for row in db.session.query(MonitoredProfile.id)
        .filter(MonitoredProfile.profile_image_path.isnot(None))
        .all()
    ]

    cleared_filenames: set[str] = set()

    for monitored_id in monitored_ids:
        # Lock/re-fetch the record immediately before eligibility evaluation.
        monitored = (
            db.session.query(MonitoredProfile)
            .filter_by(id=monitored_id)
            .with_for_update()
            .first()
        )
        if monitored is None or not monitored.profile_image_path:
            summary["skipped"] += 1
            continue

        filename = monitored.profile_image_path

        if not _is_monitored_profile_eligible(monitored, cutoff):
            continue

        # Never delete a file if any reference profile or another monitored
        # profile also references the same filename.
        if _is_filename_referenced(filename, exclude_monitored_id=monitored.id):
            summary["skipped"] += 1
            continue

        resolved_file = _safe_resolve_storage_file(storage_dir, filename)
        file_exists = resolved_file is not None and resolved_file.is_file()

        if not file_exists:
            summary["missing_files"] += 1
            if not dry_run:
                monitored.profile_image_path = None
                db.session.commit()
            cleared_filenames.add(filename)
            summary["expired_cleared"] += 1
            continue

        if dry_run:
            cleared_filenames.add(filename)
            summary["expired_cleared"] += 1
            continue

        # Re-verify symlink/boundary and clear DB reference BEFORE unlinking.
        if resolved_file.is_symlink() or resolved_file.resolve().parent != storage_dir:
            summary["skipped"] += 1
            continue

        monitored.profile_image_path = None
        db.session.commit()

        try:
            resolved_file.unlink(missing_ok=True)
        except OSError:
            current_app.logger.warning(
                "Failed to delete expired threat image file."
            )
            summary["skipped"] += 1
            continue

        cleared_filenames.add(filename)
        summary["expired_cleared"] += 1

    # 2. Identify orphaned files on disk in storage_dir only (no recursion).
    if not storage_dir.is_dir():
        return summary

    referenced_filenames = {
        row[0]
        for row in db.session.query(CreatorSocialProfile.profile_image_path)
        .filter(CreatorSocialProfile.profile_image_path.isnot(None))
        .all()
    } | {
        row[0]
        for row in db.session.query(MonitoredProfile.profile_image_path)
        .filter(MonitoredProfile.profile_image_path.isnot(None))
        .all()
    }

    if dry_run:
        referenced_filenames -= cleared_filenames

    orphan_cutoff_ts = current_time.timestamp() - orphan_grace_seconds

    for entry in storage_dir.iterdir():
        if entry.is_symlink() or not entry.is_file():
            continue
        if entry.resolve().parent != storage_dir:
            continue
        if entry.name in referenced_filenames:
            continue
        if not (entry.name.endswith(".jpg") or entry.name.endswith(".tmp")):
            continue

        try:
            if entry.stat().st_mtime > orphan_cutoff_ts:
                continue
        except OSError:
            summary["skipped"] += 1
            continue

        # Recheck DB references immediately before deletion to guard against
        # concurrent uploads or profile creations.
        if _is_filename_referenced(entry.name) and not (
            dry_run and entry.name in cleared_filenames
        ):
            summary["skipped"] += 1
            continue

        if not dry_run:
            if entry.is_symlink() or not entry.is_file():
                summary["skipped"] += 1
                continue
            try:
                entry.unlink(missing_ok=True)
            except OSError:
                current_app.logger.warning(
                    "Failed to delete orphaned threat image file."
                )
                summary["skipped"] += 1
                continue

        summary["orphans_deleted"] += 1

    return summary
