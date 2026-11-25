from datetime import datetime, timedelta, timezone
from io import BytesIO
import os
from unittest.mock import patch

from flask_jwt_extended import create_access_token
from PIL import Image
import pytest
from werkzeug.datastructures import FileStorage

from app import create_app
from app.extensions import db, limiter
from app.models.monitored_profile import MonitoredProfile
from app.models.social_profile import CreatorSocialProfile
from app.models.threat_detection import ThreatDetection
from app.models.user import User
from app.services.auth_service import hash_password
from app.services.threat_detection.image_matcher import (
    calculate_image_hash,
    image_similarity,
)
from app.services.threat_detection.image_retention import cleanup_threat_images
from app.services.threat_detection.image_storage import (
    ProfileImageError,
    save_profile_image,
)


@pytest.fixture
def threat_app(tmp_path):
    db_path = tmp_path / "threat_hardening.db"
    profile_storage = tmp_path / "profile_images"
    profile_storage.mkdir(parents=True, exist_ok=True)

    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
        "PROFILE_IMAGE_STORAGE_PATH": str(profile_storage),
        "RATELIMIT_ENABLED": True,
        "RATELIMIT_STORAGE_URI": "memory://",
        "RATELIMIT_STRATEGY": "moving-window",
        "REDIS_URL": "",
        "RATELIMIT_THREAT_ANALYZE": "2 per minute",
        "RATELIMIT_THREAT_ANALYZE_IP": "10 per minute",
        "RATELIMIT_THREAT_PROFILE_WRITE": "2 per minute",
        "RATELIMIT_THREAT_PROFILE_WRITE_IP": "10 per minute",
        "RATELIMIT_THREAT_READ": "3 per minute",
        "RETENTION_THREAT_IMAGE_DAYS": 30,
    })

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()
    try:
        limiter.reset()
    except Exception:
        pass


def _make_user(email: str, role: str = "CREATOR", verified: bool = True) -> User:
    user = User(
        email=email,
        full_name="Test User",
        password_hash=hash_password("ValidPassword123!"),
        role=role,
        email_verified=verified,
        account_status="ACTIVE",
    )
    db.session.add(user)
    db.session.commit()
    return user


def _make_png_bytes(size=(64, 64)) -> BytesIO:
    buf = BytesIO()
    Image.new("RGB", size, "blue").save(buf, format="PNG")
    buf.seek(0)
    return buf


# --- 1. Threat endpoint rate limiting ---

def test_threat_endpoints_rate_limit_unauthenticated_and_admin(threat_app):
    client = threat_app.test_client()

    # Unauthenticated requests are rejected with 401 and then rate-limited at 429
    for _ in range(3):
        resp = client.get(
            "/api/threats/detections",
            environ_base={"REMOTE_ADDR": "198.51.100.10"},
        )
        assert resp.status_code == 401

    resp_429 = client.get(
        "/api/threats/detections",
        environ_base={"REMOTE_ADDR": "198.51.100.10"},
    )
    assert resp_429.status_code == 429
    assert "Retry-After" in resp_429.headers

    # Admin user gets 403 and is also rate-limited per user key
    with threat_app.app_context():
        admin = _make_user("admin-threat@test.local", role="ADMIN")
        admin_token = create_access_token(identity=admin.id)

    headers = {"Authorization": f"Bearer {admin_token}"}
    for _ in range(3):
        resp = client.get(
            "/api/threats/detections",
            headers=headers,
            environ_base={"REMOTE_ADDR": "198.51.100.11"},
        )
        assert resp.status_code == 403

    resp_admin_429 = client.get(
        "/api/threats/detections",
        headers=headers,
        environ_base={"REMOTE_ADDR": "198.51.100.11"},
    )
    assert resp_admin_429.status_code == 429


def test_threat_analyze_and_profile_write_rate_limits_per_user(threat_app):
    client = threat_app.test_client()

    with threat_app.app_context():
        creator_a = _make_user("creator-a@test.local")
        creator_b = _make_user("creator-b@test.local")
        token_a = create_access_token(identity=creator_a.id)
        token_b = create_access_token(identity=creator_b.id)

        ref_a = CreatorSocialProfile(
            user_id=creator_a.id,
            platform="INSTAGRAM",
            username="creator_a_real",
            source="MANUAL",
        )
        db.session.add(ref_a)
        db.session.commit()
        ref_a_id = ref_a.id

    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # Creator A: 2 profile writes succeed, 3rd returns 429
    for idx in range(2):
        resp = client.post(
            "/api/threats/reference-profiles",
            headers=headers_a,
            json={"platform": "YOUTUBE", "username": f"creator_a_{idx}"},
            environ_base={"REMOTE_ADDR": "198.51.100.20"},
        )
        assert resp.status_code == 201

    resp_write_429 = client.post(
        "/api/threats/reference-profiles",
        headers=headers_a,
        json={"platform": "YOUTUBE", "username": "creator_a_overflow"},
        environ_base={"REMOTE_ADDR": "198.51.100.20"},
    )
    assert resp_write_429.status_code == 429

    # Creator B on same IP has an independent per-user limit
    resp_b = client.post(
        "/api/threats/reference-profiles",
        headers=headers_b,
        json={"platform": "YOUTUBE", "username": "creator_b_real"},
        environ_base={"REMOTE_ADDR": "198.51.100.20"},
    )
    assert resp_b.status_code == 201

    # Creator A: 2 analyze calls succeed, 3rd returns 429
    for idx in range(2):
        resp = client.post(
            "/api/threats/analyze",
            headers=headers_a,
            json={
                "reference_profile_id": ref_a_id,
                "candidate_profile": {
                    "platform": "INSTAGRAM",
                    "username": f"fake_a_{idx}",
                },
            },
            environ_base={"REMOTE_ADDR": "198.51.100.20"},
        )
        assert resp.status_code == 201

    resp_analyze_429 = client.post(
        "/api/threats/analyze",
        headers=headers_a,
        json={
            "reference_profile_id": ref_a_id,
            "candidate_profile": {
                "platform": "INSTAGRAM",
                "username": "fake_a_overflow",
            },
        },
        environ_base={"REMOTE_ADDR": "198.51.100.20"},
    )
    assert resp_analyze_429.status_code == 429


# --- 2. Threat image retention and cleanup ---

def test_threat_image_retention_protects_active_and_cleans_expired_and_orphans(
    threat_app, tmp_path
):
    storage_dir = tmp_path / "profile_images"
    other_dir = tmp_path / "identity_documents"
    other_dir.mkdir(parents=True, exist_ok=True)
    identity_file = other_dir / "identity_doc.jpg"
    identity_file.write_bytes(b"identity")

    now = datetime.now(timezone.utc)
    old_time = now - timedelta(days=45)
    recent_time = now - timedelta(days=5)

    with threat_app.app_context():
        creator = _make_user("retention@test.local")

        # Active reference profile image (even if old) must NEVER be deleted
        ref_file = storage_dir / "ref_active.jpg"
        ref_file.write_bytes(b"ref")
        ref = CreatorSocialProfile(
            user_id=creator.id,
            platform="INSTAGRAM",
            username="ref_user",
            profile_image_path="ref_active.jpg",
            created_at=old_time,
        )
        db.session.add(ref)
        db.session.flush()

        # Active detection (NEW) even if old -> protected
        active_mon_file = storage_dir / "mon_active.jpg"
        active_mon_file.write_bytes(b"active")
        mon_active = MonitoredProfile(
            submitted_by=creator.id,
            platform="INSTAGRAM",
            username="mon_active",
            profile_image_path="mon_active.jpg",
            created_at=old_time,
        )
        db.session.add(mon_active)
        db.session.flush()
        db.session.add(ThreatDetection(
            reference_profile_id=ref.id,
            monitored_profile_id=mon_active.id,
            risk_score=75.0,
            risk_level="HIGH",
            feature_scores={"username": 75.0},
            evidence=["Username similarity: 75.00%"],
            available_signals=["username"],
            missing_signals=[],
            investigation_status="NEW",
            created_at=old_time,
        ))

        # Recent resolved detection (SAFE, 5 days old) -> protected
        recent_mon_file = storage_dir / "mon_recent.jpg"
        recent_mon_file.write_bytes(b"recent")
        mon_recent = MonitoredProfile(
            submitted_by=creator.id,
            platform="INSTAGRAM",
            username="mon_recent",
            profile_image_path="mon_recent.jpg",
            created_at=recent_time,
        )
        db.session.add(mon_recent)
        db.session.flush()
        db.session.add(ThreatDetection(
            reference_profile_id=ref.id,
            monitored_profile_id=mon_recent.id,
            risk_score=20.0,
            risk_level="LOW",
            feature_scores={"username": 20.0},
            evidence=["Username similarity: 20.00%"],
            available_signals=["username"],
            missing_signals=[],
            investigation_status="SAFE",
            created_at=recent_time,
        ))

        # Expired resolved detection (DISMISSED, 45 days old) -> eligible
        expired_mon_file = storage_dir / "mon_expired.jpg"
        expired_mon_file.write_bytes(b"expired")
        mon_expired = MonitoredProfile(
            submitted_by=creator.id,
            platform="INSTAGRAM",
            username="mon_expired",
            profile_image_path="mon_expired.jpg",
            created_at=old_time,
        )
        db.session.add(mon_expired)
        db.session.flush()
        expired_det = ThreatDetection(
            reference_profile_id=ref.id,
            monitored_profile_id=mon_expired.id,
            risk_score=15.0,
            risk_level="LOW",
            feature_scores={"username": 15.0},
            evidence=["Username similarity: 15.00%"],
            available_signals=["username"],
            missing_signals=[],
            investigation_status="DISMISSED",
            created_at=old_time,
        )
        db.session.add(expired_det)

        # Expired resolved detection with missing file on disk -> handled safely
        mon_missing = MonitoredProfile(
            submitted_by=creator.id,
            platform="INSTAGRAM",
            username="mon_missing",
            profile_image_path="does_not_exist.jpg",
            created_at=old_time,
        )
        db.session.add(mon_missing)
        db.session.flush()
        db.session.add(ThreatDetection(
            reference_profile_id=ref.id,
            monitored_profile_id=mon_missing.id,
            risk_score=10.0,
            risk_level="LOW",
            feature_scores={"username": 10.0},
            evidence=["Username similarity: 10.00%"],
            available_signals=["username"],
            missing_signals=[],
            investigation_status="SAFE",
            created_at=old_time,
        ))
        db.session.commit()

        # Orphan files: one old orphan (deleted), one fresh orphan (kept)
        old_orphan = storage_dir / "old_orphan.jpg"
        old_orphan.write_bytes(b"orphan")
        old_ts = (now - timedelta(hours=2)).timestamp()
        os.utime(old_orphan, (old_ts, old_ts))

        fresh_orphan = storage_dir / "fresh_orphan.jpg"
        fresh_orphan.write_bytes(b"fresh")

        # Dry-run leaves everything untouched
        dry_summary = cleanup_threat_images(
            storage_path=storage_dir,
            retention_days=30,
            orphan_grace_seconds=3600,
            dry_run=True,
            now=now,
        )
        assert dry_summary["dry_run"] is True
        assert dry_summary["expired_cleared"] == 2
        assert dry_summary["orphans_deleted"] == 1
        assert dry_summary["missing_files"] == 1
        assert expired_mon_file.exists()
        assert old_orphan.exists()

        # Real cleanup deletes only expired & old orphan, preserving DB records
        summary = cleanup_threat_images(
            storage_path=storage_dir,
            retention_days=30,
            orphan_grace_seconds=3600,
            dry_run=False,
            now=now,
        )
        assert summary["dry_run"] is False
        assert summary["expired_cleared"] == 2
        assert summary["orphans_deleted"] == 1
        assert summary["missing_files"] == 1

        assert ref_file.exists()
        assert active_mon_file.exists()
        assert recent_mon_file.exists()
        assert fresh_orphan.exists()
        assert identity_file.exists()
        assert not expired_mon_file.exists()
        assert not old_orphan.exists()

        db.session.refresh(mon_expired)
        db.session.refresh(mon_missing)
        assert mon_expired.profile_image_path is None
        assert mon_missing.profile_image_path is None
        assert db.session.get(ThreatDetection, expired_det.id) is not None

        # Idempotent second run does nothing
        second_summary = cleanup_threat_images(
            storage_path=storage_dir,
            retention_days=30,
            orphan_grace_seconds=3600,
            dry_run=False,
            now=now,
        )
        assert second_summary["expired_cleared"] == 0
        assert second_summary["orphans_deleted"] == 0
        assert second_summary["missing_files"] == 0


def test_cleanup_threat_images_cli_dry_run(threat_app):
    runner = threat_app.test_cli_runner()
    result = runner.invoke(args=["cleanup-threat-images", "--dry-run"])
    assert result.exit_code == 0
    assert "DRY RUN" in result.output


def test_cleanup_threat_images_rejects_invalid_and_outside_storage_roots(
    threat_app, tmp_path
):
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir(parents=True, exist_ok=True)
    allowed_base = tmp_path / "allowed_base"
    allowed_base.mkdir(parents=True, exist_ok=True)

    file_not_dir = allowed_base / "not_a_dir.txt"
    file_not_dir.write_text("x", encoding="utf-8")

    with threat_app.app_context():
        # Empty path
        with pytest.raises(ValueError):
            cleanup_threat_images(storage_path="", allowed_base_dir=allowed_base)

        # Filesystem root
        with pytest.raises(ValueError):
            cleanup_threat_images(storage_path=tmp_path.anchor)

        # Outside allowed_base_dir
        with pytest.raises(ValueError):
            cleanup_threat_images(
                storage_path=outside_dir,
                allowed_base_dir=allowed_base,
            )

        # Equal to allowed_base_dir itself (must be strictly inside)
        with pytest.raises(ValueError):
            cleanup_threat_images(
                storage_path=allowed_base,
                allowed_base_dir=allowed_base,
            )

        # File instead of directory
        with pytest.raises(ValueError):
            cleanup_threat_images(
                storage_path=file_not_dir,
                allowed_base_dir=allowed_base,
            )

        # Overlapping with IDENTITY_STORAGE_PATH
        identity_dir = tmp_path / "identity_documents"
        identity_dir.mkdir(parents=True, exist_ok=True)
        threat_app.config["IDENTITY_STORAGE_PATH"] = str(identity_dir)
        with pytest.raises(ValueError):
            cleanup_threat_images(
                storage_path=identity_dir,
                allowed_base_dir=tmp_path,
            )

        # Production boundary check when TESTING is False
        threat_app.config["TESTING"] = False
        try:
            with pytest.raises(ValueError):
                cleanup_threat_images(storage_path=outside_dir)
        finally:
            threat_app.config["TESTING"] = True


def test_cleanup_preserves_shared_reference_and_active_detection_files(
    threat_app, tmp_path
):
    storage_dir = tmp_path / "profile_images"
    now = datetime.now(timezone.utc)
    old_time = now - timedelta(days=45)

    with threat_app.app_context():
        creator = _make_user("shared-ref@test.local")

        # Reference profile image shared with an expired MonitoredProfile
        shared_file = storage_dir / "shared_ref.jpg"
        shared_file.write_bytes(b"shared")

        ref = CreatorSocialProfile(
            user_id=creator.id,
            platform="INSTAGRAM",
            username="ref_shared",
            profile_image_path="shared_ref.jpg",
            created_at=old_time,
        )
        db.session.add(ref)
        db.session.flush()

        mon_shared = MonitoredProfile(
            submitted_by=creator.id,
            platform="INSTAGRAM",
            username="mon_shared",
            profile_image_path="shared_ref.jpg",
            created_at=old_time,
        )
        db.session.add(mon_shared)
        db.session.flush()
        db.session.add(ThreatDetection(
            reference_profile_id=ref.id,
            monitored_profile_id=mon_shared.id,
            risk_score=10.0,
            risk_level="LOW",
            feature_scores={"username": 10.0},
            evidence=[],
            available_signals=["username"],
            missing_signals=[],
            investigation_status="DISMISSED",
            created_at=old_time,
        ))

        # Active detection statuses (REVIEWING, CONFIRMED) must be preserved
        for idx, status in enumerate(("REVIEWING", "CONFIRMED")):
            active_file = storage_dir / f"active_{idx}.jpg"
            active_file.write_bytes(b"active")
            mon = MonitoredProfile(
                submitted_by=creator.id,
                platform="INSTAGRAM",
                username=f"mon_{status.lower()}",
                profile_image_path=active_file.name,
                created_at=old_time,
            )
            db.session.add(mon)
            db.session.flush()
            db.session.add(ThreatDetection(
                reference_profile_id=ref.id,
                monitored_profile_id=mon.id,
                risk_score=80.0,
                risk_level="HIGH",
                feature_scores={"username": 80.0},
                evidence=[],
                available_signals=["username"],
                missing_signals=[],
                investigation_status=status,
                created_at=old_time,
            ))

        db.session.commit()

        summary = cleanup_threat_images(
            storage_path=storage_dir,
            retention_days=30,
            orphan_grace_seconds=3600,
            dry_run=False,
            now=now,
        )

        assert summary["expired_cleared"] == 0
        assert summary["orphans_deleted"] == 0
        assert summary["skipped"] >= 1
        assert shared_file.exists()
        assert (storage_dir / "active_0.jpg").exists()
        assert (storage_dir / "active_1.jpg").exists()


def test_cleanup_skips_when_record_becomes_ineligible_or_orphan_referenced_concurrently(
    threat_app, tmp_path
):
    storage_dir = tmp_path / "profile_images"
    now = datetime.now(timezone.utc)
    old_time = now - timedelta(days=45)

    with threat_app.app_context():
        creator = _make_user("race@test.local")
        ref = CreatorSocialProfile(
            user_id=creator.id,
            platform="INSTAGRAM",
            username="race_ref",
            created_at=old_time,
        )
        db.session.add(ref)
        db.session.flush()

        mon_file = storage_dir / "race_mon.jpg"
        mon_file.write_bytes(b"mon")
        mon = MonitoredProfile(
            submitted_by=creator.id,
            platform="INSTAGRAM",
            username="race_mon",
            profile_image_path="race_mon.jpg",
            created_at=old_time,
        )
        db.session.add(mon)
        db.session.flush()
        db.session.add(ThreatDetection(
            reference_profile_id=ref.id,
            monitored_profile_id=mon.id,
            risk_score=15.0,
            risk_level="LOW",
            feature_scores={"username": 15.0},
            evidence=[],
            available_signals=["username"],
            missing_signals=[],
            investigation_status="DISMISSED",
            created_at=old_time,
        ))
        db.session.commit()

        # Old orphan file on disk that becomes referenced right before deletion
        orphan_file = storage_dir / "race_orphan.jpg"
        orphan_file.write_bytes(b"orphan")
        old_ts = (now - timedelta(hours=2)).timestamp()
        os.utime(orphan_file, (old_ts, old_ts))

        from app.services.threat_detection import image_retention

        orig_is_eligible = image_retention._is_monitored_profile_eligible
        orig_is_referenced = image_retention._is_filename_referenced

        def simulate_concurrent_active_detection(profile, cutoff):
            # Simulate another worker adding an active detection before check
            db.session.add(ThreatDetection(
                reference_profile_id=ref.id,
                monitored_profile_id=profile.id,
                risk_score=90.0,
                risk_level="CRITICAL",
                feature_scores={"username": 90.0},
                evidence=[],
                available_signals=["username"],
                missing_signals=[],
                investigation_status="NEW",
                created_at=now,
            ))
            db.session.commit()
            return orig_is_eligible(profile, cutoff)

        def simulate_concurrent_orphan_reference(filename, exclude_monitored_id=None):
            if filename == "race_orphan.jpg":
                # Simulate another worker referencing the file before unlink
                db.session.add(CreatorSocialProfile(
                    user_id=creator.id,
                    platform="YOUTUBE",
                    username="race_claimed",
                    profile_image_path="race_orphan.jpg",
                ))
                db.session.commit()
            return orig_is_referenced(
                filename,
                exclude_monitored_id=exclude_monitored_id,
            )

        with patch.object(
            image_retention,
            "_is_monitored_profile_eligible",
            side_effect=simulate_concurrent_active_detection,
        ), patch.object(
            image_retention,
            "_is_filename_referenced",
            side_effect=simulate_concurrent_orphan_reference,
        ):
            summary = cleanup_threat_images(
                storage_path=storage_dir,
                retention_days=30,
                orphan_grace_seconds=3600,
                dry_run=False,
                now=now,
            )

        assert summary["expired_cleared"] == 0
        assert summary["orphans_deleted"] == 0
        assert summary["skipped"] >= 1
        assert mon_file.exists()
        assert orphan_file.exists()


def test_cleanup_handles_missing_record_or_missing_file_safely(
    threat_app, tmp_path
):
    storage_dir = tmp_path / "profile_images"
    now = datetime.now(timezone.utc)
    old_time = now - timedelta(days=45)

    with threat_app.app_context():
        creator = _make_user("missing@test.local")
        mon = MonitoredProfile(
            submitted_by=creator.id,
            platform="INSTAGRAM",
            username="missing_file_mon",
            profile_image_path="nonexistent.jpg",
            created_at=old_time,
        )
        db.session.add(mon)
        db.session.commit()

        summary = cleanup_threat_images(
            storage_path=storage_dir,
            retention_days=30,
            orphan_grace_seconds=3600,
            dry_run=False,
            now=now,
        )

        assert summary["missing_files"] == 1
        assert summary["expired_cleared"] == 1
        db.session.refresh(mon)
        assert mon.profile_image_path is None


# --- 3. Image pixel-limit & decompression-bomb hardening ---

def test_save_profile_image_enforces_max_pixels(tmp_path):
    # 100x100 = 10,000 pixels, within max_dimension=200 but > max_pixels=5,000
    upload = FileStorage(
        stream=_make_png_bytes(size=(100, 100)),
        filename="wide.png",
    )

    with pytest.raises(ProfileImageError):
        save_profile_image(
            upload,
            tmp_path,
            max_dimension=200,
            max_pixels=5000,
        )


def test_image_matcher_enforces_dimension_and_pixel_limits(tmp_path):
    img_path = tmp_path / "large.png"
    Image.new("RGB", (100, 100), "green").save(img_path)

    # Exceeds max_pixels
    assert calculate_image_hash(img_path, max_dimension=200, max_pixels=5000) is None
    assert image_similarity(img_path, img_path, max_dimension=200, max_pixels=5000) is None

    # Exceeds max_dimension
    assert calculate_image_hash(img_path, max_dimension=50, max_pixels=100000) is None

    # Within limits succeeds
    assert calculate_image_hash(img_path, max_dimension=200, max_pixels=20000) is not None


def test_image_matcher_handles_decompression_bomb_warning_safely(tmp_path):
    img_path = tmp_path / "bomb.png"
    Image.new("RGB", (64, 64), "red").save(img_path)

    with patch(
        "app.services.threat_detection.image_matcher.Image.open",
        side_effect=Image.DecompressionBombWarning("Simulated bomb"),
    ):
        assert calculate_image_hash(img_path) is None
