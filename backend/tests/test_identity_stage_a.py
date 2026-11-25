from datetime import datetime, timedelta, timezone
from io import BytesIO
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch
import warnings

from flask_jwt_extended import create_access_token
from PIL import Image
import pytest

from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.verification import VerificationSubmission
from app.services.auth_service import hash_password
from app.services.document_storage import (
    QuarantineRequiredError,
    validate_document_strict,
)
from app.services.email.email_service import send_templated_email
from app.utils.logging_utils import mask_email


def _make_png_bytes(width=10, height=10) -> bytes:
    buf = BytesIO()
    img = Image.new("RGB", (width, height), color=(255, 0, 0))
    img.save(buf, format="PNG")
    return buf.getvalue()


def _make_jpeg_bytes(width=10, height=10) -> bytes:
    buf = BytesIO()
    img = Image.new("RGB", (width, height), color=(0, 255, 0))
    img.save(buf, format="JPEG")
    return buf.getvalue()


@pytest.fixture
def identity_app(tmp_path):
    db_path = tmp_path / "identity_stage_a.db"
    identity_dir = tmp_path / "identity_docs"
    quarantine_dir = tmp_path / "quarantined_docs"
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
        "RATELIMIT_ENABLED": False,
        "IDENTITY_HMAC_KEY": "test-hmac-secret-key",
        "OCR_ENCRYPTION_KEY": "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcy0xMjM=",
        "IDENTITY_STORAGE_PATH": str(identity_dir),
        "QUARANTINE_STORAGE_PATH": str(quarantine_dir),
        "UPLOAD_QUOTA_DAILY": 3,
        "UPLOAD_QUOTA_TOTAL": 4,
        "REDIS_URL": "",
    })
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def _create_verified_user(email="creator@test.local", role="CREATOR"):
    user = User(
        email=email,
        full_name="Test User",
        password_hash=hash_password("ValidPassword123!"),
        role=role,
        email_verified=True,
        account_status="ACTIVE",
    )
    db.session.add(user)
    db.session.commit()
    return user


def test_magic_byte_validation_and_normalization():
    png_bytes = _make_png_bytes()
    jpeg_bytes = _make_jpeg_bytes()

    # Valid JPEG with .jpeg extension, image/jpg alias, and application/octet-stream
    assert validate_document_strict(jpeg_bytes, declared_mime="image/jpg", filename="id.jpeg") == ("image/jpeg", ".jpg")
    assert validate_document_strict(png_bytes, declared_mime="application/octet-stream", filename="id.png") == ("image/png", ".png")

    # Mismatch: PNG bytes with .jpg extension
    with pytest.raises(QuarantineRequiredError) as exc_info:
        validate_document_strict(png_bytes, declared_mime="image/jpeg", filename="fake.jpg")
    assert exc_info.value.reason_code in {"MIME_MISMATCH", "EXTENSION_MISMATCH"}

    # Invalid magic bytes
    with pytest.raises(QuarantineRequiredError) as exc_bad:
        validate_document_strict(b"MZ\x90\x00not-a-doc", declared_mime="application/pdf", filename="bad.pdf")
    assert exc_bad.value.reason_code == "INVALID_MAGIC_BYTES"

    # Best-effort PDF active-content scan
    suspicious_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\nendobj"
    with pytest.raises(QuarantineRequiredError) as exc_pdf:
        validate_document_strict(suspicious_pdf, declared_mime="application/pdf", filename="evil.pdf")
    assert exc_pdf.value.reason_code == "SUSPICIOUS_PDF_ACTIVE_CONTENT"


def test_decompression_bomb_warning_quarantined():
    png_bytes = _make_png_bytes()
    with patch("app.services.document_storage.Image.open") as mock_open:
        mock_open.side_effect = lambda *_args, **_kwargs: warnings.warn(
            "Image size exceeds limit", Image.DecompressionBombWarning
        )
        with pytest.raises(QuarantineRequiredError) as exc_info:
            validate_document_strict(png_bytes, declared_mime="image/png", filename="bomb.png")
        assert exc_info.value.reason_code == "IMAGE_DECOMPRESSION_BOMB"


def test_quarantine_flow_never_runs_ocr_and_excluded_from_admin(identity_app):
    client = identity_app.test_client()

    with identity_app.app_context():
        creator = _create_verified_user("creator@test.local", role="CREATOR")
        admin = _create_verified_user("admin@test.local", role="ADMIN")
        creator_token = create_access_token(identity=creator.id, additional_claims={"role": "CREATOR"})
        admin_token = create_access_token(identity=admin.id, additional_claims={"role": "ADMIN"})

        # Upload disguised executable bytes as .pdf -> quarantined, OCR never called
        with patch("app.routes.verification.process_submission_ocr") as mock_ocr:
            resp = client.post(
                "/api/verification/upload",
                headers={"Authorization": f"Bearer {creator_token}"},
                data={
                    "document_type": "PASSPORT",
                    "issuing_country": "IN",
                    "document": (BytesIO(b"not-actually-a-pdf"), "doc.pdf", "application/pdf"),
                },
                content_type="multipart/form-data",
            )
            assert resp.status_code == 400
            assert resp.get_json()["error"] == "The uploaded document could not be accepted."
            mock_ocr.assert_not_called()

        quarantined_row = VerificationSubmission.query.filter_by(user_id=creator.id).first()
        assert quarantined_row is not None
        assert quarantined_row.status == "QUARANTINED"
        assert quarantined_row.quarantined is True
        assert quarantined_row.quarantine_reason == "INVALID_MAGIC_BYTES"

        quarantine_dir = Path(identity_app.config["QUARANTINE_STORAGE_PATH"])
        identity_dir = Path(identity_app.config["IDENTITY_STORAGE_PATH"])
        assert (quarantine_dir / quarantined_row.storage_key).is_file()
        assert not (identity_dir / quarantined_row.storage_key).exists()

        # Also create an AWAITING_CONFIRMATION row to verify queue exclusion
        awaiting_row = VerificationSubmission(
            user_id=creator.id,
            document_type="PAN_CARD",
            issuing_country="IN",
            storage_key="awaiting123.png",
            mime_type="image/png",
            file_size_bytes=123,
            document_hmac="a" * 64,
            status="AWAITING_CONFIRMATION",
            ocr_status="COMPLETED",
        )
        db.session.add(awaiting_row)
        db.session.commit()

        # Admin queue and total count must exclude both QUARANTINED and AWAITING_CONFIRMATION
        queue_resp = client.get(
            "/api/admin/verification/submissions",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert queue_resp.status_code == 200
        assert queue_resp.get_json()["total"] == 0
        assert queue_resp.get_json()["submissions"] == []

        # Admin document stream must refuse quarantined file
        stream_resp = client.get(
            f"/api/admin/verification/submissions/{quarantined_row.id}/document",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert stream_resp.status_code == 403


def test_upload_quotas_daily_and_total_with_quarantined_counted(identity_app):
    client = identity_app.test_client()

    with identity_app.app_context():
        creator = _create_verified_user("quota@test.local", role="CREATOR")
        token = create_access_token(identity=creator.id, additional_claims={"role": "CREATOR"})
        png_bytes = _make_png_bytes()

        # Daily quota is 3 (2 valid + 1 quarantined = 3 -> 4th blocked)
        with patch("app.routes.verification.process_submission_ocr"):
            for i in range(2):
                r = client.post(
                    "/api/verification/upload",
                    headers={"Authorization": f"Bearer {token}"},
                    data={
                        "document_type": "PASSPORT",
                        "issuing_country": "IN",
                        "document": (BytesIO(png_bytes), f"ok{i}.png", "image/png"),
                    },
                    content_type="multipart/form-data",
                )
                assert r.status_code == 201

            r_q = client.post(
                "/api/verification/upload",
                headers={"Authorization": f"Bearer {token}"},
                data={
                    "document_type": "PASSPORT",
                    "issuing_country": "IN",
                    "document": (BytesIO(b"bad"), "bad.png", "image/png"),
                },
                content_type="multipart/form-data",
            )
            assert r_q.status_code == 400

            r_daily_blocked = client.post(
                "/api/verification/upload",
                headers={"Authorization": f"Bearer {token}"},
                data={
                    "document_type": "PASSPORT",
                    "issuing_country": "IN",
                    "document": (BytesIO(png_bytes), "over_daily.png", "image/png"),
                },
                content_type="multipart/form-data",
            )
            assert r_daily_blocked.status_code == 429

        # Age existing 3 rows >24h -> daily window clears, 4th succeeds, 5th hits total quota (4)
        old_time = datetime.now(timezone.utc) - timedelta(hours=30)
        for row in VerificationSubmission.query.filter_by(user_id=creator.id).all():
            row.submitted_at = old_time
        db.session.commit()

        with patch("app.routes.verification.process_submission_ocr"):
            r4 = client.post(
                "/api/verification/upload",
                headers={"Authorization": f"Bearer {token}"},
                data={
                    "document_type": "PASSPORT",
                    "issuing_country": "IN",
                    "document": (BytesIO(png_bytes), "fourth.png", "image/png"),
                },
                content_type="multipart/form-data",
            )
            assert r4.status_code == 201

            r5_total_blocked = client.post(
                "/api/verification/upload",
                headers={"Authorization": f"Bearer {token}"},
                data={
                    "document_type": "PASSPORT",
                    "issuing_country": "IN",
                    "document": (BytesIO(png_bytes), "over_total.png", "image/png"),
                },
                content_type="multipart/form-data",
            )
            assert r5_total_blocked.status_code == 429


def test_mask_email_and_enqueued_log_masking(identity_app, caplog):
    assert mask_email("george@gmail.com") == "g***@gmail.com"
    assert mask_email("a@b.co") == "a***@b.co"
    assert mask_email("invalid") == "***"

    mock_queue = MagicMock()
    with identity_app.app_context():
        with caplog.at_level(logging.INFO):
            with patch("app.services.email.email_service.get_email_queue", return_value=mock_queue):
                ok = send_templated_email(
                    to_email="sensitive.user@example.com",
                    subject="Test",
                    template_prefix="verification",
                    context={"user_name": "Test", "otp_code": "123456"},
                    async_send=True,
                )
                assert ok is True

    log_text = "\n".join(r.getMessage() for r in caplog.records)
    assert "sensitive.user@example.com" not in log_text
    assert "s***@example.com" in log_text
