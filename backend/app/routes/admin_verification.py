
import json
from app.blockchain.hashing import HASH_VERSION, hash_audit_event
import logging
import re

from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from flask import (
    Blueprint,
    current_app,
    jsonify,
    request,
    send_file,
)
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.extensions import db
from app.models.user import User
from app.models.verification import (
    VerificationSubmission,
    VerificationReview,
)
from app.models.ocr_result import OCRResult
from app.models.admin_audit import AdminAuditLog
from app.services.email import send_review_decision_email



admin_verification_bp = Blueprint(
    "admin_verification",
    __name__,
)

logger = logging.getLogger(__name__)

REVIEWABLE_STATUSES = {
    "PENDING_REVIEW",
    "UNDER_REVIEW",
}

VALID_DECISIONS = {
    "APPROVED",
    "REJECTED",
    "NEEDS_RESUBMISSION",
}

ALLOWED_DOCUMENT_TYPES = {
    "PASSPORT",
    "DRIVING_LICENSE",
    "NATIONAL_ID",
    "PAN_CARD",
    "AADHAAR",
}

ALLOWED_MIME_TYPES = {
    "application/pdf",
    "image/jpeg",
    "image/png",
}


def _get_admin():
    admin_id = get_jwt_identity()
    admin = db.session.get(User, admin_id)

    if (
        not admin
        or admin.account_status != "ACTIVE"
        or admin.role != "ADMIN"
        or not admin.email_verified
    ):
        return None

    return admin


def _admin_submission_dict(submission):
    return {
        "id": submission.id,
        "user_email": submission.user.email,
        "document_type": submission.document_type,
        "issuing_country": submission.issuing_country,
        "status": submission.status,
        "ocr_status": submission.ocr_status,
        "ocr_confidence": submission.ocr_confidence,
        "duplicate_detected": submission.duplicate_detected,
        "submitted_at": submission.submitted_at.isoformat(),
        "reviewed_at": (
            submission.reviewed_at.isoformat()
            if submission.reviewed_at
            else None
        ),
    }



def _record_audit(admin_id, submission_id, event_type):
    audit_log = AdminAuditLog(
        admin_id=admin_id,
        submission_id=submission_id,
        event_type=event_type,
    )

    db.session.add(audit_log)

    # Populate the database-generated ID and timestamp first.
    db.session.flush()

    # Generate the hash from the canonical audit event.
    audit_log.event_hash = hash_audit_event(audit_log)
    audit_log.hash_version = HASH_VERSION



def _decrypt_value(encrypted_value, fernet):
    if not encrypted_value:
        return None

    try:
        return fernet.decrypt(
            encrypted_value.encode("utf-8")
        ).decode("utf-8")

    except InvalidToken as exc:
        raise ValueError(
            "Encrypted OCR data could not be decrypted."
        ) from exc


@admin_verification_bp.get("/submissions")
@jwt_required()
def list_review_queue():
    admin = _get_admin()

    if not admin:
        return jsonify({
            "error": "Administrator access is required."
        }), 403

    try:
        limit = int(request.args.get("limit", 25))
        offset = int(request.args.get("offset", 0))
    except (TypeError, ValueError):
        return jsonify({
            "error": "Invalid pagination parameters."
        }), 400

    if limit < 1 or limit > 100 or offset < 0:
        return jsonify({
            "error": "Limit must be 1-100 and offset cannot be negative."
        }), 400

    query = (
        VerificationSubmission.query
        .filter(
            VerificationSubmission.status.in_(
                REVIEWABLE_STATUSES
            )
        )
    )

    if request.args.get("duplicates") == "true":
        query = query.filter_by(
            duplicate_detected=True
        )

    total = query.count()

    submissions = (
        query
        .order_by(
            VerificationSubmission.submitted_at.asc()
        )
        .offset(offset)
        .limit(limit)
        .all()
    )

    return jsonify({
        "total": total,
        "limit": limit,
        "offset": offset,
        "submissions": [
            _admin_submission_dict(submission)
            for submission in submissions
        ],
    }), 200


@admin_verification_bp.get("/submissions/<submission_id>")
@jwt_required()
def get_submission_details(submission_id):
    admin = _get_admin()

    if not admin:
        return jsonify({
            "error": "Administrator access is required."
        }), 403

    submission = db.session.get(
        VerificationSubmission,
        submission_id,
    )

    if not submission:
        return jsonify({
            "error": "Submission not found."
        }), 404

    result = OCRResult.query.filter_by(
        submission_id=submission.id
    ).first()

    ocr_data = None

    if result:
        encryption_key = current_app.config.get(
            "OCR_ENCRYPTION_KEY"
        )

        if not encryption_key:
            return jsonify({
                "error": "OCR decryption is not configured."
            }), 503

        try:
            fernet = Fernet(
                encryption_key.encode("utf-8")
            )

            decrypted_text = _decrypt_value(
                result.encrypted_text,
                fernet,
            )

            decrypted_identity = _decrypt_value(
                result.encrypted_identity_data,
                fernet,
            )

            ocr_data = {
                "text": decrypted_text,
                "identity_data": (
                    json.loads(decrypted_identity)
                    if decrypted_identity
                    else None
                ),
                "extraction_status": result.extraction_status,
                "average_confidence": result.average_confidence,
                "language": result.language,
                "page_count": result.page_count,
            }

        except (InvalidToken, ValueError, TypeError):
            logger.exception(
                "OCR decryption failed for submission %s.",
                submission.id,
            )

            return jsonify({
                "error": "OCR data could not be decrypted."
            }), 500

        # Record successful access to decrypted OCR information.
        # Do not return sensitive data unless the audit event
        # has been successfully persisted.
        try:
            _record_audit(
                admin_id=admin.id,
                submission_id=submission.id,
                event_type="OCR_DETAILS_ACCESSED",
            )

            db.session.commit()

        except Exception:
            db.session.rollback()

            logger.exception(
                "OCR access audit failed for submission %s.",
                submission.id,
            )

            return jsonify({
                "error": "OCR access could not be recorded."
            }), 503

    return jsonify({
        "submission": _admin_submission_dict(submission),
        "ocr": ocr_data,
        "reviews": [
            review.to_dict()
            for review in submission.reviews
        ],
    }), 200


@admin_verification_bp.get(
    "/submissions/<submission_id>/document"
)
@jwt_required()
def get_submission_document(submission_id):
    admin = _get_admin()

    if not admin:
        return jsonify({
            "error": "Administrator access is required."
        }), 403

    submission = db.session.get(
        VerificationSubmission,
        submission_id,
    )

    if not submission:
        return jsonify({
            "error": "Submission not found."
        }), 404

    if submission.mime_type not in ALLOWED_MIME_TYPES:
        return jsonify({
            "error": "Unsupported stored document format."
        }), 415

    storage_root = Path(
        current_app.config["IDENTITY_STORAGE_PATH"]
    ).resolve()

    file_path = (
        storage_root / submission.storage_key
    ).resolve()

    if (
        file_path.parent != storage_root
        or not file_path.is_file()
    ):
        return jsonify({
            "error": "Stored document is unavailable."
        }), 404

    extension = {
        "application/pdf": "pdf",
        "image/jpeg": "jpg",
        "image/png": "png",
    }[submission.mime_type]

    try:
        _record_audit(
            admin_id=admin.id,
            submission_id=submission.id,
            event_type="DOCUMENT_ACCESSED",
        )

        # Do not disclose the document if the access audit
        # cannot be persisted.
        db.session.commit()

    except Exception:
        db.session.rollback()

        logger.exception(
            "Document access audit failed for submission %s.",
            submission.id,
        )

        return jsonify({
            "error": "Document access could not be recorded."
        }), 503

    response = send_file(
        file_path,
        mimetype=submission.mime_type,
        as_attachment=False,
        download_name=(
            f"verification-{submission.id}.{extension}"
        ),
        conditional=True,
        max_age=0,
    )

    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; sandbox"
    )

    return response


@admin_verification_bp.post(
    "/submissions/<submission_id>/review"
)
@jwt_required()
def review_submission(submission_id):
    admin = _get_admin()

    if not admin:
        return jsonify({
            "error": "Administrator access is required."
        }), 403

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({
            "error": "A JSON request body is required."
        }), 400

    decision = str(
        payload.get("decision", "")
    ).strip().upper()

    reason_code = str(
        payload.get("reason_code", "")
    ).strip().upper()

    reviewer_notes = str(
        payload.get("reviewer_notes", "")
    ).strip()

    if decision not in VALID_DECISIONS:
        return jsonify({
            "error": "Invalid review decision."
        }), 400

    if len(reviewer_notes) > 2000:
        return jsonify({
            "error": "Reviewer notes cannot exceed 2000 characters."
        }), 400

    if reason_code and not re.fullmatch(
        r"[A-Z0-9_]{2,50}",
        reason_code,
    ):
        return jsonify({
            "error": "Invalid reason code."
        }), 400

    if decision in {
        "REJECTED",
        "NEEDS_RESUBMISSION",
    } and not reason_code:
        return jsonify({
            "error": "A reason code is required for this decision."
        }), 400

    try:
        # PostgreSQL row lock prevents simultaneous decisions
        # from different administrators.
        submission = (
            VerificationSubmission.query
            .filter_by(id=submission_id)
            .with_for_update()
            .first()
        )

        if not submission:
            db.session.rollback()

            return jsonify({
                "error": "Submission not found."
            }), 404

        if submission.user_id == admin.id:
            db.session.rollback()

            return jsonify({
                "error": "Administrators cannot review their own submissions."
            }), 403

        if submission.status not in REVIEWABLE_STATUSES:
            db.session.rollback()

            return jsonify({
                "error": "This submission has already been reviewed or is unavailable."
            }), 409

        # Do not allow unsupported document categories to
        # become approved identity credentials.
        if (
            decision == "APPROVED"
            and submission.document_type not in ALLOWED_DOCUMENT_TYPES
        ):
            db.session.rollback()

            return jsonify({
                "error": (
                    "This document type is not eligible for "
                    "identity verification approval."
                )
            }), 400

        if (
            decision == "APPROVED"
            and submission.mime_type not in ALLOWED_MIME_TYPES
        ):
            db.session.rollback()

            return jsonify({
                "error": "This document format is not eligible for approval."
            }), 400

        review = VerificationReview(
            submission_id=submission.id,
            reviewer_id=admin.id,
            decision=decision,
            reason_code=reason_code or None,
            reviewer_notes=reviewer_notes or None,
        )

        submission.status = decision
        submission.reviewed_at = datetime.now(timezone.utc)

        db.session.add(review)

        _record_audit(
            admin_id=admin.id,
            submission_id=submission.id,
            event_type=f"REVIEW_{decision}",
        )

        # Review and audit event are committed atomically.
        db.session.commit()

        # Dispatch decision email notification asynchronously after successful commit
        try:
            send_review_decision_email(
                to_email=submission.user.email,
                user_name=submission.user.full_name,
                document_type=submission.document_type,
                decision=decision,
                reason_code=reason_code or None,
                reviewer_notes=reviewer_notes or None,
            )
        except Exception:
            logger.exception(
                "Failed to dispatch review notification email for submission %s",
                submission.id,
            )


        return jsonify({
            "message": "Review decision recorded.",
            "submission_id": submission.id,
            "decision": decision,
            "review": review.to_dict(),
        }), 200

    except Exception:
        db.session.rollback()

        logger.exception(
            "Review decision failed for submission %s.",
            submission_id,
        )

        return jsonify({
            "error": "Review decision could not be saved."
        }), 500


@admin_verification_bp.get("/audit-logs")
@jwt_required()
def list_admin_audit_logs():
    admin = _get_admin()

    if not admin:
        return jsonify({
            "error": "Administrator access is required."
        }), 403

    try:
        limit = int(request.args.get("limit", 50))
        offset = int(request.args.get("offset", 0))
    except (TypeError, ValueError):
        return jsonify({
            "error": "Invalid pagination parameters."
        }), 400

    if limit < 1 or limit > 100 or offset < 0:
        return jsonify({
            "error": "Limit must be 1-100 and offset cannot be negative."
        }), 400

    query = AdminAuditLog.query

    submission_id = request.args.get("submission_id")

    if submission_id:
        query = query.filter_by(
            submission_id=submission_id
        )

    total = query.count()

    logs = (
        query
        .order_by(AdminAuditLog.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return jsonify({
        "total": total,
        "limit": limit,
        "offset": offset,
        "audit_logs": [
            log.to_dict()
            for log in logs
        ],
    }), 200
