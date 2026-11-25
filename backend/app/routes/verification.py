
import logging
import re
from datetime import datetime, timedelta, timezone

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.extensions import db, limiter
from app.extensions.limiter import get_user_or_ip
from app.models.user import User

from app.models.verification import VerificationSubmission
from app.services.document_storage import (
    DocumentValidationError,
    QuarantineRequiredError,
    read_document,
    validate_document_strict,
    calculate_document_hmac,
    store_document,
    store_quarantined_document,
    delete_stored_document,
)
from app.services.ocr_service import (
    OCRProcessingError,
    process_submission_ocr,
)

verification_bp = Blueprint("verification", __name__)
logger = logging.getLogger(__name__)

ALLOWED_DOCUMENT_TYPES = {
    "PASSPORT",
    "DRIVING_LICENSE",
    "NATIONAL_ID",
    "PAN_CARD",
    "AADHAAR",
    "OTHER",
}


@verification_bp.post("/upload")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_DOCUMENT_UPLOAD_USER", "10 per hour"), key_func=get_user_or_ip)
@limiter.limit(lambda: current_app.config.get("RATELIMIT_DOCUMENT_UPLOAD_IP", "20 per hour"))
@jwt_required()
def upload_document():

    user_id = get_jwt_identity()
    user = (
        db.session.execute(
            db.select(User)
            .where(User.id == user_id)
            .with_for_update()
        )
        .scalar_one_or_none()
    )

    if not user or user.account_status != "ACTIVE":
        return jsonify({
            "error": "Account is unavailable."
        }), 401

    if not user.email_verified:
        return jsonify({
            "error": "Email verification is required."
        }), 403

    daily_quota = current_app.config.get("UPLOAD_QUOTA_DAILY", 5)
    total_quota = current_app.config.get("UPLOAD_QUOTA_TOTAL", 20)
    rolling_24h = datetime.now(timezone.utc) - timedelta(hours=24)

    total_uploads = (
        VerificationSubmission.query
        .filter_by(user_id=user.id)
        .count()
    )
    if total_uploads >= total_quota:
        return jsonify({
            "error": "Total upload quota exceeded."
        }), 429

    daily_uploads = (
        VerificationSubmission.query
        .filter(
            VerificationSubmission.user_id == user.id,
            VerificationSubmission.submitted_at >= rolling_24h,
        )
        .count()
    )
    if daily_uploads >= daily_quota:
        return jsonify({
            "error": "Daily upload quota exceeded. Please try again tomorrow."
        }), 429

    uploaded_file = request.files.get("document")

    document_type = request.form.get(
        "document_type", ""
    ).strip().upper()

    issuing_country = request.form.get(
        "issuing_country", ""
    ).strip().upper()

    if not uploaded_file:
        return jsonify({
            "error": "A document file is required."
        }), 400

    if document_type not in ALLOWED_DOCUMENT_TYPES:
        return jsonify({
            "error": "Unsupported document type."
        }), 400

    if not re.fullmatch(r"[A-Z]{2}", issuing_country):
        return jsonify({
            "error": "Issuing country must be a two-letter country code."
        }), 400

    hmac_secret = current_app.config.get("IDENTITY_HMAC_KEY")
    if not hmac_secret:
        current_app.logger.error("IDENTITY_HMAC_KEY is not configured.")
        return jsonify({
            "error": "Document service is not configured."
        }), 503

    try:
        content = read_document(uploaded_file)
    except DocumentValidationError as exc:
        return jsonify({
            "error": str(exc)
        }), 400

    document_hmac = calculate_document_hmac(content, hmac_secret)

    try:
        mime_type, extension = validate_document_strict(
            content,
            declared_mime=uploaded_file.mimetype,
            filename=uploaded_file.filename,
            max_pdf_pages=current_app.config.get("MAX_PDF_PAGES", 20),
            max_image_pixels=current_app.config.get("MAX_IMAGE_PIXELS", 30_000_000),
        )
    except QuarantineRequiredError as exc:
        quarantine_directory = current_app.config["QUARANTINE_STORAGE_PATH"]
        quarantine_key = None
        try:
            quarantine_key = store_quarantined_document(content, quarantine_directory)
            quarantined_submission = VerificationSubmission(
                user_id=user.id,
                document_type=document_type,
                issuing_country=issuing_country,
                storage_key=quarantine_key,
                mime_type=exc.safe_mime_type,
                file_size_bytes=len(content),
                document_hmac=document_hmac,
                status="QUARANTINED",
                ocr_status="FAILED",
                quarantined=True,
                quarantine_reason=exc.reason_code,
            )
            db.session.add(quarantined_submission)
            db.session.commit()
        except Exception:
            db.session.rollback()
            if quarantine_key:
                try:
                    delete_stored_document(quarantine_key, quarantine_directory)
                except Exception:
                    logger.exception("Failed to clean up quarantined document.")
            logger.exception("Failed to quarantine suspicious document.")

        return jsonify({
            "error": exc.user_message
        }), 400
    except DocumentValidationError as exc:
        return jsonify({
            "error": str(exc)
        }), 400

    storage_directory = current_app.config[
        "IDENTITY_STORAGE_PATH"
    ]

    storage_key = None

    try:
        storage_key = store_document(
            content,
            extension,
            storage_directory,
        )

        submission = VerificationSubmission(
            user_id=user.id,
            document_type=document_type,
            issuing_country=issuing_country,
            storage_key=storage_key,
            mime_type=mime_type,
            file_size_bytes=len(content),
            document_hmac=document_hmac,
            status="PENDING_REVIEW",
            ocr_status="PENDING",
        )

        db.session.add(submission)
        db.session.commit()

    except Exception:
        db.session.rollback()

        if storage_key:
            try:
                delete_stored_document(
                    storage_key,
                    storage_directory,
                )
            except Exception:
                logger.exception(
                    "Failed to clean up uploaded document."
                )

        logger.exception("Document upload failed.")

        return jsonify({
            "error": "Document upload could not be completed."
        }), 500

    submission_id = submission.id

    encryption_key = current_app.config.get(
        "OCR_ENCRYPTION_KEY"
    )

    try:
        if not encryption_key:
            raise OCRProcessingError(
                "OCR encryption is not configured."
            )

        process_submission_ocr(
            submission=submission,
            storage_directory=storage_directory,
            encryption_key=encryption_key,
            hmac_secret=hmac_secret,
        )

        db.session.commit()

    except Exception:
        db.session.rollback()

        submission = db.session.get(
            VerificationSubmission,
            submission_id,
        )

        if submission:
            submission.ocr_status = "FAILED"
            db.session.commit()

        logger.exception(
            "OCR processing failed for submission %s.",
            submission_id,
        )

    submission = db.session.get(
        VerificationSubmission,
        submission_id,
    )

    return jsonify({
        "message": "Document uploaded successfully.",
        "submission": submission.to_dict(),
    }), 201


@verification_bp.get("/submissions")
@jwt_required()
def list_submissions():
    user_id = get_jwt_identity()

    submissions = (
        VerificationSubmission.query
        .filter_by(user_id=user_id)
        .order_by(
            VerificationSubmission.submitted_at.desc()
        )
        .all()
    )

    return jsonify({
        "submissions": [
            submission.to_dict()
            for submission in submissions
        ]
    }), 200
