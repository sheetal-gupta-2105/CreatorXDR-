
import hashlib
import hmac
import json
import re
import warnings

from pathlib import Path

import pytesseract
from pytesseract import Output
from PIL import Image, ImageOps, UnidentifiedImageError
from pdf2image import convert_from_path
from pypdf import PdfReader
from cryptography.fernet import Fernet

from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models.ocr_result import OCRResult
from app.models.verification import IdentityFingerprint


MAX_PDF_PAGES = 20
MAX_IMAGE_PIXELS = 30_000_000
OCR_LANGUAGES = "eng+hin"


class OCRProcessingError(Exception):
    pass


def _get_fernet(encryption_key: str):
    if not encryption_key:
        raise OCRProcessingError(
            "OCR encryption key is not configured."
        )

    try:
        return Fernet(encryption_key.encode("utf-8"))
    except Exception as exc:
        raise OCRProcessingError(
            "OCR encryption key is invalid."
        ) from exc


def _validate_image_size(image: Image.Image):
    width, height = image.size

    if width <= 0 or height <= 0:
        raise OCRProcessingError("Invalid image dimensions.")

    if width * height > MAX_IMAGE_PIXELS:
        raise OCRProcessingError(
            "Image exceeds the permitted pixel limit."
        )


def _ocr_image(image: Image.Image):
    _validate_image_size(image)

    prepared = ImageOps.exif_transpose(image).convert("RGB")

    try:
        data = pytesseract.image_to_data(
            prepared,
            lang=OCR_LANGUAGES,
            config="--oem 1 --psm 6",
            output_type=Output.DICT,
            timeout=30,
        )
    except Exception as exc:
        raise OCRProcessingError(
            "Tesseract could not process the document."
        ) from exc
    finally:
        prepared.close()

    words = []
    confidence_values = []

    for text, confidence in zip(data["text"], data["conf"]):
        text = text.strip()

        if not text:
            continue

        words.append(text)

        try:
            confidence_value = float(confidence)

            if confidence_value >= 0:
                confidence_values.append(confidence_value)

        except (TypeError, ValueError):
            continue

    extracted_text = " ".join(words)

    average_confidence = (
        sum(confidence_values) / len(confidence_values)
        if confidence_values
        else None
    )

    return extracted_text, average_confidence


def _process_pdf(file_path: Path):
    try:
        reader = PdfReader(str(file_path), strict=True)

        if reader.is_encrypted:
            raise OCRProcessingError(
                "Encrypted PDFs cannot be processed."
            )

        page_count = len(reader.pages)

        if page_count < 1 or page_count > MAX_PDF_PAGES:
            raise OCRProcessingError(
                "PDF page count is outside the permitted range."
            )

        pages = convert_from_path(
            str(file_path),
            dpi=200,
            fmt="png",
            first_page=1,
            last_page=page_count,
            thread_count=1,
            timeout=90,
            use_pdftocairo=True,
        )

    except OCRProcessingError:
        raise
    except Exception as exc:
        raise OCRProcessingError(
            "PDF rendering failed."
        ) from exc

    page_texts = []
    page_confidences = []

    try:
        for page in pages:
            try:
                text, confidence = _ocr_image(page)

                if text:
                    page_texts.append(text)

                if confidence is not None:
                    page_confidences.append(confidence)

            finally:
                page.close()

    finally:
        for page in pages:
            try:
                page.close()
            except Exception:
                pass

    average_confidence = (
        sum(page_confidences) / len(page_confidences)
        if page_confidences
        else None
    )

    return (
        "\n\n".join(page_texts),
        average_confidence,
        page_count,
    )


def _process_image(file_path: Path):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter(
                "error",
                Image.DecompressionBombWarning,
            )

            with Image.open(file_path) as image:
                if image.format not in {"JPEG", "PNG"}:
                    raise OCRProcessingError(
                        "Unsupported image format."
                    )

                image.load()
                text, confidence = _ocr_image(image)

    except OCRProcessingError:
        raise

    except (
        OSError,
        UnidentifiedImageError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
    ) as exc:
        raise OCRProcessingError(
            "Image could not be processed."
        ) from exc

    return text, confidence, 1


def _extract_identity_candidate(text: str, document_type: str, country: str):
    """
    Conservative first-stage extraction.

    Supported initially:
    - Indian PAN card
    - Indian Aadhaar number
    - Indian passport

    Driving licence extraction is intentionally not automated yet.
    Formats vary and false matches could create incorrect duplicate flags.
    """

    if country != "IN":
        return {
            "status": "UNSUPPORTED",
            "document_number": None,
            "detected_type": None,
        }

    document_type = document_type.upper()

    pan_matches = set(
        re.findall(
            r"(?<![A-Z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Z0-9])",
            text.upper(),
        )
    )

    aadhaar_matches = set()

    for match in re.findall(
        r"(?<!\d)(?:\d{4}[\s-]?){2}\d{4}(?!\d)",
        text,
    ):
        normalized = re.sub(r"\D", "", match)

        if len(normalized) == 12:
            aadhaar_matches.add(normalized)

    passport_matches = set(
        re.findall(
            r"(?<![A-Z0-9])[A-Z][0-9]{7}(?![A-Z0-9])",
            text.upper(),
        )
    )

    candidates = []

    if document_type == "PAN_CARD":
        candidates = [
            ("PAN_CARD", value)
            for value in pan_matches
        ]

    elif document_type == "AADHAAR":
        candidates = [
            ("AADHAAR", value)
            for value in aadhaar_matches
        ]

    elif document_type == "PASSPORT":
        candidates = [
            ("PASSPORT", value)
            for value in passport_matches
        ]

    elif document_type == "NATIONAL_ID":
        candidates.extend(
            ("PAN_CARD", value)
            for value in pan_matches
        )
        candidates.extend(
            ("AADHAAR", value)
            for value in aadhaar_matches
        )

    else:
        return {
            "status": "UNSUPPORTED",
            "document_number": None,
            "detected_type": None,
        }

    # Remove duplicate candidate pairs.
    candidates = list(set(candidates))

    if not candidates:
        return {
            "status": "NOT_FOUND",
            "document_number": None,
            "detected_type": None,
        }

    if len(candidates) > 1:
        return {
            "status": "AMBIGUOUS",
            "document_number": None,
            "detected_type": None,
        }

    detected_type, document_number = candidates[0]

    return {
        "status": "EXTRACTED",
        "document_number": document_number,
        "detected_type": detected_type,
    }


def _create_identity_fingerprint(
    document_number: str,
    detected_type: str,
    country: str,
    hmac_secret: str,
):
    if not hmac_secret:
        raise OCRProcessingError(
            "Identity fingerprint key is not configured."
        )

    normalized_number = re.sub(
        r"[^A-Z0-9]",
        "",
        document_number.upper(),
    )

    fingerprint_input = (
        f"{country.upper()}|"
        f"{detected_type.upper()}|"
        f"{normalized_number}"
    )

    return hmac.new(
        hmac_secret.encode("utf-8"),
        fingerprint_input.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _register_fingerprint(
    fingerprint: str,
    submission,
):
    existing = (
        IdentityFingerprint.query
        .filter_by(fingerprint=fingerprint)
        .first()
    )

    if existing:
        submission.duplicate_detected = True
        submission.status = "UNDER_REVIEW"
        return True

    fingerprint_record = IdentityFingerprint(
        fingerprint=fingerprint,
        user_id=submission.user_id,
        submission_id=submission.id,
    )

    # A nested transaction protects the OCR result from a uniqueness
    # race if two uploads attempt to register the same fingerprint.
    try:
        with db.session.begin_nested():
            db.session.add(fingerprint_record)
            db.session.flush()

        return False

    except IntegrityError:
        existing = (
            IdentityFingerprint.query
            .filter_by(fingerprint=fingerprint)
            .first()
        )

        if not existing:
            raise

        submission.duplicate_detected = True
        submission.status = "UNDER_REVIEW"
        return True


def process_submission_ocr(
    submission,
    storage_directory: str,
    encryption_key: str,
    hmac_secret: str,
):
    storage_root = Path(storage_directory).resolve()
    file_path = (storage_root / submission.storage_key).resolve()

    if file_path.parent != storage_root or not file_path.is_file():
        raise OCRProcessingError(
            "Stored document could not be located."
        )

    fernet = _get_fernet(encryption_key)

    if submission.mime_type == "application/pdf":
        text, confidence, page_count = _process_pdf(file_path)

    elif submission.mime_type in {"image/jpeg", "image/png"}:
        text, confidence, page_count = _process_image(file_path)

    else:
        raise OCRProcessingError(
            "Unsupported document type."
        )

    if not text.strip():
        raise OCRProcessingError(
            "No readable text was detected."
        )

    encrypted_text = fernet.encrypt(
        text.encode("utf-8")
    ).decode("utf-8")

    candidate = _extract_identity_candidate(
        text=text,
        document_type=submission.document_type,
        country=submission.issuing_country,
    )

    encrypted_identity_data = None

    if candidate["status"] == "EXTRACTED":
        identity_payload = {
            "document_number": candidate["document_number"],
            "detected_type": candidate["detected_type"],
        }

        encrypted_identity_data = fernet.encrypt(
            json.dumps(identity_payload).encode("utf-8")
        ).decode("utf-8")

        fingerprint = _create_identity_fingerprint(
            document_number=candidate["document_number"],
            detected_type=candidate["detected_type"],
            country=submission.issuing_country,
            hmac_secret=hmac_secret,
        )

        _register_fingerprint(
            fingerprint=fingerprint,
            submission=submission,
        )

    result = OCRResult(
        submission_id=submission.id,
        encrypted_text=encrypted_text,
        encrypted_identity_data=encrypted_identity_data,
        extraction_status=candidate["status"],
        average_confidence=confidence,
        language=OCR_LANGUAGES,
        page_count=page_count,
    )

    db.session.add(result)

    submission.ocr_status = "COMPLETED"
    submission.ocr_confidence = confidence

    return result
