import hashlib
import hmac
import os
import re
import warnings
from io import BytesIO
from pathlib import Path
from typing import Optional
from uuid import uuid4

from PIL import Image, UnidentifiedImageError
from pypdf import PdfReader
from werkzeug.datastructures import FileStorage


MAX_DOCUMENT_SIZE = 5 * 1024 * 1024
MAX_PDF_PAGES = 20
MAX_IMAGE_PIXELS = 30_000_000

# Enforce a global PIL decompression bomb limit.
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS

# Best-effort PDF active-content keywords. Note: this scan is best-effort only;
# obfuscated or compressed PDF streams may not match raw token names, so this
# serves as defense-in-depth alongside strict parsing and rendering limits.
_SUSPICIOUS_PDF_PATTERN = re.compile(rb"/(?:JS|JavaScript|Launch|OpenAction)\b")

SUPPORTED_DOCUMENT_TYPES = {
    "PDF": {
        "mime_type": "application/pdf",
        "extension": ".pdf",
    },
    "JPEG": {
        "mime_type": "image/jpeg",
        "extension": ".jpg",
    },
    "PNG": {
        "mime_type": "image/png",
        "extension": ".png",
    },
}

_EXTENSION_TO_MIME = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
}


class DocumentValidationError(Exception):
    pass


class QuarantineRequiredError(DocumentValidationError):
    """Raised when an uploaded file is malformed, mismatched, or suspicious and must be quarantined."""

    def __init__(
        self,
        reason_code: str,
        user_message: str = "The uploaded document could not be accepted.",
        safe_mime_type: str = "application/octet-stream",
    ):
        super().__init__(user_message)
        self.reason_code = reason_code
        self.user_message = user_message
        self.safe_mime_type = safe_mime_type


def read_document(file: FileStorage) -> bytes:
    if not file or not file.filename:
        raise DocumentValidationError("A document is required.")

    content = file.stream.read(MAX_DOCUMENT_SIZE + 1)

    if not content:
        raise DocumentValidationError("The uploaded document is empty.")

    if len(content) > MAX_DOCUMENT_SIZE:
        raise DocumentValidationError("Document size cannot exceed 5 MB.")

    return content


def _detect_magic_type(content: bytes) -> tuple[str, str]:
    """Detect canonical (mime_type, extension) strictly from leading magic bytes."""
    if content.startswith(b"%PDF-"):
        return "application/pdf", ".pdf"
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", ".png"
    if content.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", ".jpg"
    raise QuarantineRequiredError(
        "INVALID_MAGIC_BYTES",
        "The uploaded document could not be accepted.",
    )


def _normalize_mime(declared_mime: Optional[str]) -> str:
    mime = (declared_mime or "").split(";", 1)[0].strip().lower()
    if mime == "image/jpg":
        return "image/jpeg"
    return mime


def _check_declared_metadata(
    detected_mime: str,
    declared_mime: Optional[str],
    filename: Optional[str],
) -> None:
    norm_mime = _normalize_mime(declared_mime)
    if norm_mime and norm_mime != "application/octet-stream" and norm_mime != detected_mime:
        raise QuarantineRequiredError(
            "MIME_MISMATCH",
            "The uploaded document could not be accepted.",
        )

    if filename:
        ext = Path(filename).suffix.lower()
        if ext:
            expected_mime = _EXTENSION_TO_MIME.get(ext)
            if expected_mime is None or expected_mime != detected_mime:
                raise QuarantineRequiredError(
                    "EXTENSION_MISMATCH",
                    "The uploaded document could not be accepted.",
                )


def validate_document_strict(
    content: bytes,
    declared_mime: Optional[str] = None,
    filename: Optional[str] = None,
    max_pdf_pages: int = MAX_PDF_PAGES,
    max_image_pixels: int = MAX_IMAGE_PIXELS,
) -> tuple[str, str]:
    if not content:
        raise DocumentValidationError("The uploaded document is empty.")

    detected_mime, extension = _detect_magic_type(content)
    _check_declared_metadata(detected_mime, declared_mime, filename)

    if detected_mime == "application/pdf":
        # Best-effort scan for embedded JavaScript or auto-launch actions.
        if _SUSPICIOUS_PDF_PATTERN.search(content):
            raise QuarantineRequiredError(
                "SUSPICIOUS_PDF_ACTIVE_CONTENT",
                "The uploaded document could not be accepted.",
            )

        try:
            reader = PdfReader(BytesIO(content), strict=True)

            if reader.is_encrypted:
                raise QuarantineRequiredError(
                    "ENCRYPTED_PDF",
                    "The uploaded document could not be accepted.",
                )

            if len(reader.pages) < 1:
                raise QuarantineRequiredError(
                    "EMPTY_PDF",
                    "The uploaded document could not be accepted.",
                )

            if len(reader.pages) > max_pdf_pages:
                raise DocumentValidationError(
                    f"PDF cannot contain more than {max_pdf_pages} pages."
                )

        except DocumentValidationError:
            raise
        except Exception as exc:
            raise QuarantineRequiredError(
                "CORRUPTED_PDF",
                "The uploaded document could not be accepted.",
            ) from exc

        return "application/pdf", ".pdf"

    expected_pil_format = "PNG" if detected_mime == "image/png" else "JPEG"
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            image = Image.open(BytesIO(content))
            image_format = image.format

            if image_format != expected_pil_format:
                raise QuarantineRequiredError(
                    "IMAGE_FORMAT_MISMATCH",
                    "The uploaded document could not be accepted.",
                )

            width, height = image.size
            if width <= 0 or height <= 0 or (width * height) > max_image_pixels:
                raise QuarantineRequiredError(
                    "IMAGE_PIXEL_LIMIT_EXCEEDED",
                    "The uploaded document could not be accepted.",
                )

            image.verify()

    except DocumentValidationError:
        raise
    except (
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
    ) as exc:
        raise QuarantineRequiredError(
            "IMAGE_DECOMPRESSION_BOMB",
            "The uploaded document could not be accepted.",
        ) from exc
    except (UnidentifiedImageError, OSError) as exc:
        raise QuarantineRequiredError(
            "CORRUPTED_IMAGE",
            "The uploaded document could not be accepted.",
        ) from exc

    return detected_mime, extension


def validate_document(content: bytes) -> tuple[str, str]:
    return validate_document_strict(content)


def calculate_document_hmac(
    content: bytes,
    secret: str,
) -> str:
    if not secret:
        raise RuntimeError("IDENTITY_HMAC_KEY is not configured.")

    return hmac.new(
        secret.encode("utf-8"),
        content,
        hashlib.sha256,
    ).hexdigest()


def store_document(
    content: bytes,
    extension: str,
    storage_directory: str,
) -> str:
    directory = Path(storage_directory).resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)

    storage_key = f"{uuid4().hex}{extension}"
    destination = directory / storage_key

    # Exclusive creation prevents accidental overwrites.
    file_descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )

    try:
        with os.fdopen(file_descriptor, "wb") as stored_file:
            stored_file.write(content)
            stored_file.flush()
            os.fsync(stored_file.fileno())

    except Exception:
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    return storage_key


def store_quarantined_document(
    content: bytes,
    quarantine_directory: str,
) -> str:
    """Store a suspicious or malformed upload in an isolated quarantine directory."""
    return store_document(content, ".quarantine", quarantine_directory)


def delete_stored_document(
    storage_key: str,
    storage_directory: str,
) -> None:
    directory = Path(storage_directory).resolve()
    destination = (directory / storage_key).resolve()

    # Prevent path traversal outside the private storage directory.
    if destination.parent != directory:
        raise ValueError("Invalid document storage key.")

    destination.unlink(missing_ok=True)
