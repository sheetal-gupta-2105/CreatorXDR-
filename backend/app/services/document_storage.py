
import hashlib
import hmac
import os
from io import BytesIO
from pathlib import Path
from uuid import uuid4

from PIL import Image, UnidentifiedImageError
from pypdf import PdfReader

from werkzeug.datastructures import FileStorage


MAX_DOCUMENT_SIZE = 5 * 1024 * 1024
MAX_PDF_PAGES = 20

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


class DocumentValidationError(Exception):
    pass


def read_document(file: FileStorage) -> bytes:
    if not file or not file.filename:
        raise DocumentValidationError("A document is required.")

    content = file.stream.read(MAX_DOCUMENT_SIZE + 1)

    if not content:
        raise DocumentValidationError("The uploaded document is empty.")

    if len(content) > MAX_DOCUMENT_SIZE:
        raise DocumentValidationError(
            "Document size cannot exceed 5 MB."
        )

    return content


def validate_document(content: bytes):
    if not content:
        raise DocumentValidationError("The uploaded document is empty.")

    # Validate PDF using its signature and parser.
    if content.startswith(b"%PDF-"):
        try:
            reader = PdfReader(BytesIO(content), strict=True)

            if reader.is_encrypted:
                raise DocumentValidationError(
                    "Encrypted PDFs are not supported."
                )

            if len(reader.pages) < 1:
                raise DocumentValidationError(
                    "The PDF contains no pages."
                )

            if len(reader.pages) > MAX_PDF_PAGES:
                raise DocumentValidationError(
                    "PDF cannot contain more than 20 pages."
                )

        except DocumentValidationError:
            raise
        except Exception as exc:
            raise DocumentValidationError(
                "The PDF file is invalid or corrupted."
            ) from exc

        return "application/pdf", ".pdf"

    # Validate actual image content, not the submitted extension.
    try:
        image = Image.open(BytesIO(content))
        image_format = image.format

        if image_format not in {"JPEG", "PNG"}:
            raise DocumentValidationError(
                "Only JPEG and PNG images are supported."
            )

        image.verify()

    except DocumentValidationError:
        raise
    except (
        UnidentifiedImageError,
        OSError,
        Image.DecompressionBombError,
    ) as exc:
        raise DocumentValidationError(
            "The uploaded image is invalid or corrupted."
        ) from exc

    if image_format == "JPEG":
        return "image/jpeg", ".jpg"

    return "image/png", ".png"


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
