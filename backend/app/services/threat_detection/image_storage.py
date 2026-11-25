
from io import BytesIO
from pathlib import Path
from uuid import uuid4
import warnings

from PIL import Image, ImageOps, UnidentifiedImageError
from werkzeug.datastructures import FileStorage


ALLOWED_FORMATS = {"JPEG", "PNG", "WEBP"}
OUTPUT_FORMAT = "JPEG"
OUTPUT_EXTENSION = ".jpg"


class ProfileImageError(ValueError):
    """Raised when a profile image fails validation."""


def save_profile_image(
    uploaded_file: FileStorage,
    storage_path: str | Path,
    max_size: int = 5 * 1024 * 1024,
    max_dimension: int = 4096,
) -> str:
    """
    Validate, normalize and privately store a profile image.

    Accepted formats: JPEG, PNG and WebP.
    Stored format: normalized JPEG.
    Returns a relative storage filename, never an absolute path.
    """

    if not uploaded_file or not uploaded_file.filename:
        raise ProfileImageError("A profile image is required.")

    stream = uploaded_file.stream

    try:
        stream.seek(0, 2)
        file_size = stream.tell()
        stream.seek(0)
    except (OSError, AttributeError):
        raise ProfileImageError("Unable to read uploaded image.")

    if file_size <= 0:
        raise ProfileImageError("The uploaded image is empty.")

    if file_size > max_size:
        raise ProfileImageError("Image must not exceed 5 MB.")

    try:
        with warnings.catch_warnings():
            warnings.simplefilter(
                "error",
                Image.DecompressionBombWarning,
            )

            with Image.open(stream) as image:
                if image.format not in ALLOWED_FORMATS:
                    raise ProfileImageError(
                        "Only JPEG, PNG and WebP images are allowed."
                    )

                if getattr(image, "n_frames", 1) != 1:
                    raise ProfileImageError(
                        "Animated images are not supported."
                    )

                width, height = image.size

                if (
                    width <= 0
                    or height <= 0
                    or width > max_dimension
                    or height > max_dimension
                ):
                    raise ProfileImageError(
                        "Image dimensions must not exceed "
                        f"{max_dimension} x {max_dimension} pixels."
                    )

                image.verify()

            stream.seek(0)

            with Image.open(stream) as image:
                image.load()
                image = ImageOps.exif_transpose(image)
                image = image.convert("RGB")

                normalized = BytesIO()
                image.save(
                    normalized,
                    format=OUTPUT_FORMAT,
                    quality=90,
                    optimize=True,
                )

        destination = Path(storage_path).resolve()
        destination.mkdir(
            parents=True,
            exist_ok=True,
        )

        filename = f"{uuid4().hex}{OUTPUT_EXTENSION}"
        final_path = destination / filename

        temporary_path = destination / f".{filename}.tmp"

        try:
            temporary_path.write_bytes(normalized.getvalue())
            temporary_path.replace(final_path)
        except OSError:
            temporary_path.unlink(missing_ok=True)
            raise ProfileImageError(
                "Image could not be stored."
            )

        return filename

    except ProfileImageError:
        raise

    except (
        UnidentifiedImageError,
        OSError,
        ValueError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
    ) as exc:
        raise ProfileImageError(
            "The uploaded file is not a valid supported image."
        ) from exc
