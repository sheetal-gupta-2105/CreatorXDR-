
from pathlib import Path

from PIL import Image, ImageOps


HASH_SIZE = 8


def calculate_image_hash(image_path: str | Path) -> str | None:
    """
    Calculate a 64-bit Difference Hash (dHash).

    Returns None when the image is missing or cannot be processed.
    """
    if not image_path:
        return None

    try:
        with Image.open(image_path) as image:
            image = ImageOps.exif_transpose(image)
            grayscale = image.convert("L")
            resized = grayscale.resize(
                (HASH_SIZE + 1, HASH_SIZE),
                Image.Resampling.LANCZOS,
            )

            pixels = list(resized.get_flattened_data())

        bits = []

        for row in range(HASH_SIZE):
            for column in range(HASH_SIZE):
                left = pixels[
                    row * (HASH_SIZE + 1) + column
                ]
                right = pixels[
                    row * (HASH_SIZE + 1) + column + 1
                ]

                bits.append(left > right)

        hash_value = 0

        for bit in bits:
            hash_value = (hash_value << 1) | int(bit)

        return f"{hash_value:016x}"

    except (OSError, ValueError, TypeError):
        return None


def hamming_distance(
    first_hash: str,
    second_hash: str,
) -> int:
    """Count differing bits between two 64-bit image hashes."""
    if (
        not first_hash
        or not second_hash
        or len(first_hash) != 16
        or len(second_hash) != 16
    ):
        raise ValueError("Both hashes must be valid 64-bit hashes.")

    try:
        first = int(first_hash, 16)
        second = int(second_hash, 16)
    except ValueError as exc:
        raise ValueError("Image hashes must be hexadecimal.") from exc

    return (first ^ second).bit_count()


def image_similarity(
    reference_path: str | Path,
    candidate_path: str | Path,
) -> float | None:
    """
    Compare two images.

    Returns a similarity score from 0 to 100.
    Returns None if either image cannot be processed.
    """
    reference_hash = calculate_image_hash(reference_path)
    candidate_hash = calculate_image_hash(candidate_path)

    if reference_hash is None or candidate_hash is None:
        return None

    distance = hamming_distance(
        reference_hash,
        candidate_hash,
    )

    similarity = (
        1 - distance / (HASH_SIZE * HASH_SIZE)
    ) * 100

    return round(similarity, 2)
