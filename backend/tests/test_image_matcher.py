
from PIL import Image, ImageDraw

from app.services.threat_detection.image_matcher import (
    calculate_image_hash,
    hamming_distance,
    image_similarity,
)


def create_test_image(path, size=(128, 128)):
    image = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(image)

    draw.rectangle(
        (15, 15, 60, 110),
        fill="black",
    )

    draw.ellipse(
        (70, 30, 115, 85),
        fill="gray",
    )

    image.save(path)
    image.close()


def test_image_hash_is_generated(tmp_path):
    image_path = tmp_path / "profile.png"
    create_test_image(image_path)

    result = calculate_image_hash(image_path)

    assert result is not None
    assert len(result) == 16


def test_same_image_has_100_percent_similarity(tmp_path):
    image_path = tmp_path / "profile.png"
    create_test_image(image_path)

    score = image_similarity(image_path, image_path)

    assert score == 100.0


def test_resized_image_has_high_similarity(tmp_path):
    original_path = tmp_path / "original.png"
    resized_path = tmp_path / "resized.png"

    create_test_image(original_path)

    with Image.open(original_path) as image:
        resized = image.resize((256, 256))
        resized.save(resized_path)
        resized.close()

    score = image_similarity(
        original_path,
        resized_path,
    )

    assert score is not None
    assert score >= 90.0


def test_missing_image_returns_none(tmp_path):
    missing_path = tmp_path / "missing.png"

    result = calculate_image_hash(missing_path)

    assert result is None


def test_hamming_distance():
    first = "0000000000000000"
    second = "0000000000000001"

    assert hamming_distance(first, second) == 1


def test_invalid_hash_is_rejected():
    import pytest

    with pytest.raises(ValueError):
        hamming_distance("invalid", "0000000000000000")
