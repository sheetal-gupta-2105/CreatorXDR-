
from io import BytesIO

import pytest
from PIL import Image
from werkzeug.datastructures import FileStorage

from app.services.threat_detection.image_storage import (
    ProfileImageError,
    save_profile_image,
)


def make_image(
    image_format="PNG",
    size=(100, 100),
    color="red",
):
    buffer = BytesIO()

    image = Image.new("RGB", size, color)
    image.save(buffer, format=image_format)
    buffer.seek(0)

    return buffer


def make_upload(
    image_format="PNG",
    filename="profile.png",
    size=(100, 100),
):
    return FileStorage(
        stream=make_image(image_format, size),
        filename=filename,
    )


def test_valid_png_is_stored_as_jpeg(tmp_path):
    upload = make_upload("PNG")

    filename = save_profile_image(
        upload,
        tmp_path,
    )

    saved_file = tmp_path / filename

    assert saved_file.exists()
    assert saved_file.suffix == ".jpg"

    with Image.open(saved_file) as image:
        assert image.format == "JPEG"
        assert image.size == (100, 100)


def test_valid_webp_is_accepted(tmp_path):
    upload = make_upload(
        image_format="WEBP",
        filename="profile.webp",
    )

    filename = save_profile_image(
        upload,
        tmp_path,
    )

    assert (tmp_path / filename).exists()


def test_valid_jpeg_is_accepted(tmp_path):
    upload = make_upload(
        image_format="JPEG",
        filename="profile.jpg",
    )

    filename = save_profile_image(
        upload,
        tmp_path,
    )

    assert (tmp_path / filename).exists()


def test_fake_extension_is_rejected(tmp_path):
    upload = make_upload(
        image_format="PNG",
        filename="profile.jpg",
    )

    upload.stream = BytesIO(b"This is not an image")

    with pytest.raises(ProfileImageError):
        save_profile_image(upload, tmp_path)


def test_unsupported_format_is_rejected(tmp_path):
    upload = make_upload(
        image_format="GIF",
        filename="profile.gif",
    )

    with pytest.raises(ProfileImageError):
        save_profile_image(upload, tmp_path)


def test_empty_upload_is_rejected(tmp_path):
    upload = FileStorage(
        stream=BytesIO(b""),
        filename="empty.png",
    )

    with pytest.raises(ProfileImageError):
        save_profile_image(upload, tmp_path)


def test_oversized_upload_is_rejected(tmp_path):
    upload = FileStorage(
        stream=BytesIO(b"x" * 1024),
        filename="large.png",
    )

    with pytest.raises(ProfileImageError):
        save_profile_image(
            upload,
            tmp_path,
            max_size=100,
        )


def test_excessive_dimensions_are_rejected(tmp_path):
    upload = make_upload(
        size=(5000, 5000),
    )

    with pytest.raises(ProfileImageError):
        save_profile_image(
            upload,
            tmp_path,
            max_dimension=4096,
        )


def test_storage_uses_random_filenames(tmp_path):
    first = save_profile_image(
        make_upload(),
        tmp_path,
    )

    second = save_profile_image(
        make_upload(),
        tmp_path,
    )

    assert first != second
    assert "/" not in first
    assert "\\" not in first


def test_original_filename_is_not_preserved(tmp_path):
    upload = make_upload(
        filename="../../malicious.png",
    )

    filename = save_profile_image(
        upload,
        tmp_path,
    )

    assert filename != "../../malicious.png"
    assert (tmp_path / filename).exists()
