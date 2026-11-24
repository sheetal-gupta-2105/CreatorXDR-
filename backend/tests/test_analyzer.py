
from PIL import Image, ImageDraw

from app.services.threat_detection.analyzer import analyze_profile


def create_profile_image(path, variant="original"):
    image = Image.new("RGB", (128, 128), "white")
    draw = ImageDraw.Draw(image)

    draw.rectangle((15, 15, 60, 110), fill="black")
    draw.ellipse((70, 30, 115, 85), fill="gray")

    if variant == "different":
        image = Image.new("RGB", (128, 128), "black")
        draw = ImageDraw.Draw(image)
        draw.rectangle((20, 20, 110, 110), fill="white")

    image.save(path)
    image.close()


def test_analyzer_detects_similar_profile(tmp_path):
    image_path = tmp_path / "creator.png"
    create_profile_image(image_path)

    reference = {
        "username": "creator_tanishq",
        "display_name": "Tanishq Creator",
        "bio": "Technology creator sharing AI projects",
        "profile_image_path": str(image_path),
    }

    candidate = {
        "username": "creator_tanishq_official",
        "display_name": "Tanishq Creator",
        "bio": "Technology creator sharing AI projects",
        "profile_image_path": str(image_path),
    }

    result = analyze_profile(reference, candidate)

    assert result["analysis_status"] == "COMPLETED"
    assert result["risk_score"] > 60
    assert result["feature_scores"]["image"] == 100.0
    assert result["candidate_username"] == candidate["username"]


def test_analyzer_handles_missing_images():
    reference = {
        "username": "creator_tanishq",
        "display_name": "Tanishq Creator",
        "bio": "Technology creator",
    }

    candidate = {
        "username": "random_person",
        "display_name": "Random Person",
        "bio": "Travel and photography",
    }

    result = analyze_profile(reference, candidate)

    assert result["analysis_status"] == "COMPLETED"
    assert "image" in result["missing_signals"]


def test_analyzer_handles_unreadable_image(tmp_path):
    bad_image = tmp_path / "broken.png"
    bad_image.write_text("not an image")

    reference = {
        "username": "creator",
        "display_name": "Creator",
        "bio": "Technology creator",
        "profile_image_path": str(bad_image),
    }

    candidate = {
        "username": "other_person",
        "display_name": "Other Person",
        "bio": "Travel photographer",
        "profile_image_path": str(bad_image),
    }

    result = analyze_profile(reference, candidate)

    assert result["analysis_status"] == "COMPLETED"
    assert "image" in result["missing_signals"]
