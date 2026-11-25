
from app.services.threat_detection.text_matcher import (
    username_similarity,
    display_name_similarity,
    bio_similarity,
)


def test_username_similarity_detects_format_variations():
    score = username_similarity(
        "@creator.official",
        "creator_official",
    )

    assert score == 100.0


def test_username_similarity_detects_similar_names():
    score = username_similarity(
        "creatorofficial",
        "creatoroffical",
    )

    assert score > 85


def test_unrelated_usernames_have_low_similarity():
    score = username_similarity(
        "creatorofficial",
        "random_person_927",
    )

    assert score < 60


def test_display_name_similarity():
    score = display_name_similarity(
        "Creator Tanishq",
        "Tanishq Creator",
    )

    assert score == 100.0


def test_bio_similarity_detects_copied_content():
    score = bio_similarity(
        "Official creator account sharing technology content",
        "Official creator account sharing technology content",
    )

    assert score == 100.0


def test_empty_values_return_zero():
    assert username_similarity("", "creator") == 0.0
    assert display_name_similarity("", "Creator") == 0.0
    assert bio_similarity("", "Some bio") == 0.0


def test_completely_different_bios_have_low_similarity():
    score = bio_similarity(
        "Travel photography and mountain adventures",
        "Professional software developer building applications",
    )

    assert score < 40
