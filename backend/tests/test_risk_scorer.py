
import pytest

from app.services.threat_detection.risk_scorer import (
    calculate_risk_score,
    get_risk_level,
)


REFERENCE = {
    "username": "tanishq_creator",
    "display_name": "Tanishq Creator",
    "bio": "Technology creator sharing AI and software projects",
}

SIMILAR_PROFILE = {
    "username": "tanishq_creator_official",
    "display_name": "Tanishq Creator",
    "bio": "Technology creator sharing AI and software projects",
}

UNRELATED_PROFILE = {
    "username": "random_traveller_92",
    "display_name": "Mountain Explorer",
    "bio": "Travel photography and mountain adventures",
}


def test_similar_profile_gets_higher_score():
    similar_result = calculate_risk_score(
        REFERENCE,
        SIMILAR_PROFILE,
        image_score=95,
    )

    unrelated_result = calculate_risk_score(
        REFERENCE,
        UNRELATED_PROFILE,
        image_score=5,
    )

    assert (
        similar_result["risk_score"]
        > unrelated_result["risk_score"]
    )


def test_missing_image_is_reported():
    result = calculate_risk_score(
        REFERENCE,
        SIMILAR_PROFILE,
        image_score=None,
    )

    assert "image" in result["missing_signals"]
    assert "image" not in result["available_signals"]
    assert result["risk_score"] >= 0


def test_feature_scores_are_returned():
    result = calculate_risk_score(
        REFERENCE,
        SIMILAR_PROFILE,
        image_score=90,
    )

    assert set(result["feature_scores"]) == {
        "username",
        "display_name",
        "bio",
        "image",
        "indicators",
    }


def test_risk_score_stays_between_zero_and_100():
    result = calculate_risk_score(
        REFERENCE,
        SIMILAR_PROFILE,
        image_score=100,
    )

    assert 0 <= result["risk_score"] <= 100


def test_invalid_image_score_is_rejected():
    with pytest.raises(ValueError):
        calculate_risk_score(
            REFERENCE,
            SIMILAR_PROFILE,
            image_score=150,
        )


def test_risk_level_boundaries():
    assert get_risk_level(10) == "LOW"
    assert get_risk_level(30) == "MEDIUM"
    assert get_risk_level(60) == "HIGH"
    assert get_risk_level(80) == "CRITICAL"


def test_result_includes_scoring_disclaimer():
    result = calculate_risk_score(
        REFERENCE,
        SIMILAR_PROFILE,
        image_score=90,
    )

    assert "not a calibrated probability" in result["scoring_note"]
