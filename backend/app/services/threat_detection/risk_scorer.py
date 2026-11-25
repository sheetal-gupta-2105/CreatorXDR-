
from app.services.threat_detection.text_matcher import (
    username_similarity,
    display_name_similarity,
    bio_similarity,
)


WEIGHTS = {
    "username": 0.25,
    "display_name": 0.20,
    "bio": 0.15,
    "image": 0.30,
    "indicators": 0.10,
}


SUSPICIOUS_KEYWORDS = {
    "official",
    "backup",
    "support",
    "real",
    "original",
    "admin",
    "help",
    "management",
}


def calculate_indicator_score(username: str, bio: str) -> float:
    """
    Calculate a supporting indicator score.

    These keywords are not proof of impersonation.
    """
    text = f"{username or ''} {bio or ''}".lower()

    matches = {
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in text.split()
    }

    if not matches:
        return 0.0

    return min(len(matches) * 25.0, 100.0)


def get_risk_level(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def calculate_risk_score(
    reference_profile: dict,
    candidate_profile: dict,
    image_score: float | None = None,
) -> dict:
    """
    Compare a candidate profile against a creator reference profile.

    Profiles use:
    username, display_name, bio

    image_score is optional and must be a 0-100 similarity score.
    """

    scores = {
        "username": username_similarity(
            reference_profile.get("username", ""),
            candidate_profile.get("username", ""),
        ),
        "display_name": display_name_similarity(
            reference_profile.get("display_name", ""),
            candidate_profile.get("display_name", ""),
        ),
        "bio": bio_similarity(
            reference_profile.get("bio", ""),
            candidate_profile.get("bio", ""),
        ),
        "image": image_score,
        "indicators": calculate_indicator_score(
            candidate_profile.get("username", ""),
            candidate_profile.get("bio", ""),
        ),
    }

    if image_score is not None and not 0 <= image_score <= 100:
        raise ValueError("Image score must be between 0 and 100.")

    available = {
        name: score
        for name, score in scores.items()
        if score is not None
    }

    available_weight = sum(
        WEIGHTS[name]
        for name in available
    )

    if available_weight == 0:
        raise ValueError("No usable detection signals were provided.")

    weighted_score = sum(
        score * WEIGHTS[name]
        for name, score in available.items()
    ) / available_weight

    final_score = round(weighted_score, 2)

    return {
        "risk_score": final_score,
        "risk_level": get_risk_level(final_score),
        "feature_scores": scores,
        "available_signals": list(available.keys()),
        "missing_signals": [
            name
            for name, score in scores.items()
            if score is None
        ],
        "evidence": [
            f"{name.replace('_', ' ').title()} similarity: {score:.2f}%"
            for name, score in available.items()
        ],
        "scoring_note": (
            "Heuristic risk score, not a calibrated probability "
            "or proof of impersonation."
        ),
    }
