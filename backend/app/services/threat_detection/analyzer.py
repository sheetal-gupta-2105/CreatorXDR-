
from app.services.threat_detection.image_matcher import (
    image_similarity,
)

from app.services.threat_detection.risk_scorer import (
    calculate_risk_score,
)


def analyze_profile(
    reference_profile: dict,
    candidate_profile: dict,
) -> dict:
    """
    Analyze a candidate social profile against a reference creator.

    Expected optional image field:
        profile_image_path
    """

    reference_image = reference_profile.get(
        "profile_image_path"
    )

    candidate_image = candidate_profile.get(
        "profile_image_path"
    )

    calculated_image_score = None

    if reference_image and candidate_image:
        calculated_image_score = image_similarity(
            reference_image,
            candidate_image,
        )

    result = calculate_risk_score(
        reference_profile=reference_profile,
        candidate_profile=candidate_profile,
        image_score=calculated_image_score,
    )

    result["reference_username"] = (
        reference_profile.get("username")
    )

    result["candidate_username"] = (
        candidate_profile.get("username")
    )

    result["analysis_status"] = "COMPLETED"

    return result
