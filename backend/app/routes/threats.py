
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models.user import User
from app.models.social_profile import CreatorSocialProfile
from app.models.monitored_profile import MonitoredProfile
from app.models.threat_detection import ThreatDetection
from app.services.threat_detection.analyzer import analyze_profile


threats_bp = Blueprint("threats", __name__)

ALLOWED_PLATFORMS = {
    "INSTAGRAM",
    "YOUTUBE",
    "TIKTOK",
    "X",
    "OTHER",
}

ALLOWED_STATUSES = {
    "NEW",
    "REVIEWING",
    "CONFIRMED",
    "SAFE",
    "DISMISSED",
}


def _get_active_creator():
    user_id = get_jwt_identity()
    user = db.session.get(User, user_id)

    if (
        not user
        or user.account_status != "ACTIVE"
        or not user.email_verified
        or user.role != "CREATOR"
    ):
        return None

    return user


def _validate_profile_payload(data):
    if not isinstance(data, dict):
        return None, "A JSON object is required."

    platform = data.get("platform", "INSTAGRAM")

    username = data.get("username")
    display_name = data.get("display_name", "")
    bio = data.get("bio", "")

    if not isinstance(platform, str):
        return None, "Platform must be text."

    platform = platform.strip().upper()

    if platform not in ALLOWED_PLATFORMS:
        return None, "Unsupported social media platform."

    if not isinstance(username, str):
        return None, "Username is required."

    username = username.strip().lstrip("@")

    if not username or len(username) > 100:
        return None, "Username must contain 1-100 characters."

    if not isinstance(display_name, str) or len(display_name) > 150:
        return None, "Display name must be text with at most 150 characters."

    if not isinstance(bio, str) or len(bio) > 5000:
        return None, "Bio must be text with at most 5000 characters."

    return {
        "platform": platform,
        "username": username,
        "display_name": display_name.strip() or None,
        "bio": bio.strip() or None,
    }, None


def _owned_reference_profile(profile_id, user_id):
    return CreatorSocialProfile.query.filter_by(
        id=profile_id,
        user_id=user_id,
    ).first()


def _owned_detection_query(user_id):
    return (
        ThreatDetection.query
        .join(
            CreatorSocialProfile,
            ThreatDetection.reference_profile_id == CreatorSocialProfile.id,
        )
        .filter(CreatorSocialProfile.user_id == user_id)
    )


@threats_bp.post("/reference-profiles")
@jwt_required()
def create_reference_profile():
    user = _get_active_creator()

    if not user:
        return jsonify({"error": "Active verified creator access is required."}), 403

    payload, error = _validate_profile_payload(request.get_json(silent=True))

    if error:
        return jsonify({"error": error}), 400

    profile = CreatorSocialProfile(
        user_id=user.id,
        platform=payload["platform"],
        username=payload["username"],
        display_name=payload["display_name"],
        bio=payload["bio"],
        source="MANUAL",
    )

    try:
        db.session.add(profile)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({
            "error": "This reference profile already exists for your account."
        }), 409
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Reference profile could not be saved."}), 500

    return jsonify({
        "message": "Reference profile created successfully.",
        "profile": profile.to_dict(),
    }), 201


@threats_bp.get("/reference-profiles")
@jwt_required()
def list_reference_profiles():
    user = _get_active_creator()

    if not user:
        return jsonify({"error": "Active verified creator access is required."}), 403

    profiles = (
        CreatorSocialProfile.query
        .filter_by(user_id=user.id)
        .order_by(CreatorSocialProfile.created_at.desc())
        .all()
    )

    return jsonify({
        "profiles": [profile.to_dict() for profile in profiles]
    }), 200


@threats_bp.post("/analyze")
@jwt_required()
def analyze_candidate_profile():
    user = _get_active_creator()

    if not user:
        return jsonify({"error": "Active verified creator access is required."}), 403

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required."}), 400

    reference_profile_id = data.get("reference_profile_id")

    if not isinstance(reference_profile_id, str) or not reference_profile_id:
        return jsonify({"error": "reference_profile_id is required."}), 400

    reference = _owned_reference_profile(reference_profile_id, user.id)

    if not reference:
        return jsonify({"error": "Reference profile not found."}), 404

    payload, error = _validate_profile_payload(data.get("candidate_profile"))

    if error:
        return jsonify({"error": error}), 400

    if payload["platform"] != reference.platform:
        return jsonify({
            "error": "Candidate and reference profiles must use the same platform."
        }), 400

    candidate = MonitoredProfile(
        submitted_by=user.id,
        platform=payload["platform"],
        username=payload["username"],
        display_name=payload["display_name"],
        bio=payload["bio"],
        source="MANUAL",
    )

    try:
        db.session.add(candidate)
        db.session.flush()

        result = analyze_profile(
            reference_profile={
                "username": reference.username,
                "display_name": reference.display_name,
                "bio": reference.bio,
            },
            candidate_profile={
                "username": candidate.username,
                "display_name": candidate.display_name,
                "bio": candidate.bio,
            },
        )

        detection = ThreatDetection(
            reference_profile_id=reference.id,
            monitored_profile_id=candidate.id,
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            feature_scores=result["feature_scores"],
            evidence=result["evidence"],
            available_signals=result["available_signals"],
            missing_signals=result["missing_signals"],
            scoring_note=result["scoring_note"],
            investigation_status="NEW",
        )

        db.session.add(detection)
        db.session.commit()

    except Exception:
        db.session.rollback()
        return jsonify({"error": "Profile analysis could not be completed."}), 500

    return jsonify({
        "message": "Profile analysis completed.",
        "candidate_profile": candidate.to_dict(),
        "detection": detection.to_dict(),
    }), 201


@threats_bp.get("/detections")
@jwt_required()
def list_detections():
    user = _get_active_creator()

    if not user:
        return jsonify({"error": "Active verified creator access is required."}), 403

    detections = (
        _owned_detection_query(user.id)
        .order_by(ThreatDetection.created_at.desc())
        .all()
    )

    results = []

    for detection in detections:
        item = detection.to_dict()
        item["candidate_profile"] = detection.monitored_profile.to_dict()
        item["reference_username"] = detection.reference_profile.username
        item["candidate_username"] = detection.monitored_profile.username
        results.append(item)

    return jsonify({
        "total": len(results),
        "detections": results,
    }), 200


@threats_bp.get("/detections/<detection_id>")
@jwt_required()
def get_detection(detection_id):
    user = _get_active_creator()

    if not user:
        return jsonify({"error": "Active verified creator access is required."}), 403

    detection = (
        _owned_detection_query(user.id)
        .filter(ThreatDetection.id == detection_id)
        .first()
    )

    if not detection:
        return jsonify({"error": "Detection not found."}), 404

    result = detection.to_dict()
    result["candidate_profile"] = detection.monitored_profile.to_dict()
    result["reference_profile"] = detection.reference_profile.to_dict()

    return jsonify({"detection": result}), 200


@threats_bp.patch("/detections/<detection_id>/status")
@jwt_required()
def update_detection_status(detection_id):
    user = _get_active_creator()

    if not user:
        return jsonify({"error": "Active verified creator access is required."}), 403

    detection = (
        _owned_detection_query(user.id)
        .filter(ThreatDetection.id == detection_id)
        .first()
    )

    if not detection:
        return jsonify({"error": "Detection not found."}), 404

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required."}), 400

    status = data.get("status")

    if not isinstance(status, str):
        return jsonify({"error": "A valid status is required."}), 400

    status = status.strip().upper()

    if status not in ALLOWED_STATUSES:
        return jsonify({
            "error": "Invalid status.",
            "allowed_statuses": sorted(ALLOWED_STATUSES),
        }), 400

    detection.investigation_status = status

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Detection status could not be updated."}), 500

    return jsonify({
        "message": "Investigation status updated.",
        "detection": detection.to_dict(),
    }), 200
