
import logging

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    jwt_required,
)

from app.extensions import db, limiter
from app.extensions.limiter import get_email_or_ip, is_401_response
from app.models.user import User, EmailVerification

from app.services.auth_service import (
    hash_password,
    verify_password,
    create_verification_challenge,
    verify_email_code,
)
from app.services.email import send_verification_email


auth_bp = Blueprint("auth", __name__)
logger = logging.getLogger(__name__)


@auth_bp.post("/register")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_REGISTER", "5 per hour; 15 per day"))
def register():

    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    full_name = data.get("full_name")
    password = data.get("password", "")

    if not email or "@" not in email or len(email) > 255:
        return jsonify({
            "error": "A valid email address is required."
        }), 400

    if not isinstance(full_name, str):
        return jsonify({
            "error": "Full name is required."
        }), 400

    full_name = full_name.strip()

    if not full_name or len(full_name) > 120:
        return jsonify({
            "error": "Full name must contain 1 to 120 characters."
        }), 400

    if not isinstance(password, str) or len(password) < 12:
        return jsonify({
            "error": "Password must contain at least 12 characters."
        }), 400

    if User.query.filter_by(email=email).first():
        return jsonify({
            "error": "Unable to register with these details."
        }), 409

    user = User(
        email=email,
        full_name=full_name,
        password_hash=hash_password(password),
        role="CREATOR",
        email_verified=False,
        account_status="ACTIVE",
    )

    try:
        db.session.add(user)
        db.session.commit()

        code = create_verification_challenge(user)

    except Exception:
        db.session.rollback()
        current_app.logger.exception("Registration failed")

        return jsonify({
            "error": "Registration could not be completed."
        }), 500

    if current_app.debug and current_app.config.get("AUTH_DEBUG_OTP"):
        current_app.logger.warning(
            "========== DEVELOPMENT EMAIL OTP =========="
        )
        current_app.logger.warning("Email: %s", email)
        current_app.logger.warning("OTP: %s", code)
        current_app.logger.warning(
            "============================================="
        )

    try:
        send_verification_email(
            to_email=user.email,
            user_name=user.full_name,
            otp_code=code,
        )
    except Exception:
        current_app.logger.exception("Failed to dispatch verification email")


    return jsonify({
        "message": "Registration successful. Verify your email.",
        "email": email,
        "verification_required": True,
    }), 201


@auth_bp.post("/verify-email")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_VERIFY_EMAIL", "10 per 15 minutes"), key_func=get_email_or_ip)
def verify_email():

    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    code = str(data.get("code", "")).strip()

    if not email or len(code) != 6 or not code.isdigit():
        return jsonify({
            "error": "Invalid verification request."
        }), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({
            "error": "Invalid verification request."
        }), 400

    if user.email_verified:
        return jsonify({
            "message": "Email already verified."
        }), 200

    challenge = (
        EmailVerification.query
        .filter_by(user_id=user.id, used_at=None)
        .order_by(EmailVerification.created_at.desc())
        .first()
    )

    if not challenge:
        return jsonify({
            "error": "No active verification code. Request a new one."
        }), 400

    valid, error = verify_email_code(challenge, code)

    if not valid:
        return jsonify({"error": error}), 400

    try:
        user.email_verified = True
        db.session.commit()

    except Exception:
        db.session.rollback()
        current_app.logger.exception(
            "Email verification update failed"
        )

        return jsonify({
            "error": "Email verification could not be completed."
        }), 500

    return jsonify({
        "message": "Email verified successfully."
    }), 200


@auth_bp.post("/login")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_LOGIN_IP", "10 per minute; 30 per hour"))
@limiter.limit(
    lambda: current_app.config.get("RATELIMIT_LOGIN_ACCOUNT", "5 per 15 minutes"),
    key_func=get_email_or_ip,
    deduct_when=is_401_response,
)
def login():

    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    if not email or not isinstance(password, str):
        return jsonify({
            "error": "Invalid email or password."
        }), 401

    user = User.query.filter_by(email=email).first()

    if not user or not verify_password(
        user.password_hash, password
    ):
        return jsonify({
            "error": "Invalid email or password."
        }), 401

    if user.account_status != "ACTIVE":
        return jsonify({
            "error": "Account is unavailable."
        }), 403

    if not user.email_verified:
        return jsonify({
            "error": "Email verification required."
        }), 403

    identity = str(user.id)

    access_token = create_access_token(
        identity=identity,
        additional_claims={"role": user.role},
    )

    refresh_token = create_refresh_token(
        identity=identity,
        additional_claims={"role": user.role},
    )

    return jsonify({
        "message": "Login successful.",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
        },
    }), 200


@auth_bp.post("/refresh")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_REFRESH_TOKEN", "30 per minute"))
@jwt_required(refresh=True)
def refresh():

    user_id = get_jwt_identity()
    user = db.session.get(User, user_id)

    if not user or user.account_status != "ACTIVE":
        return jsonify({
            "error": "Account is unavailable."
        }), 401

    if not user.email_verified:
        return jsonify({
            "error": "Email verification required."
        }), 403

    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role},
    )

    return jsonify({
        "access_token": access_token,
    }), 200


@auth_bp.get("/me")
@jwt_required()
def get_current_user():
    user_id = get_jwt_identity()
    user = db.session.get(User, user_id)

    if not user or user.account_status != "ACTIVE":
        return jsonify({
            "error": "Account is unavailable."
        }), 401

    return jsonify({
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "email_verified": user.email_verified,
    }), 200


@auth_bp.patch("/profile")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_PROFILE_UPDATE", "15 per minute"))
@jwt_required()
def update_profile():

    user_id = get_jwt_identity()
    user = db.session.get(User, user_id)

    if not user or user.account_status != "ACTIVE":
        return jsonify({
            "error": "Account is unavailable."
        }), 401

    data = request.get_json(silent=True) or {}
    full_name = data.get("full_name")

    if not isinstance(full_name, str):
        return jsonify({
            "error": "Full name is required."
        }), 400

    full_name = full_name.strip()

    if not full_name or len(full_name) > 120:
        return jsonify({
            "error": "Full name must contain 1 to 120 characters."
        }), 400

    try:
        user.full_name = full_name
        db.session.commit()

    except Exception:
        db.session.rollback()
        current_app.logger.exception("Profile update failed")

        return jsonify({
            "error": "Profile could not be updated."
        }), 500

    return jsonify({
        "message": "Profile updated successfully.",
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "email_verified": user.email_verified,
        },
    }), 200
