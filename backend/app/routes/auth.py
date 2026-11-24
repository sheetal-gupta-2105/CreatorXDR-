
import logging
import time

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    decode_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
)

from app.extensions import db, limiter
from app.extensions.limiter import get_email_or_ip, is_401_response
from app.models.user import User, EmailVerification

from app.services.auth_service import (
    check_otp_resend_allowed,
    consume_password_reset_token,
    create_password_reset_token,
    create_verification_challenge,
    hash_password,
    issue_token_pair,
    revoke_access_jti,
    revoke_refresh_family,
    rotate_refresh_token,
    verify_dummy_password,
    verify_email_code,
    verify_password,
)
from app.services.email import (
    send_password_changed_email,
    send_password_reset_email,
    send_verification_email,
)


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


@auth_bp.post("/resend-otp")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_RESEND_OTP", "5 per hour"), key_func=get_email_or_ip)
def resend_otp():

    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()

    if not email or "@" not in email or len(email) > 255:
        return jsonify({
            "error": "A valid email address is required."
        }), 400

    generic_response = {
        "message": "If an unverified account exists for that email, a new verification code has been sent."
    }

    user = User.query.filter_by(email=email).first()
    if user and user.account_status == "ACTIVE" and not user.email_verified:
        cooldown = current_app.config.get("AUTH_OTP_COOLDOWN_SECONDS", 60)
        max_per_hour = current_app.config.get("AUTH_OTP_MAX_PER_HOUR", 5)

        if check_otp_resend_allowed(user, cooldown_seconds=cooldown, max_per_hour=max_per_hour):
            try:
                code = create_verification_challenge(user)
                send_verification_email(
                    to_email=user.email,
                    user_name=user.full_name,
                    otp_code=code,
                )
            except Exception:
                db.session.rollback()
                current_app.logger.exception("Failed to resend verification OTP")

    return jsonify(generic_response), 200


@auth_bp.post("/forgot-password")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_FORGOT_PASSWORD", "3 per hour"), key_func=get_email_or_ip)
def forgot_password():

    start_time = time.monotonic()
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()

    if not email or "@" not in email or len(email) > 255:
        return jsonify({
            "error": "A valid email address is required."
        }), 400

    generic_response = {
        "message": "If an account exists for that email, a password reset link has been sent."
    }

    user = User.query.filter_by(email=email).first()
    if user and user.account_status == "ACTIVE":
        try:
            raw_token = create_password_reset_token(user, expiry_minutes=15)
            frontend_base = current_app.config.get(
                "FRONTEND_BASE_URL",
                current_app.config.get("FRONTEND_ORIGIN", "http://localhost:5173"),
            ).rstrip("/")
            reset_url = f"{frontend_base}/reset-password?token={raw_token}"
            send_password_reset_email(
                to_email=user.email,
                user_name=user.full_name,
                reset_url=reset_url,
            )
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Failed to dispatch password reset email")

    # Equalize response timing across existing and missing accounts.
    elapsed = time.monotonic() - start_time
    if elapsed < 0.05:
        time.sleep(0.05 - elapsed)

    return jsonify(generic_response), 200


@auth_bp.post("/reset-password")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_RESET_PASSWORD", "5 per hour"))
def reset_password():

    data = request.get_json(silent=True) or {}
    raw_token = data.get("token", "")
    new_password = data["new_password"] if "new_password" in data else data.get("password", "")

    if not isinstance(raw_token, str) or not raw_token.strip():
        return jsonify({
            "error": "A valid reset token is required."
        }), 400

    if not isinstance(new_password, str) or len(new_password) < 12:
        return jsonify({
            "error": "Password must contain at least 12 characters."
        }), 400

    try:
        success, user, error = consume_password_reset_token(raw_token.strip(), new_password)
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Password reset failed")
        return jsonify({
            "error": "Password reset could not be completed."
        }), 500

    if not success:
        return jsonify({"error": error}), 400

    try:
        send_password_changed_email(
            to_email=user.email,
            user_name=user.full_name,
        )
    except Exception:
        current_app.logger.exception("Failed to dispatch password changed email")

    return jsonify({
        "message": "Password reset successfully. Please sign in with your new password."
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
        verify_dummy_password(password if isinstance(password, str) else "")
        return jsonify({
            "error": "Invalid email or password."
        }), 401

    user = User.query.filter_by(email=email).first()

    if not user:
        verify_dummy_password(password)
        return jsonify({
            "error": "Invalid email or password."
        }), 401

    if not verify_password(user.password_hash, password):
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

    try:
        access_token, refresh_token, _ = issue_token_pair(user)
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to issue session tokens")
        return jsonify({
            "error": "Login could not be completed."
        }), 500

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

    jwt_data = get_jwt()
    jti = jwt_data.get("jti")

    if not jti:
        return jsonify({
            "error": "Invalid refresh token."
        }), 401

    success, access_token, refresh_token, error, status_code = rotate_refresh_token(jti)
    if not success:
        return jsonify({"error": error}), status_code

    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
    }), 200


@auth_bp.post("/logout")
@jwt_required()
def logout():

    jwt_data = get_jwt()
    user_id = get_jwt_identity()
    access_jti = jwt_data.get("jti")

    if access_jti:
        revoke_access_jti(access_jti, jwt_data.get("exp"))

    data = request.get_json(silent=True) or {}
    raw_refresh = data.get("refresh_token")
    if isinstance(raw_refresh, str) and raw_refresh.strip():
        try:
            decoded_refresh = decode_token(raw_refresh.strip())
            if decoded_refresh.get("sub") == user_id:
                family_id = decoded_refresh.get("family_id")
                if family_id:
                    revoke_refresh_family(family_id)
        except Exception:
            pass

    return jsonify({
        "message": "Logged out successfully."
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
