from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import pytest

from app import create_app
from app.extensions import db
from app.models.user import (
    EmailVerification,
    PasswordResetToken,
    RefreshToken,
    User,
)
from app.services.auth_service import (
    _DEV_REVOKED_JTIS,
    hash_password,
    hash_token,
    is_access_jti_revoked,
)


@pytest.fixture
def auth_app(tmp_path):
    db_path = tmp_path / "auth_lifecycle.db"
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
        "RATELIMIT_ENABLED": False,
        "EMAIL_PROVIDER": "console",
        "EMAIL_SYNC_FALLBACK": True,
        "FRONTEND_BASE_URL": "https://app.creatorxdr.test",
        "REDIS_URL": "",
    })
    _DEV_REVOKED_JTIS.clear()
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()
    _DEV_REVOKED_JTIS.clear()


def _create_user(
    email="creator@test.local",
    password="ValidPassword123!",
    verified=True,
    status="ACTIVE",
    role="CREATOR",
):
    user = User(
        email=email,
        full_name="Test Creator",
        password_hash=hash_password(password),
        role=role,
        email_verified=verified,
        account_status=status,
    )
    db.session.add(user)
    db.session.commit()
    return user


def test_resend_otp_cooldown_hourly_cap_invalidation_and_no_enumeration(auth_app):
    client = auth_app.test_client()

    with auth_app.app_context():
        user = _create_user(email="unverified@test.local", verified=False)
        verified_user = _create_user(email="verified@test.local", verified=True)

        # Missing account -> same generic 200
        resp_missing = client.post("/api/auth/resend-otp", json={"email": "nobody@test.local"})
        assert resp_missing.status_code == 200

        # Already verified account -> same generic 200
        resp_verified = client.post("/api/auth/resend-otp", json={"email": verified_user.email})
        assert resp_verified.status_code == 200
        assert resp_missing.get_json() == resp_verified.get_json()

        # First resend for unverified user -> sends email & creates OTP
        with patch("app.routes.auth.send_verification_email") as mock_send:
            resp1 = client.post("/api/auth/resend-otp", json={"email": user.email})
            assert resp1.status_code == 200
            assert resp1.get_json() == resp_missing.get_json()
            assert mock_send.call_count == 1
            first_otp = mock_send.call_args.kwargs["otp_code"]

        # Immediate second resend hits 60s cooldown -> generic 200, no email sent
        with patch("app.routes.auth.send_verification_email") as mock_send:
            resp_cooldown = client.post("/api/auth/resend-otp", json={"email": user.email})
            assert resp_cooldown.status_code == 200
            assert resp_cooldown.get_json() == resp_missing.get_json()
            mock_send.assert_not_called()

        # Age the first OTP past 60s cooldown so next resend succeeds & invalidates old OTP
        first_row = EmailVerification.query.filter_by(user_id=user.id).first()
        first_row.created_at = datetime.now(timezone.utc) - timedelta(seconds=65)
        db.session.commit()

        with patch("app.routes.auth.send_verification_email") as mock_send:
            resp2 = client.post("/api/auth/resend-otp", json={"email": user.email})
            assert resp2.status_code == 200
            assert mock_send.call_count == 1
            second_otp = mock_send.call_args.kwargs["otp_code"]

        db.session.refresh(first_row)
        assert first_row.used_at is not None
        assert first_otp != second_otp or first_row.used_at is not None

        # Verify that old OTP is rejected when verifying, and new OTP works
        # (even if first_otp happened to equal second_otp, only the newest unused challenge is queried)
        assert EmailVerification.query.filter_by(user_id=user.id, used_at=None).count() == 1

        # Simulate 5 challenges in the last hour -> 6th blocked silently (generic 200, no email)
        for idx in range(3):
            extra = EmailVerification(
                user_id=user.id,
                code_hash=hash_password("000000"),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
                created_at=datetime.now(timezone.utc) - timedelta(minutes=5 + idx),
            )
            db.session.add(extra)
        latest = EmailVerification.query.filter_by(user_id=user.id, used_at=None).first()
        latest.created_at = datetime.now(timezone.utc) - timedelta(seconds=120)
        db.session.commit()

        with patch("app.routes.auth.send_verification_email") as mock_send:
            resp_cap = client.post("/api/auth/resend-otp", json={"email": user.email})
            assert resp_cap.status_code == 200
            mock_send.assert_not_called()


def test_resend_and_forgot_rate_limit_identical_429_for_existing_and_missing(tmp_path):
    db_path = tmp_path / "rl_auth.db"
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
        "RATELIMIT_ENABLED": True,
        "RATELIMIT_STORAGE_URI": "memory://",
        "RATELIMIT_RESEND_OTP": "1 per minute",
        "RATELIMIT_FORGOT_PASSWORD": "1 per minute",
        "EMAIL_PROVIDER": "console",
    })
    with app.app_context():
        db.create_all()
        _create_user(email="real@test.local", verified=False)
        client = app.test_client()

        # Resend OTP 429 parity
        assert client.post("/api/auth/resend-otp", json={"email": "real@test.local"}).status_code == 200
        r_real = client.post("/api/auth/resend-otp", json={"email": "real@test.local"})
        assert client.post("/api/auth/resend-otp", json={"email": "ghost@test.local"}).status_code == 200
        r_ghost = client.post("/api/auth/resend-otp", json={"email": "ghost@test.local"})
        assert r_real.status_code == 429
        assert r_ghost.status_code == 429
        assert r_real.get_json()["error"] == r_ghost.get_json()["error"]

        # Forgot password 429 parity
        assert client.post("/api/auth/forgot-password", json={"email": "real@test.local"}).status_code == 200
        f_real = client.post("/api/auth/forgot-password", json={"email": "real@test.local"})
        assert client.post("/api/auth/forgot-password", json={"email": "ghost@test.local"}).status_code == 200
        f_ghost = client.post("/api/auth/forgot-password", json={"email": "ghost@test.local"})
        assert f_real.status_code == 429
        assert f_ghost.status_code == 429
        assert f_real.get_json()["error"] == f_ghost.get_json()["error"]

        db.session.remove()
        db.drop_all()


def test_forgot_and_reset_password_lifecycle(auth_app):
    client = auth_app.test_client()

    with auth_app.app_context():
        user = _create_user(email="resetme@test.local", password="OldPassword123!")

        # Login first to get active access + refresh tokens
        login_resp = client.post(
            "/api/auth/login",
            json={"email": user.email, "password": "OldPassword123!"},
        )
        assert login_resp.status_code == 200
        old_access = login_resp.get_json()["access_token"]
        old_refresh = login_resp.get_json()["refresh_token"]

        # Missing email returns identical 200
        resp_missing = client.post("/api/auth/forgot-password", json={"email": "missing@test.local"})
        assert resp_missing.status_code == 200

        # First forgot-password request
        with patch("app.routes.auth.send_password_reset_email") as mock_reset_email:
            resp1 = client.post("/api/auth/forgot-password", json={"email": user.email})
            assert resp1.status_code == 200
            assert resp1.get_json() == resp_missing.get_json()
            reset_url_1 = mock_reset_email.call_args.kwargs["reset_url"]
            assert reset_url_1.startswith("https://app.creatorxdr.test/reset-password?token=")
            raw_token_1 = reset_url_1.split("token=")[1]

        # Stored hashed (SHA-256), never plaintext
        row_1 = PasswordResetToken.query.filter_by(token_hash=hash_token(raw_token_1)).first()
        assert row_1 is not None
        assert row_1.token_hash != raw_token_1

        # Second forgot-password request invalidates the first token
        with patch("app.routes.auth.send_password_reset_email") as mock_reset_email:
            resp2 = client.post("/api/auth/forgot-password", json={"email": user.email})
            assert resp2.status_code == 200
            raw_token_2 = mock_reset_email.call_args.kwargs["reset_url"].split("token=")[1]

        db.session.refresh(row_1)
        assert row_1.used_at is not None

        # Short password rejected (12-char policy)
        short_resp = client.post(
            "/api/auth/reset-password",
            json={"token": raw_token_2, "new_password": "short"},
        )
        assert short_resp.status_code == 400

        # Old invalidated token rejected
        old_tok_resp = client.post(
            "/api/auth/reset-password",
            json={"token": raw_token_1, "new_password": "NewPassword123!"},
        )
        assert old_tok_resp.status_code == 400

        # Valid reset succeeds, revokes all refresh + old access tokens, sends password-changed email
        with patch("app.routes.auth.send_password_changed_email") as mock_changed:
            ok_resp = client.post(
                "/api/auth/reset-password",
                json={"token": raw_token_2, "new_password": "NewPassword123!"},
            )
            assert ok_resp.status_code == 200
            mock_changed.assert_called_once()

        # Single-use: reusing raw_token_2 fails
        reuse_resp = client.post(
            "/api/auth/reset-password",
            json={"token": raw_token_2, "new_password": "AnotherPassword123!"},
        )
        assert reuse_resp.status_code == 400

        # Old access token is invalidated immediately
        me_old = client.get("/api/auth/me", headers={"Authorization": f"Bearer {old_access}"})
        assert me_old.status_code == 401

        # Old refresh token is revoked
        ref_old = client.post("/api/auth/refresh", headers={"Authorization": f"Bearer {old_refresh}"})
        assert ref_old.status_code == 401

        # New password works for login and new access token works
        new_login = client.post(
            "/api/auth/login",
            json={"email": user.email, "password": "NewPassword123!"},
        )
        assert new_login.status_code == 200
        new_access = new_login.get_json()["access_token"]
        me_new = client.get("/api/auth/me", headers={"Authorization": f"Bearer {new_access}"})
        assert me_new.status_code == 200


def test_reset_password_expired_token_rejected(auth_app):
    client = auth_app.test_client()

    with auth_app.app_context():
        user = _create_user(email="expired@test.local")
        expired_row = PasswordResetToken(
            user_id=user.id,
            token_hash=hash_token("expired-raw-token"),
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        db.session.add(expired_row)
        db.session.commit()

        resp = client.post(
            "/api/auth/reset-password",
            json={"token": "expired-raw-token", "new_password": "NewPassword123!"},
        )
        assert resp.status_code == 400


def test_refresh_rotation_reuse_detection_and_concurrent_rotation(auth_app):
    client = auth_app.test_client()

    with auth_app.app_context():
        user = _create_user(email="rotate@test.local")
        login_resp = client.post(
            "/api/auth/login",
            json={"email": user.email, "password": "ValidPassword123!"},
        )
        assert login_resp.status_code == 200
        refresh_1 = login_resp.get_json()["refresh_token"]

        # First rotation succeeds and returns a new refresh_token
        rot_1 = client.post("/api/auth/refresh", headers={"Authorization": f"Bearer {refresh_1}"})
        assert rot_1.status_code == 200
        refresh_2 = rot_1.get_json()["refresh_token"]
        assert refresh_2 != refresh_1

        # Concurrent/duplicate rotation using refresh_1 -> 401 AND revokes entire family
        rot_reuse = client.post("/api/auth/refresh", headers={"Authorization": f"Bearer {refresh_1}"})
        assert rot_reuse.status_code == 401

        # Now refresh_2 (from the same family) must also be revoked!
        rot_2_after_reuse = client.post("/api/auth/refresh", headers={"Authorization": f"Bearer {refresh_2}"})
        assert rot_2_after_reuse.status_code == 401

        # Expired refresh token rejected
        expired_login = client.post(
            "/api/auth/login",
            json={"email": user.email, "password": "ValidPassword123!"},
        )
        exp_refresh = expired_login.get_json()["refresh_token"]
        row = RefreshToken.query.order_by(RefreshToken.created_at.desc()).first()
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        db.session.commit()
        rot_exp = client.post("/api/auth/refresh", headers={"Authorization": f"Bearer {exp_refresh}"})
        assert rot_exp.status_code == 401


def test_logout_revokes_access_and_refresh_family_and_prod_fail_closed(auth_app):
    client = auth_app.test_client()

    with auth_app.app_context():
        user = _create_user(email="logout@test.local")
        login_resp = client.post(
            "/api/auth/login",
            json={"email": user.email, "password": "ValidPassword123!"},
        )
        access = login_resp.get_json()["access_token"]
        refresh = login_resp.get_json()["refresh_token"]

        logout_resp = client.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {access}"},
            json={"refresh_token": refresh},
        )
        assert logout_resp.status_code == 200

        # Both access and refresh are now rejected
        assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {access}"}).status_code == 401
        assert client.post("/api/auth/refresh", headers={"Authorization": f"Bearer {refresh}"}).status_code == 401

        # Production fail-closed when Redis is unavailable
        auth_app.config["TESTING"] = False
        auth_app.config["DEBUG"] = False
        assert is_access_jti_revoked("some-jti") is True
        auth_app.config["TESTING"] = True


def test_suspended_and_locked_accounts_blocked_at_login_refresh_and_protected_routes(auth_app):
    client = auth_app.test_client()

    with auth_app.app_context():
        active_user = _create_user(email="status@test.local", password="ValidPassword123!")
        login_resp = client.post(
            "/api/auth/login",
            json={"email": active_user.email, "password": "ValidPassword123!"},
        )
        access = login_resp.get_json()["access_token"]
        refresh = login_resp.get_json()["refresh_token"]

        for bad_status in ("SUSPENDED", "LOCKED"):
            active_user.account_status = bad_status
            db.session.commit()

            # Wrong password -> 401 (never reveals account status)
            bad_pw = client.post(
                "/api/auth/login",
                json={"email": active_user.email, "password": "WrongPassword123!"},
            )
            assert bad_pw.status_code == 401

            # Correct password -> 403
            good_pw = client.post(
                "/api/auth/login",
                json={"email": active_user.email, "password": "ValidPassword123!"},
            )
            assert good_pw.status_code == 403

            # Protected routes blocked via central user_lookup_loader
            assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {access}"}).status_code == 401
            assert client.get("/api/verification/submissions", headers={"Authorization": f"Bearer {access}"}).status_code == 401

            # Refresh blocked
            assert client.post("/api/auth/refresh", headers={"Authorization": f"Bearer {refresh}"}).status_code == 401

            # Re-login to test next status on fresh refresh token
            active_user.account_status = "ACTIVE"
            db.session.commit()
            relogin = client.post(
                "/api/auth/login",
                json={"email": active_user.email, "password": "ValidPassword123!"},
            )
            access = relogin.get_json()["access_token"]
            refresh = relogin.get_json()["refresh_token"]
