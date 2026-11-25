from unittest.mock import patch
import pytest
from app import create_app
from app.extensions import limiter


@pytest.fixture
def rate_limited_app():
    """Create test application with limiter explicitly enabled and memory storage."""
    app = create_app({
        "TESTING": True,
        "RATELIMIT_ENABLED": True,
        "RATELIMIT_STORAGE_URI": "memory://",
        "RATELIMIT_STRATEGY": "moving-window",
        "REDIS_URL": "",
        "RATELIMIT_REGISTER": "2 per minute",
        "RATELIMIT_LOGIN_IP": "3 per minute",
        "RATELIMIT_LOGIN_ACCOUNT": "2 per minute",
        "RATELIMIT_REFRESH_TOKEN": "2 per minute",
        "RATELIMIT_VERIFY_EMAIL": "2 per minute",
        "RATELIMIT_DOCUMENT_UPLOAD_IP": "2 per minute",
        "RATELIMIT_DOCUMENT_UPLOAD_USER": "2 per minute",
    })
    return app


@pytest.fixture(autouse=True)
def reset_rate_limits():
    """Clear limiter storage between tests."""
    yield
    try:
        limiter.reset()
    except Exception:
        pass


def test_registration_rate_limit(rate_limited_app):
    client = rate_limited_app.test_client()

    with rate_limited_app.app_context():
        with patch("app.routes.auth.User.query") as mock_user_query, \
             patch("app.routes.auth.db.session.add"), \
             patch("app.routes.auth.db.session.commit"), \
             patch("app.routes.auth.create_verification_challenge", return_value="123456"), \
             patch("app.routes.auth.send_verification_email"):
            mock_user_query.filter_by.return_value.first.return_value = None

            # Request 1 & 2 succeed (limit is 2 per minute)
            for i in range(2):
                resp = client.post(
                    "/api/auth/register",
                    json={
                        "email": f"user{i}@test.local",
                        "full_name": f"User {i}",
                        "password": "ValidPassword123!",
                    },
                    environ_base={"REMOTE_ADDR": "192.0.2.1"},
                )
                assert resp.status_code == 201

            # Request 3 from same IP is rate-limited (HTTP 429)
            resp = client.post(
                "/api/auth/register",
                json={
                    "email": "user3@test.local",
                    "full_name": "User 3",
                    "password": "ValidPassword123!",
                },
                environ_base={"REMOTE_ADDR": "192.0.2.1"},
            )
            assert resp.status_code == 429
            data = resp.get_json()
            assert data["error"] == "Rate limit exceeded. Please try again later."
            assert "retry_after" in data
            assert "Retry-After" in resp.headers

            # Request from different IP succeeds
            resp_diff_ip = client.post(
                "/api/auth/register",
                json={
                    "email": "user4@test.local",
                    "full_name": "User 4",
                    "password": "ValidPassword123!",
                },
                environ_base={"REMOTE_ADDR": "192.0.2.2"},
            )
            assert resp_diff_ip.status_code == 201



def test_login_failed_attempts_account_limit(rate_limited_app):
    """Confirm login account limit only deducts on failed attempts (401)."""
    client = rate_limited_app.test_client()

    with rate_limited_app.app_context():
        with patch("app.routes.auth.User.query") as mock_query:
            # Simulate wrong password / user not found -> 401
            mock_query.filter_by.return_value.first.return_value = None

            # 2 failed attempts for victim@test.local (limit is 2 per minute)
            for _ in range(2):
                resp = client.post(
                    "/api/auth/login",
                    json={"email": "victim@test.local", "password": "wrongpassword"},
                    environ_base={"REMOTE_ADDR": "198.51.100.1"},
                )
                assert resp.status_code == 401

            # 3rd attempt for victim@test.local hits account rate limit (429) even from different IP
            resp_blocked = client.post(
                "/api/auth/login",
                json={"email": "victim@test.local", "password": "wrongpassword"},
                environ_base={"REMOTE_ADDR": "198.51.100.99"},
            )
            assert resp_blocked.status_code == 429
            assert "Retry-After" in resp_blocked.headers

            # Different email from that second IP is NOT blocked
            resp_other = client.post(
                "/api/auth/login",
                json={"email": "other@test.local", "password": "wrongpassword"},
                environ_base={"REMOTE_ADDR": "198.51.100.99"},
            )
            assert resp_other.status_code == 401


def test_proxy_fix_trusted_count(rate_limited_app):
    """Verify that when TRUSTED_PROXY_COUNT is set, client IP from X-Forwarded-For is respected."""
    app = create_app({
        "TESTING": True,
        "RATELIMIT_ENABLED": True,
        "RATELIMIT_STORAGE_URI": "memory://",
        "RATELIMIT_REGISTER": "1 per minute",
        "TRUSTED_PROXY_COUNT": 1,
    })
    client = app.test_client()

    with app.app_context():
        with patch("app.routes.auth.User.query") as mock_user_query, \
             patch("app.routes.auth.db.session.add"), \
             patch("app.routes.auth.db.session.commit"), \
             patch("app.routes.auth.create_verification_challenge", return_value="123456"), \
             patch("app.routes.auth.send_verification_email"):
            mock_user_query.filter_by.return_value.first.return_value = None

            # First request with Client IP A behind proxy
            resp1 = client.post(
                "/api/auth/register",
                json={"email": "a@test.com", "full_name": "A", "password": "Password12345!"},
                headers={"X-Forwarded-For": "203.0.113.10"},
            )
            assert resp1.status_code == 201

            # Second request with Client IP A gets 429
            resp2 = client.post(
                "/api/auth/register",
                json={"email": "a2@test.com", "full_name": "A2", "password": "Password12345!"},
                headers={"X-Forwarded-For": "203.0.113.10"},
            )
            assert resp2.status_code == 429

            # Third request with Client IP B succeeds despite same direct connection
            resp3 = client.post(
                "/api/auth/register",
                json={"email": "b@test.com", "full_name": "B", "password": "Password12345!"},
                headers={"X-Forwarded-For": "203.0.113.20"},
            )
            assert resp3.status_code == 201


def test_email_key_normalization_and_malformed_json(rate_limited_app):
    """Confirm get_email_or_ip normalizes emails and handles malformed JSON safely."""
    client = rate_limited_app.test_client()

    with rate_limited_app.app_context():
        with patch("app.routes.auth.User.query") as mock_query:
            mock_query.filter_by.return_value.first.return_value = None

            # Attempt 1 with uppercase + whitespace
            resp1 = client.post(
                "/api/auth/login",
                json={"email": "  MixedCase@Test.Local ", "password": "wrong"},
                environ_base={"REMOTE_ADDR": "198.51.100.10"},
            )
            assert resp1.status_code == 401

            # Attempt 2 with lowercase from different IP -> shares normalized account bucket
            resp2 = client.post(
                "/api/auth/login",
                json={"email": "mixedcase@test.local", "password": "wrong"},
                environ_base={"REMOTE_ADDR": "198.51.100.11"},
            )
            assert resp2.status_code == 401

            # Attempt 3 hits account limit (2 per minute)
            resp3 = client.post(
                "/api/auth/login",
                json={"email": "MIXEDCASE@TEST.LOCAL", "password": "wrong"},
                environ_base={"REMOTE_ADDR": "198.51.100.12"},
            )
            assert resp3.status_code == 429

            # Malformed JSON falls back to IP without crashing
            resp_bad_json = client.post(
                "/api/auth/login",
                data="{not-valid-json",
                content_type="application/json",
                environ_base={"REMOTE_ADDR": "198.51.100.50"},
            )
            assert resp_bad_json.status_code == 401


def test_upload_per_user_rate_limit(rate_limited_app):
    """Confirm document upload limit is keyed per JWT user ID and falls back to IP."""
    from types import SimpleNamespace
    from flask_jwt_extended import create_access_token

    client = rate_limited_app.test_client()

    with rate_limited_app.app_context():
        token_user_1 = create_access_token(identity="user-1", additional_claims={"role": "CREATOR"})
        token_user_2 = create_access_token(identity="user-2", additional_claims={"role": "CREATOR"})

        def _fake_get(_model, ident):
            return SimpleNamespace(
                id=ident,
                account_status="ACTIVE",
                email_verified=False,
                tokens_valid_after=None,
                role="CREATOR",
            )

        def _fake_execute(_stmt):
            from unittest.mock import MagicMock
            res = MagicMock()
            res.scalar_one_or_none.return_value = _fake_get(None, "user-1")
            return res

        with patch("app.db.session.get", side_effect=_fake_get), \
             patch("app.routes.verification.db.session.execute", side_effect=_fake_execute):
            # User 1 makes 2 requests from different IPs (hits user limit of 2 per minute; IP limit is 2 per IP)
            for idx in range(2):
                resp = client.post(
                    "/api/verification/upload",
                    headers={"Authorization": f"Bearer {token_user_1}"},
                    environ_base={"REMOTE_ADDR": f"198.51.100.{20 + idx}"},
                )
                assert resp.status_code == 403

            # User 1's 3rd request from a fresh IP is rate-limited by user ID
            resp_u1_blocked = client.post(
                "/api/verification/upload",
                headers={"Authorization": f"Bearer {token_user_1}"},
                environ_base={"REMOTE_ADDR": "198.51.100.22"},
            )
            assert resp_u1_blocked.status_code == 429

            # User 2 from the first IP is NOT blocked by User 1's user-keyed bucket
            resp_u2 = client.post(
                "/api/verification/upload",
                headers={"Authorization": f"Bearer {token_user_2}"},
                environ_base={"REMOTE_ADDR": "198.51.100.20"},
            )
            assert resp_u2.status_code == 403


def test_429_logging_excludes_pii(rate_limited_app, caplog):
    """Confirm 429 warning logs exclude email/tokens."""
    import logging

    client = rate_limited_app.test_client()

    with rate_limited_app.app_context():
        with caplog.at_level(logging.WARNING):
            with patch("app.routes.auth.User.query") as mock_query:
                mock_query.filter_by.return_value.first.return_value = None
                for _ in range(3):
                    client.post(
                        "/api/auth/login",
                        json={"email": "secret-pii@test.local", "password": "secret-password"},
                        environ_base={"REMOTE_ADDR": "203.0.113.55"},
                    )

    warning_messages = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING and "Rate limit exceeded" in r.getMessage()]
    assert len(warning_messages) >= 1
    for msg in warning_messages:
        assert "secret-pii@test.local" not in msg
        assert "secret-password" not in msg

