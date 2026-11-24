from unittest.mock import MagicMock, patch
import pytest
from app import create_app
from app.services.email.provider import ConsoleEmailProvider, SMTPEmailProvider
from app.services.email.email_service import (
    send_templated_email,
    send_verification_email,
    send_password_reset_email,
    send_review_decision_email,
)
from app.tasks.email_tasks import execute_email_job


@pytest.fixture
def app():
    app = create_app()
    app.config.update({
        "TESTING": True,
        "EMAIL_PROVIDER": "console",
        "EMAIL_FROM_ADDRESS": "security@test.creatorxdr",
        "EMAIL_FROM_NAME": "CreatorXDR Test Security",
    })
    return app


def test_console_email_provider():
    provider = ConsoleEmailProvider()
    result = provider.send_email(
        to_email="creator@test.local",
        subject="Test Subject",
        html_body="<p>Test</p>",
        text_body="Test",
        from_email="noreply@test.local",
        from_name="Test Sender",
    )
    assert result is True


def test_smtp_email_provider_success():
    provider = SMTPEmailProvider(
        host="smtp.test.local",
        port=587,
        username="user",
        password="secretpassword",
        use_tls=True,
    )

    with patch("app.services.email.provider.smtplib.SMTP") as mock_smtp_cls:
        mock_instance = MagicMock()
        mock_smtp_cls.return_value = mock_instance

        result = provider.send_email(
            to_email="creator@test.local",
            subject="Test OTP",
            html_body="<p>Your code is 123456</p>",
            text_body="Your code is 123456",
        )

        assert result is True
        mock_instance.ehlo.assert_called()
        mock_instance.starttls.assert_called_once()
        mock_instance.login.assert_called_once_with("user", "secretpassword")
        mock_instance.sendmail.assert_called_once()


def test_smtp_email_provider_ssl():
    provider = SMTPEmailProvider(
        host="smtp.test.local",
        port=465,
        use_ssl=True,
    )

    with patch("app.services.email.provider.smtplib.SMTP_SSL") as mock_smtp_ssl_cls:
        mock_instance = MagicMock()
        mock_smtp_ssl_cls.return_value = mock_instance

        result = provider.send_email(
            to_email="creator@test.local",
            subject="SSL Test",
            html_body="<p>SSL Test</p>",
            text_body="SSL Test",
        )

        assert result is True
        mock_smtp_ssl_cls.assert_called_once_with("smtp.test.local", 465, timeout=10)
        mock_instance.sendmail.assert_called_once()




def test_send_verification_email_template_rendering(app):
    with app.test_request_context():
        with patch("app.services.email.email_service.execute_email_job") as mock_exec:
            success = send_verification_email(
                to_email="alice@example.com",
                user_name="Alice Smith",
                otp_code="987654",
                async_send=False,
            )

            assert success is True
            mock_exec.assert_called_once()
            call_kwargs = mock_exec.call_args.kwargs
            assert call_kwargs["to_email"] == "alice@example.com"
            assert "Verify your email" in call_kwargs["subject"]
            assert "987654" in call_kwargs["text_body"]
            assert "987654" in call_kwargs["html_body"]
            assert "Alice Smith" in call_kwargs["html_body"]


def test_send_password_reset_email_rendering(app):
    with app.test_request_context():
        with patch("app.services.email.email_service.execute_email_job") as mock_exec:
            success = send_password_reset_email(
                to_email="alice@example.com",
                user_name="Alice Smith",
                reset_url="https://app.creatorxdr.com/reset?token=xyz123",
                async_send=False,
            )

            assert success is True
            mock_exec.assert_called_once()
            call_kwargs = mock_exec.call_args.kwargs
            assert "Password Reset Request" in call_kwargs["subject"]
            assert "https://app.creatorxdr.com/reset?token=xyz123" in call_kwargs["html_body"]
            assert "https://app.creatorxdr.com/reset?token=xyz123" in call_kwargs["text_body"]


@pytest.mark.parametrize("decision,expected_subject_part,expected_body_part", [
    ("APPROVED", "Approved", "APPROVED"),
    ("REJECTED", "Rejected", "REJECTED"),
    ("NEEDS_RESUBMISSION", "Resubmission", "NEEDS RESUBMISSION"),
])
def test_send_review_decision_email_rendering(app, decision, expected_subject_part, expected_body_part):
    with app.test_request_context():
        with patch("app.services.email.email_service.execute_email_job") as mock_exec:
            success = send_review_decision_email(
                to_email="creator@example.com",
                user_name="Bob Creator",
                document_type="PASSPORT",
                decision=decision,
                reason_code="BLURRY_DOCUMENT" if decision != "APPROVED" else None,
                reviewer_notes="Please take a clearer picture" if decision != "APPROVED" else None,
                async_send=False,
            )

            assert success is True
            mock_exec.assert_called_once()
            call_kwargs = mock_exec.call_args.kwargs
            assert expected_subject_part in call_kwargs["subject"]
            assert expected_body_part in call_kwargs["html_body"]
            assert "PASSPORT" in call_kwargs["html_body"]


def test_execute_email_job_console_execution():
    with patch("app.services.email.provider.ConsoleEmailProvider.send_email", return_value=True) as mock_send:
        execute_email_job(
            to_email="test@example.com",
            subject="Subj",
            html_body="<p>Hi</p>",
            text_body="Hi",
            provider_name="console",
            config_dict={"EMAIL_FROM_ADDRESS": "noreply@creatorxdr.local"},
        )
        mock_send.assert_called_once()


def test_queue_enqueues_when_redis_available(app):
    with app.test_request_context():
        mock_queue = MagicMock()
        with patch("app.services.email.email_service.get_email_queue", return_value=mock_queue):
            success = send_templated_email(
                to_email="test@example.com",
                subject="Test Subject",
                template_prefix="verification",
                context={"user_name": "Test", "otp_code": "112233"},
                async_send=True,
            )
            assert success is True
            mock_queue.enqueue.assert_called_once()
            call_kwargs = mock_queue.enqueue.call_args.kwargs
            assert call_kwargs["result_ttl"] == 60
            assert call_kwargs["failure_ttl"] == 300


def test_jinja2_html_autoescape_xss(app):
    """Verify that malicious reviewer notes or user names are HTML-escaped."""
    with app.test_request_context():
        with patch("app.services.email.email_service.execute_email_job") as mock_exec:
            send_review_decision_email(
                to_email="creator@example.com",
                user_name="<script>alert('xss')</script>",
                document_type="PASSPORT",
                decision="REJECTED",
                reason_code="INVALID",
                reviewer_notes="<script>badCode()</script>",
                async_send=False,
            )
            mock_exec.assert_called_once()
            html_body = mock_exec.call_args.kwargs["html_body"]
            assert "<script>" not in html_body
            assert "&lt;script&gt;badCode()&lt;/script&gt;" in html_body
            assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in html_body


def test_sync_fallback_disabled_in_prod(app):
    """Verify that when EMAIL_SYNC_FALLBACK=False, email is not synchronously sent if queue is down."""
    app.config["EMAIL_SYNC_FALLBACK"] = False
    with app.test_request_context():
        with patch("app.services.email.email_service.get_email_queue", return_value=None), \
             patch("app.services.email.email_service.execute_email_job") as mock_exec:
            success = send_templated_email(
                to_email="test@example.com",
                subject="Test Subject",
                template_prefix="verification",
                context={"user_name": "Test", "otp_code": "112233"},
                async_send=True,
            )
            assert success is False
            mock_exec.assert_not_called()


def test_email_failure_does_not_break_registration(app):
    """Confirm dispatch failure after commit is caught and does not turn into a 500 error."""
    client = app.test_client()
    with app.app_context():
        with patch("app.routes.auth.send_verification_email", side_effect=Exception("Simulated mail failure")), \
             patch("app.routes.auth.create_verification_challenge", return_value="123456"):
            with patch("app.routes.auth.User.query") as mock_query, \
                 patch("app.routes.auth.db.session.add"), \
                 patch("app.routes.auth.db.session.commit"):
                mock_query.filter_by.return_value.first.return_value = None
                response = client.post("/api/auth/register", json={
                    "email": "newuser@example.com",
                    "full_name": "New User",
                    "password": "Password123456!",
                })
                assert response.status_code == 201
                data = response.get_json()
                assert data["verification_required"] is True


