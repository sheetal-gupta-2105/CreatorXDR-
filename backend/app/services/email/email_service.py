import logging
from typing import Optional
from flask import render_template, current_app
from app.tasks.email_tasks import get_email_queue, execute_email_job

logger = logging.getLogger(__name__)


def send_templated_email(
    to_email: str,
    subject: str,
    template_prefix: str,
    context: dict,
    async_send: bool = True,
) -> bool:
    """
    Renders both HTML and plain-text templates with Jinja2 and dispatches the email.
    If Redis and RQ are reachable and async_send is True, queues the task.
    Otherwise, executes synchronously.
    """
    context_with_subject = dict(context)
    context_with_subject["subject"] = subject

    html_template = f"email/{template_prefix}.html"
    text_template = f"email/{template_prefix}.txt"

    try:
        html_body = render_template(html_template, **context_with_subject)
    except Exception as e:
        logger.warning("Could not render HTML template %s: %s", html_template, str(e))
        html_body = ""

    try:
        text_body = render_template(text_template, **context_with_subject)
    except Exception as e:
        logger.error("Could not render text template %s: %s", text_template, str(e))
        text_body = ""

    config_dict = {
        "EMAIL_PROVIDER": current_app.config.get("EMAIL_PROVIDER", "console"),
        "EMAIL_FROM_ADDRESS": current_app.config.get("EMAIL_FROM_ADDRESS"),
        "EMAIL_FROM_NAME": current_app.config.get("EMAIL_FROM_NAME"),
        "SMTP_HOST": current_app.config.get("SMTP_HOST"),
        "SMTP_PORT": current_app.config.get("SMTP_PORT"),
        "SMTP_USER": current_app.config.get("SMTP_USER"),
        "SMTP_PASSWORD": current_app.config.get("SMTP_PASSWORD"),
        "SMTP_USE_TLS": current_app.config.get("SMTP_USE_TLS"),
        "SMTP_USE_SSL": current_app.config.get("SMTP_USE_SSL"),
    }
    provider_name = config_dict["EMAIL_PROVIDER"]

    if async_send:
        try:
            queue = get_email_queue()
            if queue:
                # Set short TTLs so sensitive parameters (like OTPs) do not linger in Redis
                queue.enqueue(
                    execute_email_job,
                    to_email=to_email,
                    subject=subject,
                    html_body=html_body,
                    text_body=text_body,
                    provider_name=provider_name,
                    config_dict=config_dict,
                    result_ttl=60,       # Keep successful job record for only 60 seconds
                    failure_ttl=300,     # Keep failed job record for 5 minutes maximum
                )
                logger.info("Enqueued email '%s' for '%s'", subject, to_email)
                return True
        except Exception as e:
            logger.warning("Failed to enqueue email task (%s)", str(e))

    # Synchronous execution fallback when queue is unavailable or async_send is False
    allow_sync_fallback = current_app.config.get("EMAIL_SYNC_FALLBACK", False)
    if allow_sync_fallback or not async_send:
        if async_send:
            logger.warning(
                "Triggering synchronous email fallback for '%s' because Redis/queue was unavailable (EMAIL_SYNC_FALLBACK is enabled).",
                to_email,
            )
        try:
            execute_email_job(
                to_email=to_email,
                subject=subject,
                html_body=html_body,
                text_body=text_body,
                provider_name=provider_name,
                config_dict=config_dict,
            )
            return True
        except Exception as e:
            logger.error("Synchronous email delivery failed: %s", str(e))
            return False

    logger.warning(
        "Email '%s' to '%s' dropped because async queue was unavailable and EMAIL_SYNC_FALLBACK is disabled.",
        subject,
        to_email,
    )
    return False



def send_verification_email(to_email: str, user_name: str, otp_code: str, async_send: bool = True) -> bool:
    """Dispatches the email OTP verification code."""
    return send_templated_email(
        to_email=to_email,
        subject="CreatorXDR - Verify your email address",
        template_prefix="verification",
        context={
            "user_name": user_name,
            "otp_code": otp_code,
        },
        async_send=async_send,
    )


def send_password_reset_email(to_email: str, user_name: str, reset_url: str, async_send: bool = True) -> bool:
    """Dispatches password reset link."""
    return send_templated_email(
        to_email=to_email,
        subject="CreatorXDR - Password Reset Request",
        template_prefix="password_reset",
        context={
            "user_name": user_name,
            "reset_url": reset_url,
        },
        async_send=async_send,
    )


def send_review_decision_email(
    to_email: str,
    user_name: str,
    document_type: str,
    decision: str,
    reason_code: Optional[str] = None,
    reviewer_notes: Optional[str] = None,
    async_send: bool = True,
) -> bool:
    """Dispatches review result email notification based on the decision."""
    decision_map = {
        "APPROVED": ("Identity Verification Approved", "verification_approved"),
        "REJECTED": ("Identity Verification Update: Rejected", "verification_rejected"),
        "NEEDS_RESUBMISSION": ("Identity Verification: Resubmission Required", "verification_resubmission"),
    }

    if decision not in decision_map:
        logger.warning("No email template mapped for decision '%s'", decision)
        return False

    subject_suffix, template_prefix = decision_map[decision]
    subject = f"CreatorXDR - {subject_suffix}"

    return send_templated_email(
        to_email=to_email,
        subject=subject,
        template_prefix=template_prefix,
        context={
            "user_name": user_name,
            "document_type": document_type,
            "reason_code": reason_code,
            "reviewer_notes": reviewer_notes,
        },
        async_send=async_send,
    )
