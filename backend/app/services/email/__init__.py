from app.services.email.provider import EmailProvider, ConsoleEmailProvider, SMTPEmailProvider
from app.services.email.email_service import (
    send_templated_email,
    send_verification_email,
    send_password_reset_email,
    send_review_decision_email,
)

__all__ = [
    "EmailProvider",
    "ConsoleEmailProvider",
    "SMTPEmailProvider",
    "send_templated_email",
    "send_verification_email",
    "send_password_reset_email",
    "send_review_decision_email",
]
