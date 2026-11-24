from abc import ABC, abstractmethod
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

logger = logging.getLogger(__name__)


class EmailProvider(ABC):
    """Abstract base class for email sending providers."""

    @abstractmethod
    def send_email(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: str,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
    ) -> bool:
        """Send an email to a single recipient."""
        raise NotImplementedError


class ConsoleEmailProvider(EmailProvider):
    """
    Console/Dev email provider.
    Outputs email delivery details to logs without network transmission.
    Prevents leaking sensitive data in production while ensuring dev visibility.
    """

    def send_email(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: str,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
    ) -> bool:
        sender = f"{from_name} <{from_email}>" if from_name and from_email else (from_email or "default")
        logger.info(
            "=== [DEV CONSOLE EMAIL] ===\nTo: %s\nFrom: %s\nSubject: %s\n--- Body (Plaintext) ---\n%s\n===========================",
            to_email,
            sender,
            subject,
            text_body,
        )
        return True


class SMTPEmailProvider(EmailProvider):
    """
    Standard SMTP email provider with STARTTLS / SSL support.
    """

    def __init__(
        self,
        host: str,
        port: int = 587,
        username: str = "",
        password: str = "",
        use_tls: bool = True,
        use_ssl: bool = False,
        default_from_email: str = "no-reply@creatorxdr.local",
        default_from_name: str = "CreatorXDR Security",
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.use_ssl = use_ssl
        self.default_from_email = default_from_email
        self.default_from_name = default_from_name

    def send_email(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: str,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
    ) -> bool:
        sender_email = from_email or self.default_from_email
        sender_name = from_name or self.default_from_name
        formatted_from = f"{sender_name} <{sender_email}>" if sender_name else sender_email

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = formatted_from
        msg["To"] = to_email

        # Attach text first, then html (standard MIME multipart/alternative practice)
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        if html_body:
            msg.attach(MIMEText(html_body, "html", "utf-8"))

        try:
            if self.use_ssl:
                server = smtplib.SMTP_SSL(self.host, self.port, timeout=10)
            else:
                server = smtplib.SMTP(self.host, self.port, timeout=10)

            with server:
                server.ehlo()
                if self.use_tls and not self.use_ssl:
                    server.starttls()
                    server.ehlo()

                if self.username and self.password:
                    server.login(self.username, self.password)

                server.sendmail(sender_email, [to_email], msg.as_string())

            logger.info("Email '%s' sent successfully to %s via SMTP", subject, to_email)
            return True

        except Exception as e:
            logger.error("Failed to send email to %s via SMTP: %s", to_email, str(e))
            raise
