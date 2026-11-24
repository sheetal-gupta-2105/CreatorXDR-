
import re

import click

from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config import Config
from app.extensions import db, migrate, jwt, limiter


from app.models import (
    User,
    EmailVerification,
    VerificationSubmission,
    VerificationReview,
    IdentityFingerprint,
    OCRResult,
    AdminAuditLog,
    MerkleBatch,
    MerkleBatchLeaf,
)

from app.routes import (
    health_bp,
    auth_bp,
    verification_bp,
    admin_verification_bp,
    admin_blockchain_bp,
)

from app.services.auth_service import (
    _ensure_utc,
    hash_password,
    is_access_jti_revoked,
)


def create_app(test_config=None):
    app = Flask(__name__)

    app.config.from_object(Config)

    if test_config:
        app.config.update(test_config)
        if test_config.get("TESTING") and "RATELIMIT_ENABLED" not in test_config:
            app.config["RATELIMIT_ENABLED"] = False

    if not app.config.get("SQLALCHEMY_DATABASE_URI"):
        raise RuntimeError("DATABASE_URL is not configured")

    if not app.config.get("JWT_SECRET_KEY"):
        raise RuntimeError("JWT_SECRET_KEY is not configured")

    # Warn loudly if EMAIL_PROVIDER is console in a production environment
    if not app.config.get("DEBUG") and not app.config.get("TESTING"):
        if app.config.get("EMAIL_PROVIDER") == "console":
            app.logger.warning(
                "CRITICAL WARNING: EMAIL_PROVIDER is set to 'console' in a production environment. "
                "Outgoing emails (verification OTPs, password resets, review decisions) will only be printed to server logs "
                "and will not be delivered to users. Configure an SMTP or transactional email provider for production."
            )

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(_jwt_header, jwt_payload):
        jti = jwt_payload.get("jti")
        token_type = jwt_payload.get("type")

        if token_type == "access" and jti and is_access_jti_revoked(jti):
            return True

        user_id = jwt_payload.get("sub")
        if user_id:
            user = db.session.get(User, user_id)
            if user and user.tokens_valid_after:
                valid_after = _ensure_utc(user.tokens_valid_after)
                issued_at_ms = jwt_payload.get("issued_at_ms")
                if issued_at_ms is not None:
                    if int(issued_at_ms) < int(valid_after.timestamp() * 1000):
                        return True
                else:
                    iat = int(jwt_payload.get("iat", 0))
                    if iat <= int(valid_after.timestamp()):
                        return True

        return False

    @jwt.revoked_token_loader
    def revoked_token_callback(_jwt_header, _jwt_payload):
        return jsonify({"error": "Token has been revoked."}), 401

    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data.get("sub")
        user = db.session.get(User, identity)
        if not user or user.account_status != "ACTIVE":
            return None
        return user

    @jwt.user_lookup_error_loader
    def user_lookup_error_callback(_jwt_header, _jwt_data):
        return jsonify({"error": "Account is unavailable."}), 401

    # Configure ProxyFix if trusted proxies are present
    trusted_proxies = app.config.get("TRUSTED_PROXY_COUNT", 0)
    if trusted_proxies > 0:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=trusted_proxies,
            x_proto=trusted_proxies,
            x_host=trusted_proxies,
            x_port=trusted_proxies,
            x_prefix=trusted_proxies,
        )

    # Configure Limiter.
    # Flask-Limiter's init_app() mutates instance-level runtime state on the module-level
    # singleton (e.g. _storage_dead, _storage, _limiter, _in_memory_fallback, and
    # limit_manager._default_limits). In multi-app test sessions, stale state from an
    # earlier create_app() call leaks into subsequent apps, so we reset those internal
    # attributes before re-initializing against the new app's config.
    limiter.enabled = bool(app.config.get("RATELIMIT_ENABLED", True))
    limiter._storage_dead = False
    limiter._storage = None
    limiter._limiter = None
    limiter._in_memory_fallback = []
    limiter.limit_manager._default_limits = []
    limiter.limit_manager._application_limits = []
    limiter.initialized = False
    limiter.init_app(app)

    # Register custom 429 error handler
    @app.errorhandler(429)
    def ratelimit_handler(e):
        app.logger.warning(
            "Rate limit exceeded on %s %s from IP %s",
            request.method,
            request.path,
            request.remote_addr,
        )
        retry_after = getattr(e, "retry_after", None)
        if retry_after is None:
            # Fallback estimation from description if available
            retry_after = 60

        response = jsonify({
            "error": "Rate limit exceeded. Please try again later.",
            "retry_after": int(retry_after),
        })
        response.status_code = 429
        response.headers["Retry-After"] = str(int(retry_after))
        return response



    # Configure CORS
    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": [app.config["FRONTEND_ORIGIN"]]
            }
        },
        supports_credentials=True,
    )

    # Register health routes
    app.register_blueprint(
        health_bp,
        url_prefix="/api",
    )

    # Register authentication routes
    app.register_blueprint(
        auth_bp,
        url_prefix="/api/auth",
    )

    # Register identity verification routes
    app.register_blueprint(
        verification_bp,
        url_prefix="/api/verification",
    )

    # Register administrator verification routes
    app.register_blueprint(
        admin_verification_bp,
        url_prefix="/api/admin/verification",
    )

    # Register administrator blockchain routes
    app.register_blueprint(
        admin_blockchain_bp,
        url_prefix="/api/admin/blockchain",
    )

    # Secure administrator creation command
    @app.cli.command("create-admin")
    def create_admin():
        """Create an administrator account securely."""

        email = click.prompt(
            "Administrator email"
        ).strip().lower()

        if not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            email,
        ):
            raise click.ClickException(
                "Please enter a valid email address."
            )

        existing_user = User.query.filter_by(
            email=email
        ).first()

        if existing_user:
            raise click.ClickException(
                "An account with this email already exists. "
                "No account was changed."
            )

        password = click.prompt(
            "Administrator password",
            hide_input=True,
            confirmation_prompt=True,
        )

        if len(password) < 12:
            raise click.ClickException(
                "Password must contain at least 12 characters."
            )

        admin = User(
            email=email,
            password_hash=hash_password(password),
            role="ADMIN",
            email_verified=True,
            account_status="ACTIVE",
        )

        try:
            db.session.add(admin)
            db.session.commit()

        except Exception:
            db.session.rollback()

            raise click.ClickException(
                "Administrator account could not be created."
            )

        click.echo(
            f"Administrator account created for {email}."
        )

    # Handle oversized document uploads
    @app.errorhandler(RequestEntityTooLarge)
    def handle_large_upload(error):
        return jsonify({
            "error": (
                "Request is too large. "
                "Maximum document size is 5 MB."
            )
        }), 413

    return app
