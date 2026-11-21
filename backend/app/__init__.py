
import re

import click

from flask import Flask, jsonify
from flask_cors import CORS
from werkzeug.exceptions import RequestEntityTooLarge

from app.config import Config
from app.extensions import db, migrate, jwt

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
)

from app.services.auth_service import hash_password


def create_app(test_config=None):
    app = Flask(__name__)

    app.config.from_object(Config)

    if test_config:
        app.config.update(test_config)

    if not app.config.get("SQLALCHEMY_DATABASE_URI"):
        raise RuntimeError("DATABASE_URL is not configured")

    if not app.config.get("JWT_SECRET_KEY"):
        raise RuntimeError("JWT_SECRET_KEY is not configured")

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)

    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": [app.config["FRONTEND_ORIGIN"]]
            }
        },
        supports_credentials=True,
    )

    app.register_blueprint(
        health_bp,
        url_prefix="/api",
    )

    app.register_blueprint(
        auth_bp,
        url_prefix="/api/auth",
    )

    app.register_blueprint(
        verification_bp,
        url_prefix="/api/verification",
    )

    app.register_blueprint(
        admin_verification_bp,
        url_prefix="/api/admin/verification",
    )

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

    @app.errorhandler(RequestEntityTooLarge)
    def handle_large_upload(error):
        return jsonify({
            "error": (
                "Request is too large. "
                "Maximum document size is 5 MB."
            )
        }), 413

    return app
