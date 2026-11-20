
from app.routes.health import health_bp
from app.routes.auth import auth_bp
from app.routes.verification import verification_bp
from app.routes.admin_verification import admin_verification_bp

__all__ = [
    "health_bp",
    "auth_bp",
    "verification_bp",
    "admin_verification_bp",
]
