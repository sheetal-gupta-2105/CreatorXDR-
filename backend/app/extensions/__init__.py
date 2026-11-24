from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from app.extensions.limiter import limiter

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()

__all__ = ["db", "migrate", "jwt", "limiter"]
