
from flask import Blueprint, jsonify
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.extensions import db

health_bp = Blueprint("health", __name__)


@health_bp.get("/health")
def health_check():
    try:
        db.session.execute(text("SELECT 1"))

        return jsonify({
            "status": "healthy",
            "service": "CreatorXDR API",
            "database": "connected",
        }), 200

    except SQLAlchemyError:
        db.session.rollback()

        return jsonify({
            "status": "unavailable",
            "service": "CreatorXDR API",
            "database": "disconnected",
        }), 503
