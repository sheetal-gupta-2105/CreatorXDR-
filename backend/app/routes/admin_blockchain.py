import logging

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.extensions import db
from app.models import User, MerkleBatch
from app.blockchain.ethereum import get_ethereum_client
from app.blockchain.anchor_service import (
    anchor_merkle_batch,
    AnchorServiceError,
)
from app.blockchain.batch_service import verify_merkle_batch


admin_blockchain_bp = Blueprint(
    "admin_blockchain",
    __name__,
)

logger = logging.getLogger(__name__)


def _get_admin():
    admin_id = get_jwt_identity()
    admin = db.session.get(User, admin_id)

    if (
        not admin
        or admin.account_status != "ACTIVE"
        or admin.role != "ADMIN"
        or not admin.email_verified
    ):
        return None

    return admin


def _admin_required():
    admin = _get_admin()

    if not admin:
        return jsonify({
            "error": "Administrator access is required."
        }), 403

    return None


@admin_blockchain_bp.get("/overview")
@jwt_required()
def blockchain_overview():
    denied = _admin_required()
    if denied:
        return denied

    counts = {
        "total": MerkleBatch.query.count(),
        "pending": MerkleBatch.query.filter_by(
            status="PENDING_ANCHOR"
        ).count(),
        "anchored": MerkleBatch.query.filter_by(
            status="ANCHORED"
        ).count(),
        "failed": MerkleBatch.query.filter_by(
            status="FAILED"
        ).count(),
    }

    try:
        client = get_ethereum_client()
        connection = client.get_connection_info()

        return jsonify({
            "success": True,
            "batches": counts,
            "blockchain": {
                "connected": connection["connected"],
                "chain_id": connection["chain_id"],
                "account_address": connection["account_address"],
                "contract_address": connection["contract_address"],
                "contract_version": connection["contract_version"],
                "total_anchored_roots": (
                    client.contract.functions.totalAnchoredRoots().call()
                ),
            },
        }), 200

    except Exception:
        logger.exception("Blockchain overview connection failed.")

        return jsonify({
            "success": False,
            "batches": counts,
            "blockchain": {
                "connected": False,
            },
            "error": "Unable to connect to the configured blockchain network.",
        }), 503


@admin_blockchain_bp.get("/batches")
@jwt_required()
def list_blockchain_batches():
    denied = _admin_required()
    if denied:
        return denied

    try:
        limit = int(request.args.get("limit", 25))
        offset = int(request.args.get("offset", 0))
    except (TypeError, ValueError):
        return jsonify({
            "error": "Limit and offset must be integers."
        }), 400

    if not 1 <= limit <= 100 or offset < 0:
        return jsonify({
            "error": "Limit must be 1-100 and offset cannot be negative."
        }), 400

    status = request.args.get("status", "").strip().upper()

    query = MerkleBatch.query

    if status:
        if status not in {
            "PENDING_ANCHOR",
            "ANCHORED",
            "FAILED",
        }:
            return jsonify({
                "error": "Invalid batch status."
            }), 400

        query = query.filter_by(status=status)

    total = query.count()

    batches = (
        query
        .order_by(
            MerkleBatch.created_at.desc(),
            MerkleBatch.id.desc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )

    return jsonify({
        "success": True,
        "total": total,
        "limit": limit,
        "offset": offset,
        "batches": [batch.to_dict() for batch in batches],
    }), 200


@admin_blockchain_bp.get("/batches/<batch_id>")
@jwt_required()
def get_blockchain_batch(batch_id):
    denied = _admin_required()
    if denied:
        return denied

    batch = db.session.get(MerkleBatch, batch_id)

    if not batch:
        return jsonify({
            "error": "Merkle batch not found."
        }), 404

    result = batch.to_dict()
    result["leaves"] = [
        leaf.to_dict()
        for leaf in batch.leaves
    ]

    return jsonify({
        "success": True,
        "batch": result,
    }), 200


@admin_blockchain_bp.post("/batches/<batch_id>/anchor")
@jwt_required()
def anchor_blockchain_batch(batch_id):
    denied = _admin_required()
    if denied:
        return denied

    try:
        result = anchor_merkle_batch(batch_id)

        return jsonify(result), 200

    except ValueError as exc:
        return jsonify({
            "success": False,
            "error": str(exc),
        }), 400

    except AnchorServiceError as exc:
        return jsonify({
            "success": False,
            "error": str(exc),
        }), 409

    except Exception:
        logger.exception(
            "Unexpected error while anchoring batch %s",
            batch_id,
        )

        return jsonify({
            "success": False,
            "error": "Blockchain anchoring failed. Check backend logs.",
        }), 502


@admin_blockchain_bp.get("/batches/<batch_id>/verify")
@jwt_required()
def verify_blockchain_batch(batch_id):
    denied = _admin_required()
    if denied:
        return denied

    batch = db.session.get(MerkleBatch, batch_id)

    if not batch:
        return jsonify({
            "error": "Merkle batch not found."
        }), 404

    database_valid = verify_merkle_batch(batch_id)

    result = {
        "success": True,
        "batch_id": batch.id,
        "merkle_root": batch.merkle_root,
        "database_integrity": {
            "verified": database_valid,
        },
        "on_chain": {
            "checked": False,
            "anchored": False,
        },
    }

    if not database_valid:
        return jsonify(result), 200

    try:
        client = get_ethereum_client()
        root_bytes = bytes.fromhex(batch.merkle_root)

        anchored = client.contract.functions.isAnchored(
            root_bytes
        ).call()

        result["on_chain"] = {
            "checked": True,
            "anchored": anchored,
            "chain_id": client.chain_id,
            "contract_address": client.contract_address,
        }

        if anchored:
            anchor = client.contract.functions.getAnchor(
                root_bytes
            ).call()

            result["on_chain"]["timestamp"] = anchor[0]
            result["on_chain"]["submitter"] = anchor[1]

        return jsonify(result), 200

    except Exception:
        logger.exception(
            "On-chain verification failed for batch %s",
            batch_id,
        )

        result["on_chain"]["error"] = (
            "Unable to verify the root against the blockchain."
        )

        return jsonify(result), 503
