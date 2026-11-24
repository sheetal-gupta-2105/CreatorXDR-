
from datetime import datetime, timezone

from web3 import Web3

from app.extensions import db
from app.models import MerkleBatch
from app.blockchain.ethereum import get_ethereum_client
from app.blockchain.batch_service import verify_merkle_batch


class AnchorServiceError(Exception):
    """Raised when a Merkle batch cannot be anchored."""


class AnchorTransactionFailed(AnchorServiceError):
    """Raised when Ethereum confirms a failed transaction."""


def _get_anchor_event(client, root_bytes):
    """
    Find the RootAnchored event for a root.

    Used for reconciliation when Ethereum already contains the root
    but PostgreSQL has not yet recorded the transaction.
    """
    event = client.contract.events.RootAnchored

    logs = event.get_logs(
        from_block=0,
        to_block="latest",
        argument_filters={"merkleRoot": root_bytes},
    )

    if not logs:
        raise AnchorServiceError(
            "Root exists on-chain, but its RootAnchored event was not found."
        )

    return max(logs, key=lambda log: log["blockNumber"])


def _save_anchor_details(batch, client, event_log):
    """Persist confirmed blockchain details to PostgreSQL."""
    block_number = event_log["blockNumber"]
    block = client.w3.eth.get_block(block_number)

    batch.status = "ANCHORED"
    batch.chain_id = client.chain_id
    batch.contract_address = client.contract_address
    batch.transaction_hash = Web3.to_hex(event_log["transactionHash"])
    batch.block_number = block_number
    batch.anchored_at = datetime.fromtimestamp(
        block["timestamp"],
        tz=timezone.utc,
    )

    db.session.commit()


def anchor_merkle_batch(batch_id: str, wait_timeout: int = 120):
    """
    Anchor a verified Merkle batch on Ethereum.

    Workflow:
    1. Lock and load the batch.
    2. Validate its status and Merkle integrity.
    3. Check whether the root is already anchored.
    4. Submit the transaction if necessary.
    5. Wait for its receipt.
    6. Persist blockchain details only after confirmation.

    Transient errors leave the batch PENDING_ANCHOR so it can be retried.
    """

    if not isinstance(batch_id, str) or not batch_id.strip():
        raise ValueError("A valid batch_id is required.")

    if (
        isinstance(wait_timeout, bool)
        or not isinstance(wait_timeout, int)
        or wait_timeout <= 0
    ):
        raise ValueError("wait_timeout must be a positive integer.")

    try:
        # Lock the batch row to reduce concurrent submissions.
        batch = (
            MerkleBatch.query
            .filter_by(id=batch_id)
            .with_for_update()
            .first()
        )

        if batch is None:
            raise AnchorServiceError(
                f"Merkle batch not found: {batch_id}"
            )

        if batch.status == "ANCHORED":
            return {
                "success": True,
                "message": "Batch is already recorded as anchored.",
                "batch": batch.to_dict(),
            }

        if batch.status != "PENDING_ANCHOR":
            raise AnchorServiceError(
                f"Batch cannot be anchored from status: {batch.status}"
            )

        # Verify the complete batch before interacting with Ethereum.
        if not verify_merkle_batch(batch_id):
            raise AnchorServiceError(
                "Merkle batch integrity verification failed."
            )

        # Validate the root format.
        try:
            root_bytes = bytes.fromhex(batch.merkle_root)
        except (TypeError, ValueError) as exc:
            raise AnchorServiceError(
                "Merkle root is not valid hexadecimal."
            ) from exc

        if len(root_bytes) != 32:
            raise AnchorServiceError(
                "Merkle root must contain exactly 32 bytes."
            )

        if root_bytes == bytes(32):
            raise AnchorServiceError(
                "Cannot anchor a zero Merkle root."
            )

        client = get_ethereum_client()

        # Check for a previous successful transaction.
        already_anchored = client.contract.functions.isAnchored(
            root_bytes
        ).call()

        if already_anchored:
            # Reconcile PostgreSQL with the existing on-chain record.
            event_log = _get_anchor_event(client, root_bytes)

            _save_anchor_details(batch, client, event_log)

            return {
                "success": True,
                "message": "Existing on-chain anchor reconciled with database.",
                "batch": batch.to_dict(),
            }

        # Prepare the transaction.
        nonce = client.w3.eth.get_transaction_count(
            client.account.address,
            "pending",
        )

        transaction = client.contract.functions.anchorRoot(
            root_bytes
        ).build_transaction({
            "from": client.account.address,
            "nonce": nonce,
            "chainId": client.chain_id,
            "gasPrice": client.w3.eth.gas_price,
            "gas": 150000,
        })

        # Sign locally. The private key is never sent to the RPC provider.
        signed_transaction = client.account.sign_transaction(
            transaction
        )

        tx_hash = client.w3.eth.send_raw_transaction(
            signed_transaction.raw_transaction
        )

        # Wait for the Ethereum transaction receipt.
        receipt = client.w3.eth.wait_for_transaction_receipt(
            tx_hash,
            timeout=wait_timeout,
        )

        # A mined transaction can still have failed.
        if receipt["status"] != 1:
            batch.status = "FAILED"
            db.session.commit()

            raise AnchorTransactionFailed(
                f"Ethereum transaction failed: {Web3.to_hex(tx_hash)}"
            )

        # Retrieve the event emitted by this confirmed transaction.
        event_logs = client.contract.events.RootAnchored().process_receipt(
            receipt
        )

        matching_logs = [
            log for log in event_logs
            if log["args"]["merkleRoot"] == root_bytes
        ]

        if not matching_logs:
            # Leave status pending. A later retry can reconcile via chain logs.
            raise AnchorServiceError(
                "Transaction succeeded, but RootAnchored event was not found."
            )

        _save_anchor_details(
            batch,
            client,
            matching_logs[0],
        )

        return {
            "success": True,
            "message": "Merkle root successfully anchored on Ethereum.",
            "transaction_hash": Web3.to_hex(tx_hash),
            "block_number": receipt["blockNumber"],
            "batch": batch.to_dict(),
        }

    except Exception:
        # Do not overwrite a previously committed status.
        # If Ethereum succeeded but the DB commit failed, the next attempt
        # can detect the on-chain root and reconcile it.
        db.session.rollback()
        raise
