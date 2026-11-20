
import hashlib
from typing import List, Tuple


def hash_pair(left: str, right: str) -> str:
    """Hash two hexadecimal SHA-256 hashes together."""
    combined = bytes.fromhex(left) + bytes.fromhex(right)
    return hashlib.sha256(combined).hexdigest()


def build_merkle_tree(event_hashes: List[str]) -> Tuple[str, List[List[str]]]:
    """
    Build a Merkle tree from event hashes.

    If a level has an odd number of nodes, duplicate the last node.
    Returns the Merkle root and all tree levels.
    """
    if not event_hashes:
        raise ValueError("Cannot build a Merkle tree without event hashes")

    for event_hash in event_hashes:
        if len(event_hash) != 64:
            raise ValueError("Every event hash must be a SHA-256 hash")

        try:
            bytes.fromhex(event_hash)
        except ValueError as exc:
            raise ValueError("Event hashes must be valid hexadecimal strings") from exc

    current_level = [h.lower() for h in event_hashes]
    levels = [current_level]

    while len(current_level) > 1:
        next_level = []

        for index in range(0, len(current_level), 2):
            left = current_level[index]

            if index + 1 < len(current_level):
                right = current_level[index + 1]
            else:
                right = left

            next_level.append(hash_pair(left, right))

        levels.append(next_level)
        current_level = next_level

    return current_level[0], levels


def verify_merkle_root(event_hashes: List[str], expected_root: str) -> bool:
    """Verify that event hashes produce the expected Merkle root."""
    if not isinstance(expected_root, str) or len(expected_root) != 64:
        return False

    try:
        actual_root, _ = build_merkle_tree(event_hashes)
    except (ValueError, TypeError):
        return False

    return actual_root == expected_root.lower()
