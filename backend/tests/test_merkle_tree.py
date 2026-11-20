
import pytest

from app.blockchain.merkle_tree import (
    build_merkle_tree,
    verify_merkle_root,
)


HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64


def test_single_leaf_is_root():
    root, levels = build_merkle_tree([HASH_A])

    assert root == HASH_A
    assert len(levels) == 1


def test_two_leaves_create_one_root():
    root, levels = build_merkle_tree([HASH_A, HASH_B])

    assert len(root) == 64
    assert len(levels) == 2
    assert len(levels[1]) == 1


def test_odd_number_of_leaves():
    root, levels = build_merkle_tree([HASH_A, HASH_B, HASH_C])

    assert len(root) == 64
    assert len(levels[0]) == 3
    assert len(levels[1]) == 2
    assert len(levels[2]) == 1


def test_four_leaves_create_three_levels():
    root, levels = build_merkle_tree(
        [HASH_A, HASH_B, HASH_C, HASH_D]
    )

    assert len(levels) == 3
    assert len(levels[1]) == 2
    assert len(levels[2]) == 1


def test_merkle_root_verification():
    hashes = [HASH_A, HASH_B, HASH_C]
    root, _ = build_merkle_tree(hashes)

    assert verify_merkle_root(hashes, root)


def test_modified_hash_fails_verification():
    hashes = [HASH_A, HASH_B]
    root, _ = build_merkle_tree(hashes)

    modified = [HASH_A, HASH_C]

    assert not verify_merkle_root(modified, root)


def test_empty_tree_is_rejected():
    with pytest.raises(ValueError):
        build_merkle_tree([])


def test_invalid_hash_is_rejected():
    with pytest.raises(ValueError):
        build_merkle_tree(["invalid"])
