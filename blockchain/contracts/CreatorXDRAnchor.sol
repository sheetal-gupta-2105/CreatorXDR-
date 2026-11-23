
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CreatorXDRAnchor {
    // Contract version
    string public constant CONTRACT_VERSION = "1.0.0";

    // Ownership
    address public owner;
    address public pendingOwner;

    // Merkle root information
    struct Anchor {
        uint256 timestamp;
        address submitter;
    }

    // Merkle root => anchor details
    mapping(bytes32 => Anchor) private anchors;

    // Total successfully anchored roots
    uint256 public totalAnchoredRoots;

    // Events
    event RootAnchored(
        bytes32 indexed merkleRoot,
        uint256 timestamp,
        address indexed submitter
    );

    event OwnershipTransferStarted(
        address indexed currentOwner,
        address indexed pendingOwner
    );

    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );

    // Custom errors
    error Unauthorized();
    error InvalidMerkleRoot();
    error RootAlreadyAnchored();
    error InvalidOwner();
    error NotPendingOwner();

    // Constructor
    constructor() {
        owner = msg.sender;
    }

    // Restrict functions to the contract owner
    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert Unauthorized();
        }
        _;
    }

    // Register a Merkle root on Ethereum
    function anchorRoot(bytes32 merkleRoot)
        external
        onlyOwner
    {
        if (merkleRoot == bytes32(0)) {
            revert InvalidMerkleRoot();
        }

        if (anchors[merkleRoot].timestamp != 0) {
            revert RootAlreadyAnchored();
        }

        uint256 currentTimestamp = block.timestamp;

        anchors[merkleRoot] = Anchor({
            timestamp: currentTimestamp,
            submitter: msg.sender
        });

        totalAnchoredRoots++;

        emit RootAnchored(
            merkleRoot,
            currentTimestamp,
            msg.sender
        );
    }

    // Check whether a Merkle root has been anchored
    function isAnchored(bytes32 merkleRoot)
        external
        view
        returns (bool)
    {
        return anchors[merkleRoot].timestamp != 0;
    }

    // Retrieve anchor details
    function getAnchor(bytes32 merkleRoot)
        external
        view
        returns (
            uint256 timestamp,
            address submitter
        )
    {
        Anchor memory anchor = anchors[merkleRoot];

        return (
            anchor.timestamp,
            anchor.submitter
        );
    }

    // Initiate ownership transfer
    function transferOwnership(address newOwner)
        external
        onlyOwner
    {
        if (newOwner == address(0)) {
            revert InvalidOwner();
        }

        pendingOwner = newOwner;

        emit OwnershipTransferStarted(
            owner,
            newOwner
        );
    }

    // New owner must explicitly accept ownership
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) {
            revert NotPendingOwner();
        }

        address previousOwner = owner;

        owner = pendingOwner;
        pendingOwner = address(0);

        emit OwnershipTransferred(
            previousOwner,
            owner
        );
    }
}
