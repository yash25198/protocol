// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.27;

import {MerkleProofLib} from "solady/utils/MerkleProofLib.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";

error InvalidLeavesCommitment();

/**
 * @title BitcoinLightClient
 * @notice A Bitcoin client implementation that maintains a Merkle Mountain Range (MMR)
 * of Bitcoin block headers for verification purposes
 *
 * Each block is stored as a leaf of the MMR containing:
 * - Block hash
 * - Block height
 * - Cumulative chainwork
 * Updates to the MMR root rely on a ZK proof that the new leaves satisfy the Bitcoin Consensus rules.
 */
contract BitcoinLightClient {
    bytes32 public mmrRoot;
    BlockLeaf public initialCheckpointLeaf;

    struct BlockLeaf {
        bytes32 blockHash;
        uint64 height;
        uint256 cumulativeChainwork;
    }

    event BlockTreeUpdated(bytes32 treeRoot);

    /**
     * @notice Initializes the light client with an MMR root and initial checkpoint
     * @param _mmrRoot The initial MMR root
     * @param _initialCheckpointLeaf The initial checkpoint block leaf
     */
    constructor(bytes32 _mmrRoot, BlockLeaf memory _initialCheckpointLeaf) {
        mmrRoot = _mmrRoot;
        initialCheckpointLeaf = _initialCheckpointLeaf;
    }

    /**
     * @notice Updates the MMR root. The caller must ensure:
     * - The new root is built from a previously known header and all new headers satisfy PoW rules
     * - All leaves being committed to the MMR are provably available (stored in calldata/blobspace)
     * @param priorMmrRoot The expected current MMR root
     * @param newMmrRoot The new MMR root to update to
     * @dev Updates the root only if:
     *      1. The prior root matches the current stored root
     *      2. The prior root is different from the new root
     */
    function updateRoot(bytes32 priorMmrRoot, bytes32 newMmrRoot) internal {
        if (priorMmrRoot != mmrRoot || priorMmrRoot == newMmrRoot) return;

        mmrRoot = newMmrRoot;
        emit BlockTreeUpdated(newMmrRoot);
    }

    /**
     * @notice Verifies a block is included in the current MMR tree
     * @param blockLeaf The block leaf to verify inclusion for
     * @param inclusionProof The MMR proof for inclusion. Contains sibling hashes that are:
     *        - Combined with the leaf until reaching a peak
     *        - Then combined with other peaks to form the bagged peaks
     *        - Finally combined with the leaf count to form the root
     * @return bool True if the block is included in the current tree
     */
    function proveBlockInclusion(
        BlockLeaf memory blockLeaf,
        bytes32[] calldata inclusionProof
    ) public view returns (bool) {
        return MerkleProofLib.verify(inclusionProof, mmrRoot, buildLeafCommitment(blockLeaf));
    }

    /**
     * @notice Builds a commitment leaf from a BlockLeaf struct
     * @param blockLeaf The block leaf to build a commitment for
     * @return bytes32 The commitment hash
     */
    function buildLeafCommitment(BlockLeaf memory blockLeaf) public pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                blockLeaf.blockHash,
                bytes32(uint256(blockLeaf.height)),
                bytes32(blockLeaf.cumulativeChainwork)
            );
    }
}
