// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.27;

library Types {
    // --------- LIGHT CLIENT TYPES --------- //
    struct BlockLeaf {
        bytes32 blockHash;
        uint64 height;
        uint256 cumulativeChainwork;
    }

    // --------- EXCHANGE SETTLEMENT TYPES --------- //
    enum SwapState {
        None,
        Proved,
        Completed
    }

    struct DepositVault {
        uint256 vaultIndex;
        uint64 depositTimestamp;
        uint256 depositAmount;
        uint256 depositFee;
        uint64 expectedSats;
        bytes22 btcPayoutScriptPubKey;
        address specifiedPayoutAddress;
        address ownerAddress;
        bytes32 nonce;
    }

    struct ProposedSwap {
        uint256 swapIndex;
        bytes32 aggregateVaultCommitment;
        BlockLeaf proposedBlockLeaf;
        uint64 liquidityUnlockTimestamp;
        address specifiedPayoutAddress;
        uint256 totalSwapFee;
        uint256 totalSwapAmount;
        SwapState state;
    }

    struct SwapProofPublicInputs {
        bytes32 proposedBlockHash;
        bytes32 aggregateVaultCommitment;
        bytes32 previousMmrRoot;
        bytes32 newMmrRoot;
        bytes32 compressedLeavesCommitment;
        uint256 proposedBlockCumulativeChainwork;
        address specifiedPayoutAddress;
        uint64 proposedBlockHeight;
        uint64 confirmationBlocks;
        uint256 totalSwapFee;
        uint256 totalSwapAmount;
    }
}
