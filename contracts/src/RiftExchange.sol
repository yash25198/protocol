// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.27;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {UUPSUpgradeable} from "@openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/access/OwnableUpgradeable.sol";

import {BitcoinLightClientUpgradeable} from "./BitcoinLightClientUpgradeable.sol";

error LiquidityUnavailable();
error InvalidDepositVaultIndexes();
error ReservationNotExpired();
error SwapNotProved();
error StillInChallengePeriod();
error OverwrittenProposedBlock();
error NewDepositsPaused();
error NotApprovedHypernode();
error TransferFailed();
error InvalidFeeRouterAddress();
error DepositAmountIsZero();
error SatOutputTooLow();
error DepositVaultNotOverwritable();
error InvalidScriptPubKey();
error DepositVaultDoesNotExist();
error SwapDoesNotExist();
error EmptyDepositVault();
error DepositStillLocked();
error InvalidBlockInclusionProof();

/**
 * @title RiftExchange
 * @notice A decentralized exchange for cross-chain Bitcoin to ERC20 swaps
 * @dev Uses a Bitcoin light client and zero-knowledge proofs for verification
 */
contract RiftExchange is BitcoinLightClientUpgradeable, OwnableUpgradeable, UUPSUpgradeable {
    // --------- TYPES --------- //
    enum SwapState {
        None,
        Proved,
        Completed
    }

    struct DepositVault {
        uint256 vaultIndex; // 0 is sentinel, otherwise naturally ordered
        uint64 depositTimestamp;
        uint256 depositAmount; // smallest ERC20 unit (non-buffered)
        uint64 expectedSats; // BTC output amount in satoshis
        bytes22 btcPayoutScriptPubKey; // p2wpkh only
        address specifiedPayoutAddress;
        address ownerAddress;
        bytes32 salt; // sha256(blockhash[0],vaultIndex,chainId)
    }

    struct ProposedSwap {
        bytes32 aggregateVaultCommitment;
        BlockLeaf proposedBlockLeaf;
        uint64 liquidityUnlockTimestamp;
        address specifiedPayoutAddress;
        SwapState state;
    }

    struct ProofPublicInputs {
        bytes32 naturalTxid;
        bytes32 merkleRoot;
        bytes32 aggregateVaultHash;
        uint64 depositVaultCount;
        bytes32 retargetBlockHash;
        uint64 safeBlockHeight;
        uint64 safeBlockHeightDelta;
        uint64 confirmationBlockHeightDelta;
        bytes32[] blockHashes;
        uint256[] blockChainworks;
        address paymentRecipient;
        uint256 totalSwapOutputAmount;
        bool isTransactionProof;
    }

    // --------- CONSTANTS --------- //
    uint16 public constant depositLockupPeriod = 8 hours;
    uint16 public constant minOutputSats = 1000; // to prevent dust errors
    // TODO: Challenge period should scale with the number of blocks in the proof.
    // Set it to 2x the estimated proof generation time for n blocks.
    uint32 public constant challengePeriod = 5 minutes;
    uint32 public constant minProtocolFee = 100_000; // 10 cents USDC
    uint8 public constant protocolFeeBP = 10; // maker + taker fee = 0.1%
    // Since upgradeable contracts cannot use immutable state variables,
    // we use constants instead to reduce gas costs (no SLOADs).
    // Note: This approach makes deployments more complex.
    /// @dev FOR BASE MAINNET DEPLOYMENT:
    IERC20 public constant depositToken = IERC20(0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913);
    uint8 public constant tokenDecimals = 6;
    bytes32 public constant circuitVerificationKey = 0x00334569e4b8059d7b1a70c011d7d92b5d3ce28f2148b32cd2396aeda3ae5af1;
    ISP1Verifier public constant verifierContract = ISP1Verifier(0x3B6041173B80E77f038f3F2C0f9744f04837185e);
    address public constant feeRouterAddress = 0xfEe8d79961c529E06233fbF64F96454c2656BFEE;
    bool public constant isDepositNewLiquidityPaused = false;

    // --------- STATE --------- //

    bytes32[] public vaultCommitments;
    bytes32[] public swapCommitments;

    // --------- EVENTS --------- //

    event VaultUpdated(DepositVault vault);
    event SwapUpdated(ProposedSwap swap);

    // --------- MODIFIERS --------- //
    modifier newDepositsNotPaused() {
        if (isDepositNewLiquidityPaused) {
            revert NewDepositsPaused();
        }
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    //--------- CONSTRUCTOR ---------//
    function initialize(
        bytes32 _mmrRoot,
        BlockLeaf calldata _initialCheckpointLeaf,
        address initialOwner
    ) public initializer {
        __UUPSUpgradeable_init();
        __Ownable_init(initialOwner);
        __BitcoinLightClientUpgradeable_init(_mmrRoot, _initialCheckpointLeaf);
    }

    //--------- WRITE FUNCTIONS ---------//
    /// @notice Deposits new liquidity into a new vault
    /// @param specifiedPayoutAddress Address to receive swap proceeds
    /// @param depositAmount Amount of ERC20 tokens to deposit
    /// @param expectedSats Expected BTC output in satoshis
    /// @param btcPayoutScriptPubKey Bitcoin script for receiving BTC
    function depositLiquidity(
        address specifiedPayoutAddress,
        uint256 depositAmount,
        uint256 expectedSats,
        bytes22 btcPayoutScriptPubKey
    ) external {
        // [0] create deposit liquidity request
        (DepositVault memory vault, bytes32 depositHash) = prepareDeposit(
            specifiedPayoutAddress,
            depositAmount,
            expectedSats,
            btcPayoutScriptPubKey,
            vaultCommitments.length
        );

        // [1] add deposit hash to vault commitments
        vaultCommitments.push(depositHash);

        // [2] finalize deposit
        finalizeDeposit(vault, depositHash);
    }

    /// @notice Deposits new liquidity by overwriting an existing empty vault
    /// @param specifiedPayoutAddress Address to receive swap proceeds
    /// @param depositAmount Amount of ERC20 tokens to deposit
    /// @param expectedSats Expected BTC output in satoshis
    /// @param btcPayoutScriptPubKey Bitcoin script for receiving BTC
    /// @param overwriteVault Existing empty vault to overwrite
    function depositLiquidityWithOverwrite(
        address specifiedPayoutAddress,
        uint256 depositAmount,
        uint256 expectedSats,
        bytes22 btcPayoutScriptPubKey,
        DepositVault calldata overwriteVault
    ) external {
        // [0] create deposit liquidity request
        (DepositVault memory vault, bytes32 depositHash) = prepareDeposit(
            specifiedPayoutAddress,
            depositAmount,
            expectedSats,
            btcPayoutScriptPubKey,
            overwriteVault.vaultIndex
        );

        // [1] ensure passed vault is real and overwritable
        validateDepositVaultCommitment(overwriteVault);
        if (overwriteVault.depositAmount != 0) revert DepositVaultNotOverwritable();

        // [2] overwrite deposit vault
        vaultCommitments[overwriteVault.vaultIndex] = depositHash;

        // [3] finalize deposit
        finalizeDeposit(vault, depositHash);
    }

    /// @notice Checks invariants and creates new deposit vault struct
    /// @dev Validates deposit amounts and creates vault structure
    /// @return Tuple of the new vault and its commitment hash
    function prepareDeposit(
        address specifiedPayoutAddress,
        uint256 depositAmount,
        uint256 expectedSats,
        bytes22 btcPayoutScriptPubKey,
        uint256 depositVaultIndex
    ) internal returns (DepositVault memory, bytes32) {
        // [0] ensure deposit amount is greater than min protocol fee
        if (depositAmount < minProtocolFee) revert DepositAmountIsZero();

        // [1] ensure expected sat output is above minimum to prevent dust errors
        if (expectedSats < minOutputSats) revert SatOutputTooLow();

        // [2] ensure scriptPubKey is valid
        if (!validateP2WPKHScriptPubKey(btcPayoutScriptPubKey)) revert InvalidScriptPubKey();

        DepositVault memory vault = DepositVault({
            vaultIndex: depositVaultIndex,
            depositTimestamp: uint64(block.timestamp),
            depositAmount: depositAmount,
            expectedSats: expectedSats,
            btcPayoutScriptPubKey: btcPayoutScriptPubKey,
            specifiedPayoutAddress: specifiedPayoutAddress,
            ownerAddress: msg.sender,
            salt: keccak256(abi.encode(blockhash(block.number - 1), depositVaultIndex, block.chainid))
        });
        return (vault, hashDepositVault(vault));
    }

    /// @notice Completes deposit by emitting event and transferring tokens
    function finalizeDeposit(DepositVault memory vault, bytes32 depositHash) internal {
        emit VaultUpdated(vault);
        if (!depositToken.transferFrom(msg.sender, address(this), vault.depositAmount)) revert TransferFailed();
    }

    /// @notice Withdraws liquidity from a deposit vault after the lockup period
    /// @param vault The deposit vault to withdraw from
    /// @dev Reverts if vault doesn't exist, is empty, or still in lockup period
    function withdrawLiquidity(DepositVault calldata vault) external {
        // [0] validate deposit vault exists
        validateDepositVaultCommitment(vault);

        // [1] ensure deposit amount is non-zero
        if (vault.depositAmount == 0) revert EmptyDepositVault();

        // [2] ensure the deposit vault is not time locked
        if (block.timestamp < vault.depositTimestamp + depositLockupPeriod) revert DepositStillLocked();

        // [3] update deposit vault commitment
        DepositVault memory updatedVault = vault;
        updatedVault.depositAmount = 0;
        bytes32 updatedVaultHash = hashDepositVault(updatedVault);
        vaultCommitments[vault.vaultIndex] = updatedVaultHash;

        // [4] transfer funds to vault owner
        emit VaultUpdated(updatedVault);
        if (!depositToken.transfer(vault.ownerAddress, vault.depositAmount)) {
            revert TransferFailed();
        }
    }

    function submitSwapProof(
        bytes32 proposedBlockHash,
        uint64 proposedBlockHeight,
        address specifiedPayoutAddress,
        DepositVault[] calldata vaults,
        bytes calldata proof,
        ProposedSwap calldata overwriteSwap,
        bytes32 priorMmrRoot,
        bytes32 newMmrRoot,
        bytes calldata encodedBlockLeaves
    ) external {
        if (overwriteSwap.state != SwapState.Completed) revert();

        // [2] craft public inputs
        bytes memory publicInputs = abi.encode(
            buildPublicInputs(
                depositVaultIndexes,
                bitcoinTxId,
                merkleRoot,
                safeBlockHeight,
                proposedBlockHeight,
                confirmationBlockHeight,
                blockHashes,
                blockChainworks,
                paymentRecipient,
                totalSwapOutputAmount,
                true
            )
        );

        // [3] verify proof (will revert if invalid)
        verifierContract.verifyProof(circuitVerificationKey, publicInputs, proof);

        // [4] add verified block to block hash storage contract
        (safeBlockHeight, proposedBlockHeight, confirmationBlockHeight, blockHashes, blockChainworks); // TODO: audit

        // [5] create swap reservation
        bytes32 depositVaultCommitment = keccak256(abi.encode(depositVaultIndexes));

        proposedSwaps.push(
            ProposedSwap({
                depositVaultCommitment: depositVaultCommitment,
                liquidityUnlockTimestamp: uint64(block.timestamp) + challengePeriod,
                proposedBlockHeight: proposedBlockHeight,
                proposedBlockHash: blockHashes[proposedBlockHeight - safeBlockHeight],
                state: SwapState.Proved,
                paymentRecipient: paymentRecipient,
                totalSwapOutputAmount: totalSwapOutputAmount
            })
        );

        emit ProofSubmitted(msg.sender, proposedSwaps.length, bitcoinTxId);
    }

    function buildBlockProofPublicInputs(
        uint32 safeBlockHeight,
        uint64 confirmationBlockHeight,
        bytes32[] memory blockHashes,
        uint256[] memory blockChainworks
    ) public view returns (ProofPublicInputs memory) {
        // TODO: Annotate this
        uint64 proposedBlockHeight = confirmationBlockHeight - 1;
        return
            ProofPublicInputs({
                naturalTxid: bytes32(0),
                merkleRoot: bytes32(0),
                aggregateVaultHash: bytes32(0),
                depositVaultCount: 0,
                safeBlockHeight: safeBlockHeight,
                safeBlockHeightDelta: proposedBlockHeight - safeBlockHeight,
                confirmationBlockHeightDelta: confirmationBlockHeight - proposedBlockHeight,
                blockHashes: blockHashes,
                blockChainworks: blockChainworks,
                paymentRecipient: address(0),
                totalSwapOutputAmount: 0,
                isTransactionProof: false
            });
    }

    function buildPublicInputs(
        uint256[] memory depositVaultIndexes,
        bytes32 bitcoinTxId,
        bytes32 merkleRoot,
        uint32 safeBlockHeight,
        uint64 proposedBlockHeight,
        uint64 confirmationBlockHeight,
        bytes32[] memory blockHashes,
        uint256[] memory blockChainworks,
        address paymentRecipient,
        uint256 totalSwapOutputAmount,
        bool isTransactionProof
    ) public view returns (ProofPublicInputs memory) {
        bytes32 aggregateVaultHash = bytes32(0);
        for (uint256 i = 0; i < depositVaultIndexes.length; i++) {
            aggregateVaultHash = keccak256(
                abi.encode(aggregateVaultHash, depositVaults[depositVaultIndexes[i]].depositHash)
            );
        }
        return
            ProofPublicInputs({
                naturalTxid: bitcoinTxId,
                merkleRoot: merkleRoot,
                aggregateVaultHash: aggregateVaultHash,
                depositVaultCount: uint64(depositVaultIndexes.length),
                retargetBlockHash: getBlockHash(calculateRetargetHeight(safeBlockHeight)),
                safeBlockHeight: safeBlockHeight,
                safeBlockHeightDelta: proposedBlockHeight - safeBlockHeight,
                confirmationBlockHeightDelta: confirmationBlockHeight - proposedBlockHeight,
                blockHashes: blockHashes,
                blockChainworks: blockChainworks,
                paymentRecipient: paymentRecipient,
                totalSwapOutputAmount: totalSwapOutputAmount,
                isTransactionProof: isTransactionProof
            });
    }

    function releaseLiquidity(ProposedSwap calldata swap, bytes32[] calldata bitcoinBlockInclusionProof) external {
        // [0] validate swap exists
        validateSwapCommitment(swap);

        // [1] validate swap has been proved
        if (swap.state != SwapState.Proved) {
            revert SwapNotProved();
        }

        // [2] ensure challenge period has passed since proof submission
        if (block.timestamp < swap.liquidityUnlockTimestamp) {
            revert StillInChallengePeriod();
        }

        // [3] ensure swap block is still part of longest chain
        if (!proveBlockInclusion(swap.proposedBlockLeaf, bitcoinBlockInclusionProof))
            revert InvalidBlockInclusionProof();

        // [6] update completed swap hash
        ProposedSwap memory updatedSwap = swap;
        updatedSwap.state = SwapState.Completed;
        bytes32 updatedSwapHash = hashSwap(updatedSwap);
        swapCommitments[swap.swapIndex] = updatedSwapHash;

        // [7] release protocol fee
        uint256 protocolFee = (swap.totalSwapOutputAmount * protocolFeeBP) / bpScale;
        if (protocolFee < minProtocolFee) {
            protocolFee = minProtocolFee;
        }

        emit SwapUpdated(updatedSwap);

        if (!depositToken.transfer(feeRouterAddress, protocolFee)) {
            revert TransferFailed();
        }

        // [8] release funds to buyers ETH payout address
        if (!depositToken.transfer(swap.paymentRecipient, swap.totalSwapOutputAmount - protocolFee)) {
            revert TransferFailed();
        }
    }

    //--------- READ FUNCTIONS ---------//

    function getVaultCommitmentsLength() public view returns (uint256) {
        return vaultCommitments.length;
    }

    function getSwapCommitmentsLength() public view returns (uint256) {
        return swapCommitments.length;
    }

    function getVaultCommitment(uint256 vaultIndex) public view returns (bytes32) {
        return vaultCommitments[vaultIndex];
    }

    function getSwapCommitment(uint256 swapIndex) public view returns (bytes32) {
        return swapCommitments[swapIndex];
    }

    //--------- INTERNAL FUNCTIONS ---------//

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function hashDepositVault(DepositVault calldata vault) internal pure returns (bytes32) {
        return keccak256(abi.encode(vault));
    }

    function hashSwap(ProposedSwap calldata swap) internal pure returns (bytes32) {
        return keccak256(abi.encode(swap));
    }

    /// @notice Validates that a scriptPubKey follows the P2WPKH format (OP_0(0x00) + OP_PUSHBYTES_20(0x14) + <20-byte-pubkey-hash>)
    function validateP2WPKHScriptPubKey(bytes22 scriptPubKey) internal view returns (bool) {
        return scriptPubKey[0] == 0x00 && scriptPubKey[1] == 0x14;
    }

    function validateDepositVaultCommitment(DepositVault calldata vault) internal view returns (bytes32) {
        bytes32 vaultHash = hashDepositVault(vault);
        if (vaultHash != vaultCommitments[vault.vaultIndex]) {
            revert DepositVaultDoesNotExist();
        }
        return vaultHash;
    }

    function validateSwapCommitment(ProposedSwap calldata swap) internal view returns (bytes32) {
        bytes32 swapHash = hashSwap(swap);
        if (swapHash != swapCommitments[swap.swapIndex]) {
            revert SwapDoesNotExist();
        }
        return swapHash;
    }
}
