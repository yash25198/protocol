// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.27;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {UUPSUpgradeable} from "@openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/access/OwnableUpgradeable.sol";

import {BlockHashStorageUpgradeable} from "./BlockHashStorageUpgradeable.sol";

error LiquidityUnavailable();
error InvalidDepositVaultIndexes();
error InvalidExchangeRate();
error ReservationNotExpired();
error SwapNotProved();
error StillInChallengePeriod();
error OverwrittenProposedBlock();
error NewDepositsPaused();
error NotApprovedHypernode();
error TransferFailed();
error InvalidFeeRouterAddress();

interface IERC20 {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    function transfer(address recipient, uint256 amount) external returns (bool);

    function balanceOf(address account) external view returns (uint256);

    function allowance(address owner, address spender) external view returns (uint256);

    function approve(address spender, uint256 amount) external returns (bool);

    function decimals() external view returns (uint8);
}

contract RiftExchange is BlockHashStorageUpgradeable, OwnableUpgradeable, UUPSUpgradeable {
    // --------- TYPES --------- //
    enum SwapState {
        None,
        Proved,
        Completed
    }

    struct LiquidityProvider {
        uint256[] depositVaultIndexes;
    }

    struct DepositVault {
        address owner;
        uint64 depositTimestamp;
        uint256 vaultBalance;
        // amount of token's smallest unit (buffered to 18 digits) per 1 sat
        uint64 exchangeRate;
        bytes22 btcPayoutLockingScript;
        address paymentRecipient;
        // Deposit data commitment and nonce: includes block hash to prevent precomputation
        bytes32 depositHash;
    }

    struct Swap {
        // hash of all indexes
        uint256 totalSwapOutputAmount;
        bytes32 depositVaultCommitment;
        bytes32 proposedBlockHash;
        uint64 proposedBlockHeight;
        uint64 liquidityUnlockedTimestamp;
        address paymentRecipient;
        SwapState state;
    }

    struct ProofPublicInputs {
        bytes32 natural_txid;
        bytes32 merkle_root;
        bytes32 aggregate_vault_hash;
        uint64 deposit_vault_count;
        bytes32 retarget_block_hash;
        uint64 safe_block_height;
        uint64 safe_block_height_delta;
        uint64 confirmation_block_height_delta;
        bytes32[] block_hashes;
        uint256[] block_chainworks;
        address payment_recipient;
        uint256 total_swap_output_amount;
        bool is_transaction_proof;
    }

    // --------- CONSTANTS --------- //
    uint256 public constant scale = 1e18;
    uint256 public constant bpScale = 10e3;
    uint32 public constant reservationLockupPeriod = 4 hours;
    uint32 public constant challengePeriod = 5 minutes;
    uint32 public constant minProtocolFee = 10e4;
    IERC20 public depositToken;
    uint8 public tokenDecimals;
    bytes32 public circuitVerificationKey;
    ISP1Verifier public verifierContract;

    // --------- STATE --------- //
    bool public isDepositNewLiquidityPaused;
    uint8 public protocolFeeBP;
    address feeRouterAddress;

    // TODO: depositVaults and swaps should be reusing old indexes instead of append-only
    DepositVault[] public depositVaults;
    Swap[] public swaps;
    mapping(address => LiquidityProvider) liquidityProviders;
    mapping(address => bool) public permissionedHypernodes;

    // --------- EVENTS --------- //
    event LiquidityDeposited(address indexed depositor, uint256 depositVaultIndex, uint256 amount, uint64 exchangeRate);
    event ProofSubmitted(address indexed prover, uint256 swapIndex, bytes32 bitcoinTxId);
    event ExchangeRateUpdated(uint256 indexed globalVaultIndex, uint64 newExchangeRate, uint256 unreservedBalance);
    event SwapComplete(uint256 swapIndex, uint256 totalSwapOutputAmount, uint256 protocolFee);
    event LiquidityWithdrawn(uint256 indexed globalVaultIndex, uint256 amountWithdrawn);
    event ProtocolFeeUpdated(uint8 newProtocolFeeBP);

    // --------- MODIFIERS --------- //
    modifier newDepositsNotPaused() {
        if (isDepositNewLiquidityPaused) {
            revert NewDepositsPaused();
        }
        _;
    }

    modifier onlyApprovedHypernode() {
        if (!permissionedHypernodes[msg.sender]) {
            revert NotApprovedHypernode();
        }
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    //--------- CONSTRUCTOR ---------//
    function initialize(
        uint256 initialCheckpointHeight,
        bytes32 initialBlockHash,
        bytes32 initialRetargetBlockHash,
        uint256 initialChainwork,
        address verifierContractAddress,
        address depositTokenAddress,
        address payable initialFeeRouterAddress,
        address initialOwner,
        bytes32 verificationKeyHash,
        address[] memory initialPermissionedHypernodes
    ) public initializer {
        __UUPSUpgradeable_init();
        __Ownable_init(initialOwner);
        __BlockHashStorageUpgradeable_init(
            initialCheckpointHeight,
            initialChainwork,
            initialBlockHash,
            initialRetargetBlockHash
        );

        // Initialize other state variables
        depositToken = IERC20(depositTokenAddress);
        tokenDecimals = IERC20(depositTokenAddress).decimals();
        circuitVerificationKey = verificationKeyHash;
        verifierContract = ISP1Verifier(verifierContractAddress);
        if (initialFeeRouterAddress == address(0)) {
            revert InvalidFeeRouterAddress();
        }
        feeRouterAddress = initialFeeRouterAddress;

        // Move initial assignments here
        isDepositNewLiquidityPaused = false;
        protocolFeeBP = 10; // 10 bps = 0.1%

        for (uint256 i = 0; i < initialPermissionedHypernodes.length; i++) {
            permissionedHypernodes[initialPermissionedHypernodes[i]] = true;
        }
    }

    //--------- WRITE FUNCTIONS ---------//
    function depositLiquidity(
        uint256 depositAmount,
        uint64 exchangeRate,
        bytes22 btcPayoutLockingScript,
        address paymentRecipient
    ) public newDepositsNotPaused {
        // [0] validate btc exchange rate
        if (exchangeRate == 0) {
            revert InvalidExchangeRate();
        }

        // [1] create new liquidity provider if it doesn't exist
        if (liquidityProviders[msg.sender].depositVaultIndexes.length == 0) {
            liquidityProviders[msg.sender] = LiquidityProvider({depositVaultIndexes: new uint256[](0)});
        }

        uint256 depositVaultIndex = depositVaults.length;

        // [2] calculate expected BTC output in satoshis based on the deposit amount and exchange rate
        uint256 bufferedAmountToReserve = bufferTo18Decimals(depositAmount, tokenDecimals);
        uint64 expectedSatsOutput = uint64(bufferedAmountToReserve / exchangeRate);

        // [3] create deposit hash to save on SLOADS, include prevrandao to prevent precomputation
        bytes32 depositHash = keccak256(
            abi.encode(
                expectedSatsOutput,
                depositAmount,
                btcPayoutLockingScript,
                depositVaultIndex,
                paymentRecipient,
                block.prevrandao
            )
        );

        // [4] create new deposit vault
        depositVaults.push(
            DepositVault({
                owner: msg.sender,
                depositTimestamp: uint64(block.timestamp),
                vaultBalance: depositAmount,
                exchangeRate: exchangeRate,
                btcPayoutLockingScript: btcPayoutLockingScript,
                paymentRecipient: paymentRecipient,
                depositHash: depositHash
            })
        );

        // [5] add deposit vault index to liquidity provider
        addDepositVaultIndexToLP(msg.sender, depositVaultIndex);

        emit LiquidityDeposited(msg.sender, depositVaultIndex, depositAmount, exchangeRate);

        // [6] transfer deposit token to contract
        if (!depositToken.transferFrom(msg.sender, address(this), depositAmount)) {
            revert TransferFailed();
        }
    }

    function withdrawLiquidity(
        uint256 globalVaultIndex // index of vault in depositVaults
    ) public {
        // [1] ensure enough time has passed since deposit
        if (block.timestamp < depositVaults[globalVaultIndex].depositTimestamp + reservationLockupPeriod) {
            revert ReservationNotExpired();
        }

        // [2] retrieve the vault
        DepositVault storage vault = depositVaults[globalVaultIndex];

        // [3] withdraw funds to vault owner
        uint256 amountToWithdraw = vault.vaultBalance;
        vault.vaultBalance = 0;

        emit LiquidityWithdrawn(globalVaultIndex, amountToWithdraw);

        if (!depositToken.transfer(vault.owner, amountToWithdraw)) {
            revert TransferFailed();
        }
    }

    function buildBlockProofPublicInputs(
        uint32 safeBlockHeight,
        uint64 confirmationBlockHeight,
        bytes32[] memory blockHashes,
        uint256[] memory blockChainworks
    ) public view returns (ProofPublicInputs memory) {
        uint64 proposedBlockHeight = confirmationBlockHeight - MINIMUM_CONFIRMATION_DELTA;
        return
            ProofPublicInputs({
                natural_txid: bytes32(0),
                merkle_root: bytes32(0),
                aggregate_vault_hash: bytes32(0),
                deposit_vault_count: 0,
                retarget_block_hash: getBlockHash(calculateRetargetHeight(safeBlockHeight)),
                safe_block_height: safeBlockHeight,
                safe_block_height_delta: proposedBlockHeight - safeBlockHeight,
                confirmation_block_height_delta: confirmationBlockHeight - proposedBlockHeight,
                block_hashes: blockHashes,
                block_chainworks: blockChainworks,
                payment_recipient: address(0),
                total_swap_output_amount: 0,
                is_transaction_proof: false
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
                natural_txid: bitcoinTxId,
                merkle_root: merkleRoot,
                aggregate_vault_hash: aggregateVaultHash,
                deposit_vault_count: uint64(depositVaultIndexes.length),
                retarget_block_hash: getBlockHash(calculateRetargetHeight(safeBlockHeight)),
                safe_block_height: safeBlockHeight,
                safe_block_height_delta: proposedBlockHeight - safeBlockHeight,
                confirmation_block_height_delta: confirmationBlockHeight - proposedBlockHeight,
                block_hashes: blockHashes,
                block_chainworks: blockChainworks,
                payment_recipient: paymentRecipient,
                total_swap_output_amount: totalSwapOutputAmount,
                is_transaction_proof: isTransactionProof
            });
    }

    function submitSwapProof(
        uint256[] memory depositVaultIndexes,
        address paymentRecipient,
        uint256 totalSwapOutputAmount,
        bytes32 bitcoinTxId,
        bytes32 merkleRoot,
        uint32 safeBlockHeight,
        uint64 proposedBlockHeight,
        uint64 confirmationBlockHeight,
        bytes32[] memory blockHashes,
        uint256[] memory blockChainworks,
        bytes memory proof
    ) public onlyApprovedHypernode {
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
        addBlock(safeBlockHeight, proposedBlockHeight, confirmationBlockHeight, blockHashes, blockChainworks); // TODO: audit

        // [5] create swap reservation
        bytes32 depositVaultCommitment = keccak256(abi.encode(depositVaultIndexes));

        swaps.push(
            Swap({
                depositVaultCommitment: depositVaultCommitment,
                liquidityUnlockedTimestamp: uint64(block.timestamp) + challengePeriod,
                proposedBlockHeight: proposedBlockHeight,
                proposedBlockHash: blockHashes[proposedBlockHeight - safeBlockHeight],
                state: SwapState.Proved,
                paymentRecipient: paymentRecipient,
                totalSwapOutputAmount: totalSwapOutputAmount
            })
        );

        emit ProofSubmitted(msg.sender, swaps.length, bitcoinTxId);
    }

    function releaseLiquidity(uint256 swapIndex, uint256[] memory depositVaultIndexes) public {
        // [0] retrieve swap order
        Swap storage swap = swaps[swapIndex];

        // [1] make sure the deposit vault indexes are valid by checking the commitment
        bytes32 depositVaultCommitment = keccak256(abi.encode(depositVaultIndexes));
        if (swap.depositVaultCommitment != depositVaultCommitment) {
            revert InvalidDepositVaultIndexes();
        }

        // [2] validate swap proof has been submitted
        if (swap.state != SwapState.Proved) {
            revert SwapNotProved();
        }

        // [3] ensure challenge period has passed since proof submission
        if (block.timestamp < swap.liquidityUnlockedTimestamp) {
            revert StillInChallengePeriod();
        }

        // [4] ensure swap block is still part of longest chain
        if (getBlockHash(swap.proposedBlockHeight) != swap.proposedBlockHash) {
            revert OverwrittenProposedBlock();
        }

        // [5] ensure each reserved deposit vault has not been reserved before, if it has not set it to zero
        for (uint256 i = 0; i < depositVaultIndexes.length; i++) {
            if (depositVaults[depositVaultIndexes[i]].vaultBalance == 0) {
                revert LiquidityUnavailable();
            }
            depositVaults[depositVaultIndexes[i]].vaultBalance = 0;
        }

        // [6] mark swap as completed
        swap.state = SwapState.Completed;

        // [7] release protocol fee
        uint256 protocolFee = (swap.totalSwapOutputAmount * protocolFeeBP) / bpScale;
        if (protocolFee < minProtocolFee) {
            protocolFee = minProtocolFee;
        }

        emit SwapComplete(swapIndex, swap.totalSwapOutputAmount, protocolFee);

        if (!depositToken.transfer(feeRouterAddress, protocolFee)) {
            revert TransferFailed();
        }

        // [8] release funds to buyers ETH payout address
        if (!depositToken.transfer(swap.paymentRecipient, swap.totalSwapOutputAmount - protocolFee)) {
            revert TransferFailed();
        }
    }

    function proveBlocks(
        uint32 safeBlockHeight,
        uint64 confirmationBlockHeight,
        bytes32[] memory blockHashes,
        uint256[] memory blockChainworks,
        bytes calldata proof
    ) external {
        // [0] craft public inputs
        bytes memory publicInputs = abi.encode(
            buildBlockProofPublicInputs(safeBlockHeight, confirmationBlockHeight, blockHashes, blockChainworks)
        );

        // [1] verify proof (will revert if invalid)
        verifierContract.verifyProof(circuitVerificationKey, publicInputs, proof);

        // [2] add verified blocks to block hash storage contract
        addBlock(
            safeBlockHeight,
            confirmationBlockHeight - MINIMUM_CONFIRMATION_DELTA,
            confirmationBlockHeight,
            blockHashes,
            blockChainworks
        );
    }

    // --------- ONLY OWNER --------- //
    function updateNewLiquidityDepositsPaused(bool newPauseState) external onlyOwner {
        isDepositNewLiquidityPaused = newPauseState;
    }

    function updateFeeRouter(address payable newProtocolAddress) public onlyOwner {
        if (newProtocolAddress == address(0)) {
            revert InvalidFeeRouterAddress();
        }
        feeRouterAddress = newProtocolAddress;
    }

    function updateProtocolFee(uint8 newProtocolFeeBP) public onlyOwner {
        protocolFeeBP = newProtocolFeeBP;
        emit ProtocolFeeUpdated(newProtocolFeeBP);
    }

    function addPermissionedHypernode(address hypernode) external onlyOwner {
        permissionedHypernodes[hypernode] = true;
    }

    function removePermissionedHypernode(address hypernode) external onlyOwner {
        permissionedHypernodes[hypernode] = false;
    }

    //--------- READ FUNCTIONS ---------//

    function getLiquidityProvider(address lpAddress) public view returns (LiquidityProvider memory) {
        return liquidityProviders[lpAddress];
    }

    function getDepositVaultsLength() public view returns (uint256) {
        return depositVaults.length;
    }

    function getSwapLength() public view returns (uint256) {
        return swaps.length;
    }

    function getAreDepositsPaused() public view returns (bool) {
        return isDepositNewLiquidityPaused;
    }

    function getDepositVault(uint256 depositIndex) public view returns (DepositVault memory) {
        return depositVaults[depositIndex];
    }

    //--------- INTERNAL FUNCTIONS ---------//

    function addDepositVaultIndexToLP(address lpAddress, uint256 vaultIndex) internal {
        liquidityProviders[lpAddress].depositVaultIndexes.push(vaultIndex);
    }

    function bufferTo18Decimals(uint256 amount, uint8 decimals) internal pure returns (uint256) {
        if (decimals < 18) {
            return amount * (10 ** (18 - decimals));
        }
        return amount;
    }

    function updateCircuitVerificationKey(bytes32 newVerificationKey) public onlyOwner {
        circuitVerificationKey = newVerificationKey;
    }

    function updateVerifierContract(address newVerifierContractAddress) public onlyOwner {
        verifierContract = ISP1Verifier(newVerifierContractAddress);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
