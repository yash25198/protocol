// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.27;

import {Types} from "./Types.sol";
import {Constants} from "./Constants.sol";
import {Errors} from "./Errors.sol";

import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";

library CommitmentVerificationLib {
    function hashDepositVault(Types.DepositVault memory vault) internal pure returns (bytes32) {
        return EfficientHashLib.hash(abi.encode(vault));
    }

    function hashSwap(Types.ProposedSwap memory swap) internal pure returns (bytes32) {
        return EfficientHashLib.hash(abi.encode(swap));
    }

    /// @notice Validates that a scriptPubKey follows the P2WPKH format (OP_0(0x00) + OP_PUSHBYTES_20(0x14) + <20-byte-pubkey-hash>)
    function validateP2WPKHScriptPubKey(bytes22 scriptPubKey) internal pure returns (bool) {
        return scriptPubKey[0] == 0x00 && scriptPubKey[1] == 0x14;
    }

    function validateDepositVaultCommitment(
        Types.DepositVault calldata vault,
        bytes32[] storage vaultCommitments
    ) internal view returns (bytes32) {
        bytes32 vaultHash = hashDepositVault(vault);
        if (vaultHash != vaultCommitments[vault.vaultIndex]) {
            revert Errors.DepositVaultDoesNotExist();
        }
        return vaultHash;
    }

    function validateSwapCommitment(
        Types.ProposedSwap calldata swap,
        bytes32[] storage swapCommitments
    ) internal view returns (bytes32) {
        bytes32 swapHash = hashSwap(swap);
        if (swapHash != swapCommitments[swap.swapIndex]) {
            revert Errors.SwapDoesNotExist();
        }
        return swapHash;
    }

    function validateDepositVaultCommitments(
        Types.DepositVault[] calldata vaults,
        bytes32[] storage vaultCommitments
    ) internal view returns (bytes32) {
        bytes32[] memory vaultHashes = new bytes32[](vaults.length);
        for (uint256 i = 0; i < vaults.length; i++) {
            vaultHashes[i] = validateDepositVaultCommitment(vaults[i], vaultCommitments);
        }
        return EfficientHashLib.hash(vaultHashes);
    }
}
