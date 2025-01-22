// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;
import {Types} from "./Types.sol";

library Events {
    event BlockTreeUpdated(bytes32 treeRoot, bytes compressedBlockLeaves);
    event VaultUpdated(Types.DepositVault vault, Types.VaultUpdateContext context);
    event SwapUpdated(Types.ProposedSwap swap, Types.SwapUpdateContext context);
}
