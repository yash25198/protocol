// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.27;
import {Types} from "./Types.sol";

library Events {
    event BlockTreeUpdated(bytes32 treeRoot);
    event VaultUpdated(Types.DepositVault vault);
    event SwapUpdated(Types.ProposedSwap swap);
}
