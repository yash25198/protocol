// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.0;

import {ERC20} from "solmate/tokens/ERC20.sol";

// Mock USDC contract
contract MockUSDC is ERC20 {
    constructor() ERC20("Tether USD", "USDC", 6) {}

    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}
