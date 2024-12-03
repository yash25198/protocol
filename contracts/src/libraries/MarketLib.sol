// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.27;
import {Constants} from "./Constants.sol";

library MarketLib {
    /// @notice Calculates protocol fee for a given deposit amount
    /// @param amount The amount being deposited/swapped
    /// @return protocolFee The calculated protocol fee, either 0.1% or MIN_PROTOCOL_FEE, whichever is larger
    function calculateFeeFromAmount(uint256 amount) internal pure returns (uint256 protocolFee) {
        // [0] return $0.1 or 0.1% of swap value, whatever is larger
        protocolFee = (amount * Constants.PROTOCOL_FEE_BP) / 10e3; // bpScale value
        if (protocolFee < Constants.MIN_PROTOCOL_FEE) protocolFee = Constants.MIN_PROTOCOL_FEE;
    }
}
