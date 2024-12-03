// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.27;

library Constants {
    uint16 public constant DEPOSIT_LOCKUP_PERIOD = 8 hours;
    uint16 public constant MIN_OUTPUT_SATS = 1000; // to prevent dust errors
    // TODO: Challenge period should scale with the number of blocks in the proof.
    // Set it to 2x the estimated proof generation time for n blocks.
    uint32 public constant CHALLENGE_PERIOD = 5 minutes;
    uint32 public constant MIN_PROTOCOL_FEE = 100_000; // 10 cents USDC
    uint32 public constant MIN_DEPOSIT_AMOUNT = MIN_PROTOCOL_FEE + 1;
    uint8 public constant PROTOCOL_FEE_BP = 10; // maker + taker fee = 0.1%
    uint8 public constant MIN_CONFIRMATION_BLOCKS = 2;
}
