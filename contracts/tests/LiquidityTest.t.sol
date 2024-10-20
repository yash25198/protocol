// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {ExchangeTestBase} from "./ExchangeTestBase.t.sol";
import {RiftExchange} from "../src/RiftExchange.sol";

contract LiquidityDepositTest is ExchangeTestBase {
    function testLpReservationHash() public view {
        uint64[] memory expectedSatsOutputArray = new uint64[](1);
        bytes22 btcPayoutLockingScript = hex"0014841b80d2cc75f5345c482af96294d04fdd66b2b7";
        expectedSatsOutputArray[0] = 1230;

        bytes32 vaultHash;

        // [5] check if there is enough liquidity in each deposit vaults to reserve
        for (uint256 i = 0; i < expectedSatsOutputArray.length; i++) {
            console.log("hashable chunk");
            console.logBytes(abi.encode(expectedSatsOutputArray[i], btcPayoutLockingScript, vaultHash));
            // [0] retrieve deposit vault
            vaultHash = sha256(abi.encode(expectedSatsOutputArray[i], btcPayoutLockingScript, vaultHash));
        }

        console.log("Vault hash:");
        console.logBytes32(vaultHash);
    }

    // //--------- DEPOSIT TESTS ---------//
    function testDepositLiquidity() public {
        deal(address(usdt), testAddress, 1_000_000_000_000_000e6); // Mint USDT (6 decimals)
        vm.startPrank(testAddress);

        console.log("Starting deposit liquidity...");
        console.log("testaddress USDT balance: ", usdt.balanceOf(testAddress));

        bytes22 btcPayoutLockingScript = 0x0014841b80d2cc75f5345c482af96294d04fdd66b2b7;
        uint64 exchangeRate = 2557666;
        uint256 depositAmount = 1_000_000_000_000_000e6; // 1b USDT

        usdt.approve(address(riftExchange), depositAmount);

        uint256 gasBefore = gasleft();
        riftExchange.depositLiquidity(depositAmount, exchangeRate, btcPayoutLockingScript, testAddress);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("Gas used for deposit:", gasUsed);

        uint256 vaultIndex = riftExchange.getDepositVaultsLength() - 1;
        RiftExchange.DepositVault memory deposit = riftExchange.getDepositVault(vaultIndex);

        assertEq(deposit.vaultBalance, depositAmount, "Deposit amount mismatch");
        assertEq(deposit.exchangeRate, exchangeRate, "BTC exchange rate mismatch");
        assertEq(deposit.btcPayoutLockingScript, btcPayoutLockingScript, "BTC payout locking script mismatch");
        assertEq(deposit.paymentRecipient, testAddress, "Payment recipient mismatch");

        vm.stopPrank();
    }

    // // --------- RESERVATION TESTS ---------//
    function testSubmitSwapProof() public {
        // Setup
        uint256 totalAmount = 1_000_000_000e6; // 1 billion USDT
        deal(address(usdt), testAddress, totalAmount);
        vm.startPrank(testAddress);
        usdt.approve(address(riftExchange), totalAmount);
        bytes22 btcPayoutLockingScript = 0x0014841b80d2cc75f5345c482af96294d04fdd66b2b7;
        uint64 exchangeRate = 69;
        uint256 depositAmount = 500_000_000e6; // 500 million USDT

        // Deposit liquidity
        riftExchange.depositLiquidity(depositAmount, exchangeRate, btcPayoutLockingScript, testAddress);
        vm.stopPrank();

        // Setup for submitSwapProof
        uint256[] memory depositVaultIndexes = new uint256[](1);
        depositVaultIndexes[0] = 0;
        address paymentRecipient = address(0x123);
        uint256 totalSwapOutputAmount = 100_000_000e6; // 100 million USDT
        bytes32 bitcoinTxId = keccak256("exampleTxId");
        bytes32 merkleRoot = keccak256("exampleMerkleRoot");
        uint32 safeBlockHeight = 861295;
        uint64 proposedBlockHeight = 861296;
        uint64 confirmationBlockHeight = 861297;

        bytes32[] memory blockHashes = new bytes32[](3);
        uint256[] memory blockChainworks = new uint256[](3);
        for (uint i = 0; i < 3; i++) {
            blockHashes[i] = keccak256(abi.encodePacked("blockHash", i));
            blockChainworks[i] = (i + 100) + 44089395307995885530261766224;
        }
        blockHashes[0] = 0x000000000000000000029224f14319a515d7d9d907ecc89d6fb5f8826e45b3df;
        blockChainworks[0] = 44089395307995885530261766224;

        bytes memory proof = abi.encodePacked("exampleProof");

        // Switch to hypernode account
        vm.startPrank(hypernode1);

        // Call submitSwapProof
        uint256 gasBefore = gasleft();
        riftExchange.submitSwapProof(
            depositVaultIndexes,
            paymentRecipient,
            totalSwapOutputAmount,
            bitcoinTxId,
            merkleRoot,
            safeBlockHeight,
            proposedBlockHeight,
            confirmationBlockHeight,
            blockHashes,
            blockChainworks,
            proof
        );
        uint256 gasUsed = gasBefore - gasleft();
        console.log("Gas used for submitSwapProof:", gasUsed);

        // Verify the swap state
        (
            uint256 totalSwapOutputAmount1,
            bytes32 depositVaultCommitment,
            bytes32 proposedBlockHash,
            uint64 proposedBlockHeight1,
            uint64 liquidityUnlockedTimestamp,
            address paymentRecipient1,
            RiftExchange.SwapState state
        ) = riftExchange.swaps(riftExchange.getSwapLength() - 1);

        assertEq(uint8(state), uint8(RiftExchange.SwapState.Proved), "Swap state should be Proved");
        assertEq(proposedBlockHash, blockHashes[proposedBlockHeight - safeBlockHeight], "Proposed block hash mismatch");
        assertEq(
            liquidityUnlockedTimestamp,
            block.timestamp + riftExchange.challengePeriod(),
            "Liquidity unlock timestamp mismatch"
        );
        assertEq(paymentRecipient1, paymentRecipient, "Payment recipient mismatch");
        assertEq(totalSwapOutputAmount1, totalSwapOutputAmount, "Total swap output amount mismatch");

        // Verify that blocks were added to the block hash storage
        bytes32 storedBlockHash = riftExchange.getBlockHash(safeBlockHeight);
        assertEq(storedBlockHash, blockHashes[0], "Stored block hash mismatch");

        vm.stopPrank();
    }

    // //--------- WITHDRAW TESTS ---------//

    function testWithdrawLiquidity() public {
        // setup
        uint256 totalAmount = 5_000_000e6; // 5 million USDT
        deal(address(usdt), testAddress, totalAmount);
        vm.startPrank(testAddress);
        usdt.approve(address(riftExchange), totalAmount);

        // [0] initial deposit
        uint192 depositAmount = 5_000_000e6; // 5 million USDT
        bytes22 btcPayoutLockingScript = 0x0014841b80d2cc75f5345c482af96294d04fdd66b2b7;
        uint64 exchangeRate = 50;
        riftExchange.depositLiquidity(depositAmount, exchangeRate, btcPayoutLockingScript, testAddress);

        // Record initial balance
        uint256 initialBalance = usdt.balanceOf(testAddress);
        // wait 8 hours
        vm.warp(block.timestamp + 9 hours);

        // [1] withdraw liquidity
        riftExchange.withdrawLiquidity(0);

        // [2] check if the balance has decreased correctly
        RiftExchange.DepositVault memory depositAfterWithdrawal = riftExchange.getDepositVault(0);
        assertEq(depositAfterWithdrawal.vaultBalance, 0, "Vault balance should be 0 after full withdrawal");

        // [3] check if the funds reached the LP's address
        uint256 finalBalance = usdt.balanceOf(testAddress);
        assertEq(
            finalBalance,
            initialBalance + uint256(depositAmount),
            "LP's balance should increase by the withdrawn amount"
        );

        vm.stopPrank();
    }
}
