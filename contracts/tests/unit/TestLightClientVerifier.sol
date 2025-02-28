// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/src/Test.sol";
import {RiftTest} from "../utils/RiftTest.sol";

import {Types} from "../../src/libraries/Types.sol";
import {LightClientVerificationLib} from "../../src/libraries/LightClientVerificationLib.sol";

/**
 * @notice Harness contract that exposes LightClientVerificationLib as external functions
 *         so we can call them via normal external calls in our tests.
 */
contract LightClientVerificationLibHarness {
    function proveBlockInclusion(
        Types.BlockLeaf calldata blockLeaf,
        bytes32[] calldata siblings,
        bytes32[] calldata peaks,
        uint32 leafCount,
        bytes32 mmrRoot
    ) external pure returns (bool) {
        return LightClientVerificationLib.proveBlockInclusion(blockLeaf, siblings, peaks, leafCount, mmrRoot);
    }
}

contract LightClientVerifierUnitTest is RiftTest {
    LightClientVerificationLibHarness internal harness;

    function setUp() public override {
        super.setUp();
        harness = new LightClientVerificationLibHarness();
    }

    function testFuzz_blockLeafHasherImplementations(Types.BlockLeaf memory leaf, uint256) public {
        bytes32 hashedLeafFFI = _hashBlockLeafFFI(leaf);
        bytes32 hashedLeafSolidity = LightClientVerificationLib.buildLeafCommitment(leaf);
        assertEq(hashedLeafFFI, hashedLeafSolidity);
    }

    function testFuzz_verifyMMRProof(uint32 blockHeight, uint256) public {
        // Generate a MMR proof using the sdk
        blockHeight = uint32(bound(blockHeight, 0, 100)); // no benefit to making this huge, just slower
        Types.MMRProof memory proof = _generateFakeBlockMMRProofFFI(blockHeight);

        bool verified = harness.proveBlockInclusion(
            proof.blockLeaf,
            proof.siblings,
            proof.peaks,
            proof.leafCount,
            proof.mmrRoot
        );

        assertEq(verified, true, "proveBlockInclusion failed");
    }

    function test_validateScriptPubKey() public pure {
        // p2pkh
        bytes25 p2pkh = bytes25(hex"76a914fd5ec8ae0fd939ac925a8eccdc990fbbae9badcc88ac");
        // p2sh
        bytes25 p2sh = bytes25(hex"a9145d16d60c9bb88d9e7c8ee042c676ac978ceea77487");
        // p2wpkh
        bytes25 p2wpkh = bytes25(hex"00148bd9d208f3980a310156dc7a87883fead70d32e0");

        bool valid = LightClientVerificationLib.validateScriptPubKey(p2pkh);
        assertEq(valid, true, "validateScriptPubKey failed, p2pkh");

        valid = LightClientVerificationLib.validateScriptPubKey(p2sh);
        assertEq(valid, true, "validateScriptPubKey failed, p2sh");

        valid = LightClientVerificationLib.validateScriptPubKey(p2wpkh);
        assertEq(valid, true, "validateScriptPubKey failed, p2wpkh");
    }
}
