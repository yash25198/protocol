// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import "../src/MMRegistry.sol";

contract MMRegistryTest is Test {
    MMRegistry public registry;
    address public alice = address(0x1);
    address public bob = address(0x2);
    address public charlie = address(0x3);

    function setUp() public {
        registry = new MMRegistry();
    }

    function testAddMarketMaker() public {
        vm.prank(alice);
        registry.addMarketMaker("Alice's Server");

        (string memory server, address owner) = registry.mms(0);
        assertEq(server, "Alice's Server");
        assertEq(owner, alice);
        assertEq(registry.getMarketMakersCount(), 1);
    }

    function testCannotAddDuplicateMarketMaker() public {
        vm.startPrank(alice);
        registry.addMarketMaker("Alice's Server");
        vm.expectRevert(MarketMakerAlreadyRegistered.selector);
        registry.addMarketMaker("Alice's Second Server");
        vm.stopPrank();
    }

    function testCannotAddMarketMakerWithLongServerName() public {
        string memory longServerName = new string(253);
        vm.prank(alice);
        vm.expectRevert(ServerNameTooLong.selector);
        registry.addMarketMaker(longServerName);
    }

    function testDeleteMarketMaker() public {
        vm.prank(alice);
        registry.addMarketMaker("Alice's Server");

        vm.prank(alice);
        registry.deleteMarketMaker();

        assertEq(registry.getMarketMakersCount(), 0);
    }

    function testDeleteMarketMakerReorganizesArray() public {
        vm.prank(alice);
        registry.addMarketMaker("Alice's Server");

        vm.prank(bob);
        registry.addMarketMaker("Bob's Server");

        vm.prank(charlie);
        registry.addMarketMaker("Charlie's Server");

        vm.prank(alice);
        registry.deleteMarketMaker();

        assertEq(registry.getMarketMakersCount(), 2);
        (string memory server, address owner) = registry.mms(0);
        assertEq(server, "Charlie's Server");
        assertEq(owner, charlie);
    }

    function testCannotDeleteNonExistentMarketMaker() public {
        vm.prank(alice);
        vm.expectRevert(NotMarketMaker.selector);
        registry.deleteMarketMaker();
    }

    function testFetchMarketMakerSlice() public {
        vm.prank(alice);
        registry.addMarketMaker("Alice's Server");

        vm.prank(bob);
        registry.addMarketMaker("Bob's Server");

        vm.prank(charlie);
        registry.addMarketMaker("Charlie's Server");

        MMRegistry.MarketMaker[] memory slice = registry.fetchMarketMakerSlice(1, 3);
        assertEq(slice.length, 2);
        assertEq(slice[0].server, "Bob's Server");
        assertEq(slice[1].server, "Charlie's Server");
    }

    function testCannotFetchInvalidSlice() public {
        vm.prank(alice);
        registry.addMarketMaker("Alice's Server");

        vm.expectRevert(InvalidRange.selector);
        registry.fetchMarketMakerSlice(0, 2);

        vm.expectRevert(InvalidRange.selector);
        registry.fetchMarketMakerSlice(1, 1);

        vm.expectRevert(InvalidRange.selector);
        registry.fetchMarketMakerSlice(1, 0);
    }

    function testEdgeCaseEmptyRegistry() public {
        assertEq(registry.getMarketMakersCount(), 0);

        vm.expectRevert(InvalidRange.selector);
        registry.fetchMarketMakerSlice(0, 1);
    }

    function testEdgeCaseSingleMarketMaker() public {
        vm.prank(alice);
        registry.addMarketMaker("Alice's Server");

        MMRegistry.MarketMaker[] memory slice = registry.fetchMarketMakerSlice(0, 1);
        assertEq(slice.length, 1);
        assertEq(slice[0].server, "Alice's Server");

        vm.expectRevert(InvalidRange.selector);
        registry.fetchMarketMakerSlice(0, 2);
    }

    function testFuzzAddDeleteMarketMakers(uint8 numOperations) public {
        address[] memory users = new address[](numOperations);
        for (uint i = 0; i < numOperations; i++) {
            users[i] = address(uint160(i + 1));
        }

        uint256 expectedCount = 0;
        bool[] memory isMarketMaker = new bool[](numOperations);

        for (uint i = 0; i < numOperations; i++) {
            if (uint256(keccak256(abi.encodePacked(i))) % 2 == 0) {
                // Add market maker
                vm.prank(users[i]);
                registry.addMarketMaker(string(abi.encodePacked("Server ", i)));
                expectedCount++;
                isMarketMaker[i] = true;
            } else if (expectedCount > 0) {
                // Delete market maker
                uint256 indexToDelete = uint256(keccak256(abi.encodePacked(i))) % numOperations;
                if (isMarketMaker[indexToDelete]) {
                    vm.prank(users[indexToDelete]);
                    registry.deleteMarketMaker();
                    expectedCount--;
                    isMarketMaker[indexToDelete] = false;
                }
            }
        }

        assertEq(registry.getMarketMakersCount(), expectedCount);
    }
}
