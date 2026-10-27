// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MockERC20, ForcedStake, SafeStake} from "../src/Staking.sol";

/// Minimal cheatcode interface so this example needs no forge-std dependency.
interface Vm {
    function prank(address) external;
    function expectRevert(bytes calldata) external;
    function addr(uint256) external returns (address);
}

/// Demonstrates the DG-AC-001 "forced staking" class: the vulnerable contract
/// lets an attacker move a victim's approved tokens without consent, and the
/// fixed contract rejects exactly that call.
contract ForcedStakeTest {
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    MockERC20 token;
    address victim;
    address attacker;
    address node;

    function setUp() public {
        token = new MockERC20();
        victim = vm.addr(1);
        attacker = vm.addr(2);
        node = vm.addr(3);
    }

    // VULNERABLE: attacker force-stakes the victim's tokens; attacker spends none.
    function test_Vulnerable_AttackerForcesVictimStake() public {
        ForcedStake staking = new ForcedStake(token);

        token.mint(victim, 1_000 ether);
        vm.prank(victim);
        token.approve(address(staking), 1_000 ether); // standing allowance only

        vm.prank(attacker); // msg.sender == attacker, user == victim
        staking.stake(victim, node, 1_000 ether);

        require(token.balanceOf(victim) == 0, "victim should have been drained");
        require(
            staking.stakeByNodeByUser(victim, node) == 1_000 ether,
            "stake forced onto victim"
        );
        require(token.balanceOf(attacker) == 0, "attacker spent nothing of their own");
    }

    // FIXED: the same cross-account call reverts; only the owner or an authorized
    // operator can stake on someone's behalf.
    function test_Fixed_RejectsForcedStake() public {
        SafeStake staking = new SafeStake(token);

        token.mint(victim, 1_000 ether);
        vm.prank(victim);
        token.approve(address(staking), 1_000 ether);

        vm.prank(attacker);
        vm.expectRevert(bytes("not authorized"));
        staking.stakeFor(victim, node, 1_000 ether);

        require(token.balanceOf(victim) == 1_000 ether, "victim keeps their tokens");
    }

    // FIXED: an explicitly authorized operator CAN stake on the user's behalf.
    function test_Fixed_AuthorizedOperatorAllowed() public {
        SafeStake staking = new SafeStake(token);

        token.mint(victim, 1_000 ether);
        vm.prank(victim);
        token.approve(address(staking), 1_000 ether);
        vm.prank(victim);
        staking.setAuthorized(attacker, true); // victim opts in explicitly

        vm.prank(attacker);
        staking.stakeFor(victim, node, 1_000 ether);

        require(staking.stakeByNodeByUser(victim, node) == 1_000 ether, "authorized stake ok");
    }
}
