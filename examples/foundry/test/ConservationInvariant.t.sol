// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MockERC20, SafeStake} from "../src/Staking.sol";

interface Vm {
    function prank(address) external;
    function addr(uint256) external returns (address);
}

/// Invariant template: **token solvency** -- the staking contract must always
/// hold at least the sum of every accounted stake. If this ever breaks, the
/// contract cannot honor withdrawals (insolvency).
///
/// This self-contained version asserts the invariant after a scripted sequence,
/// so it runs with no forge-std dependency. The PRODUCTION pattern is a
/// handler-based fuzzing invariant:
///
///   contract Handler is Test { ...random stake/unstake/withdraw... }
///   contract Inv is StdInvariant, Test {
///       function setUp() { targetContract(address(handler)); }
///       function invariant_solvent() public view {
///           assertGe(token.balanceOf(address(staking)), handler.totalStaked());
///       }
///   }
///
/// See docs/rules.md for how DeFiGuard pairs a rule with an invariant.
contract ConservationInvariantTest {
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    MockERC20 token;
    SafeStake staking;
    address[3] users;
    uint256 ghostTotalStaked;

    function setUp() public {
        token = new MockERC20();
        staking = new SafeStake(token);
        for (uint256 i; i < 3; i++) {
            users[i] = vm.addr(i + 1);
            token.mint(users[i], 1_000 ether);
            vm.prank(users[i]);
            token.approve(address(staking), type(uint256).max);
        }
    }

    function _stake(uint256 who, uint256 amount) internal {
        address u = users[who % 3];
        vm.prank(u);
        staking.stake(address(uint160(0xA11CE)), amount);
        ghostTotalStaked += amount;
        _assertSolvent();
    }

    function _assertSolvent() internal view {
        require(
            token.balanceOf(address(staking)) >= ghostTotalStaked,
            "INVARIANT BROKEN: contract balance < total accounted stake"
        );
    }

    function test_SolvencyHoldsAcrossStakes() public {
        _stake(0, 100 ether);
        _stake(1, 250 ether);
        _stake(2, 400 ether);
        _stake(0, 50 ether);
        // after every step the solvency identity held (checked in _stake)
        require(ghostTotalStaked == 800 ether, "accounting mismatch");
        require(token.balanceOf(address(staking)) == 800 ether, "balance mismatch");
    }
}
