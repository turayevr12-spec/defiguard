// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// VULNERABLE: `stake` pulls tokens from the caller-supplied `user` with no
/// check that msg.sender == user. Anyone can force-stake a third party's tokens
/// as long as that party left a standing allowance. (DG-AC-001)
contract ForcedStake {
    IERC20 public token;
    mapping(address => mapping(address => uint256)) public stakeByNodeByUser;

    constructor(IERC20 _token) {
        token = _token;
    }

    function stake(address user, address node, uint256 amount) external {
        if (user == address(0)) user = msg.sender; // a default, NOT an auth check
        token.transferFrom(user, address(this), amount);
        stakeByNodeByUser[user][node] += amount;
    }
}
