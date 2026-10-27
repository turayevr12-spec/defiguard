// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// FIXED: staking is bound to msg.sender. If delegated staking is ever needed it
/// must verify an explicit permit/operator authorization -- never the ambient
/// allowance alone. (should NOT trigger DG-AC-001)
contract SafeStake {
    IERC20 public token;
    mapping(address => mapping(address => uint256)) public stakeByNodeByUser;

    constructor(IERC20 _token) {
        token = _token;
    }

    function stake(address node, uint256 amount) external {
        address user = msg.sender;
        token.transferFrom(user, address(this), amount);
        stakeByNodeByUser[user][node] += amount;
    }

    // delegated variant kept safe by an explicit authorization check
    function stakeFor(address user, address node, uint256 amount) external {
        require(msg.sender == user || authorized[user][msg.sender], "not authorized");
        token.transferFrom(user, address(this), amount);
        stakeByNodeByUser[user][node] += amount;
    }

    mapping(address => mapping(address => bool)) public authorized;
}
