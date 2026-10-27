// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Minimal ERC20 for the example (not production code).
contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "balance");
        uint256 a = allowance[from][msg.sender];
        require(a >= amount, "allowance");
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// VULNERABLE: `stake` pulls from the caller-supplied `user`, with no check that
/// msg.sender == user. Mirrors the DG-AC-001 "forced staking" class.
contract ForcedStake {
    MockERC20 public token;
    mapping(address => mapping(address => uint256)) public stakeByNodeByUser;

    constructor(MockERC20 _token) {
        token = _token;
    }

    function stake(address user, address node, uint256 amount) external {
        if (user == address(0)) user = msg.sender; // default, NOT authorization
        token.transferFrom(user, address(this), amount);
        stakeByNodeByUser[user][node] += amount;
    }
}

/// FIXED: staking is bound to msg.sender; delegated staking requires explicit
/// authorization, never the ambient allowance alone.
contract SafeStake {
    MockERC20 public token;
    mapping(address => mapping(address => uint256)) public stakeByNodeByUser;
    mapping(address => mapping(address => bool)) public authorized;

    constructor(MockERC20 _token) {
        token = _token;
    }

    function stake(address node, uint256 amount) external {
        _stake(msg.sender, node, amount);
    }

    function stakeFor(address user, address node, uint256 amount) external {
        require(msg.sender == user || authorized[user][msg.sender], "not authorized");
        _stake(user, node, amount);
    }

    function setAuthorized(address operator, bool ok) external {
        authorized[msg.sender][operator] = ok;
    }

    function _stake(address user, address node, uint256 amount) internal {
        token.transferFrom(user, address(this), amount);
        stakeByNodeByUser[user][node] += amount;
    }
}
