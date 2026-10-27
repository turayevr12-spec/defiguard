// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// VULNERABLE: `deposits[user]` grows every time addDeposit is called, and
/// `total` iterates the whole array. After enough deposits the loop exceeds the
/// block gas limit and `total` (and anything that calls it) reverts forever.
/// Mirrors the idOS node-staking unbounded-loop DoS class. (DG-DOS-001)
contract UnboundedRewards {
    mapping(address => uint256[]) public deposits;

    function addDeposit(uint256 amount) external {
        deposits[msg.sender].push(amount);
    }

    function total(address user) external view returns (uint256 sum) {
        for (uint256 i; i < deposits[user].length; i++) {
            sum += deposits[user][i];
        }
    }
}
