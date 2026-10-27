// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// VULNERABLE: withdraw sends ETH via a low-level call, THEN updates balance.
/// The callee can re-enter before `balances` is zeroed. (DG-EXT-001)
contract ReentrantVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}(""); // interaction first
        require(ok, "transfer failed");
        balances[msg.sender] -= amount; // effect AFTER interaction -> reentrancy
    }
}
