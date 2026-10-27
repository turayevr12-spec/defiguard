// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// FIXED: checks-effects-interactions -- balance is updated BEFORE the external
/// call, and the function is also guarded. (should NOT trigger the DG-EXT-001
/// "state write after external call" MEDIUM; the low-level call itself is still
/// noted at LOW, which is expected hygiene guidance.)
contract SafeVault {
    mapping(address => uint256) public balances;
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked, "reentrant");
        _locked = true;
        _;
        _locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount; // effect BEFORE interaction
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
