// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// REVIEW: uses delegatecall into an implementation. Not a bug by itself, but
/// the implementation MUST share this contract's storage layout or writes will
/// corrupt `owner`/`implementation`. (DG-DC-001)
contract DelegateProxy {
    address public owner;
    address public implementation;

    function forward(bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory out) = implementation.delegatecall(data);
        require(ok, "delegatecall failed");
        return out;
    }
}
