// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IImpl {
    function run(bytes calldata data) external returns (bytes memory);
}

/// FIXED: a normal external call runs in the callee's own storage context, so
/// there is no storage-layout coupling to get wrong. (should NOT trigger DG-DC-001)
contract NoDelegate {
    address public owner;
    IImpl public implementation;

    function forward(bytes calldata data) external returns (bytes memory) {
        return implementation.run(data);
    }
}
