// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// FIXED: the same growable array, but `total` is paginated -- the caller bounds
/// the work with `start`/`count`, so no single call iterates the whole (possibly
/// huge) array. The loop runs to `end`, never to `deposits[user].length`.
/// (should NOT trigger DG-DOS-001)
contract BoundedRewards {
    mapping(address => uint256[]) public deposits;

    function addDeposit(uint256 amount) external {
        deposits[msg.sender].push(amount);
    }

    function totalRange(address user, uint256 start, uint256 count)
        external
        view
        returns (uint256 sum)
    {
        uint256 end = start + count;
        uint256 len = deposits[user].length;
        if (end > len) end = len;
        for (uint256 i = start; i < end; i++) {
            sum += deposits[user][i];
        }
    }
}
