// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MockPayableTarget {
    uint256 public totalReceived;

    function receiveValue() external payable {
        totalReceived += msg.value;
    }
}
