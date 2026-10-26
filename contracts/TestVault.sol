// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TestVault {
    uint256 public balance;

    event VaultDeposit(address caller, uint256 value, bytes data);
    event VaultDangerousAction(address caller, uint256 value, bytes data);
    event VaultHarmlessAction(address caller, uint256 value, bytes data);

    function deposit() external payable {
        balance += msg.value;
        emit VaultDeposit(msg.sender, msg.value, msg.data);
    }

    function dangerousAction(uint256 amount) external {
        balance -= amount;
        emit VaultDangerousAction(msg.sender, 0, msg.data);
    }

    function harmlessAction() external {
        emit VaultHarmlessAction(msg.sender, 0, msg.data);
    }
}