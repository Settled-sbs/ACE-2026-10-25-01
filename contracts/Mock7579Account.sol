// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IExecutionHook {
    function preCheck(
        address msgSender,
        uint256 msgValue,
        bytes calldata msgData
    ) external returns (bytes memory hookData);

    function postCheck(bytes calldata hookData) external;
    function onInstall(bytes calldata data) external;
}

contract Mock7579Account {
    IExecutionHook public hook;

    constructor(address hook_) {
        hook = IExecutionHook(hook_);
    }

    function installHook(bytes calldata data) external {
        hook.onInstall(data);
    }

    // Emulate an ERC-7579-style single-call execution lifecycle.
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external payable returns (bytes memory result) {
        require(msg.value == value, "value mismatch");

        // Encode the standard execute(bytes32,bytes) outer call shape.
        bytes32 mode = bytes32(0);
        bytes memory packedCall = abi.encodePacked(
            target,
            bytes32(value),
            data
        );

        bytes memory msgData = abi.encodeWithSignature(
            "execute(bytes32,bytes)",
            mode,
            packedCall
        );

        bytes memory hookData = hook.preCheck(
            msg.sender,
            value,
            msgData
        );

        (bool ok, bytes memory returned) =
            target.call{value: value}(data);

        if (!ok) {
            assembly {
                revert(add(returned, 32), mload(returned))
            }
        }

        hook.postCheck(hookData);
        return returned;
    }

    receive() external payable {}
}