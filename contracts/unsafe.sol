// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract LowLevelExample {
    function sendEth(address payable target) public payable {
        target.call{value: msg.value}(""); // <- это небезопасно
    }

    function safeSend(address payable target) public payable {
        (bool success, ) = target.call{value: msg.value}("");
        require(success, "Failed to send");
    }
}