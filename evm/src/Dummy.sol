// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

contract Dummy {
    uint public count;

    function stake(bytes memory stakeData) public {
        count++;
    }
}
