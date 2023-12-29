// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "./interfaces/IStake.sol";

contract Vault is AccessControl {
    using SafeERC20 for IERC20;
    IStake public stakingContract;

    address public voyager;

    mapping(bytes32 => bytes) public ourContractsOnChain;

    // iDepositMessage(uint256,bytes32,bytes,address,uint256,uint256,bytes)
    bytes4 public constant I_DEPOSIT_MESSAGE_SELECTOR =
        bytes4(
            keccak256(
                "iDepositMessage(uint256,bytes32,bytes,address,uint256,uint256,bytes)"
            )
        );

    constructor(address _voyager) {
        voyager = _voyager;
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function setStakingContract(
        address _stakingContract
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        stakingContract = IStake(_stakingContract);
    }

    function setContractsOnChain(
        bytes32 chainIdBytes,
        address contractAddr
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        ourContractsOnChain[chainIdBytes] = toBytes(contractAddr);
    }

    function stake(uint256 _amount, address _token) external {
        IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);
        stakingContract.stake(msg.sender, _token, _amount);
    }

    function unstake(uint256 _amount, address _token) external {
        stakingContract.unstake(msg.sender, _token, _amount);
    }

    function iStake(
        bytes32 destChainIdBytes,
        address srcToken,
        uint256 amount,
        uint256 destAmount,
        address userAddress
    ) public payable {
        bytes memory recipientVaultContract = ourContractsOnChain[
            destChainIdBytes
        ];
        bytes memory message = abi.encode(userAddress);
        bool success;

        (success, ) = voyager.call{value: msg.value}(
            abi.encodeWithSelector(
                I_DEPOSIT_MESSAGE_SELECTOR,
                0,
                destChainIdBytes,
                recipientVaultContract,
                srcToken,
                amount,
                destAmount,
                message
            )
        );

        require(success, "unsuccessful");
    }

    function handleMessage(
        address tokenSent,
        uint256 amount,
        bytes memory message
    ) external {
        // Checking if the sender is the voyager contract
        require(msg.sender == voyager, "only voyager");

        // // Checking if the request initiated by our contract only from the source chain
        // require(sourceSenderAddress == toAddress(ourContractsOnChain[srcChainIdBytes]), "not our contract");

        IERC20(tokenSent).safeIncreaseAllowance(
            address(stakingContract),
            amount
        );
        // decoding the data we sent from the source chain
        address user = abi.decode(message, (address));
        // calling the stake function
        stakingContract.stake(user, tokenSent, amount);
    }

    function approve(
        address token,
        address spender,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        IERC20(token).approve(spender, amount);
    }

    function toBytes(address addr) public pure returns (bytes memory b) {
        assembly {
            let m := mload(0x40)
            addr := and(addr, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            mstore(
                add(m, 20),
                xor(0x140000000000000000000000000000000000000000, addr)
            )
            mstore(0x40, add(m, 52))
            b := m
        }
    }

    //     function toAddress(bytes memory _bytes) public pure returns (address addr) {
    //     bytes20 srcTokenAddress;
    //     assembly {
    //       srcTokenAddress := mload(add(_bytes, 0x20))
    //     }
    //     addr = address(srcTokenAddress);
    //   }
}