// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableEIP712 {
    
    struct Order {
        address maker;
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 amountOut;
        uint256 expiry;
    }

    // Уязвимость 1. DOMAIN_SEPARATOR должен быть immutable.
    bytes32 public DOMAIN_SEPARATOR;
    
    constructor(){
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("MyDApp"),
                keccak256("1.0.0"),
                block.chainid,  // ОК
                address(this)   // ОК
            )
        );
    }

    bytes32 public constant ORDER_TYPEHASH = keccak256(
        "Order(address maker,address tokenIn,address tokenOut,uint256 amountIn,uint256 amountOut,uint256 expiry)"
    );

    mapping(bytes32 => bool) public usedSignatures;

    // Уязвимая функция проверки подписи
    function verifyOrder(
        Order calldata order,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (address) {
        bytes32 orderHash = keccak256(
            abi.encode(
                ORDER_TYPEHASH,
                order.maker,
                order.tokenIn,
                order.tokenOut,
                order.amountIn,
                order.amountOut,
                order.expiry
            )
        );

        // Уязвимость 2: Нет префикса \x19\x01
        bytes32 digest = orderHash;

        // Уязвимость 3: Не проверяется, что подпись не использовалась
        address signer = ecrecover(digest, v, r, s);
        require(signer == order.maker, "Invalid signature");

        usedSignatures[digest] = true;
        return signer;
    }
}