// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.17;

import "forge-std/Test.sol";

contract EcrecoverTest is Test {
    struct EIP712Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }

    struct Message {
        address from;
        address to;
        string content;
    }

    bytes32 constant DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name, string version, uint256 chainId,address verifyingContract"
        );
    bytes32 constant MESSAGE_TYPEHASH =
        keccak256("Message(address from,address to,string content");

    function testVerifySimpleMessage() public {
        uint256 _alicePrivateKey = 0xA11CE;
        address alice = vm.addr(_alicePrivateKey);

        bytes memory _message = "This signature was created by Alice";
        bytes32 _messageHash = keccak256(_message);

        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(
            _alicePrivateKey,
            _messageHash
        );

        // signature is the combination of rsv
        //
        // bytes memory _signature = new bytes(65);
        // assembly {
        //     mstore(add(_signature, 32), _r)
        //     mstore(add(_signature, 64), _s)
        //     mstore8(add(_signature, 96), _v)
        // }
        // console.logBytes(_signature);
        // => 0xb6abacba4c3efdaea5824cc2355de98fc507ba4d0091fb16571cf2bcbf885aef7233de999cc75964b213d4e6770d94311fafe116a66fbc81b92cf3b4166f456f1b

        assertTrue(_isValidSignature(alice, _messageHash, _v, _r, _s));
    }

    function testVerifyEIP712StructuredMessage() public {
        uint256 _alicePrivateKey = 0xA11CE;
        uint256 _bobPrivateKey = 0xB0B;
        address _alice = vm.addr(_alicePrivateKey);
        address _bob = vm.addr(_bobPrivateKey);

        // We can pass an arbitrary struct as the transaction data
        Message memory _message = Message({
            from: _alice,
            to: _bob,
            content: "Hi, bob!"
        });

        bytes32 _digest = _getTypedDataHash(_message);

        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(_alicePrivateKey, _digest);

        assertTrue(_isValidEIP712Message(_alice, _digest, _v, _r, _s));
    }

    function _getTypedDataHash(
        Message memory _message
    ) public view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    "\x19\x01",
                    _getDomainSeparator(),
                    _getStructHash(_message)
                )
            );
    }

    function _getDomainSeparator() internal view returns (bytes32) {
        EIP712Domain memory _domain = EIP712Domain({
            name: "SigTest",
            version: "1",
            chainId: 1,
            verifyingContract: address(this)
        });

        return
            keccak256(
                abi.encode(
                    DOMAIN_TYPEHASH,
                    keccak256(bytes(_domain.name)),
                    keccak256(bytes(_domain.version)),
                    _domain.chainId,
                    _domain.verifyingContract
                )
            );
    }

    function _getStructHash(
        Message memory _message
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    MESSAGE_TYPEHASH,
                    _message.from,
                    _message.to,
                    _message.content
                )
            );
    }

    function _isValidSignature(
        address _target,
        bytes32 _messageHash,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) internal pure returns (bool) {
        address _signer = ecrecover(_messageHash, _v, _r, _s);
        return _target == _signer;
    }

    function _isValidEIP712Message(
        address _sender,
        bytes32 _digest,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) internal pure returns (bool) {
        return ecrecover(_digest, _v, _r, _s) == _sender;
    }
}
