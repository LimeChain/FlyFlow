// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.34;

import {SimpleAccount} from "@account-abstraction/contracts/samples/SimpleAccount.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "@account-abstraction/contracts/core/Helpers.sol";
import {ZKNOX_falcon} from "../ETHFALCON/src/ZKNOX_falcon.sol";

/// @title FalconAccount
/// @author pqc-4337-laim
/// @notice ERC-4337 v0.7 account that delegates signature verification to a
///         ZKNoxHQ ETHFALCON verifier (DD-9). Stores the SSTORE2-pointer form
///         of the public key (C-005 resolution / amendment A-003); the raw
///         897-byte Falcon-512 key is supplied off-chain via the signer
///         module, encoded by the test setup, and written into the verifier's
///         SSTORE2 storage before initialization.
contract FalconAccount is SimpleAccount {
    /// @notice Reverts when the verifier fails to decode the signature
    ///         (format error). Cryptographic failure returns
    ///         SIG_VALIDATION_FAILED via the standard validationData path
    ///         instead, so this is reserved strictly for malformed input.
    error SignatureMalformed();

    /// @dev Selector of the external `verify(bytes,bytes32,bytes)` overload
    ///      on `ZKNOX_falcon`. Computed via keccak256 of the explicit
    ///      signature because `ZKNOX_falcon.verify.selector` is ambiguous
    ///      under argument-dependent lookup — the verifier also exposes an
    ///      internal 4-arg `verify(bytes,bytes,uint256[],uint256[])`.
    bytes4 private constant _VERIFY_SELECTOR =
        bytes4(keccak256("verify(bytes,bytes32,bytes)"));

    /// @notice Immutable reference to the ZKNoxHQ Falcon verifier this account
    ///         delegates `_validateSignature` to. Deployed once per test
    ///         instance per DD-9; never shared across accounts in production.
    ZKNOX_falcon public immutable falconVerifier;

    /// @notice 20-byte SSTORE2 pointer returned by `falconVerifier.setKey()`,
    ///         packed via `abi.encodePacked(pointer)`. The verifier interprets
    ///         the first 20 bytes of this field as the SSTORE2 contract
    ///         address holding the ABI-encoded compacted NTT-domain key.
    ///         NOT the raw 897-byte Falcon-512 NIST-encoded key.
    bytes public publicKey;

    /// @notice Construct the account implementation against a fixed
    ///         EntryPoint and Falcon verifier. Both are immutable; per-account
    ///         state lives on the proxy initialized via `initialize`.
    /// @param  anEntryPoint The ERC-4337 v0.7 EntryPoint singleton.
    /// @param  _verifier    The ZKNoxHQ Falcon verifier instance.
    constructor(IEntryPoint anEntryPoint, ZKNOX_falcon _verifier)
        SimpleAccount(anEntryPoint)
    {
        falconVerifier = _verifier;
    }

    /// @notice Initialize the proxy with Alice's SSTORE2-pointer public key.
    /// @dev    The first parameter intentionally shadows
    ///         `SimpleAccount.initialize(address)` by selector — the Falcon
    ///         path identifies the signer via `publicKey`, not via the
    ///         SimpleAccount `owner` field, so it is unused here. Do NOT
    ///         forward to `super.initialize(...)`; that would create a
    ///         misleading dual-identity model.
    /// @param  _publicKey 20-byte SSTORE2 pointer bytes from
    ///                    `falconVerifier.setKey(rawPublicKey)`.
    function initialize(address, bytes calldata _publicKey)
        public
        initializer
    {
        publicKey = _publicKey;
    }

    /// @inheritdoc SimpleAccount
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 validationData) {
        try falconVerifier.verify(publicKey, userOpHash, userOp.signature) returns (bytes4 result) {
            return result == _VERIFY_SELECTOR
                ? SIG_VALIDATION_SUCCESS
                : SIG_VALIDATION_FAILED;
        } catch {
            revert SignatureMalformed();
        }
    }
}
