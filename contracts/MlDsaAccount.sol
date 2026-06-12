// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.34;

import {SimpleAccount} from "@account-abstraction/contracts/samples/SimpleAccount.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "@account-abstraction/contracts/core/Helpers.sol";
import {ZKNOX_dilithium} from "../ETHDILITHIUM/src/ZKNOX_dilithium.sol";

/// @title MlDsaAccount
/// @author FlyFlow
/// @notice ERC-4337 v0.7 account that delegates signature verification to a
///         ZKNoxHQ ETHDILITHIUM verifier (DD-9). Stores the SSTORE2-pointer
///         form of the public key (per architecture §Data Models —
///         DD-7 reshaped payload is SSTORE2-written, only the 20-byte
///         pointer lives on the account); the raw 1,312-byte ML-DSA-44
///         NIST-encoded key is supplied off-chain via the signer module,
///         ABI-encoded by the test setup into the (aHat, tr, t1) tuple the
///         verifier's `_readPubKey` decodes, and SSTORE2-written by
///         `dilithiumVerifier.setKey()` before initialization.
contract MlDsaAccount is SimpleAccount {
    /// @notice Reverts when the verifier fails to decode the signature
    ///         (format error). Cryptographic failure returns
    ///         SIG_VALIDATION_FAILED via the standard validationData path
    ///         instead, so this is reserved strictly for malformed input.
    error SignatureMalformed();

    /// @dev Selector of the external `verify(bytes,bytes32,bytes)` overload
    ///      on `ZKNOX_dilithium`. Computed via keccak256 of the explicit
    ///      signature because `ZKNOX_dilithium.verify.selector` is ambiguous
    ///      under argument-dependent lookup — the verifier also exposes a
    ///      4-arg `verify(bytes,bytes,bytes,bytes)` returning `bool`.
    bytes4 private constant _VERIFY_SELECTOR =
        bytes4(keccak256("verify(bytes,bytes32,bytes)"));

    /// @notice Immutable reference to the ZKNoxHQ ML-DSA verifier this
    ///         account delegates `_validateSignature` to. Deployed once per
    ///         test instance per DD-9; never shared across accounts in
    ///         production.
    ZKNOX_dilithium public immutable dilithiumVerifier;

    /// @notice 20-byte SSTORE2 pointer returned by
    ///         `dilithiumVerifier.setKey()`, packed via
    ///         `abi.encodePacked(pointer)`. The verifier interprets the first
    ///         20 bytes of this field as the SSTORE2 contract address holding
    ///         the ABI-encoded `(aHatEncoded, tr, t1Encoded)` tuple. NOT the
    ///         raw 1,312-byte ML-DSA-44 NIST-encoded key — hence the
    ///         `Pointer` suffix (amendment A-006).
    bytes public publicKeyPointer;

    /// @notice Construct the account implementation against a fixed
    ///         EntryPoint and ML-DSA verifier. Both are immutable; per-account
    ///         state lives on the proxy initialized via `initialize`.
    /// @param  anEntryPoint The ERC-4337 v0.7 EntryPoint singleton.
    /// @param  _verifier    The ZKNoxHQ ML-DSA verifier instance.
    constructor(IEntryPoint anEntryPoint, ZKNOX_dilithium _verifier)
        SimpleAccount(anEntryPoint)
    {
        dilithiumVerifier = _verifier;
    }

    /// @notice Initialize the proxy with Alice's SSTORE2-pointer public key.
    /// @dev    The first parameter intentionally shadows
    ///         `SimpleAccount.initialize(address)` by selector — the ML-DSA
    ///         path identifies the signer via `publicKeyPointer`, not via the
    ///         SimpleAccount `owner` field, so it is unused here. Do NOT
    ///         forward to `super.initialize(...)`; that would create a
    ///         misleading dual-identity model.
    /// @param  _publicKeyPointer 20-byte SSTORE2 pointer bytes from
    ///                    `dilithiumVerifier.setKey(encodedPayload)`.
    function initialize(address, bytes calldata _publicKeyPointer)
        public
        initializer
    {
        publicKeyPointer = _publicKeyPointer;
    }

    /// @inheritdoc SimpleAccount
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 validationData) {
        try dilithiumVerifier.verify(publicKeyPointer, userOpHash, userOp.signature) returns (bytes4 result) {
            return result == _VERIFY_SELECTOR
                ? SIG_VALIDATION_SUCCESS
                : SIG_VALIDATION_FAILED;
        } catch {
            revert SignatureMalformed();
        }
    }
}
