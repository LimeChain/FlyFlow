// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.34;

import {SimpleAccount} from "@account-abstraction/contracts/samples/SimpleAccount.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "@account-abstraction/contracts/core/Helpers.sol";
import {ZKNOX_ethdilithium} from "../ETHDILITHIUM/src/ZKNOX_ethdilithium.sol";

/// @title MlDsaEthAccount
/// @author pqc-4337-laim
/// @notice ERC-4337 v0.7 account that delegates signature verification to a
///         ZKNoxHQ ETHDILITHIUM ETH-variant verifier (`ZKNOX_ethdilithium`)
///         — the Keccak-PRG fork of ML-DSA-44. Stores the SSTORE2-pointer
///         form of the reshaped public key (amendment A-006); the raw
///         1,312-byte ML-DSA-44 NIST-encoded key is supplied off-chain via
///         the signer module, reshaped by `preparePublicKeyForDeployment`
///         with two `keccakXofFactory` factories (DD-1 collapse + A-002),
///         and SSTORE2-written by `dilithiumEthVerifier.setKey()` before
///         initialization. Signature-side byte-compatibility with the NIST
///         variant is preserved (DD-8 LOCKED — `cTilde(32) || z(2304) ||
///         h(84)` raw concat, 2,420 B total); only the XOF primitive driving
///         keygen + sign differs between the two variants.
contract MlDsaEthAccount is SimpleAccount {
    /// @notice Reverts when the verifier fails to decode the signature
    ///         (format error). Cryptographic failure returns
    ///         SIG_VALIDATION_FAILED via the standard validationData path
    ///         instead, so this is reserved strictly for malformed input.
    error SignatureMalformed();

    /// @dev Selector of the external `verify(bytes,bytes32,bytes)` overload
    ///      on `ZKNOX_ethdilithium`. Computed via keccak256 of the explicit
    ///      signature because `ZKNOX_ethdilithium.verify.selector` is
    ///      ambiguous under argument-dependent lookup — the verifier also
    ///      exposes a 4-arg `verify(bytes,bytes,bytes,bytes)` returning
    ///      `bool`.
    bytes4 private constant _VERIFY_SELECTOR =
        bytes4(keccak256("verify(bytes,bytes32,bytes)"));

    /// @notice Immutable reference to the ZKNoxHQ ML-DSA-ETH verifier this
    ///         account delegates `_validateSignature` to. Deployed once per
    ///         test instance per DD-9; never shared across accounts in
    ///         production. Separate from the NIST-variant `MlDsaAccount`'s
    ///         `dilithiumVerifier`: keys + signatures are NOT interchangeable
    ///         between the two variants (identical ζ produces different
    ///         keypairs under SHAKE vs Keccak-PRG — DD-1 LOCKED).
    ZKNOX_ethdilithium public immutable dilithiumEthVerifier;

    /// @notice 20-byte SSTORE2 pointer returned by
    ///         `dilithiumEthVerifier.setKey()`, packed via
    ///         `abi.encodePacked(pointer)`. The verifier interprets the first
    ///         20 bytes of this field as the SSTORE2 contract address holding
    ///         the ABI-encoded `(aHatEncoded, tr, t1Encoded)` tuple. NOT the
    ///         raw 1,312-byte ML-DSA-44 NIST-encoded key — hence the
    ///         `Pointer` suffix (amendment A-006).
    bytes public publicKeyPointer;

    /// @notice Construct the account implementation against a fixed
    ///         EntryPoint and ML-DSA-ETH verifier. Both are immutable;
    ///         per-account state lives on the proxy initialized via
    ///         `initialize`.
    /// @param  anEntryPoint The ERC-4337 v0.7 EntryPoint singleton.
    /// @param  _verifier    The ZKNoxHQ ML-DSA-ETH verifier instance.
    constructor(IEntryPoint anEntryPoint, ZKNOX_ethdilithium _verifier)
        SimpleAccount(anEntryPoint)
    {
        dilithiumEthVerifier = _verifier;
    }

    /// @notice Initialize the proxy with Alice's SSTORE2-pointer public key.
    /// @dev    The first parameter intentionally shadows
    ///         `SimpleAccount.initialize(address)` by selector — the
    ///         ML-DSA-ETH path identifies the signer via `publicKeyPointer`,
    ///         not via the SimpleAccount `owner` field, so it is unused
    ///         here. Do NOT forward to `super.initialize(...)`; that would
    ///         create a misleading dual-identity model.
    /// @param  _publicKeyPointer 20-byte SSTORE2 pointer bytes from
    ///                    `dilithiumEthVerifier.setKey(encodedPayload)`.
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
        try dilithiumEthVerifier.verify(publicKeyPointer, userOpHash, userOp.signature) returns (bytes4 result) {
            return result == _VERIFY_SELECTOR
                ? SIG_VALIDATION_SUCCESS
                : SIG_VALIDATION_FAILED;
        } catch {
            revert SignatureMalformed();
        }
    }
}
