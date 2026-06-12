// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.34;

import {SimpleAccount} from "@account-abstraction/contracts/samples/SimpleAccount.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "@account-abstraction/contracts/core/Helpers.sol";
import {ZKNOX_ethfalcon} from "./imports/FalconRef.sol";

/// @title FalconEthAccount
/// @author FlyFlow
/// @notice ERC-4337 v0.7 account that delegates signature verification to a
///         ZKNoxHQ ETHFALCON ETH-variant verifier (`ZKNOX_ethfalcon`)
///         — the Keccak-based HashToPoint variant of Falcon-512. Stores the
///         SSTORE2-pointer form of the reshaped public key; the raw 897-byte
///         Falcon-512 NIST-encoded key is supplied off-chain via the signer
///         module, reshaped by `preparePublicKeyForDeployment`
///         (`test/signers/falcon-eth.ts`) which delegates to the fork's
///         `encodeFalconPublicKey` exported from the `utils-eth` subpath
///         of the `noble/post-quantum` package (raw → forward-NTT →
///         compactPoly256 → `abi.encode(uint256[])`), and SSTORE2-written
///         by `falconEthVerifier.setKey()` before initialization. Signature byte-compatibility with the NIST Falcon
///         variant is preserved at the wire format (1,064-byte
///         `salt || s2_compact` raw concat); only the XOF primitive driving
///         hash-to-point differs between the two variants (SHAKE-256 vs
///         Keccak-256).
/// @custom:experimental This library is not audited yet, do not use in production.
contract FalconEthAccount is SimpleAccount {
    /// @notice Reverts when the verifier fails to decode the signature
    ///         (format error — e.g. wrong-length signature triggering BytesLib
    ///         OOB inside the verifier). Cryptographic failure (well-formed
    ///         signature that fails verification) returns SIG_VALIDATION_FAILED
    ///         via the standard validationData path instead, so this custom
    ///         error is reserved strictly for malformed input. AC-6's dual-path
    ///         walker binds to this error name on the `accountAddress`.
    error SignatureMalformed();

    /// @dev Selector of the external `verify(bytes,bytes32,bytes)` overload on
    ///      `ZKNOX_ethfalcon`. Computed via keccak256 of the explicit signature
    ///      string because `ZKNOX_ethfalcon.verify.selector` is ambiguous under
    ///      argument-dependent lookup — the verifier also exposes other
    ///      `verify` overloads (4-arg `verify(bytes,bytes,bytes,bytes)`
    ///      returning `bool`). Same selector-resolution pattern as
    ///      `MlDsaEthAccount` — both ETH-variant verifiers share the 3-arg
    ///      overload shape.
    bytes4 private constant _VERIFY_SELECTOR =
        bytes4(keccak256("verify(bytes,bytes32,bytes)"));

    /// @notice Immutable reference to the ZKNoxHQ Falcon-ETH verifier this
    ///         account delegates `_validateSignature` to. Deployed once per
    ///         test instance per DD-9; never shared across accounts in
    ///         production. Separate from the NIST-variant `FalconAccount`'s
    ///         `falconVerifier`: keys + signatures are NOT interchangeable
    ///         between the two variants (identical message produces different
    ///         hash-to-point output under SHAKE-256 vs Keccak-256, so the
    ///         on-chain verification path cannot consume NIST-signed payloads
    ///         and vice versa).
    ZKNOX_ethfalcon public immutable falconEthVerifier;

    /// @notice 20-byte SSTORE2 pointer returned by
    ///         `falconEthVerifier.setKey()`, packed via
    ///         `abi.encodePacked(pointer)`. The verifier interprets the first
    ///         20 bytes of this field as the SSTORE2 contract address holding
    ///         the ABI-encoded `uint256[]` of compacted NTT-domain public-key
    ///         coefficients. NOT the raw 897-byte Falcon-512 NIST-encoded key
    ///         — hence the `Pointer` suffix (mirrors ml-dsa-eth amendment
    ///         A-006's SSTORE2-pointer naming discipline).
    bytes public publicKeyPointer;

    /// @notice Construct the account implementation against a fixed
    ///         EntryPoint and Falcon-ETH verifier. Both are immutable;
    ///         per-account state lives on the proxy initialized via
    ///         `initialize`.
    /// @param  anEntryPoint The ERC-4337 v0.7 EntryPoint singleton.
    /// @param  _verifier    The ZKNoxHQ Falcon-ETH verifier instance.
    constructor(IEntryPoint anEntryPoint, ZKNOX_ethfalcon _verifier)
        SimpleAccount(anEntryPoint)
    {
        falconEthVerifier = _verifier;
    }

    /// @notice Initialize the proxy with Alice's SSTORE2-pointer public key.
    /// @dev    The first parameter intentionally shadows
    ///         `SimpleAccount.initialize(address)` by selector — the
    ///         Falcon-ETH path identifies the signer via `publicKeyPointer`,
    ///         not via the SimpleAccount `owner` field, so it is unused
    ///         here. Do NOT forward to `super.initialize(...)`; that would
    ///         create a misleading dual-identity model. Shadow-discipline
    ///         matches `MlDsaEthAccount`.
    /// @param  _publicKeyPointer 20-byte SSTORE2 pointer bytes from
    ///                    `falconEthVerifier.setKey(encodedPayload)`.
    function initialize(address, bytes calldata _publicKeyPointer)
        public
        initializer
    {
        publicKeyPointer = _publicKeyPointer;
    }

    /// @notice Validate a Falcon-ETH-signed user operation by delegating to
    ///         the pinned `falconEthVerifier`.
    /// @dev    The verifier's 3-arg `verify(bytes,bytes32,bytes)` overload
    ///         returns its own function selector on success by convention.
    ///         Matching against `_VERIFY_SELECTOR` converts that into the
    ///         ERC-4337 `SIG_VALIDATION_SUCCESS` sentinel. Any other return
    ///         value maps to `SIG_VALIDATION_FAILED` (cryptographic failure —
    ///         EntryPoint does NOT execute, no revert). An internal revert
    ///         during verification (e.g. malformed signature triggering
    ///         BytesLib OOB) is caught and re-thrown as the typed
    ///         `SignatureMalformed()` custom error — AC-6's malformed-path
    ///         contract.
    /// @param  userOp     The packed user operation whose `signature` field
    ///                    holds the 1,064-byte `salt || s2_compact` payload.
    /// @param  userOpHash Keccak-256 hash of the user op per ERC-4337 v0.7.
    /// @return validationData `SIG_VALIDATION_SUCCESS` on valid signature,
    ///                    `SIG_VALIDATION_FAILED` on cryptographic failure.
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 validationData) {
        try falconEthVerifier.verify(publicKeyPointer, userOpHash, userOp.signature) returns (bytes4 result) {
            return result == _VERIFY_SELECTOR
                ? SIG_VALIDATION_SUCCESS
                : SIG_VALIDATION_FAILED;
        } catch {
            revert SignatureMalformed();
        }
    }
}
