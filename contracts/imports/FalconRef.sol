// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title FalconRef
 * @notice Reference file that forces Hardhat to compile the ETHFALCON
 *         submodule's production verifier contracts AND emit their artifact
 *         JSON under a project path so `viem.deployContract("ZKNOX_falcon")`
 *         can resolve them. Mirrors DilithiumRef.sol — see that file's NOTE
 *         about HH3's artifact-emission rule (project-file-defined contracts
 *         only; submodule contracts pulled in by transitive import are
 *         compiled but no artifact JSON is written).
 *
 * @dev    Imports only production verifiers. Foundry test helpers
 *         (`ZKNOX_PythonSigner.sol`, `ZKNOX_display.sol`,
 *         `ZKNOX_epervier.sol`, `ZKNOX_ethepervier.sol`) pull in
 *         `forge-std/Test.sol` and are out of scope for the AA on-chain path.
 *         NFR-5: zero modifications to submodule sources.
 *
 *         The empty wrappers inherit the submodule contracts so HH3 emits
 *         artifacts under this file's path; tests deploy the wrapper which
 *         is byte-for-byte equivalent.
 */

import {ZKNOX_falcon as _ZKNOX_falcon} from "../../ETHFALCON/src/ZKNOX_falcon.sol";
import {ZKNOX_ethfalcon as _ZKNOX_ethfalcon} from "../../ETHFALCON/src/ZKNOX_ethfalcon.sol";

contract ZKNOX_falcon is _ZKNOX_falcon {}
contract ZKNOX_ethfalcon is _ZKNOX_ethfalcon {}

// -----------------------------------------------------------------------------
// Story 1-1 Task T2 — appended below. Lines 1..29 above are byte-preserved
// from the pre-T2 baseline (AC-NFR-10). The new import and contract below
// land as a pure append per the story's "FalconRef.sol extension (AC-A-4)"
// snippet and the T2 constraint "leave all existing lines byte-identical".
// -----------------------------------------------------------------------------

import {hashToPointEVM} from "../../ETHFALCON/src/ZKNOX_HashToPoint.sol";

/**
 * @title ZKNOX_HashToPointExposed
 * @author LimeChain
 * @notice Thin wrapper that exposes the upstream `hashToPointEVM` free function
 *         (`ETHFALCON/src/ZKNOX_HashToPoint.sol:22`) as an externally-callable
 *         contract method so Hardhat can emit an artifact and the Story 1-1
 *         Task T2 fixture generator can deploy it and call `.compute()` via a
 *         `staticCall` to capture G2 hash-to-point ground-truth vectors (DD-25
 *         Option C — trust anchor is the pinned Solidity source).
 * @dev    `hashToPointEVM` is a Solidity free function, so this wrapper cannot
 *         use the inheriting-wrapper pattern used by `ZKNOX_falcon` /
 *         `ZKNOX_ethfalcon` above; instead it imports the free function and
 *         forwards the two arguments. The method is `pure` — no state reads or
 *         writes — so a `staticCall` from the fixture generator returns the
 *         `uint256[]` output without a transaction. Gas cost is non-zero inside
 *         the method body (keccak256 loop); "pure" refers to state-purity only.
 */
contract ZKNOX_HashToPointExposed {
    /**
     * @notice Hash `msgHash` to a Falcon-512 polynomial point in Z_q (q=12289)
     *         using the Keccak256-based XOF defined by ETHFALCON.
     * @dev    Forwards to the upstream `hashToPointEVM` free function. Returns
     *         an array of exactly 512 coefficients, each `< 12289`.
     * @param  salt    40-byte salt value for domain separation.
     * @param  msgHash Message hash (variable length — typically a
     *                 keccak256-derived 32-byte digest).
     * @return coeffs  Array of 512 coefficients in Z_q representing the
     *                 hash-to-point result.
     */
    function compute(bytes memory salt, bytes memory msgHash)
        external
        pure
        returns (uint256[] memory coeffs)
    {
        return hashToPointEVM(salt, msgHash);
    }
}
