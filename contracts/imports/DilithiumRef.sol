// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title DilithiumRef
 * @notice Reference file that forces Hardhat to compile the ETHDILITHIUM
 *         submodule's production verifier contracts. See FalconRef.sol for
 *         the compile-graph rationale.
 *
 * @dev    Imports only production verifiers. Foundry test helpers
 *         (`ZKNOX_PythonSigner.sol`) are excluded. NFR-5: zero modifications
 *         to submodule sources.
 *
 *         HH3 only emits artifact JSON for contracts defined in project
 *         files (`contracts/`) or `npmFilesToBuild` paths. Submodule files
 *         pulled in by transitive import are compiled but no artifact JSON
 *         is written, so `viem.deployContract("ZKNOX_dilithium")` fails
 *         with HHE1000. The empty wrappers below inherit the submodule
 *         contracts so HH3 emits artifacts under this file's path; tests
 *         deploy the wrapper which is byte-for-byte equivalent.
 *
 *         Story 1 AC-1-9 note: `ZKNOX_keccak_prng.sol` is a free-functions-
 *         only file (struct `KeccakPrng` + `initPrng` / `refill` / `nextByte`
 *         at file scope, no contract) and is already compiled transitively
 *         via `ZKNOX_ethdilithium` → `ZKNOX_SampleInBall` →
 *         `ZKNOX_keccak_prng`. solc emits no standalone artifact for free-
 *         functions files, but the compiled source IS recorded in the
 *         build-info produced under this file's path — `check-compile-
 *         warnings.cjs` enforces the zero-warning requirement across the
 *         full graph (see `hardhat.config.ts` for rationale).
 */

import {ZKNOX_dilithium as _ZKNOX_dilithium} from "../../ETHDILITHIUM/src/ZKNOX_dilithium.sol";
import {ZKNOX_ethdilithium as _ZKNOX_ethdilithium} from "../../ETHDILITHIUM/src/ZKNOX_ethdilithium.sol";

contract ZKNOX_dilithium is _ZKNOX_dilithium {}
contract ZKNOX_ethdilithium is _ZKNOX_ethdilithium {}
