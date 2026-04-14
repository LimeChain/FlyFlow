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
 */

import "../../ETHDILITHIUM/src/ZKNOX_dilithium.sol";
import "../../ETHDILITHIUM/src/ZKNOX_ethdilithium.sol";
