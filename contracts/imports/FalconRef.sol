// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title FalconRef
 * @notice Reference file that forces Hardhat to compile the ETHFALCON
 *         submodule's production verifier contracts along with the project's
 *         own contracts. The Hardhat compiler walks the import graph from
 *         this file, so every contract transitively imported here is compiled
 *         and emitted as an artifact under `artifacts/ETHFALCON/...`.
 *
 * @dev    We intentionally import ONLY production verifier sources. Foundry
 *         test helpers (`ZKNOX_PythonSigner.sol`, `ZKNOX_display.sol`,
 *         `ZKNOX_epervier.sol`, `ZKNOX_ethepervier.sol`) pull in
 *         `forge-std/Test.sol` and are out of scope for the AA on-chain path.
 *         NFR-5: zero modifications to submodule sources.
 */

import "../../ETHFALCON/src/ZKNOX_falcon.sol";
import "../../ETHFALCON/src/ZKNOX_ethfalcon.sol";
import "../../ETHFALCON/src/ZKNOX_falcon_encodings.sol";
import "../../ETHFALCON/src/ZKNOX_falcon_deploy.sol";
