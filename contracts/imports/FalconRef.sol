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
