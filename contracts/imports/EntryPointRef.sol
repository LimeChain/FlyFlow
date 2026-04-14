// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

// This file exists solely to surface eth-infinitism's EntryPoint to Hardhat's
// compilation graph so that TypeChain emits the `EntryPoint` TypeScript type
// consumed by `test/fixtures/entryPoint.ts`. It deploys no code of its own.
import "@account-abstraction/contracts/core/EntryPoint.sol";
