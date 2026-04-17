import type { HardhatUserConfig } from "hardhat/config";

import hardhatToolboxViemPlugin from "@nomicfoundation/hardhat-toolbox-viem";

// ETHDILITHIUM submodule compile path (Story 1 AC-1-9):
//
// The ZKNOX_* contracts from `ETHDILITHIUM/src/` are pulled into the build
// graph via transitive import from `contracts/imports/DilithiumRef.sol`,
// which declares thin inheriting wrappers for each contract we need HH3 to
// emit artifact JSON for. HH3 only emits artifacts for contracts defined
// in files under `paths.sources.solidity` (default: `./contracts`) or listed
// in `solidity.npmFilesToBuild` — submodule files pulled in by transitive
// import are compiled (and thus covered by AC-1-9's compile-without-warnings
// requirement via `check-compile-warnings.cjs` tolerating `ETHDILITHIUM/`
// locations) but do not emit artifacts on their own.
//
// We deliberately do NOT add `ETHDILITHIUM/src` to `paths.sources.solidity`:
// that directory also contains `ZKNOX_PythonSigner.sol` which imports
// `forge-std/Test.sol` for Foundry-only test harness use, which would drag
// the entire forge-std tree into the compile graph and emit >256 solc
// warnings (exceeding solc's "more than 256 warnings" cap, producing an
// unlocatable warning line that defeats `check-compile-warnings.cjs`).
// The Ref-wrapper pattern is already established in this repo for the
// analogous ETHFALCON compile path (`contracts/imports/FalconRef.sol`).
//
// Pinned ETHDILITHIUM submodule SHA is read deterministically from the
// parent-tree gitlink at runtime by downstream Story 1 tasks:
// `git submodule status ETHDILITHIUM | awk '{print $1}' | sed 's/^[+-]//'`
// (current recorded pin) and `git -C ETHDILITHIUM rev-parse HEAD` (current
// submodule HEAD). `.gitmodules` only records the URL; the pin itself lives
// in the parent tree per standard Git submodule convention.
const config: HardhatUserConfig = {
  plugins: [hardhatToolboxViemPlugin],
  solidity: {
    version: "0.8.34",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      evmVersion: "cancun",
    },
    npmFilesToBuild: [
      "@account-abstraction/contracts/core/EntryPoint.sol",
      "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol",
    ],
  },
  networks: {
    // Pin the simulated chain to Cancun so the EIP-7825 per-tx gas cap
    // (2^24 = 16,777,216 gas) introduced by Osaka does not activate.
    // ML-DSA on-chain verification exceeds that cap when executed via
    // EntryPoint.handleOps in Story 5-1's gas benchmark. Matches the
    // Solidity `evmVersion: cancun` above.
    hardhat: {
      type: "edr-simulated",
      hardfork: "cancun",
    },
  },
};

export default config;
