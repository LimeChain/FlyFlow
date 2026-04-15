import type { HardhatUserConfig } from "hardhat/config";

import hardhatToolboxViemPlugin from "@nomicfoundation/hardhat-toolbox-viem";

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
