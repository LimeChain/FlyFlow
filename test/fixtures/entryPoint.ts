/**
 * EntryPoint test fixture
 *
 * Deploys a fresh eth-infinitism `EntryPoint` (v0.7, PackedUserOperation-based)
 * via Hardhat 3's viem toolbox and returns it together with a publicClient and
 * the preconfigured wallet clients so callers can:
 *   - read chain state (`publicClient`)
 *   - sign/send txs from funded accounts (`walletClients`)
 *   - invoke EntryPoint methods via the typed viem contract instance
 *
 * Deploys eth-infinitism's `EntryPoint` directly. HH3's
 * `solidity.npmFilesToBuild` list in `hardhat.config.ts` pulls
 * `@account-abstraction/contracts/core/EntryPoint.sol` into the compile graph
 * and emits its artifact, so no project-side subclass is needed.
 *
 * HH3 toolbox-viem API note: the `viem` helpers live on a NetworkConnection,
 * not directly on `hre`. Usage pattern is `await hre.network.connect()` then
 * `connection.viem.deployContract(...)`. This mirrors the documented
 * `@nomicfoundation/hardhat-viem@^3.x` surface shipped inside
 * `@nomicfoundation/hardhat-toolbox-viem@5.0.3`.
 *
 * Ref: Story 1-1 Task 4, Amendment A-001 §4
 */

import hre from "hardhat";

export async function deployEntryPoint() {
  const connection = await hre.network.connect();
  const { viem } = connection;

  const publicClient = await viem.getPublicClient();
  const walletClients = await viem.getWalletClients();
  const entryPoint = await viem.deployContract("EntryPoint");

  return { entryPoint, publicClient, walletClients };
}
