---
id: "2-1"
slug: ecdsa-account
status: done
created: 2026-04-14
completed: 2026-04-14
---

# Story: EcdsaAccount + acceptance/rejection tests

## User Story
As an engineer, I want an ECDSA baseline smart account that passes the standard 4337 validation path, so that PQC schemes have a reference to compare against.

## Acceptance Criteria

- AC-1: Given a deployed `EcdsaAccount` with `owner` set to Alice's address, When Alice signs a UserOp with her ECDSA private key and it is submitted to `validateUserOp`, Then it returns `SIG_VALIDATION_SUCCESS` (`0`).
- AC-2: Given the same account (owned by Alice), When Bob signs the UserOp with his own ECDSA keypair, Then `validateUserOp` returns `SIG_VALIDATION_FAILED` (`1`) because `ecrecover` returns Bob's address, not Alice's.
- AC-3: Given Alice's valid signature, When byte 0 of the signature is bit-flipped, Then `ecrecover` returns `address(0)` or an unrelated address and `validateUserOp` returns `SIG_VALIDATION_FAILED`.
- AC-4: Given the `EcdsaAccount` source, When inspected, Then it contains no `_validateSignature` override (inherits SimpleAccount directly — DD-10).

## Architecture Guardrails

**Amendment A-001 is binding.** DD-1 in `docs/architecture.md` is AMENDED: toolchain is Hardhat 3.x + viem + `node:test`/`node:assert/strict` (no chai, no ethers, no TypeChain, no hardhat-gas-reporter). Assertions in test files use `node:assert/strict`. The scaffold (Story 1-1) already runs on this stack.

**DD-10 [LOCKED] — baseline is unmodified SimpleAccount.** `EcdsaAccount` MUST NOT override `_validateSignature` or any validation-path method. The contract is either (a) a thin subclass that only declares the constructor `constructor(IEntryPoint anEntryPoint) SimpleAccount(anEntryPoint) {}` and inherits everything else, or (b) a direct alias via `contract EcdsaAccount is SimpleAccount`. No method bodies. No extra logic. Any deviation breaks DD-10 and triggers a Rule 4 HALT.

Rationale: the baseline gas measurement in Story 5-1 must reflect eth-infinitism's exact `_validateSignature` code path. Any identical-looking reimplementation risks compiling to different bytecode.

**Verification path (from SimpleAccount, inherited):**
```solidity
function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
    internal override virtual returns (uint256 validationData)
{
    bytes32 hash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
    if (owner != ECDSA.recover(hash, userOp.signature))
        return SIG_VALIDATION_FAILED;  // 1
    return SIG_VALIDATION_SUCCESS;     // 0
}
```
The inherited path uses OpenZeppelin `MessageHashUtils.toEthSignedMessageHash` (EIP-191 prefix) + `ECDSA.recover`. This is byte-for-byte compatible with viem's `signMessage({ message: { raw: hash } })` that `test/signers/ecdsa.ts` already produces — `privateKeyToAccount(pk).signMessage({ message: { raw: userOpHash } })` applies the same `"\x19Ethereum Signed Message:\n32"` prefix. Story 1-1's smoke test already proved the signer emits a 65-byte `r||s||v` over this prefix.

**SimpleAccount initialization model:** `SimpleAccount` inherits `Initializable` and `UUPSUpgradeable`. The constructor calls `_disableInitializers()` (locks the implementation). Owner is assigned via `initialize(address anOwner)`, which is guarded by `initializer`. For a PoC with no proxy-deployment workflow, tests deploy the account directly and call `initialize(alice)` — this works because the deployed instance is a fresh contract, not a proxy-delegated implementation. The `_disableInitializers()` call in the parent constructor does not prevent `initialize` on a newly-deployed concrete instance (it locks calls on the *logic* contract reached via delegatecall — not relevant here since we're not using a proxy).

**EntryPoint integration (v0.7, PackedUserOperation-based):**
- `validateUserOp(PackedUserOperation calldata, bytes32 userOpHash, uint256 missingAccountFunds)` lives on `BaseAccount` — inherited via SimpleAccount. Gated by `_requireFromEntryPoint()` which checks `msg.sender == entryPoint()`.
- For AC-1/AC-2/AC-3, tests MAY either (a) submit through `entryPoint.handleOps([op], beneficiary)` end-to-end, or (b) call `validateUserOp` directly from a wallet impersonating the EntryPoint via viem's `testClient.impersonateAccount` + `setBalance`. Option (b) gives a direct numeric return (`0` vs `1`) which is what the ACs assert on; option (a) requires decoding `FailedOp` / `UserOperationEvent.success`. **Use option (b)** — it reads the raw `validationData` return value and matches AC-2/AC-3's literal `SIG_VALIDATION_FAILED (1)` assertion without ambiguity. Option (a) is reserved for Story 5-1's benchmark path.
- `userOpHash` passed in is computed by EntryPoint as `keccak256(abi.encode(innerHash, entryPointAddress, chainId))` where `innerHash` is over the packed UserOp fields. `test/signers/ecdsa.ts` already implements this exact hash — reuse it verbatim. Canonical reference: `IEntryPoint.getUserOpHash(userOp)` — tests MAY call it on the live EntryPoint to cross-check.

**userOpHash field layout (from `UserOperationLib` / `PackedUserOperation.sol`, consumed by `ecdsa.ts`):** `sender (address)`, `nonce (uint256)`, `keccak256(initCode) (bytes32)`, `keccak256(callData) (bytes32)`, `accountGasLimits (bytes32)`, `preVerificationGas (uint256)`, `gasFees (bytes32)`, `keccak256(paymasterAndData) (bytes32)`. All are already encoded correctly inside `signUserOp("ecdsa", …)` — do not re-derive.

**Wrong-key setup (AC-2):** Generate two independent ECDSA keypairs via `keygen("ecdsa")`. Deploy the account and call `initialize(aliceAddress)`. Sign the UserOp with Bob's `secretKey`. `ecrecover` returns Bob's address → `!= owner` → `SIG_VALIDATION_FAILED`.

**Bit-flip setup (AC-3):** Sign with Alice's key normally, then flip a single bit inside byte 0 of the signature's `r` component (e.g., XOR `0x01`). The resulting `r, s, v` either (a) makes `ecrecover` return `address(0)` (malleability / no valid point), or (b) returns an unrelated address. Either way `!= owner` → `SIG_VALIDATION_FAILED`. The inherited `ECDSA.recover` in OpenZeppelin accepts any 65-byte signature; it does not revert for well-formed-but-wrong signatures. It MAY revert for specific malleability cases (high-s, invalid v) — if bit-flipping byte 0 produces a revert from the OpenZeppelin library (e.g., `ECDSAInvalidSignature`), the test must catch it and treat the revert as an equivalent rejection (AC-3 says "returns `address(0)` OR an unrelated address AND `validateUserOp` returns `SIG_VALIDATION_FAILED`" — if recovery reverts inside OZ, we document it as a stronger form of rejection). Prefer flipping a bit in the middle of `r` (e.g., byte 5) where OZ's malleability checks are less likely to revert — this matches the spec's "invalid-but-parseable" intent from architecture.md §WF-2.

**Test layout (PD-2 extension, greenfield for `test/accounts/`):** Story 2-1 creates `test/accounts/ecdsa.test.ts` — one file covering all four ACs. Splitting acceptance vs rejection into two files is unnecessary for a baseline that inherits SimpleAccount unchanged (no shared fixture logic to move). Reviewer-preferred if a future story (3-2, 4-2) demonstrates the per-scheme split, Story 2-1 can be refactored for consistency.

**Compile graph:** `EcdsaAccount.sol` imports from `@account-abstraction/contracts/samples/SimpleAccount.sol` and `@account-abstraction/contracts/interfaces/IEntryPoint.sol` — both are npm-resolved. `SimpleAccount.sol` transitively pulls in OpenZeppelin (`@openzeppelin/contracts`, present in `node_modules/` as a transitive dep of `@account-abstraction/contracts`). Add `@account-abstraction/contracts/samples/SimpleAccount.sol` to `hardhat.config.ts` `solidity.npmFilesToBuild` only if Hardhat's default source-file discovery does not follow the import graph from `contracts/EcdsaAccount.sol`. Verify empirically: `npm run compile` after adding the file — if `SimpleAccount`'s artifact is missing, add the entry.

> Ref: docs/architecture.md#Design Rationale — DD-10 (baseline must be unmodified SimpleAccount)
> Ref: docs/architecture.md#Smart Contract Interfaces — EcdsaAccount shape
> Ref: docs/architecture.md#Error Handling Strategy — validationData return semantics
> Ref: docs/architecture.md#Testing Strategy — test-file conventions and fresh-keypair-per-test rule
> Ref: docs/amendments.md#A-001 — HH3 + viem + node:test toolchain (BINDING)
> Ref: docs/stories/1-1-project-scaffold.md — signer harness contract and verified interfaces

## Verified Interfaces

### `keygen("ecdsa")`
- **Source:** `test/signers/ecdsa.ts:27`
- **Signature:** `export function keygen(): Keypair` (returns `{ publicKey: Uint8Array /* 20 bytes, address */, secretKey: Uint8Array /* 32 bytes, raw privkey */ }`)
- **File hash:** `3e2541c1899e6a6baee1b3dc71d06269419f30eb9faf562b66e7a8ce643dc24c`
- **Plan match:** ✓ Matches plan §Interface Contracts and Story 1-1 exports

### `signUserOp("ecdsa", secretKey, userOp, entryPointAddress, chainId)`
- **Source:** `test/signers/ecdsa.ts:47`
- **Signature:** `export async function signUserOp(secretKey: Uint8Array, userOp: UnsignedUserOp, entryPointAddress: string, chainId: bigint): Promise<PackedUserOperation>`
- **File hash:** `3e2541c1899e6a6baee1b3dc71d06269419f30eb9faf562b66e7a8ce643dc24c`
- **Plan match:** ✓ Matches plan §Interface Contracts. Uses `privateKeyToAccount(pk).signMessage({ message: { raw: userOpHash } })` — 65-byte `r||s||v` over EIP-191 prefix. Computes userOpHash per EIP-4337 v0.7 `keccak256(abi.encode(innerHash, entryPointAddress, chainId))`.

### `keygen`/`signUserOp` dispatcher
- **Source:** `test/signers/index.ts:45` (`keygen`), `test/signers/index.ts:56` (`signUserOp`)
- **Signature:** exported types `Scheme = "ecdsa" | "falcon" | "mldsa"`, `Keypair`, `UnsignedUserOp`, `PackedUserOperation`
- **File hash:** `5f571b4ecbe7d6a709d45df187320a5641c94aa5e2695be649170f6fc1189238`
- **Plan match:** ✓ Matches plan §Interface Contracts

### `deployEntryPoint()`
- **Source:** `test/fixtures/entryPoint.ts:27`
- **Signature:** `export async function deployEntryPoint(): Promise<{ entryPoint, publicClient, walletClients }>` via `hre.network.connect()` → `viem.deployContract("EntryPoint")`
- **File hash:** `95104f6690c0d34496cebe738a0bec1b7f23315c540fab9e6458a0136684e2fd`
- **Plan match:** ✓ Returns typed viem contract instance with `.address` and `.abi`

### `SimpleAccount` (upstream, inherited by `EcdsaAccount`)
- **Source:** `node_modules/@account-abstraction/contracts/samples/SimpleAccount.sol:42` (constructor), `:90` (`initialize`), `:105` (`_validateSignature`)
- **Signature:**
  - `constructor(IEntryPoint anEntryPoint)` — locks implementation via `_disableInitializers()`
  - `function initialize(address anOwner) public virtual initializer`
  - `function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash) internal override virtual returns (uint256 validationData)` — uses `MessageHashUtils.toEthSignedMessageHash(userOpHash)` + `ECDSA.recover(hash, userOp.signature)`
  - `function execute(address dest, uint256 value, bytes calldata func) external` — gated by `_requireFromEntryPointOrOwner()`
- **File hash:** `8075e38726cac91e9f80051833bf61c8ad26650795eab75af276c3f71169fc0a`
- **Plan match:** ✓ Matches architecture §Smart Contract Interfaces

### `BaseAccount.validateUserOp` (upstream, inherited transitively)
- **Source:** `node_modules/@account-abstraction/contracts/core/BaseAccount.sol:35`
- **Signature:** `function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) external virtual override returns (uint256 validationData)` — gated by `_requireFromEntryPoint()`, calls `_validateSignature` then `_validateNonce` then `_payPrefund`
- **File hash:** `d48e2cd1ccc779369ddf08716e0099133c703a4c52f52f0594c1220cb64fadc0`
- **Plan match:** ✓ This is the exact method the test AC-1/AC-2/AC-3 asserts on

### `Helpers.sol` constants (upstream)
- **Source:** `node_modules/@account-abstraction/contracts/core/Helpers.sol:11,18`
- **Signature:** `uint256 constant SIG_VALIDATION_FAILED = 1;` / `uint256 constant SIG_VALIDATION_SUCCESS = 0;`
- **File hash:** `4ec549dbe1685def37cbe8699eb5376ce4466dcd0c6ffffd7c0d7e0f7a5b89a3`
- **Plan match:** ✓ These are the literal numeric values tests assert

## Tasks

- [x] **Task 1: `contracts/EcdsaAccount.sol` — minimal SimpleAccount baseline**
  - Maps to: AC-1, AC-2, AC-3, AC-4
  - Files: `contracts/EcdsaAccount.sol` (new)
  - SPDX + `pragma solidity 0.8.34;` (match the Hardhat config version; `SimpleAccount.sol` pragma is `^0.8.23` which is compatible)
  - `import {SimpleAccount} from "@account-abstraction/contracts/samples/SimpleAccount.sol";`
  - `import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";`
  - Body: `contract EcdsaAccount is SimpleAccount { constructor(IEntryPoint anEntryPoint) SimpleAccount(anEntryPoint) {} }`
  - NatSpec: `@title EcdsaAccount`, `@author`, `@notice Baseline ERC-4337 account — intentionally empty body per DD-10. Inherits SimpleAccount unchanged so gas measurements reflect eth-infinitism's reference implementation.`
  - NO `_validateSignature`, NO `initialize` override, NO `execute` override, NO custom errors, NO new events. The body must be a single-line constructor and nothing else (AC-4 grep target).
  - If `hardhat compile` fails to find `SimpleAccount`'s artifact, add `"@account-abstraction/contracts/samples/SimpleAccount.sol"` to `solidity.npmFilesToBuild` in `hardhat.config.ts` and re-run. Log this as a deviation under Rule 1 (minor — additive config change, not a pattern change).

- [x] **Task 2: `test/accounts/ecdsa.test.ts` — acceptance + rejection tests**
  - Maps to: AC-1, AC-2, AC-3, AC-4
  - Files: `test/accounts/ecdsa.test.ts` (new; create `test/accounts/` directory)
  - Framework: `node:test` (`describe`, `it`) + `node:assert/strict`. Match the style of `test/smoke.test.ts`. Do NOT import chai or `hardhat-chai-matchers`.
  - Imports: `deployEntryPoint` from `../fixtures/entryPoint.js`, `keygen` + `signUserOp` + `UnsignedUserOp` from `../signers/index.js`, viem helpers (`bytesToHex`, `toHex`, `parseEther`) as needed, `hre` from `"hardhat"` for `hre.network.connect()` (needed for test client + contract deploy).
  - Shared setup per test file: a helper `async function setup()` that (a) calls `deployEntryPoint()`, (b) generates Alice's keypair via `keygen("ecdsa")`, (c) deploys `EcdsaAccount` via `viem.deployContract("EcdsaAccount", [entryPoint.address])`, (d) calls `account.write.initialize([aliceAddress])` from a wallet client, (e) funds the account (1 ETH via `testClient.setBalance` or a wallet transfer) so `_payPrefund` doesn't cause issues on option (a) paths, (f) returns `{ entryPoint, account, alice, publicClient, walletClients, testClient }`. Use fresh keypairs per test (architecture §Test Data).
  - **Invoking `validateUserOp` directly (chosen path — see Guardrails):** impersonate the EntryPoint address with viem's test client: `await testClient.impersonateAccount({ address: entryPoint.address })` + `await testClient.setBalance({ address: entryPoint.address, value: parseEther("1") })`. Then call `account.read.validateUserOp([packedUserOp, userOpHash, 0n], { account: entryPoint.address })` — viem's `read` path with an `account` override lets `msg.sender` be the impersonated EntryPoint without producing a state-changing tx. `validateUserOp` is declared `external` (non-view) in BaseAccount; use `simulateContract` if `read` rejects it, and assert on `result.result`. Both approaches return the `uint256 validationData` without emitting a transaction.
  - Construct the UserOp: build an `UnsignedUserOp` with `sender: account.address`, `nonce: 0n`, `initCode: "0x"`, `callData: "0x"`, `accountGasLimits`/`gasFees` as zero `bytes32`, `preVerificationGas: 0n`, `paymasterAndData: "0x"`. Compute `userOpHash` either (a) by calling `entryPoint.read.getUserOpHash([packedOp])` on-chain (canonical — no drift risk) or (b) replicate locally. Prefer (a) — it removes the chance of an off-by-one in the test fixture silently passing because the signer and verifier both use the same drifted hash.
  - **AC-1 — Alice signs, expect 0:**
    - Sign: `const signed = await signUserOp("ecdsa", alice.secretKey, userOp, entryPoint.address, chainId);`
    - Call `validateUserOp(signed, userOpHash, 0n)` with EntryPoint as msg.sender; assert return value `=== 0n` (`SIG_VALIDATION_SUCCESS`).
  - **AC-2 — Bob signs (owner is still Alice), expect 1:**
    - Generate Bob's keypair: `const bob = keygen("ecdsa");` (fresh, independent)
    - Sign with Bob: `const signed = await signUserOp("ecdsa", bob.secretKey, userOp, entryPoint.address, chainId);`
    - Call `validateUserOp`; assert return value `=== 1n` (`SIG_VALIDATION_FAILED`).
  - **AC-3 — bit-flipped sig, expect 1 (or equivalent rejection):**
    - Produce Alice's valid signed op, then flip one bit inside byte 5 of `r` (offset 5 from `0x02` — i.e., the 6th byte of the hex string after the `0x` prefix, but treat as Uint8 for clarity). Construct: `const bytes = hexToBytes(signed.signature); bytes[5] ^= 0x01; const corrupted = bytesToHex(bytes);` Re-assemble `PackedUserOperation` with the corrupted `signature`.
    - Call `validateUserOp`; assert return value `=== 1n`. If the call reverts (OpenZeppelin `ECDSAInvalidSignature` on malleability) catch with `await assert.rejects(promise)` and document the revert as an equivalent-or-stronger rejection — AC-3's intent is "not SUCCESS". Start with the `=== 1n` expectation; add the rejects fallback only if OZ rejects outright.
  - **AC-4 — source inspection:**
    - Pure grep-style assertion — read `contracts/EcdsaAccount.sol` from disk with `fs.readFileSync` (node: `readFile` from `"node:fs/promises"`), assert the source does NOT contain `_validateSignature` (case-sensitive substring match). Also assert it DOES contain `is SimpleAccount`. This is the DD-10 human-review check mechanized.
  - Suggested test names (for `node:test` `it` labels): `"AC-1: valid owner signature returns SIG_VALIDATION_SUCCESS"`, `"AC-2: wrong-key signature returns SIG_VALIDATION_FAILED"`, `"AC-3: bit-flipped signature returns SIG_VALIDATION_FAILED"`, `"AC-4: source contains no _validateSignature override"`.

- [x] **Task 3: Wire `EcdsaAccount` into the compile graph + smoke-verify compile**
  - Maps to: AC-1 (enabling), AC-4 (enabling)
  - Files: possibly `hardhat.config.ts` (append `@account-abstraction/contracts/samples/SimpleAccount.sol` to `solidity.npmFilesToBuild` if needed)
  - Run `npm run compile` — verify zero non-submodule warnings (the tolerated ETHFALCON `slen` warning from C-001 is expected). If compile emits any new warnings on `EcdsaAccount.sol` or `SimpleAccount.sol`, stop and diagnose before proceeding (likely pragma or unused-import issue).
  - Run `npm test` — verify the Story 1-1 smoke test still passes AND the new `test/accounts/ecdsa.test.ts` passes all 4 cases.

## must_haves

truths:
  - "`contracts/EcdsaAccount.sol` exists, declares `contract EcdsaAccount is SimpleAccount` with a single-line constructor `constructor(IEntryPoint anEntryPoint) SimpleAccount(anEntryPoint) {}`, and contains no `_validateSignature` identifier anywhere in the file (DD-10)"
  - "`hardhat compile` succeeds with zero non-submodule warnings after adding `EcdsaAccount.sol`; only the tolerated ETHFALCON `slen` warning (C-001) is permitted"
  - "A deployed `EcdsaAccount` initialized with Alice's 20-byte address accepts a UserOp signed by Alice: `validateUserOp(signedOp, userOpHash, 0)` called from the EntryPoint returns `0n` (SIG_VALIDATION_SUCCESS)"
  - "The same deployed account rejects a UserOp signed by Bob (independently-generated keypair): `validateUserOp` returns `1n` (SIG_VALIDATION_FAILED)"
  - "The same deployed account rejects a UserOp whose signature has had one bit flipped inside the `r` component: `validateUserOp` returns `1n` OR reverts with an OpenZeppelin `ECDSAInvalidSignature`-class error (both count as rejection)"
  - "`test/accounts/ecdsa.test.ts` exists, uses `node:test` + `node:assert/strict`, imports only from `../fixtures/entryPoint.js` and `../signers/index.js` and viem (no chai, no `hardhat-chai-matchers`, no ethers)"
  - "Tests compute `userOpHash` via `entryPoint.read.getUserOpHash(packedOp)` on the live EntryPoint (canonical), not via a hand-rolled duplicate of `test/signers/ecdsa.ts`'s hashing logic"
  - "Each test generates fresh ECDSA keypairs via `keygen(\"ecdsa\")` — no hardcoded private keys in the test file"
  - "`test/accounts/ecdsa.test.ts` includes an AC-4 source-inspection assertion that reads `contracts/EcdsaAccount.sol` and asserts `_validateSignature` is absent from the file contents"

artifacts:
  - path: "contracts/EcdsaAccount.sol"
    contains: ["SimpleAccount", "IEntryPoint", "EcdsaAccount"]
  - path: "test/accounts/ecdsa.test.ts"
    contains: ["deployEntryPoint", "keygen", "signUserOp", "validateUserOp", "SIG_VALIDATION", "_validateSignature"]

key_links:
  - pattern: "is SimpleAccount"
    in: ["contracts/EcdsaAccount.sol"]
  - pattern: "constructor(IEntryPoint"
    in: ["contracts/EcdsaAccount.sol"]
  - pattern: "@account-abstraction/contracts/samples/SimpleAccount.sol"
    in: ["contracts/EcdsaAccount.sol"]
  - pattern: "node:test"
    in: ["test/accounts/ecdsa.test.ts"]
  - pattern: "node:assert/strict"
    in: ["test/accounts/ecdsa.test.ts"]
  - pattern: "deployEntryPoint"
    in: ["test/accounts/ecdsa.test.ts"]
  - pattern: "keygen(\"ecdsa\")"
    in: ["test/accounts/ecdsa.test.ts"]
  - pattern: "signUserOp(\"ecdsa\""
    in: ["test/accounts/ecdsa.test.ts"]
  - pattern: "impersonateAccount"
    in: ["test/accounts/ecdsa.test.ts"]
  - pattern: "getUserOpHash"
    in: ["test/accounts/ecdsa.test.ts"]

## Dev Notes (advisory)

**No new external dependencies.** Story 2-1 adds zero packages to `package.json`. Everything needed is already installed by Story 1-1: `@account-abstraction/contracts@^0.7.0` (provides `SimpleAccount`, `BaseAccount`, `IEntryPoint`, `Helpers`), `@openzeppelin/contracts` (transitive — used by SimpleAccount), `viem@^2.43.0` (test client, impersonation, hash helpers), `hardhat@^3.3.0` + `@nomicfoundation/hardhat-toolbox-viem@^5.0.3`. If `npm ls @openzeppelin/contracts` shows it unresolved, add it explicitly as a devDependency — this would be a Rule 1 deviation.

**Testing standards (established by Story 1-1, reused here):**
- Test runner: `node:test` (HH3 default via `@nomicfoundation/hardhat-node-test-runner` included in toolbox-viem).
- Assertions: `node:assert/strict` — `assert.equal`, `assert.strictEqual`, `assert.rejects`, `assert.match`. No chai.
- Test file naming: `*.test.ts` under `test/`.
- Fresh keypairs per test (architecture §Test Data).
- Fixtures stay under `test/fixtures/`; this story adds `test/accounts/` as a new sibling directory, matching architecture §Testing Strategy §Test Structure.

> Ref: test/smoke.test.ts — node:test + node:assert reference style already in-tree

**Version audit at implementation time:** All package versions are pinned from Story 1-1. Implement skill should check `package.json` at audit time — no web-search required unless a version drift is proposed.

**Solidity version choice:** use `pragma solidity 0.8.34;` on `EcdsaAccount.sol` to exactly match `hardhat.config.ts` `solidity.version`. `SimpleAccount.sol`'s pragma (`^0.8.23`) is compatible with 0.8.34.

**AC-3 bit-flip resilience:** OpenZeppelin's `ECDSA.recover` (used transitively by `SimpleAccount._validateSignature`) can revert with `ECDSAInvalidSignature` or `ECDSAInvalidSignatureS` for certain malleability conditions. The test MUST handle both outcomes — a numeric `1n` return OR a revert. The AC's intent is "not SUCCESS"; both failure modes satisfy it. Flipping a bit inside `r` (byte offset 5 of the 65-byte signature) is the safest choice: it stays well away from `s` (offset 32-63, subject to high-s malleability checks) and `v` (offset 64, subject to value-in-{27,28} checks).

**Why direct `validateUserOp` and not `entryPoint.handleOps`:** AC-1/AC-2/AC-3 assert on the literal `uint256` return values `0` and `1`. `handleOps` does not expose that return — it propagates via `FailedOp(opIndex, reason)` (for AA23/AA24 signature-error reasons) which requires revert-reason parsing. Story 5-1 will exercise `handleOps` for gas measurement; Story 2-1's job is the numeric-return validation path. Impersonating the EntryPoint via viem's test client is the standard HH3 pattern for this.

**What is NOT in this story:**
- `SimpleAccountFactory` / ERC-1967 proxy deployment — not needed for the PoC. Tests deploy the account directly.
- UUPS upgrade paths (`_authorizeUpgrade`) — inherited and unused.
- Any benchmark or gas-reporter integration — that is Story 5-1.
- End-to-end `handleOps` flow — that is Story 5-1.

## Detected Patterns

Codebase scanned for analogous patterns:
- **Scanned for existing `contracts/*.sol` patterns:** Only `contracts/imports/FalconRef.sol` and `contracts/imports/DilithiumRef.sol` exist — both are single-line `import "ETHFALCON/src/ZKNOX_falcon.sol";` files. Not analogous to a full contract definition. Greenfield for account contracts.
- **Scanned for existing `test/*.test.ts` patterns:** `test/smoke.test.ts` is the single prior test file. It uses `node:test` + `node:assert/strict`, imports fixtures via `.js` extensions (ESM requirement), and uses `describe`/`it` blocks. Pattern established.
- **Scanned for existing fixture patterns:** `test/fixtures/entryPoint.ts` is the single prior fixture. Pattern: `async function deploy*()` returning a `{contract, publicClient, walletClients}` shape from `hre.network.connect().viem`. Pattern established.

| Pattern | Value | Sampled from | Established? |
|---------|-------|-------------|-------------|
| Test runner | `node:test` + `node:assert/strict` | `test/smoke.test.ts` | ✅ Established (single reference; A-001 binding) |
| ESM import extensions | `.js` suffix on relative imports | `test/smoke.test.ts`, `test/fixtures/entryPoint.ts`, `test/signers/index.ts` | ✅ Established |
| Deploy pattern | `hre.network.connect()` → `viem.deployContract(name, args?)` | `test/fixtures/entryPoint.ts` | ✅ Established |
| Signer dispatch | `test/signers/index.ts` re-exports + switches on `Scheme` | `test/signers/index.ts` | ✅ Established |
| Test file naming | `*.test.ts` under `test/` | `test/smoke.test.ts` | ✅ Established |
| Contract file (non-import) | n/a — greenfield | — | ⚠ First occurrence |

No conflicts detected. Contract-file pattern is greenfield for this repo; follow the shape prescribed in Task 1.

## Wave Structure

Story 2-1 is Wave 2 (`sprint-status.yaml`), parallel with 3-1 and 4-1 — disjoint files enforce wave independence. Internally the 3 tasks are sequential:

- **Sub-wave A:** Task 1 (write `EcdsaAccount.sol`) — independent, no prior artifacts needed beyond Story 1-1 scaffold.
- **Sub-wave B:** Task 2 (write `test/accounts/ecdsa.test.ts`) — depends on Task 1 (test imports the deployed contract).
- **Sub-wave C:** Task 3 (compile + test gate) — depends on Tasks 1 and 2.

Wave-independence audit vs Stories 3-1 and 4-1: Story 2-1 touches `contracts/EcdsaAccount.sol` + `test/accounts/ecdsa.test.ts`; 3-1 will touch `contracts/FalconAccount.sol` + `test/signers/falcon.ts` + `test/accounts/falcon.test.ts`; 4-1 will touch `contracts/MlDsaAccount.sol` + `test/signers/ml-dsa.ts` + `test/accounts/mldsa.test.ts`. Zero shared output files. `hardhat.config.ts` is a potential collision if all three stories need to append to `solidity.npmFilesToBuild` — Story 2-1 may need to add `SimpleAccount.sol` there; this is an append-only, commutative edit and won't cause wave conflict, but merge order should be deterministic. Flag for the parent orchestrator.
