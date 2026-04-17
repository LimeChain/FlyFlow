---
id: "5-1"
slug: gas-benchmark
epic: 5
wave: 3
size: M
status: draft
created: 2026-04-15
dependencies: ["2-1", "3-1", "4-1"]
---

# Story: Gas benchmark + variance test + calldata decomposition

## User Story
As an engineer, I want gas consumed per scheme captured deterministically across 3 runs, so that overhead numbers are trustworthy.

## Acceptance Criteria

- AC-1 (AMENDED by A-001): Given all three deployed accounts, When the benchmark test runs `entryPoint.handleOps([signedUserOp])` for each scheme, Then Hardhat 3's built-in gas tracking captures per-scheme gas used (e.g., via `publicClient.estimateGas` on the transaction or `network.provider`'s gas measurements).
- AC-2: Given 3 repeated benchmark runs on the same devnet state, When gas values are collected per scheme, Then `(max - min) / mean < 0.01` for each scheme (NFR-3).
- AC-3: Given gas per scheme, When computing calldata cost from `userOp.signature` bytes (16 gas/non-zero byte, 4 gas/zero byte) and subtracting from total, Then both calldata cost and execution cost are reported separately (AC-A-1).
- AC-4: Given a partial failure where one scheme fails validation, When the benchmark completes, Then the failing scheme is recorded with its failure reason and remaining schemes still produce valid gas data (AC-U-1).
- AC-5: Given the full benchmark suite, When measured wall-clock, Then total elapsed time is ≤ 5 minutes (NFR-4).

## Architecture Guardrails

**A-001 [BINDING] — no `hardhat-gas-reporter`.** HH3 has no `hardhat-gas-reporter` port; AC-1's original wording referenced it but is now amended. Gas is captured natively via viem's receipt API: after `entryPoint.write.handleOps([signedOp], beneficiary)` returns a tx hash, read `await publicClient.getTransactionReceipt({ hash }).gasUsed` for the actual post-execution gas. Do NOT install `hardhat-gas-reporter` — its peer-dep pins HH2.

**A-002 [BINDING] — proxy deployment pattern.** All three accounts are deployed via `ERC1967Proxy` pointing at a freshly-deployed implementation. The Story 2-1/3-1/4-1 `setup()` functions already encode this; reuse their patterns. `solidity.npmFilesToBuild` already includes `@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol` (see hardhat.config.ts:18).

**A-003 [BINDING] — PQC accounts store SSTORE2 pointer, not raw pubkey.** `FalconAccount.initialize` / `MlDsaAccount.initialize` take a 20-byte pointer returned by `registerPublicKey(verifier, rawKey, publicClient?)`. The raw 897/1312-byte NIST key is NOT passed to `initialize`.

**A-004 [BINDING] — ML-DSA-44, not ML-DSA-65.** `ml_dsa44.keygen()` returns 1312-byte pubkey + 2560-byte secret; `ml_dsa44.sign(hash, sk)` returns a 2420-byte blob (cTilde 32 + z 2304 + h 84).

**C-006 [BINDING, enabling prerequisite for AC-2].** `test/signers/ecdsa.ts` uses viem's `signMessage`, which occasionally produces a high-S signature that OpenZeppelin's `ECDSA.recover` rejects as `ECDSAInvalidSignature()` before the recovered address is compared to the owner. On a single signature this is intermittent (~1/N); under a 3-run benchmark loop the probability of polluting AC-2's variance assertion is high. **Task 1 of this story hardens `signUserOp("ecdsa", …)` with low-S normalization** (EIP-2): after `privateKeyToAccount(pk).signMessage({ message: { raw: hash } })`, parse the 65-byte `r||s||v`, check if `s > n/2` where `n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`; if so replace `s ← n - s` and toggle `v` (27↔28). All consumers of `signUserOp("ecdsa", …)` — Story 2-1 test, Story 5-1 benchmark, any future scheme — inherit the fix.

**C-010.1 (informational, do NOT expand scope).** The benchmark harness may extract a reusable `buildUnsignedUserOp` helper shared with the existing account tests; if it does, C-010.1 (wasted Falcon sign in Story 3-2 AC-3 setup) becomes trivially fixable in a later touch. This story does NOT refactor the failure-class test files.

**Gas capture mechanism (AC-1):**
- Use `entryPoint.write.handleOps([signedOp], beneficiary)` → returns `txHash` (viem).
- `await publicClient.waitForTransactionReceipt({ hash })` → returns `receipt`.
- `receipt.gasUsed` is a `bigint` — the actual EVM gas consumed, including 21000 base tx cost, calldata cost, and execution.
- Rejected alternative: `publicClient.estimateGas(...)` returns pre-execution estimate, may overestimate, and would require building a tx object rather than using the typed contract's `write.handleOps`. Receipt-based is authoritative for benchmarking real execution cost.

**Bundler impersonation + account prefund (for `handleOps`):**
- Unlike `validateUserOp` (Stories 2-1/3-1/4-1), `handleOps` is called by the bundler, not the EntryPoint. Use any wallet client as the bundler — `walletClients[0]`. `handleOps` accesses the account's `entryPoint.balanceOf(account)` (deposit) and potentially pulls prefund; fund the account with a deposit first: `await entryPoint.write.depositTo([account.address], { value: parseEther("1") })` from any wallet.
- `beneficiary` is the bundler's own address: pass `walletClients[0].account.address`.
- Do NOT impersonate the EntryPoint for this story — that pattern is for direct `validateUserOp` calls. The benchmark executes the full bundler path on purpose (matches WF-1 Step 5).

**AC-2 variance (<1%):**
- Hardhat 3's EDR is deterministic within one test process: identical inputs + identical chain state yield identical `gasUsed`. Three successive `handleOps` calls with the SAME signed UserOp in the SAME `it()` block should produce identical gas — `variance = 0 < 0.01`.
- A re-signed UserOp across runs (fresh nonce or different randomness) would produce variance. **Keep the signed op identical across the 3 runs.** Because `handleOps` increments the account's nonce, the first run's op would revert on runs 2-3 with `AA25 invalid account nonce`. Workaround: sign 3 UserOps with nonces `0n, 1n, 2n` up-front on identical chain state; they differ only in the nonce field, and the signature over each canonical userOpHash is itself different but deterministic. The calldata gas will differ by zero-byte count of the nonce field — acceptable because all three nonces fit in one non-zero byte each (0, 1, 2), so calldata cost is identical.
- If variance > 0 on the same EDR state post-Task 1 fix, investigate for non-determinism (timestamp-dependent verifier logic, auto-mining difficulty) — but the expectation is 0.

**AC-3 calldata decomposition (EIP-2028 post-Istanbul schedule, unchanged under Cancun for calldata):**
- Non-zero byte: 16 gas. Zero byte: 4 gas.
- Compute from `userOp.signature` only (the per-scheme variable portion). Total gas minus signature-calldata cost = execution cost (includes other calldata, base tx 21000, and EVM execution).
- Helper shape:
  ```ts
  function signatureCalldataGas(sigHex: `0x${string}`): bigint {
    const bytes = hexToBytes(sigHex);
    let nonZero = 0n, zero = 0n;
    for (const b of bytes) (b === 0 ? zero++ : nonZero++);
    return nonZero * 16n + zero * 4n;
  }
  ```

**AC-4 partial-failure shape:**
```ts
type Scheme = "ecdsa" | "falcon" | "mldsa";
type BenchResult =
  | { scheme: Scheme; status: "ok"; runs: bigint[]; mean: bigint; variance: number;
      totalGas: bigint; calldataGas: bigint; executionGas: bigint }
  | { scheme: Scheme; status: "failed"; reason: string };
```
Wrap each scheme's benchmark block in try/catch. Collect results into an array. The test asserts AC-2 only for `status === "ok"` schemes; records failures for AC-4 downstream (Story 5-2 reads this shape). `assert.ok(results.length === 3)` — every scheme must produce a result record, success or failure.

**AC-5 wall-clock risk (flag, do not pre-mitigate):**
- Falcon and ML-DSA on-chain verification timeouts in Stories 3-1/4-1 are `120_000` ms. Three schemes × 3 runs = 9 handleOps calls; worst-case ~9×120s = 18 minutes, well above the 5-minute NFR.
- In practice, verification is ~1-5s (the 120s is a pessimistic ceiling). Measure wall-clock via `performance.now()` and log it; fail the test if elapsed > `5 * 60 * 1000` ms.
- Fix-when-touched: if the test fails AC-5 on HH3 EDR hardware variance, reduce from 3 runs → 2 runs (determinism on EDR makes N=2 sufficient for a 0-variance assertion). Do NOT pre-reduce — AC-2 explicitly requires 3.

**Persisting gas data for Story 5-2:**
- After all schemes finish, write the `BenchResult[]` array as JSON to `test/bench/gas-data.json` (or a path Story 5-2's report generator can reuse). Using `node:fs/promises` `writeFile` with `JSON.stringify(results, (_, v) => typeof v === "bigint" ? v.toString() : v, 2)` (bigint serializer). The path is an implementation choice — keep it inside `test/bench/` so it's colocated with the benchmark.

> Ref: docs/architecture.md#Key Workflows — WF-1 (benchmark happy path), WF-4 (calldata vs computation decomposition)
> Ref: docs/architecture.md#Error Handling Strategy — `SIG_VALIDATION_SUCCESS`/`SIG_VALIDATION_FAILED` semantics on the validateUserOp return path (benchmark path is handleOps but same codes surface inside)
> Ref: docs/amendments.md#A-001 — gas-capture amendment (BINDING)
> Ref: docs/amendments.md#A-002 — ERC1967Proxy deployment (BINDING)
> Ref: docs/amendments.md#A-003 — SSTORE2 pointer storage (BINDING)
> Ref: docs/amendments.md#A-004 — ML-DSA-44 parameter set (BINDING)
> Ref: docs/concerns.md#C-006 — low-S hardening (BINDING, enabling for AC-2)
> Ref: docs/stories/2-1-ecdsa-account.md — EcdsaAccount setup pattern
> Ref: docs/stories/3-1-falcon-account.md — FalconAccount setup + falcon fixture
> Ref: docs/stories/4-1-mldsa-account.md — MlDsaAccount setup + mldsa fixture

## Verified Interfaces

### `keygen(scheme)` dispatcher
- **Source:** `test/signers/index.ts:45`
- **Signature:** `export function keygen(scheme: "ecdsa" | "falcon" | "mldsa"): Keypair`
- **File hash:** `5f571b4ecbe7d6a709d45df187320a5641c94aa5e2695be649170f6fc1189238`
- **Plan match:** ✓ Matches plan §Interface Contracts

### `signUserOp(scheme, secretKey, userOp, entryPointAddress, chainId)`
- **Source:** `test/signers/index.ts:56`
- **Signature:** `export async function signUserOp(scheme: Scheme, secretKey: Uint8Array, userOp: UnsignedUserOp, entryPointAddress: string, chainId: bigint): Promise<PackedUserOperation>`
- **File hash:** `5f571b4ecbe7d6a709d45df187320a5641c94aa5e2695be649170f6fc1189238`
- **Plan match:** ✓ Matches plan §Interface Contracts

### ECDSA signer (MODIFIED by Task 1 of this story)
- **Source:** `test/signers/ecdsa.ts:33` (`signUserOp`)
- **Signature (current, pre-Task-1):** `export async function signUserOp(secretKey: Uint8Array, userOp: UnsignedUserOp, entryPointAddress: string, chainId: bigint): Promise<PackedUserOperation>` — calls `privateKeyToAccount(…).signMessage({ message: { raw: userOpHash } })` and returns the signature as-is.
- **File hash (pre-Task-1):** `1ef0a14340e06082f5ea4178aa360f31e4669f9fd2aebbe26c188177299c660a`
- **Plan match:** ✓ Matches plan §Interface Contracts. Task 1 of this story adds a low-S normalization step before returning; the exported signature remains byte-compatible (still 65 bytes `r||s||v`, still EIP-191-prefixed). `SimpleAccount._validateSignature` via OZ `ECDSA.recover` accepts either form; the normalization only removes the upper-half-S rejection path.

### Falcon signer
- **Source:** `test/signers/falcon.ts:32` (`keygen`), `:37` (`signUserOp`)
- **Signature:** `keygen` returns `{ publicKey: Uint8Array /* 897 bytes */, secretKey: Uint8Array /* 1281 bytes */ }`; `signUserOp` returns `PackedUserOperation` with `signature` = 1064-byte ZKNOX-encoded `salt(40) || s2_compact(1024)`.
- **File hash:** `b8e63db038d0bf80a5808b47591700a6b07ba899967f1ef1449779af82738e80`
- **Plan match:** ✓

### ML-DSA signer
- **Source:** `test/signers/ml-dsa.ts:26` (`keygen`), `:31` (`signUserOp`)
- **Signature:** `keygen` returns `{ publicKey: Uint8Array /* 1312 bytes */, secretKey: Uint8Array /* 2560 bytes */ }` (ML-DSA-44 per A-004); `signUserOp` returns `PackedUserOperation` with `signature` = 2420-byte noble blob.
- **File hash:** `cdd38b845222974a937a12e4d72ea83d5359c728df29ece4b613799a2aa500bd`
- **Plan match:** ✓ Matches A-004 amended AC-1/AC-2.

### `computeUserOpHash`
- **Source:** `test/signers/userOpHash.ts:20`
- **Signature:** `export function computeUserOpHash(userOp: UnsignedUserOp, entryPointAddress: string, chainId: bigint): \`0x${string}\``
- **File hash:** `b1903d7438791be3ef810a37ecd336d9f9f9c1d2f2baf612b598355d36a21501`
- **Plan match:** ✓ Shared ERC-4337 v0.7 hash helper; tests may prefer `entryPoint.read.getUserOpHash([packed])` for cross-check.

### `deployEntryPoint`
- **Source:** `test/fixtures/entryPoint.ts:27`
- **Signature:** `export async function deployEntryPoint(): Promise<{ entryPoint, publicClient, walletClients }>` via `hre.network.connect()` — each call opens an isolated chain.
- **File hash:** `95104f6690c0d34496cebe738a0bec1b7f23315c540fab9e6458a0136684e2fd`
- **Plan match:** ✓
- **NOTE for benchmark:** deploying the verifier and account on a separate `hre.network.connect()` call from the EntryPoint puts them on different chains. The Falcon/ML-DSA account tests deploy EntryPoint inside their own `setup()` via `viem.deployContract("EntryPoint")` on the shared connection. The benchmark should follow the same single-connection pattern — do NOT call `deployEntryPoint()` from the fixture alongside `deployFalconVerifier(viem)` on a different `viem`.

### `deployFalconVerifier` + `registerPublicKey` (Falcon)
- **Source:** `test/fixtures/falcon.ts:26` (`deployFalconVerifier`), `:31` (`registerPublicKey`)
- **Signature:**
  - `deployFalconVerifier(viem: ViemConnection): Promise<{ falconVerifier }>`
  - `registerPublicKey(falconVerifier, rawPublicKey: Uint8Array, publicClient: PublicClient): Promise<Hex>` — **3-arg form**; requires `publicClient` for the SSTORE2-pointer bytecode existence check at the end.
- **File hash:** `16ee8e7642094ee17314b0f8fae309dd14b77bc83f6c8e036dcb322c9a9b4f5e`
- **Plan match:** ✓

### `deployDilithiumVerifier` + `registerPublicKey` (ML-DSA)
- **Source:** `test/fixtures/mldsa.ts:35` (`deployDilithiumVerifier`), `:45` (`registerPublicKey`)
- **Signature:**
  - `deployDilithiumVerifier(viem?: ViemConnection): Promise<{ dilithiumVerifier, publicClient, walletClients }>` — `viem` optional; if omitted, opens its own connection (see C-008.1 informational).
  - `registerPublicKey(dilithiumVerifier, rawPublicKey: Uint8Array): Promise<Hex>` — **2-arg form**, no `publicClient` parameter (divergence from Falcon; C-008.1/C-008.2 noted informationally — do NOT refactor here).
- **File hash:** `1e2d175423d09cef270b1809c69a48314d1e8b610b46eec1b894c46801e5cd89`
- **Plan match:** ✓

### `EntryPoint.handleOps`
- **Source:** `node_modules/@account-abstraction/contracts/core/EntryPoint.sol:174` (impl), `node_modules/@account-abstraction/contracts/interfaces/IEntryPoint.sol:154` (interface)
- **Signature:** `function handleOps(PackedUserOperation[] calldata ops, address payable beneficiary) public nonReentrant`
- **File hash (impl):** `ddad73961da5bad85f0656d9c8e6e729d36a02854198765d335fb59205a55b9e`
- **File hash (interface):** `06f97dfe27d09b478a1e82855ab57485b11ea68e3804b03e879f184bbc667fb7`
- **Plan match:** ✓ Called via viem as `entryPoint.write.handleOps([[signedOp], beneficiaryAddress])`.

### `EntryPoint.depositTo` (via inherited `StakeManager`)
- **Source:** `node_modules/@account-abstraction/contracts/core/StakeManager.sol:63`
- **Signature:** `function depositTo(address account) public virtual payable`
- **Plan match:** ✓ Called via viem as `entryPoint.write.depositTo([account.address], { value: parseEther("1") })` to fund the account's prefund balance before `handleOps`.

### `EntryPoint.getUserOpHash` (canonical hash for cross-check)
- **Source:** `node_modules/@account-abstraction/contracts/interfaces/IEntryPoint.sol` (defined in interface; implementation in `EntryPoint.sol` via `UserOperationLib`).
- **Signature:** `function getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32)`
- **Plan match:** ✓ Used by Stories 2-1/3-1/4-1 as the authoritative hash cross-check; benchmark may re-use for AC-1 logging.

## Tasks

- [ ] **Task 1: Low-S hardening in `test/signers/ecdsa.ts`** — **PREREQUISITE for AC-2**
  - Maps to: AC-2 (enabling; eliminates the C-006 flake family)
  - Files: `test/signers/ecdsa.ts` (modify), `test/signers/ecdsa.test.ts` (new unit test)
  - After the `account.signMessage({ message: { raw: userOpHash } })` call, before returning, normalize the 65-byte signature to low-S:
    - Parse `r = sigBytes[0..32]`, `s = sigBytes[32..64]`, `v = sigBytes[64]`.
    - secp256k1 curve order: `n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n` and `halfN = n >> 1n`.
    - If `bytesToBigInt(s) > halfN`: replace `s ← bigIntToBytes32(n - s_bigint)` and toggle `v` (`27 ↔ 28`; under EIP-155 variants the same parity flip applies to `v % 2`).
    - Re-concatenate `r || s || v`, return in `signature` field as `0x${hex}`.
  - Unit test `test/signers/ecdsa.test.ts` (new file, do NOT colocate with benchmark):
    - Generate many signatures (e.g., 100) over varied inputs; assert every returned `s` is ≤ `halfN`.
    - Assert that recovering the address from the normalized signature still returns the signer's address (via `recoverAddress` from `viem`).
    - Framework: `node:test` + `node:assert/strict` (established).
  - **Do NOT modify** the exported function signature, the keygen function, or the dispatcher. Consumers remain unchanged.

- [ ] **Task 2: Benchmark harness in `test/bench/gas-benchmark.test.ts`**
  - Maps to: AC-1, AC-2, AC-3, AC-4, AC-5
  - Files: `test/bench/gas-benchmark.test.ts` (new), `test/bench/gas-data.json` (new, produced at test-run time)
  - Directory is greenfield — create `test/bench/`. Matches architecture §Testing Strategy §Test Structure (`test/benchmark/gas-benchmark.test.ts` is the architectural intent; `test/bench/` is the shorter project convention — either is acceptable. Prefer `test/bench/` for consistency with filename brevity; log as Rule 1 style deviation if reviewer prefers `test/benchmark/`).
  - Framework: `node:test` + `node:assert/strict`. Test timeout per `it` block: `{ timeout: 5 * 60_000 }` (matches AC-5).
  - Single `hre.network.connect()` call shared across EntryPoint + verifiers + accounts (follow `test/accounts/mldsa.test.ts:42-49` pattern — cross-fixture network sharing is the documented constraint).
  - For each scheme in `["ecdsa", "falcon", "mldsa"] as const`, per-scheme block wrapped in try/catch:
    1. **Deploy scheme-specific stack:**
       - ECDSA: `viem.deployContract("EcdsaAccount", [entryPoint.address])` → `ERC1967Proxy` with `initialize(aliceAddress)` init-data. `aliceAddress = bytesToHex(alice.publicKey)`.
       - Falcon: `deployFalconVerifier(viem)` → `registerPublicKey(falconVerifier, alice.publicKey, publicClient)` → deploy `FalconAccount` impl with `[entryPoint.address, falconVerifier.address]` → proxy with `initialize(ZERO_ADDRESS, pointerHex)`.
       - ML-DSA: `deployDilithiumVerifier(viem)` → `registerPublicKey(dilithiumVerifier, alice.publicKey)` (2-arg) → deploy `MlDsaAccount` impl → proxy with `initialize(ZERO_ADDRESS, pointerHex)`.
    2. **Fund the account's EntryPoint deposit:** `await entryPoint.write.depositTo([proxy.address], { value: parseEther("1") })` from `walletClients[0]`.
    3. **Build 3 unsigned UserOps** with nonces `0n, 1n, 2n` (other fields identical; `sender = proxy.address`, all gas fields zero bytes32, empty callData/initCode/paymasterAndData).
    4. **Sign each:** `await signUserOp(scheme, alice.secretKey, op, entryPoint.address, chainId)`.
    5. **Submit each via handleOps:** `const hash = await entryPoint.write.handleOps([[signed]], walletClients[0].account.address);` then `const receipt = await publicClient.waitForTransactionReceipt({ hash });` collect `receipt.gasUsed`.
    6. **Compute per-run:**
       - `totalGas = receipt.gasUsed` (bigint)
       - `calldataGas = signatureCalldataGas(signed.signature)` using the helper in Guardrails (16 × nonZero + 4 × zero over `hexToBytes(signed.signature)`)
       - `executionGas = totalGas - calldataGas` (does not subtract base tx 21000 — that remains in the "execution + other calldata" bucket; the decomposition is specifically the per-scheme variable signature portion vs everything else, per WF-4 step 3).
    7. **Variance:** `mean = (r0 + r1 + r2) / 3n`; `max = max(...)`, `min = min(...)`; `variance = Number(max - min) / Number(mean)` (convert for float division). Assert `variance < 0.01` (AC-2).
    8. **Record `BenchResult`** with runs + mean + variance + calldata/execution breakdown (use run 0's totalGas/calldataGas/executionGas for the single-scheme summary — all three runs are expected to match byte-for-byte).
  - Wrap each scheme block in try/catch; on failure push `{ scheme, status: "failed", reason: err.message }` and continue (AC-4).
  - Track wall-clock: `const startMs = performance.now();` at test start; `const elapsedMs = performance.now() - startMs;` at end. Assert `elapsedMs < 5 * 60 * 1000` (AC-5). Log `elapsedMs` unconditionally so Story 5-2 / future gate checks can read the number.
  - Write results to `test/bench/gas-data.json` via `writeFile` + bigint-aware `JSON.stringify` replacer.
  - Assertions summary:
    - `assert.equal(results.length, 3)` — every scheme has a record.
    - For each `status === "ok"` result: `assert.ok(result.variance < 0.01, ...)` — AC-2.
    - For each `status === "ok"` result: `assert.equal(result.totalGas, result.calldataGas + result.executionGas)` — AC-3 arithmetic sanity.
    - `assert.ok(elapsedMs < 300_000, ...)` — AC-5.
    - AC-1 is satisfied by the fact that `receipt.gasUsed` is captured and written into each `BenchResult`.
    - AC-4 is satisfied by the try/catch per-scheme structure plus the `results.length === 3` assertion; add an explicit `it("AC-4: simulated per-scheme failure preserves other schemes' data")` case where one scheme's signature is deliberately corrupted (e.g., zero the first byte) and verify the other two still produce valid `runs: bigint[]` arrays. Keep this as a separate, smaller test (its runtime is well under AC-5's budget).

- [ ] **Task 3: Verification + full gate**
  - Maps to: all ACs (integration)
  - Files: none modified; runs `npm run compile && npm test`.
  - Gate all pre-existing 28 tests still pass (baselines: Stories 1-1, 2-1, 3-1, 3-2, 4-1, 4-2). The ECDSA flake family (C-006 AC-1/AC-3 variants) should be deterministic post-Task-1 — verify the same AC-3 case that previously flaked now passes 3 consecutive runs.
  - New test files: `test/signers/ecdsa.test.ts` (Task 1 unit test) and `test/bench/gas-benchmark.test.ts` (Task 2) pass their full AC set.
  - Confirm `test/bench/gas-data.json` was produced and contains three records (structural sanity for Story 5-2).

## must_haves

truths:
  - "`test/signers/ecdsa.ts` returns signatures with `s ≤ n/2` for every call; given 100 fresh signatures, none have `s > halfN` (unit-tested in `test/signers/ecdsa.test.ts`)"
  - "`test/signers/ecdsa.ts`'s `signUserOp` still returns a 65-byte `r||s||v` in `signature`, and the EIP-191 prefixed message still recovers to the signer's address via viem `recoverAddress`"
  - "`test/bench/gas-benchmark.test.ts` exists, uses `node:test` + `node:assert/strict`, and deploys all three accounts via `ERC1967Proxy` on a single `hre.network.connect()` connection"
  - "For each scheme, the benchmark executes `entryPoint.write.handleOps([[signedOp]], bundlerAddress)` 3 times (with nonces 0/1/2) on the same chain state and records `receipt.gasUsed` for each run"
  - "Per scheme with `status === 'ok'`: `(max(runs) - min(runs)) / mean(runs) < 0.01` (AC-2, variance ratio assertion)"
  - "Per scheme with `status === 'ok'`: `totalGas === calldataGas + executionGas` where `calldataGas = sum(16 if b!=0 else 4 for b in signature_bytes)` (AC-3)"
  - "If one scheme's block throws, the benchmark collects a `{ scheme, status: 'failed', reason }` record for it and still emits `{ status: 'ok' }` records for the other two schemes (AC-4)"
  - "`results.length === 3` at the end of the benchmark run — every scheme has exactly one record, success or failure"
  - "Total wall-clock measured via `performance.now()` is below `5 * 60 * 1000` ms (AC-5)"
  - "Benchmark writes `test/bench/gas-data.json` containing the three `BenchResult` records, bigint-serialized as strings"
  - "All pre-existing tests (Stories 1-1/2-1/3-1/3-2/4-1/4-2) still pass — no regression"
  - "Benchmark does NOT install or reference `hardhat-gas-reporter` anywhere (A-001 binding)"

artifacts:
  - path: "test/signers/ecdsa.ts"
    contains: ["halfN", "bigIntToBytes", "privateKeyToAccount", "signMessage"]
  - path: "test/signers/ecdsa.test.ts"
    contains: ["node:test", "low-S", "halfN"]
  - path: "test/bench/gas-benchmark.test.ts"
    contains: ["handleOps", "waitForTransactionReceipt", "gasUsed", "signatureCalldataGas", "depositTo", "performance.now", "BenchResult"]
  - path: "test/bench/gas-data.json"
    contains: ["ecdsa", "falcon", "mldsa", "runs", "totalGas"]

key_links:
  - pattern: "halfN"
    in: ["test/signers/ecdsa.ts", "test/signers/ecdsa.test.ts"]
  - pattern: "handleOps"
    in: ["test/bench/gas-benchmark.test.ts"]
  - pattern: "waitForTransactionReceipt"
    in: ["test/bench/gas-benchmark.test.ts"]
  - pattern: "depositTo"
    in: ["test/bench/gas-benchmark.test.ts"]
  - pattern: "performance.now"
    in: ["test/bench/gas-benchmark.test.ts"]
  - pattern: "signatureCalldataGas"
    in: ["test/bench/gas-benchmark.test.ts"]
  - pattern: "deployFalconVerifier"
    in: ["test/bench/gas-benchmark.test.ts"]
  - pattern: "deployDilithiumVerifier"
    in: ["test/bench/gas-benchmark.test.ts"]
  - pattern: "ERC1967Proxy"
    in: ["test/bench/gas-benchmark.test.ts"]

## Dev Notes (advisory)

**No new external dependencies.** Zero packages added. Everything is already in `package.json`: `@account-abstraction/contracts@^0.7.0` (EntryPoint, PackedUserOperation), `@noble/post-quantum@^0.6.1` (already consumed via signer modules), `@nomicfoundation/hardhat-toolbox-viem@^5.0.3`, `hardhat@^3.3.0`, `viem@^2.43.0`. No `hardhat-gas-reporter` (forbidden — A-001). No test-assertion library beyond `node:assert/strict`. No new package audit required — reuse Story 1-1's version pins.

**Testing standards (established, reused):** `node:test` + `node:assert/strict`; ESM `.js` extensions on relative imports; fresh keypairs per test (architecture §Test Data); fixture location `test/fixtures/`; new test-file location `test/bench/` (greenfield sibling of `test/accounts/`).

**Timing and flakiness posture:** the `5 * 60_000` ms timeout on each `it` block is a hard ceiling; AC-5's 5-minute budget is the real target. If EDR performance degrades under future HH3 versions, the timeout surfaces it as a test failure rather than a silent hang.

**Why deposit the account (not prefund via testClient):** `handleOps` pulls the prefund via `entryPoint.getSenderStorage[sender].deposit`, not from the account's ETH balance. Using `testClient.setBalance` on the account has no effect on the deposit ledger; `entryPoint.write.depositTo([account.address], { value })` is the correct path. The Story 2-1/3-1/4-1 tests use `testClient.setBalance` on the *EntryPoint* to fund impersonated-EntryPoint calls to `validateUserOp`; that is a different mechanism.

**Bigint JSON serialization:** `JSON.stringify` throws on bigints natively. Use a replacer: `(_, v) => typeof v === "bigint" ? v.toString() : v`. Story 5-2's report generator must reverse this — strings → `BigInt(s)` — but that's Story 5-2's concern, not 5-1's.

**What is NOT in this story:**
- Markdown report generation (Story 5-2).
- README update (Story 5-2).
- PQC test-helper refactor (C-010.1 informational; do not expand).
- Story 3-2/4-2 AC-3 setup optimization (C-010.1 informational; do not touch).
- `hardhat-gas-reporter` (forbidden by A-001).
- Benchmark running against testnets (DD boundary: Local Hardhat Network only).

**Version audit:** All package versions pinned by Story 1-1 are production-suitable for this story — no web-search required. If a downstream version bump is proposed, re-audit at that time.

> Ref: test/accounts/mldsa.test.ts — proxy + single-connection setup reference
> Ref: test/accounts/falcon.test.ts — Falcon proxy + verifier fixture reference
> Ref: test/accounts/ecdsa.test.ts — direct validateUserOp path (baseline for the non-benchmark tests that remain)

## Detected Patterns

Codebase scanned for analogous patterns (Stories 2-1, 3-1, 4-1 `setup()` and test files; `test/fixtures/*`; `test/signers/*`):

| Pattern | Value | Sampled from | Established? |
|---------|-------|-------------|-------------|
| Test runner | `node:test` + `node:assert/strict` | `test/accounts/{ecdsa,falcon,mldsa}.test.ts`, `test/signers/falcon-encoding.test.ts` | ✅ Established |
| ESM import extensions | `.js` suffix on relative imports | all test files | ✅ Established |
| Single network connection | `const connection = await hre.network.connect(); const { viem } = connection;` then deploy all contracts on `viem` | `test/accounts/mldsa.test.ts:42-49`, `test/accounts/falcon.test.ts:40-47` | ✅ Established |
| Proxy deployment | deploy impl → `encodeFunctionData({ abi, functionName: "initialize", args })` → `viem.deployContract("ERC1967Proxy", [impl.address, initData])` → `viem.getContractAt("{Name}Account", proxy.address)` | `test/accounts/{ecdsa,falcon,mldsa}.test.ts` | ✅ Established |
| Verifier fixture shape | `deploy{Scheme}Verifier(viem) → { verifier }`; `registerPublicKey(verifier, rawKey, …) → pointerHex` | `test/fixtures/{falcon,mldsa}.ts` | ⚠ Divergent arity — Falcon `registerPublicKey` takes 3 args (w/ `publicClient`), ML-DSA takes 2. Both inlined in Verified Interfaces above; implementer must call each correctly (C-008.1/C-008.2 informational, do NOT fix here). |
| UnsignedUserOp builder | `function buildUnsignedUserOp(sender): UnsignedUserOp` — zero-initialized non-sender fields | `test/accounts/{ecdsa,falcon,mldsa}.test.ts` (identical bodies) | ✅ Established (candidate for shared helper; scope-deferred per C-010.1) |
| Canonical userOp hash | `entryPoint.read.getUserOpHash([packed])` | `test/accounts/{ecdsa,falcon,mldsa}.test.ts` | ✅ Established (cross-check; optional for benchmark) |
| Test file naming | `*.test.ts` under `test/` | all test files | ✅ Established |
| Test directory for benchmark | n/a — greenfield | — | ⚠ First occurrence — `test/bench/` chosen per Task 2 |

No blocking conflicts. The Falcon/ML-DSA `registerPublicKey` arity divergence (3-arg vs 2-arg) is explicitly inlined in Verified Interfaces so the implementer cannot miswire it.

## Wave Structure

Story 5-1 is Wave 3 (plan §Wave Assignments), running alongside 3-2 and 4-2 (both complete). Dependencies 2-1, 3-1, 4-1 all done.

Internal sub-wave structure — sequential, NOT parallelizable within the story:

- **Sub-wave A:** Task 1 (low-S hardening) — modifies `test/signers/ecdsa.ts` + new unit test. MUST complete before Task 2 or the benchmark's 3-run variance assertion may hit the C-006 flake family.
- **Sub-wave B:** Task 2 (benchmark harness) — depends on Task 1 for deterministic ECDSA signing.
- **Sub-wave C:** Task 3 (compile + full-suite gate) — depends on Tasks 1 and 2.

Wave-independence audit vs Wave 3 siblings (3-2, 4-2, both complete): Story 5-1 touches `test/signers/ecdsa.ts`, `test/signers/ecdsa.test.ts` (new), `test/bench/gas-benchmark.test.ts` (new), `test/bench/gas-data.json` (new, runtime artifact). No conflict with 3-2/4-2's files (`test/accounts/falcon-failures.test.ts`, `test/accounts/mldsa-failures.test.ts`). Low-S hardening in `test/signers/ecdsa.ts` is a behavior-preserving refactor — Stories 2-1 and 3-2/4-2 consumers see byte-compatible signatures (still 65 bytes, still EIP-191 recoverable). No downstream re-verification required beyond Task 3's full-suite gate.
