---
id: "3-2"
slug: falcon-failure-classes
status: complete
created: 2026-04-15
completed_at: 2026-04-15
gate5: pass
---

# Story: Falcon failure-class tests

## User Story
As an engineer, I want Falcon to distinguish malformed from crypto-invalid signatures, so that debugging signature failures is tractable.

## Acceptance Criteria

**Source ACs (verbatim from `docs/plan.md` Story 3-2):**

- AC-1: Given a `FalconAccount` owned by Alice, When Bob signs with his own Falcon keypair, Then `validateUserOp` returns `SIG_VALIDATION_FAILED` (crypto failure against Alice's public key).
- AC-2: Given Alice's valid Falcon signature, When one bit of the signature bytes is flipped (signature remains parseable), Then `validateUserOp` returns `SIG_VALIDATION_FAILED`.
- AC-3: Given a malformed Falcon signature (truncated to 100 bytes or filled with zeros such that `ZKNOX_falcon` decode reverts), When submitted, Then the call reverts with `SignatureMalformed()`.
- AC-4: Test assertions use `expect(...).to.be.revertedWithCustomError(account, 'SignatureMalformed')` for AC-3 and `expect(returnValue).to.equal(1)` for AC-1/AC-2.

**AC-4 translation (binding — A-001):** Amendment A-001 dropped chai in favour of `node:test` + `node:assert/strict`. The plan AC-4 above uses chai/hardhat-chai-matchers phrasing; the implementation MUST use the Node-native equivalents already established by `test/accounts/ecdsa.test.ts` and `test/accounts/mldsa.test.ts`:

- For AC-1 and AC-2 (return value check): `assert.equal(validationData, 1n)` where `validationData = SIG_VALIDATION_FAILED = 1n` (imported from `@account-abstraction/contracts/core/Helpers.sol` on-chain; literal `1n` off-chain — mirror the `SIG_VALIDATION_SUCCESS = 0n` constant already at `test/accounts/falcon.test.ts:33`).
- For AC-3 (revert check): `await assert.rejects(simulateValidateUserOp(...), (err) => { ... })` with a predicate that walks the viem error chain via `err.walk((e) => e instanceof ContractFunctionRevertedError)` and asserts `revert.data?.errorName === "SignatureMalformed"`. This is the same pattern `test/accounts/ecdsa.test.ts:207-233` uses for the ECDSA bit-flip revert path — the only difference is the expected error name.

## Architecture Guardrails

**Amendments are binding.** A-001 (HH3 + viem + `node:test`/`node:assert/strict`), A-002 (ERC1967Proxy deployment), and A-003 (account stores 20-byte SSTORE2 pointer, not raw key) apply as inherited from Story 3-1. No new architecture decisions for this story.

**Test framework (A-001 — BINDING):** `node:test` + `node:assert/strict` only. NO `chai`, NO `hardhat-chai-matchers`, NO `expect(...).to.be.revertedWithCustomError(...)`. The plan AC-4 phrasing is pre-amendment and must be translated per the section above.

**Fresh `ZKNOX_falcon` per setup (DD-9 LOCKED):** Each `setup()` call deploys a new verifier instance. Never reuse across tests — failure-class tests share the same single-connection, single-deployment pattern as Story 3-1's happy path. Mirror the `setup()` helper at `test/accounts/falcon.test.ts:37-75` verbatim.

**Submodule untouched (NFR-5 / DD-3 LOCKED):** Zero modifications to `ETHFALCON/` sources. The revert-on-decode behavior this story asserts (AC-3) is upstream behavior; we consume it, we do not shape it.

**`SignatureMalformed` semantics (inlined from Story 3-1):** `FalconAccount._validateSignature` at `contracts/FalconAccount.sol:73-84` wraps `falconVerifier.verify(publicKey, userOpHash, userOp.signature)` in try/catch. Cryptographic failure → `result != _VERIFY_SELECTOR` → returns `SIG_VALIDATION_FAILED (1)`. Decode/parse failure inside the verifier → Solidity revert → caught → re-thrown as `revert SignatureMalformed()`. AC-1 and AC-2 exercise the first path; AC-3 exercises the second.

**Bit-flip locus (AC-2 parseability — CRITICAL):** `ZKNOX_falcon.verify` reads `sig[0..40]` as the salt and `sig[40..1064]` as 32 big-endian `uint256` words (see `ETHFALCON/src/ZKNOX_falcon.sol:81-122` — assembly path at `_readPubKey`/`_readSig`). Flipping a bit in:

- **Bytes 0..39 (salt region)** → signature remains structurally parseable. `hashToPointNIST(salt, h)` produces a different challenge point, the `(s1, s2)` short-vector check fails cryptographically, `verify` returns `0xFFFFFFFF`, `_validateSignature` returns `1n`. ✓ Safe.
- **Bytes 40..1063 (s2_compact region)** → MOSTLY safe: the 32 `uint256` words are always valid `uint256` decodes, but each 16-bit lane inside a word is later constrained to be `< q (12289)` in the Algorithm-18 canonicity checks. Flipping a high bit in the wrong lane can push a coefficient past `q` and trigger a REVERT inside the verifier, which becomes `SignatureMalformed` instead of `SIG_VALIDATION_FAILED`. **To guarantee AC-2's "still parseable, returns 1n" intent, flip a bit inside the salt region (e.g., `sigBytes[5] ^= 0x01`) — same locus Story 2-1 ECDSA AC-3 uses at `test/accounts/ecdsa.test.ts:195`.**

**Malformed locus (AC-3 — CRITICAL):** The plan offers two phrasings ("truncated to 100 bytes OR filled with zeros"). Pick ONE and justify:

- **Truncation to 100 bytes** (RECOMMENDED): `signature = bytesToHex(new Uint8Array(100))` or `signature = signed.signature.slice(0, 2 + 100 * 2)`. The verifier's assembly-level length check (`sig.length != 1064`) reverts before any coefficient work — cheapest deterministic malformed path.
- **All-zeros 1064 bytes**: `signature = bytesToHex(new Uint8Array(1064))`. Passes length check; fails inside hashToPointNIST/NTT arithmetic OR the `(s1, s2) != 0` short-vector check. Also triggers `SignatureMalformed` via the catch arm, but the revert point is further inside the verifier (slower, harder to reason about).

Recommendation: use truncation. It exercises the same `try/catch → SignatureMalformed` path with the shortest trace.

**AC-1 wrong-key setup:** Register the account with Alice's public key via `registerPublicKey(falconVerifier, alice.publicKey, publicClient)`, then sign with **Bob's** `secretKey` generated by a second `keygen("falcon")` call. The account's stored `publicKey` points at Alice's SSTORE2 pointer; Bob's signature decodes parseably, `hashToPointNIST` runs cleanly, but the short-vector check against Alice's `h` fails cryptographically → `verify` returns `0xFFFFFFFF` → `_validateSignature` returns `1n`.

**Cross-story scope boundary:**
- Gas profiling → Story 5-1 (not here).
- ML-DSA failure classes → Story 4-2 (separate file `test/accounts/mldsa-failures.test.ts` — not yet drafted).
- Invalid public-key at `initialize()` → Story 3-1 concern (belongs to the happy-path story, not here).

**Known flaky:** C-006 (ECDSA AC-1 flake) is out of scope — Falcon does not use `ecrecover` at all. If any pre-existing flake surfaces during this story's test run, it is C-006 and unrelated.

> Ref: docs/amendments.md#A-001 — HH3 + viem + node:test/node:assert/strict (BINDING; translates plan AC-4's chai phrasing)
> Ref: docs/amendments.md#A-002 — ERC1967Proxy account deployment (BINDING; inherited via setup())
> Ref: docs/amendments.md#A-003 — PQC accounts store SSTORE2 pointer (BINDING; inherited)
> Ref: docs/architecture.md#Smart Contract Interfaces — FalconAccount shape; _validateSignature try/catch contract
> Ref: docs/architecture.md#Error Handling Strategy — SignatureMalformed rationale
> Ref: docs/stories/3-1-falcon-account.md — setup(), signer, encoding-bridge conventions this story reuses unmodified
> Ref: docs/concerns.md#C-001 — tolerated ETHFALCON `slen` warning (pass-through during compile)
> Ref: docs/concerns.md#C-006 — ECDSA AC-1 flake (unrelated; do not conflate with Falcon results)
> Ref: docs/concerns.md#C-009 — deferred Story 3-1 code-review items (not blocking)

## Verified Interfaces

### `registerPublicKey(falconVerifier, rawPublicKey, publicClient)`
- **Source:** `test/fixtures/falcon.ts:31-61`
- **Signature:** `export async function registerPublicKey(falconVerifier: Awaited<ReturnType<typeof deployFalconVerifier>>["falconVerifier"], rawPublicKey: Uint8Array, publicClient: PublicClient): Promise<Hex>`
- **File hash:** `16ee8e7642094ee17314b0f8fae309dd14b77bc83f6c8e036dcb322c9a9b4f5e`
- **Behavior:** ABI-encodes the raw 897-byte Falcon key via `encodePublicKeyForZKNOX`, simulates `setKey` to capture the predicted SSTORE2 pointer, broadcasts the write, then asserts the predicted pointer has deployed bytecode via `publicClient.getBytecode({ address: pointerHex })` (hardening against simulate/write address drift).
- **Plan match:** ✓ Matches. Note the 3-parameter form — `publicClient` is required (not optional); the setup must pass the connection's `publicClient` or the bytecode assertion cannot run.

### `deployFalconVerifier(viem)`
- **Source:** `test/fixtures/falcon.ts:26-29`
- **File hash:** (same file as above) `16ee8e7642094ee17314b0f8fae309dd14b77bc83f6c8e036dcb322c9a9b4f5e`
- **Signature:** `export async function deployFalconVerifier(viem: ViemConnection): Promise<{ falconVerifier }>`
- **Behavior:** Deploys a fresh `ZKNOX_falcon` (no constructor args). Must be called from within the SAME `hre.network.connect()`-derived `viem` connection as every other contract in the test (DD-9 + single-connection invariant — `test/accounts/falcon.test.ts:37-42`).
- **Plan match:** ✓ Matches architecture §Smart Contract Interfaces.

### `FalconAccount._validateSignature` (consumed, not modified)
- **Source:** `contracts/FalconAccount.sol:73-84`
- **File hash:** `c9008de9281faa0362c9e15cd1ffec45983566f0604f3f33f44d436d3829f725`
- **Signature (as wrapped by viem at the exposed `validateUserOp` entry point):** `validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) external returns (uint256 validationData)` (inherited from SimpleAccount; calls the override on line 73).
- **Return semantics:** `0` on success, `1` on cryptographic failure (`SIG_VALIDATION_FAILED`). REVERTS with `SignatureMalformed()` if `falconVerifier.verify` itself reverts (malformed input / decode failure). No other exit paths.
- **Plan match:** ✓ Matches Story 3-1 AC-4.

### `keygen("falcon")` (consumed, not modified)
- **Source:** `test/signers/falcon.ts:32-35` (dispatched via `test/signers/index.ts:49-50`)
- **File hash:** `b8e63db038d0bf80a5808b47591700a6b07ba899967f1ef1449779af82738e80` (falcon.ts), `5f571b4ecbe7d6a709d45df187320a5641c94aa5e2695be649170f6fc1189238` (index.ts)
- **Signature:** `keygen(scheme: "falcon"): { publicKey: Uint8Array /* 897 bytes */, secretKey: Uint8Array /* 1281 bytes */ }`
- **Determinism:** noble's `falcon512.keygen()` uses `crypto.getRandomValues` by default — each call produces a fresh keypair. Two back-to-back calls (Alice, Bob) yield statistically distinct keys; no seeding required for AC-1.
- **Plan match:** ✓ Matches plan §Interface Contracts.

### `signUserOp("falcon", secretKey, userOp, entryPointAddress, chainId)` (consumed, not modified)
- **Source:** `test/signers/falcon.ts:37-50` (dispatched via `test/signers/index.ts:66-67`)
- **File hash:** `b8e63db038d0bf80a5808b47591700a6b07ba899967f1ef1449779af82738e80`
- **Signature:** `signUserOp(scheme: "falcon", secretKey: Uint8Array, userOp: UnsignedUserOp, entryPointAddress: string, chainId: bigint): Promise<PackedUserOperation>`
- **Behavior:** Computes `userOpHash` via the shared `computeUserOpHash` helper, calls `falcon512.sign(hexToBytes(userOpHash), secretKey)` to produce a noble-format detached signature, then reshapes it to the 1064-byte `salt(40) || s2_compact(1024)` ZKNOX payload via `encodeSignatureForZKNOX`. Returns the `PackedUserOperation` with `signature` as a `0x`-prefixed hex string of exactly 1064 bytes.
- **Plan match:** ✓ Matches plan §Interface Contracts.

### `encodeSignatureForZKNOX` / `encodePublicKeyForZKNOX` (consumed, reference-only)
- **Source:** `test/signers/falcon-encoding.ts:128-147, 159-192`
- **File hash:** `d305e565e4879d4bb4a517a22be53453544cfcb3f621aba3db41dce53b1607d7`
- **Use:** This story does NOT call the encoders directly. Bit-flipping and truncation operate on the already-encoded `signed.signature` hex (the 1064-byte blob). Listed here only to confirm the encoding pipeline is deterministic and the 1064-byte invariant the bit-flip test relies on is source-truth, not hearsay.

### `test/accounts/falcon.test.ts` reference setup
- **Source:** `test/accounts/falcon.test.ts:37-108`
- **File hash:** `49b90f2e3eeae8176277c9b5588f404789b5cbb2a837e697ec34711cd6a971c3`
- **Use:** Reuse `setup()`, `buildUnsignedUserOp(sender)`, `canonicalUserOpHash(entryPoint, packed)`, and `simulateValidateUserOp(account, entryPointAddress, signed, userOpHash)` verbatim. The failure-class file either imports these helpers from a new shared module OR copies them wholesale — decide at implementation time based on the project's `test/helpers/` convention (currently none exists; inline copy is acceptable, matching the Story 2-1 → 3-1 → 4-1 pattern of self-contained test files).

## Tasks

- [ ] **Task 1: `test/accounts/falcon-failures.test.ts` — author AC-1/AC-2/AC-3 tests**
  - Maps to: AC-1, AC-2, AC-3, AC-4 (translated)
  - Files: `test/accounts/falcon-failures.test.ts` (new)
  - Framework: `node:test` + `node:assert/strict` (A-001). DO NOT import `chai`, `hardhat-chai-matchers`, or any `.to.be.revertedWithCustomError` matcher.
  - Imports to mirror from `test/accounts/falcon.test.ts`: `hre`, `assert`, `{ describe, it }`, `{ encodeFunctionData, hexToBytes, bytesToHex, parseEther, BaseError, ContractFunctionRevertedError }` from viem, `{ deployFalconVerifier, registerPublicKey }` from `../fixtures/falcon.js`, `{ keygen, signUserOp, type PackedUserOperation, type UnsignedUserOp }` from `../signers/index.js`.
  - Constants to mirror: `SIG_VALIDATION_FAILED = 1n`, `ZERO_BYTES32`, `ZERO_ADDRESS` (same literals as the happy-path file — copy the three `const` declarations).
  - `setup()` helper: copy verbatim from `test/accounts/falcon.test.ts:37-75`. Returns `{ entryPoint, account, alice, falconVerifier, chainId, testClient, publicClient }` — but note the happy-path helper does NOT currently return `publicClient`; include it in the return so the bit-flip test can share the connection if a future refactor needs it. (Pure inline copy is also acceptable; add `publicClient` to the return only if helpful.)
  - `buildUnsignedUserOp`, `canonicalUserOpHash`, `simulateValidateUserOp`: copy verbatim from the happy-path file.
  - **AC-1 — wrong key returns 1n:**
    - In setup, the account is initialized with `alice.publicKey`'s pointer. Inside the test, call `keygen("falcon")` a SECOND time to produce `bob`.
    - Build the userOp with `account.address` as sender. Sign with `bob.secretKey`: `const signed = await signUserOp("falcon", bob.secretKey, userOp, entryPoint.address, chainId);`
    - `const userOpHash = await canonicalUserOpHash(entryPoint, signed);`
    - `const validationData = await simulateValidateUserOp(account, entryPoint.address, signed, userOpHash);`
    - `assert.equal(validationData, SIG_VALIDATION_FAILED);` // === 1n
    - Timeout: `{ timeout: 120_000 }` (Falcon verification is slow on HH3 EDR — mirror the happy-path AC-3 timeout).
  - **AC-2 — bit-flip in salt region returns 1n:**
    - Sign normally with `alice.secretKey`, obtain `signed` and `userOpHash` as in the happy path.
    - `const sigBytes = hexToBytes(signed.signature);` — expect `sigBytes.length === 1064`.
    - Flip one bit inside the salt region: `sigBytes[5] ^= 0x01;` (byte 5 is well inside `[0, 40)`). Do NOT flip inside the s2_compact region (`[40, 1064)`) — see Architecture Guardrails "Bit-flip locus" for why.
    - `const corrupted: PackedUserOperation = { ...signed, signature: bytesToHex(sigBytes) };`
    - Call `simulateValidateUserOp(account, entryPoint.address, corrupted, userOpHash)` and assert `validationData === SIG_VALIDATION_FAILED` (1n).
    - Timeout: `{ timeout: 120_000 }`.
    - If the call unexpectedly reverts with `SignatureMalformed` (i.e. the chosen byte turned out to corrupt structure rather than content), the test fails loudly rather than catching and downgrading — that is a signal to re-read the architecture guardrail, not a test-infra bug.
  - **AC-3 — malformed signature reverts with SignatureMalformed:**
    - Build userOp and get a valid `signed` / `userOpHash` as in AC-2 (the signature is discarded; `userOpHash` is still used because it is computed from the unsigned fields the account re-hashes).
    - Truncate: `const malformed: PackedUserOperation = { ...signed, signature: bytesToHex(new Uint8Array(100)) };` (100 zero bytes, ≠ 1064).
    - Assertion (chai-free — the A-001 translation):
      ```ts
      await assert.rejects(
        () => simulateValidateUserOp(account, entryPoint.address, malformed, userOpHash),
        (err: unknown) => {
          if (!(err instanceof BaseError)) throw err;
          const revert = err.walk(
            (e) => e instanceof ContractFunctionRevertedError,
          ) as ContractFunctionRevertedError | null;
          return revert?.data?.errorName === "SignatureMalformed";
        },
      );
      ```
      This is structurally identical to `test/accounts/ecdsa.test.ts:207-233`'s rejection-extraction pattern; only the expected `errorName` differs.
    - Timeout: `{ timeout: 120_000 }`.
  - Suggested `describe` label: `"Story 3-2 — FalconAccount failure classes"`. Suggested `it` labels: `"AC-1: wrong signer returns SIG_VALIDATION_FAILED"`, `"AC-2: bit-flipped signature (salt region) returns SIG_VALIDATION_FAILED"`, `"AC-3: malformed signature reverts with SignatureMalformed"`.

- [ ] **Task 2: Verify against the deployed FalconAccount**
  - Maps to: AC-1, AC-2, AC-3
  - Files: none (runs the Task 1 tests)
  - Run `npm test -- test/accounts/falcon-failures.test.ts` (or the full `npm test`) and confirm all three new tests PASS against the current `contracts/FalconAccount.sol` at commit with file hash `c9008de9281faa0362c9e15cd1ffec45983566f0604f3f33f44d436d3829f725`. No contract changes are expected; the behavior this story asserts was built in Story 3-1.
  - If AC-2 unexpectedly reverts with `SignatureMalformed` instead of returning 1n → re-check the bit-flip locus (must be inside `[0, 40)` salt region, not `[40, 1064)` s2 region). The architecture guardrail explains why.
  - If AC-3 returns 1n instead of reverting → the truncation path is being silently accepted; investigate whether the verifier's length check changed upstream (C-001 re-evaluation trigger). Story 3-2 does NOT modify the verifier regardless.
  - If a pre-existing flake (C-006 ECDSA) surfaces during the run, mark it as baselined — unrelated to Falcon.

- [ ] **Task 3: Compile + full test gate**
  - Maps to: AC-1, AC-2, AC-3, AC-4
  - Run `npm run compile` — only the tolerated ETHFALCON `slen` warning (C-001) may appear. No project-authored warnings.
  - Run `npm test` — verify: (a) Story 1-1 smoke continues to pass; (b) Story 2-1 `ecdsa.test.ts` continues to pass (modulo C-006 flake); (c) Story 3-1 `falcon.test.ts` continues to pass; (d) Story 4-1 `mldsa.test.ts` continues to pass; (e) new Story 3-2 `falcon-failures.test.ts` passes all three tests.
  - Code review prep: no new patterns introduced, no deviations expected. If any structural deviation is discovered during implementation, log under Rule 1/2 of `.claude/rules/code-standards.md` and flag at commit.

## must_haves

truths:
  - "`test/accounts/falcon-failures.test.ts` exists and uses `node:test` + `node:assert/strict` (A-001); imports neither `chai` nor `hardhat-chai-matchers`."
  - "AC-1 test: account initialized with `alice.publicKey` pointer, UserOp signed with a SECOND `keygen(\"falcon\")` keypair's `secretKey` (Bob), and `validateUserOp` via `account.simulate.validateUserOp(..., { account: entryPoint.address })` returns `1n` (`SIG_VALIDATION_FAILED`)."
  - "AC-2 test: Alice signs a valid UserOp, ONE bit of the signature is flipped inside the 40-byte salt region (offset in `[0, 40)` — e.g. `sigBytes[5] ^= 0x01`), signature hex length is still 1064 bytes, and `validateUserOp` returns `1n`."
  - "AC-3 test: signature is replaced with 100 zero bytes (or equivalent length-invariant malformed blob), and `simulateValidateUserOp` is asserted to reject via `assert.rejects(..., predicate)` where the predicate walks the viem error chain with `err.walk((e) => e instanceof ContractFunctionRevertedError)` and requires `revert.data?.errorName === \"SignatureMalformed\"`."
  - "No `contracts/` Solidity files are modified by this story — FalconAccount's failure behavior was defined in Story 3-1 and is consumed here."
  - "No `ETHFALCON/` submodule files are modified (NFR-5); `git diff ETHFALCON/` remains empty after Task 1-3."
  - "`npm run compile` and `npm test` both succeed; the only compile warning is the tolerated ETHFALCON `slen` warning (C-001); no test is `t.skip`-ed, `.todo`-ed, or otherwise silenced."

artifacts:
  - path: "test/accounts/falcon-failures.test.ts"
    contains: ["node:test", "node:assert/strict", "deployFalconVerifier", "registerPublicKey", "keygen", "signUserOp", "SIG_VALIDATION_FAILED", "SignatureMalformed", "ContractFunctionRevertedError", "assert.rejects"]

key_links:
  - pattern: "import assert from \"node:assert/strict\""
    in: ["test/accounts/falcon-failures.test.ts"]
  - pattern: "keygen(\"falcon\")"
    in: ["test/accounts/falcon-failures.test.ts"]
  - pattern: "signUserOp("
    in: ["test/accounts/falcon-failures.test.ts"]
  - pattern: "sigBytes[5] ^="
    in: ["test/accounts/falcon-failures.test.ts"]
  - pattern: "new Uint8Array(100)"
    in: ["test/accounts/falcon-failures.test.ts"]
  - pattern: "errorName === \"SignatureMalformed\""
    in: ["test/accounts/falcon-failures.test.ts"]

## Dev Notes (advisory)

- **Single network connection per test:** mirror the `setup()` at `test/accounts/falcon.test.ts:37-75`. A second `hre.network.connect()` inside the same test would produce a fresh chain with no deployed verifier — the staticcall returns empty data, decode fails, and `SignatureMalformed` fires spuriously. The same invariant documented at `test/accounts/mldsa.test.ts:37-46` applies here.
- **`simulate.validateUserOp`, not `write`:** the account's `validateUserOp` return value is only observable via `simulate` (with `{ account: entryPoint.address }` impersonation). `write` propagates through `FailedOp` reverts rather than the raw return. Established Story 2-1, reused Story 3-1/4-1.
- **Timeout budget:** Falcon on-chain verification under HH3 EDR runs slow — `{ timeout: 120_000 }` per test is the proven ceiling from `test/accounts/falcon.test.ts:132`. Three tests × 120s worst-case = 6 minutes wall-clock for this file; still well under the Story 5-1 NFR-4 suite-total budget.
- **Bob's keypair seeding:** no explicit seeding required. noble's `falcon512.keygen()` draws from `crypto.getRandomValues`; collision with Alice is ~1 in 2^(pk-entropy) — negligible.
- **Why Story 3-1 already ensured AC-3's revert path works:** Story 3-1 AC-4's structural assertion `source.match(/try\s+falconVerifier\.verify[\s\S]{0,400}?\}\s*catch[\s\S]{0,200}?SignatureMalformed/)` (at `test/accounts/falcon.test.ts:171-174`) was explicitly tightened during Story 3-1 code review precisely so Story 3-2's AC-3 would have a static-structural guarantee backing its runtime assertion. Trust the structural guard; this story adds the runtime.
- **File placement:** new test file lives at `test/accounts/falcon-failures.test.ts` alongside `falcon.test.ts`. Do not add to `falcon.test.ts` itself — the PD-2 wave-isolation principle keeps happy-path and failure-class in separate files so future parallelism isn't blocked by intra-file merge pressure.

> Ref: test/accounts/ecdsa.test.ts#AC-3 — ContractFunctionRevertedError walk pattern (reused verbatim for AC-3)
> Ref: test/accounts/falcon.test.ts#setup — helper shape copied into the new failure-class file

## Detected Patterns

| Pattern | Value | Sampled from | Established? |
|---------|-------|--------------|-------------|
| Test framework | `node:test` + `node:assert/strict` | `test/accounts/ecdsa.test.ts`, `test/accounts/falcon.test.ts`, `test/accounts/mldsa.test.ts` | ✅ Established (A-001) |
| Test file naming | `{scheme}.test.ts` for happy-path, `{scheme}-failures.test.ts` for failure classes | `test/accounts/falcon.test.ts` (happy); 3-2 introduces `-failures` suffix by convention mirroring failure-class scope | ✅ Established (happy-path naming); new `-failures` suffix is the natural extension — single-file-per-scope convention |
| Account deploy | `ERC1967Proxy` over implementation (A-002) | `test/accounts/ecdsa.test.ts:~`, `test/accounts/falcon.test.ts:51-64`, `test/accounts/mldsa.test.ts:54-67` | ✅ Established |
| EntryPoint impersonation | `testClient.impersonateAccount` + `setBalance(parseEther("1"))` + `simulate.validateUserOp(..., { account: entryPoint.address })` | `test/accounts/falcon.test.ts:66-107`, `test/accounts/mldsa.test.ts:69-110` | ✅ Established |
| Revert extraction | `err.walk((e) => e instanceof ContractFunctionRevertedError)` → `revert?.data?.errorName` | `test/accounts/ecdsa.test.ts:215-233` | ✅ Established |
| Bit-flip for "still parseable" | `sigBytes[5] ^= 0x01` (byte 5 chosen inside a low-risk region) | `test/accounts/ecdsa.test.ts:195` | ✅ Established |
| Per-test `{ timeout: 120_000 }` for PQC | 120s ceiling on any AC that runs on-chain PQC verification | `test/accounts/falcon.test.ts:132`, `test/accounts/mldsa.test.ts:135` | ✅ Established |
| Fresh verifier per `setup()` | `await viem.deployContract("ZKNOX_falcon")` inside setup, never hoisted | `test/fixtures/falcon.ts:27`, `test/accounts/falcon.test.ts:46` | ✅ Established (DD-9 LOCKED) |

No conflicts detected. All patterns are drawn from at least two analogous files in the existing suite.

## Wave Structure

Single wave (3 tasks, strict sequence):

- **Task 1** — author the test file (authoring work, no dependencies).
- **Task 2** — run the new file against current `FalconAccount.sol` (depends on Task 1's output file).
- **Task 3** — full compile + full `npm test` gate (depends on Task 2 passing).

No parallelism opportunity — the three tasks are linear. This story is small (one new file, three tests) and does not warrant sub-task fan-out.

## Inlined-vs-Referenced quality signal

Inlined (rules 1-2 of the Inline Decision List — correctness-critical):
- AC-4 translation from chai to `node:test` + `assert.rejects` + `ContractFunctionRevertedError` walk (without this, the story would propose chai syntax forbidden by A-001).
- Bit-flip locus constraint (AC-2): salt region `[0, 40)` vs s2_compact region `[40, 1064)` with the parseability trade-off — mis-locating the flip converts AC-2 into AC-3 and the test silently inverts meaning.
- Malformed choice (AC-3): truncation-to-100-bytes chosen over all-zeros-1064, with justification (shortest trace into the revert path).
- AC-1 setup detail: second `keygen("falcon")` call for Bob with the account registered under Alice's pointer — the exact shape of "crypto failure against a different key".
- `SignatureMalformed` semantic boundary (crypto fail → 1n vs decode fail → revert) — the whole story hinges on this distinction.
- `registerPublicKey` 3-parameter signature (fixture now requires `publicClient`) — mis-reading this as 2-arg would break the setup silently.
- Node-native rejection-extraction snippet — reproduced inline because the chai-free form is not obvious and is load-bearing for AC-3.

Referenced via `> Ref:` (rules 3-5 — discoverable):
- FalconAccount contract shape (lives in 3-1's Architecture Guardrails and the source itself).
- SimpleAccount proxy patterns (inherited from A-002).
- `ZKNOX_falcon.verify` assembly-level behavior (upstream submodule).
- Compile-warnings gate (Story 1-1 convention).
- Shared test helpers' internals (`computeUserOpHash`, `encodeSignatureForZKNOX`) — consumed, not analyzed.
- Pattern precedents: single-connection invariant, impersonation, per-test timeouts — all live in sibling test files and are Codebase Scan "✅ Established".
