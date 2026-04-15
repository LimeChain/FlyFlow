---
id: "4-2"
slug: mldsa-failure-classes
title: "ML-DSA failure-class tests"
size: S
epic: 4
wave: 3
status: complete
dependencies: ["4-1"]
created: 2026-04-15
completed_at: 2026-04-15
gate5: pass
---

# Story: ML-DSA failure-class tests

## User Story
As an engineer, I want ML-DSA to distinguish malformed from crypto-invalid signatures, so that debugging signature failures is tractable.

## Acceptance Criteria

**Source ACs (verbatim from `docs/plan.md` Story 4-2):**

- AC-1: Given an `MlDsaAccount` owned by Alice, When Bob signs with his own ML-DSA keypair, Then `validateUserOp` returns `SIG_VALIDATION_FAILED`.
- AC-2: Given Alice's valid ML-DSA signature, When byte 0 is bit-flipped, Then `validateUserOp` returns `SIG_VALIDATION_FAILED`.
- AC-3: Given a malformed ML-DSA signature (truncated or bad encoding), When submitted, Then the call reverts with `SignatureMalformed()`.

**Plan-AC-4 is absent for Story 4-2** (the plan stops at AC-3 — contrast Story 3-2, which carried a plan AC-4 describing chai-style assertion syntax that A-001 later invalidated). The assertion-framework constraint still binds via A-001: `node:test` + `node:assert/strict` only; no chai, no `hardhat-chai-matchers`. The assertion mechanics are inlined under Tasks.

**AC-2 byte-offset clarification (BINDING — do not interpret "byte 0" literally):** The plan phrase "byte 0 is bit-flipped" is a description of the failure class ("flip a bit somewhere in the signature and confirm it still decodes") not a literal offset requirement. Flipping at offset 0 is inside the 32-byte `cTilde` region and is safe (see Architecture Guardrails — "Bit-flip locus"), but Story 3-2 established byte 5 as the precedent flip offset ("well inside a hash-only region, not adjacent to any length/framing byte"). **This story flips `sigBytes[5] ^= 0x01`** — byte 5 is inside cTilde's [0, 32) hash region and is the documented analogue of Falcon's byte-5-in-salt locus. If the implementer prefers byte 0 for literal plan compliance, that is equally correct (both are in cTilde); the story file standardizes on byte 5 so the test mirrors `test/accounts/falcon-failures.test.ts:179` structurally.

## Architecture Guardrails

**Amendments are binding.** A-001 (HH3 + viem + `node:test`/`node:assert/strict`), A-002 (ERC1967Proxy deployment), A-003 (account stores 20-byte SSTORE2 pointer), and A-004 (ML-DSA-44 parameter set) all apply — inherited from Story 4-1. No new architecture decisions for this story.

**Test framework (A-001 — BINDING):** `node:test` + `node:assert/strict` only. NO `chai`, NO `hardhat-chai-matchers`, NO `expect(...).to.be.revertedWithCustomError(...)`.

**Fresh `ZKNOX_dilithium` per setup (DD-9 LOCKED):** Each `setup()` call deploys a new verifier instance. Never reuse across tests — failure-class tests share the same single-connection, single-deployment pattern as Story 4-1's happy path. Mirror the `setup()` helper at `test/accounts/mldsa.test.ts:36-78` verbatim.

**Submodule untouched (NFR-5 / DD-3 LOCKED):** Zero modifications to `ETHDILITHIUM/` or `ETHFALCON/` sources. The revert-on-slice behavior this story asserts (AC-3) is upstream behavior; we consume it.

**ML-DSA-44 signature layout (A-004 + ZKNOX_dilithium.sol:80 — INLINED because the bit-flip reasoning hinges on it):** the 2,420-byte signature blob this story bit-flips and truncates is laid out as:

| Region | Offset | Length | Role in `verifyInternal` |
|--------|--------|--------|--------------------------|
| `cTilde` | `[0, 32)` | 32 B | Fiat-Shamir challenge hash. Input to `sampleInBallNist(cTilde, TAU, q)` (line 145) and compared against the recomputed `finalHash` (line 166). NEVER fed through a norm/range check. |
| `z` | `[32, 2336)` | 2,304 B | Bit-packed response polynomial vector (l=4 polys × 256 coeffs × 18 bits = 2,304 bytes under GAMMA_1=2^17). `unpackZ` requires `length >= 2304` and reverts on shortfall (`ZKNOX_dilithium_core.sol:104`). Decoded coefficients are z-norm-checked in assembly against `GAMMA_1 - BETA` (`ZKNOX_dilithium.sol:~128` — fails soft, returns `false`). |
| `h` | `[2336, 2420)` | 84 B | Hint vector. `unpackH` returns `(false, h)` on malformed hints (soft fail, no revert). |

**`SignatureMalformed` semantics (inlined from Story 4-1):** `MlDsaAccount._validateSignature` at `contracts/MlDsaAccount.sol:76-87` wraps `dilithiumVerifier.verify(publicKey, userOpHash, userOp.signature)` in try/catch. Cryptographic failure → `result != _VERIFY_SELECTOR` → returns `SIG_VALIDATION_FAILED (1)`. Slice/decode failure inside the verifier → Solidity revert → caught → re-thrown as `revert SignatureMalformed()`. AC-1 and AC-2 exercise the first path; AC-3 exercises the second.

**Bit-flip locus (AC-2 parseability — CRITICAL):** the flip MUST land inside the cTilde region `[0, 32)` for AC-2 to honor its "still parseable, returns `SIG_VALIDATION_FAILED`" intent:

- **Bytes 0..31 (cTilde)** → signature remains structurally parseable. `slice(signature, 0, 32)` succeeds, `unpackZ` decodes normally (bits in [32..2336) unchanged), `unpackH` decodes normally. A different `cTilde` feeds `sampleInBallNist` → different challenge polynomial `c` → `A*z - c*t1` reconstruction mismatches → `finalHash != bytes32(cTilde)` (line 166) → `verifyInternal` returns `false` → external `verify` returns `0xFFFFFFFF` → `_validateSignature` returns `1n`. ✓ Safe.
- **Bytes 32..2335 (z region)** → MOSTLY safe (all z-coefficient checks are soft failures), but flipping high bits inside an 18-bit coefficient lane can push `alteredCoeff` past the `2*GAMMA_1` implicit range expected by `alteredCoeff < _gamma1 ? _gamma1 - alteredCoeff : _q + _gamma1 - alteredCoeff` (`ZKNOX_dilithium_core.sol:120`). Result is still `false`, not revert — so actually safe. But the story stays inside cTilde for symmetry with the Falcon precedent.
- **Bytes 2336..2419 (h region)** → RISKY. `unpackH`'s `omegaVal` ordering checks (`hBytes[j] <= hBytes[j-1]` at `ZKNOX_dilithium_core.sol:53`) return `(false, h)`, which is soft — `dilithiumCore1` propagates `foo=false`, `verifyInternal` returns `false`. Also safe mechanically. But less obviously so under inspection.
- **Outside [0, 2420) (truncation / extension)** → TRIGGERS REVERT. `slice(signature, 2336, 84)` reverts on OOB when `length < 2420`; `slice(signature, 32, 2304)` reverts when `length < 2336`. Both paths reach the `MlDsaAccount` catch arm → `SignatureMalformed`. **This is what AC-3 exercises.**

Recommendation: **flip `sigBytes[5] ^= 0x01`** — byte 5 is well inside cTilde `[0, 32)`, mirrors Story 3-2 / ECDSA byte-5 locus conventions, and maximally separates the test from any slice/length boundary.

**Malformed locus (AC-3 — CRITICAL):** Use **100 zero bytes** as the malformed signature (`bytesToHex(new Uint8Array(100))`). Reasoning:

- `ZKNOX_dilithium.verify` (line 69) begins by assembly-reading the 20-byte pk pointer (not signature-length-dependent), then executes `slice(signature, 0, 32)` on a 100-byte input (succeeds), then `slice(signature, 32, 2304)` — this tries to read 2,304 bytes starting at offset 32 from a 100-byte buffer and REVERTS in the `BytesLib.slice` bounds check. The revert propagates through the outer `try/catch` in `MlDsaAccount._validateSignature` which re-throws as `SignatureMalformed()`. Shortest-trace malformed path available — identical pattern to Story 3-2's AC-3 (100-zero-bytes for Falcon).
- Other malformed candidates considered and rejected: a full-length 2,420-byte all-zeros blob would parse through `slice`, succeed `unpackZ` (`inputBytes.length == 2304 >= requiredBytes`), and then fail the `omegaVal < kIdx` check in `unpackH` to return `false` — i.e. collapse into AC-2 (return `1n`) instead of AC-3 (revert). The 100-byte truncation path is the only length-invariant malformed candidate that definitively hits the revert arm.

**AC-1 wrong-key setup:** Register the account with Alice's public key via `registerPublicKey(dilithiumVerifier, alice.publicKey)`, then sign with **Bob's** `secretKey` generated by a second `keygen("mldsa")` call. The account's stored `publicKey` points at Alice's SSTORE2 pointer; Bob's signature decodes parseably, `sampleInBallNist` runs cleanly against Bob-derived `cTilde`, but the `A*z - c*t1` reconstruction against Alice's stored `aHat`/`t1` produces a different `finalHash`, line-166 comparison fails → `verifyInternal` returns `false` → external `verify` returns `0xFFFFFFFF` → `_validateSignature` returns `1n`.

**Cross-story scope boundary:**
- Gas profiling → Story 5-1 (not here).
- Falcon failure classes → Story 3-2 (done — `test/accounts/falcon-failures.test.ts`).
- Invalid public-key at `initialize()` → Story 4-1 concern (belongs to the happy-path story, not here).

**Known flaky:** C-006 (ECDSA AC-1 flake) is out of scope — ML-DSA does not use `ecrecover` at all. If any pre-existing flake surfaces during this story's test run, it is C-006 and unrelated.

> Ref: docs/amendments.md#A-001 — HH3 + viem + node:test/node:assert/strict (BINDING; translates any plan chai phrasing)
> Ref: docs/amendments.md#A-002 — ERC1967Proxy account deployment (BINDING; inherited via setup())
> Ref: docs/amendments.md#A-003 — PQC accounts store SSTORE2 pointer (BINDING; inherited)
> Ref: docs/amendments.md#A-004 — ML-DSA-44 parameter set, 2,420-byte signature (BINDING; determines the layout above)
> Ref: docs/architecture.md#Smart Contract Interfaces — MlDsaAccount shape; _validateSignature try/catch contract
> Ref: docs/architecture.md#Error Handling Strategy — SignatureMalformed rationale
> Ref: docs/stories/4-1-mldsa-account.md — setup(), signer, encoding-bridge conventions this story reuses unmodified
> Ref: docs/stories/3-2-falcon-failure-classes.md — the sibling Falcon failure-class story this one mirrors in shape
> Ref: docs/concerns.md#C-001 — tolerated ETHFALCON `slen` warning (pass-through during compile)
> Ref: docs/concerns.md#C-006 — ECDSA AC-1 flake (unrelated; do not conflate with ML-DSA results)
> Ref: docs/concerns.md#C-008 — deferred Story 4-1 code-review items (not blocking; see Fixture-divergence note)
> Ref: docs/concerns.md#C-010 — deferred Story 3-2 code-review item (AC-3 predicate binding pattern this story reuses)

## Verified Interfaces

### `deployDilithiumVerifier(viem?)`
- **Source:** `test/fixtures/mldsa.ts:35-43`
- **File hash:** `1e2d175423d09cef270b1809c69a48314d1e8b610b46eec1b894c46801e5cd89`
- **Signature:** `export async function deployDilithiumVerifier(viem?: ViemConnection): Promise<{ dilithiumVerifier, publicClient, walletClients }>`
- **Behavior:** Deploys a fresh `ZKNOX_dilithium` (no constructor args). Optional `viem` parameter allows the caller to inject an existing connection so every contract lands on the same HH3 chain (DD-9 + single-connection invariant). Story 4-1's `setup()` passes `viem` explicitly.
- **Plan match:** ✓ Matches. Use the `viem` override in `setup()` — pass the connection's `viem` so `EntryPoint`, the verifier, the proxy, and the account all share one chain.

### `registerPublicKey(dilithiumVerifier, rawPublicKey)` ⚠ DIVERGES from Falcon equivalent
- **Source:** `test/fixtures/mldsa.ts:45-69`
- **File hash:** `1e2d175423d09cef270b1809c69a48314d1e8b610b46eec1b894c46801e5cd89`
- **Signature:** `export async function registerPublicKey(dilithiumVerifier, rawPublicKey: Uint8Array): Promise<Hex>` — **2 arguments** (no `publicClient`).
- **Behavior:** ABI-encodes the 1,312-byte NIST key via `preparePublicKeyForDeployment` into the `(aHatEncoded, tr, t1Encoded)` tuple, simulates `setKey` to capture the predicted SSTORE2 pointer, broadcasts the write, then asserts the returned pointer has `length === 20` bytes (a structural tautology given `abi.encodePacked(address)`).
- **Plan match:** ✓ Matches A-003.
- **⚠ Fixture divergence from Falcon (for implementer awareness):** `test/fixtures/falcon.ts:registerPublicKey` is a 3-argument form `(falconVerifier, rawPublicKey, publicClient)` that additionally asserts the predicted pointer has deployed bytecode via `publicClient.getBytecode({ address })`. That hardening was added during Story 3-1 review to guard against simulate/write address drift. The ML-DSA fixture has NOT been updated to match — C-008.1 and C-008.2 track the same divergence.
  - **Options at implementation time (implementer's deviation call, not this story's):**
    - (a) Mirror the Falcon hardening: change `registerPublicKey` to `(dilithiumVerifier, rawPublicKey, publicClient)` and add a `getBytecode` assertion. This is a Rule 2 moderate deviation (changes a fixture signature consumed by `test/accounts/mldsa.test.ts:52`). Requires updating the Story 4-1 happy-path callsite in the same commit to keep `npm test` green. Resolves C-008.1/C-008.2 partially.
    - (b) Leave the fixture at 2 args for this story and log a concern update noting that C-008.1/C-008.2 now also pre-date a test-file that could have benefited from the hardening. Zero-risk, zero-scope.
  - **Story 4-2 default:** option (b). Story 4-2's ACs do not require the bytecode hardening — the tests exercise failure paths where `setKey` has already succeeded before the test's assertions run. If the implementer picks (a) anyway, flag as Rule 2 at commit time.

### `MlDsaAccount._validateSignature` (consumed, not modified)
- **Source:** `contracts/MlDsaAccount.sol:76-87`
- **File hash:** `69618d4b80cac77e4d15118a3f9c1917afa29a3e6cdb251370e3888b84802edf`
- **Signature (at the exposed `validateUserOp` entry point):** `validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) external returns (uint256 validationData)` (inherited from SimpleAccount; calls the override on line 76).
- **Return semantics:** `0` on success, `1` on cryptographic failure (`SIG_VALIDATION_FAILED`). REVERTS with `SignatureMalformed()` if `dilithiumVerifier.verify` itself reverts (malformed input / slice OOB). No other exit paths.
- **`SignatureMalformed` custom error:** declared at `contracts/MlDsaAccount.sol:24` — confirmed present via Story 4-1 AC-4 (structural grep at `test/accounts/mldsa.test.ts:179-182`).
- **Plan match:** ✓ Matches Story 4-1 AC-4.

### `keygen("mldsa")` (consumed, not modified)
- **Source:** `test/signers/ml-dsa.ts:26-29` (dispatched via `test/signers/index.ts:51-52`)
- **File hashes:** `cdd38b845222974a937a12e4d72ea83d5359c728df29ece4b613799a2aa500bd` (ml-dsa.ts), `5f571b4ecbe7d6a709d45df187320a5641c94aa5e2695be649170f6fc1189238` (index.ts)
- **Signature:** `keygen(scheme: "mldsa"): { publicKey: Uint8Array /* 1312 bytes */, secretKey: Uint8Array /* 2560 bytes */ }`
- **Determinism:** noble's `ml_dsa44.keygen()` uses `crypto.getRandomValues` by default — each call produces a fresh keypair. Two back-to-back calls (Alice, Bob) yield statistically distinct keys; no seeding required for AC-1.
- **Plan match:** ✓ Matches plan §Interface Contracts (as amended by A-004).

### `signUserOp("mldsa", secretKey, userOp, entryPointAddress, chainId)` (consumed, not modified)
- **Source:** `test/signers/ml-dsa.ts:31-44` (dispatched via `test/signers/index.ts:68-69`)
- **File hash:** `cdd38b845222974a937a12e4d72ea83d5359c728df29ece4b613799a2aa500bd`
- **Signature:** `signUserOp(scheme: "mldsa", secretKey: Uint8Array, userOp: UnsignedUserOp, entryPointAddress: string, chainId: bigint): Promise<PackedUserOperation>`
- **Behavior:** Computes `userOpHash` via the shared `computeUserOpHash` helper, calls `ml_dsa44.sign(hexToBytes(userOpHash), secretKey)` to produce the noble-format 2,420-byte `cTilde(32)||z(2304)||h(84)` blob (byte-compatible with ZKNOX's `slice` layout — no encoding bridge needed on the signature side). Returns the `PackedUserOperation` with `signature` as a `0x`-prefixed hex string of exactly 2,420 bytes.
- **Plan match:** ✓ Matches plan §Interface Contracts (as amended by A-004).

### `EntryPoint.getUserOpHash` (consumed, not modified)
- **Source:** `@account-abstraction/contracts/core/EntryPoint.sol` (v0.7, via npm — submodule-equivalent)
- **Signature (as exposed through viem):** `entryPoint.read.getUserOpHash([packed: PackedUserOperation]): Promise<0x${string}>` — wraps the Solidity `getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32)`.
- **Behavior:** Hashes the non-signature fields of the UserOp together with the EntryPoint address and chain ID. The `signature` field is NOT part of the hash, which is why AC-3 can replace the signature with zeros while keeping the `userOpHash` computed from the signed-but-discarded helper — see C-010.1 on the Falcon side for why this is a mild inefficiency rather than a correctness issue.
- **Plan match:** ✓ Matches ERC-4337 v0.7 EntryPoint.

### `test/accounts/mldsa.test.ts` reference setup
- **Source:** `test/accounts/mldsa.test.ts:36-111`
- **File hash:** `cd255649edd5d78b3706ddc48ac1e1e675db37b34260a7cb061f38d4677c9307`
- **Use:** Reuse `setup()`, `buildUnsignedUserOp(sender)`, `canonicalUserOpHash(entryPoint, packed)`, and `simulateValidateUserOp(account, entryPointAddress, signed, userOpHash)` verbatim. The failure-class file inlines copies of these helpers — matching the Story 2-1 → 3-1 → 3-2 → 4-1 pattern of self-contained test files (no `test/helpers/` shared module exists yet; PD-2 wave-isolation prefers per-file copies over cross-file helper coupling).

## Tasks

- [ ] **Task 1: `test/accounts/mldsa-failures.test.ts` — author AC-1/AC-2/AC-3 tests**
  - Maps to: AC-1, AC-2, AC-3
  - Files: `test/accounts/mldsa-failures.test.ts` (new)
  - Framework: `node:test` + `node:assert/strict` (A-001). DO NOT import `chai`, `hardhat-chai-matchers`, or any `.to.be.revertedWithCustomError` matcher.
  - Imports to mirror from `test/accounts/mldsa.test.ts` and `test/accounts/falcon-failures.test.ts`: `hre`, `assert`, `{ describe, it }`, `{ encodeFunctionData, hexToBytes, bytesToHex, parseEther, BaseError, ContractFunctionRevertedError }` from viem, `{ deployDilithiumVerifier, registerPublicKey }` from `../fixtures/mldsa.js`, `{ keygen, signUserOp, type PackedUserOperation, type UnsignedUserOp }` from `../signers/index.js`.
  - Constants to mirror (copy verbatim): `SIG_VALIDATION_FAILED = 1n`, `ZERO_BYTES32`, `ZERO_ADDRESS`.
  - `setup()` helper: copy verbatim from `test/accounts/mldsa.test.ts:36-78`. Returns `{ entryPoint, account, alice, dilithiumVerifier, chainId, testClient }`. (No need to thread `publicClient` into the return — AC-2/AC-3 don't use it; keep the helper shape identical to the happy-path file.)
  - `buildUnsignedUserOp`, `canonicalUserOpHash`, `simulateValidateUserOp`: copy verbatim from the happy-path file (lines 80-111).
  - **AC-1 — wrong key returns 1n:**
    - In `setup()`, the account is initialized with Alice's pointer. Inside the test, call `keygen("mldsa")` a SECOND time to produce `bob`.
    - Build the userOp with `account.address` as sender. Sign with `bob.secretKey`: `const signed = await signUserOp("mldsa", bob.secretKey, userOp, entryPoint.address, chainId);`
    - `const userOpHash = await canonicalUserOpHash(entryPoint, signed);`
    - `const validationData = await simulateValidateUserOp(account, entryPoint.address, signed, userOpHash);`
    - `assert.equal(validationData, SIG_VALIDATION_FAILED);` // === 1n
    - Timeout: `{ timeout: 120_000 }` (ML-DSA on-chain verification is slow under HH3 EDR — mirror the happy-path AC-3 timeout at `test/accounts/mldsa.test.ts:135`).
  - **AC-2 — bit-flip in cTilde region returns 1n:**
    - Sign normally with `alice.secretKey`, obtain `signed` and `userOpHash` as in the happy path.
    - `const sigBytes = hexToBytes(signed.signature);` — expect `sigBytes.length === 2420`.
    - Flip one bit inside the cTilde region: `sigBytes[5] ^= 0x01;` (byte 5 is well inside `[0, 32)`). Do NOT flip inside `[32, 2420)` — see Architecture Guardrails "Bit-flip locus" for why cTilde is the canonical safe region.
    - `const corrupted: PackedUserOperation = { ...signed, signature: bytesToHex(sigBytes) };`
    - Call `simulateValidateUserOp(account, entryPoint.address, corrupted, userOpHash)` and assert `validationData === SIG_VALIDATION_FAILED` (1n).
    - Timeout: `{ timeout: 120_000 }`.
    - If the call unexpectedly reverts with `SignatureMalformed` (i.e. the chosen byte turned out to corrupt framing), the test fails loudly rather than catching and downgrading — that is a signal to re-read the architecture guardrail, not a test-infra bug.
  - **AC-3 — malformed signature reverts with SignatureMalformed:**
    - Build userOp and get a valid `signed` / `userOpHash` as in AC-2 (the signature is discarded; `userOpHash` is still used because EntryPoint's `getUserOpHash` hashes only non-signature fields).
    - Truncate: `const malformed: PackedUserOperation = { ...signed, signature: bytesToHex(new Uint8Array(100)) };` (100 zero bytes, ≠ 2420). The verifier's `slice(signature, 32, 2304)` at `ZKNOX_dilithium.sol:80` reverts on OOB; `MlDsaAccount`'s try/catch translates it to `SignatureMalformed()`.
    - Before calling `simulateValidateUserOp`, capture `const accountAddress = account.address.toLowerCase();` — needed for the HH3 EDR fallback path in the predicate (see below).
    - Assertion (chai-free — dual-path predicate proven in Story 3-2 under HH3 EDR):
      ```ts
      await assert.rejects(
        () =>
          simulateValidateUserOp(
            account,
            entryPoint.address,
            malformed,
            userOpHash,
          ),
        (err: unknown) => {
          if (!(err instanceof BaseError)) throw err;
          // Canonical viem path: ContractFunctionRevertedError with a decoded
          // `data.errorName`. Populated when viem's ABI-aware decoder runs.
          const revert = err.walk(
            (e) => e instanceof ContractFunctionRevertedError,
          ) as ContractFunctionRevertedError | null;
          if (revert?.data?.errorName === "SignatureMalformed") return true;
          // HH3 EDR path: the revert surfaces as a `SolidityError` at the chain
          // tail and viem's decoder doesn't populate `errorName`, but the EDR
          // message text deterministically contains "SignatureMalformed()".
          // Bind the match to the account-under-test's address so that the
          // co-defined `SignatureMalformed()` in FalconAccount (same selector,
          // different contract) can't spuriously satisfy this predicate if the
          // error chain's contract attribution is ever fuzzy.
          const message = err.message.toLowerCase();
          return (
            /custom error 'signaturemalformed\(\)'/.test(message) &&
            message.includes(accountAddress)
          );
        },
      );
      ```
      This is structurally identical to `test/accounts/falcon-failures.test.ts:221-250`'s rejection-extraction pattern — the expected `errorName` is the same (`SignatureMalformed`) because both `FalconAccount` and `MlDsaAccount` declare the same custom error name (different contracts, but the selector-form string is identical — hence the origin-contract binding).
    - Timeout: `{ timeout: 120_000 }`.
  - Suggested `describe` label: `"Story 4-2 — MlDsaAccount failure classes"`. Suggested `it` labels: `"AC-1: wrong signer returns SIG_VALIDATION_FAILED"`, `"AC-2: bit-flipped signature (cTilde region) returns SIG_VALIDATION_FAILED"`, `"AC-3: malformed signature reverts with SignatureMalformed"`.

- [ ] **Task 2: Verify against the deployed MlDsaAccount**
  - Maps to: AC-1, AC-2, AC-3
  - Files: none (runs the Task 1 tests)
  - Run `npm test -- test/accounts/mldsa-failures.test.ts` (or the full `npm test`) and confirm all three new tests PASS against the current `contracts/MlDsaAccount.sol` at file hash `69618d4b80cac77e4d15118a3f9c1917afa29a3e6cdb251370e3888b84802edf`. No contract changes are expected; the behavior this story asserts was built in Story 4-1.
  - If AC-2 unexpectedly reverts with `SignatureMalformed` instead of returning 1n → re-check the bit-flip locus (must be inside `[0, 32)` cTilde region, not `[32, 2420)`). The architecture guardrail explains why.
  - If AC-3 returns 1n instead of reverting → the truncation-slice path is being silently accepted; investigate whether ZKNOX_dilithium's `slice` boundary check changed upstream (NFR-5 re-evaluation trigger). Story 4-2 does NOT modify the verifier regardless.
  - If a pre-existing flake (C-006 ECDSA) surfaces during the run, mark it as baselined — unrelated to ML-DSA.

- [ ] **Task 3: Compile + full test gate**
  - Maps to: AC-1, AC-2, AC-3
  - Run `npm run compile` — only the tolerated ETHFALCON `slen` warning (C-001) may appear. No project-authored warnings.
  - Run `npm test` — verify: (a) Story 1-1 smoke continues to pass; (b) Story 2-1 `ecdsa.test.ts` continues to pass (modulo C-006 flake); (c) Story 3-1 `falcon.test.ts` continues to pass (if Story 3-1 has resumed; if still paused per C-007, skip); (d) Story 3-2 `falcon-failures.test.ts` continues to pass; (e) Story 4-1 `mldsa.test.ts` continues to pass; (f) new Story 4-2 `mldsa-failures.test.ts` passes all three tests.
  - Code review prep: no new patterns introduced, no deviations expected if the implementer picks option (b) on the fixture-divergence call. If option (a) is picked, log the fixture-signature change as Rule 2 at commit time per `.claude/rules/code-standards.md`.

## must_haves

truths:
  - "`test/accounts/mldsa-failures.test.ts` exists and uses `node:test` + `node:assert/strict` (A-001); imports neither `chai` nor `hardhat-chai-matchers`."
  - "AC-1 test: account initialized with `alice.publicKey` pointer, UserOp signed with a SECOND `keygen(\"mldsa\")` keypair's `secretKey` (Bob), and `validateUserOp` via `account.simulate.validateUserOp(..., { account: entryPoint.address })` returns `1n` (`SIG_VALIDATION_FAILED`)."
  - "AC-2 test: Alice signs a valid UserOp, ONE bit of the signature is flipped inside the 32-byte cTilde region (offset in `[0, 32)` — e.g. `sigBytes[5] ^= 0x01`), signature hex length is still 2420 bytes, and `validateUserOp` returns `1n`."
  - "AC-3 test: signature is replaced with 100 zero bytes (length ≠ 2420), and `simulateValidateUserOp` is asserted to reject via `assert.rejects(..., predicate)` where the predicate walks the viem error chain with `err.walk((e) => e instanceof ContractFunctionRevertedError)` and requires either `revert.data?.errorName === \"SignatureMalformed\"` OR the EDR-tail message matches `/custom error 'signaturemalformed\\(\\)'/` AND includes the account's lowercased address (origin-contract binding)."
  - "No `contracts/` Solidity files are modified by this story — MlDsaAccount's failure behavior was defined in Story 4-1 and is consumed here."
  - "No `ETHDILITHIUM/` or `ETHFALCON/` submodule files are modified (NFR-5); `git diff ETHDILITHIUM/ ETHFALCON/` remains empty after Task 1-3."
  - "`npm run compile` and `npm test` both succeed; the only compile warning is the tolerated ETHFALCON `slen` warning (C-001); no test is `t.skip`-ed, `.todo`-ed, or otherwise silenced."

artifacts:
  - path: "test/accounts/mldsa-failures.test.ts"
    contains: ["node:test", "node:assert/strict", "deployDilithiumVerifier", "registerPublicKey", "keygen", "signUserOp", "SIG_VALIDATION_FAILED", "SignatureMalformed", "ContractFunctionRevertedError", "assert.rejects"]

key_links:
  - pattern: "import assert from \"node:assert/strict\""
    in: ["test/accounts/mldsa-failures.test.ts"]
  - pattern: "keygen(\"mldsa\")"
    in: ["test/accounts/mldsa-failures.test.ts"]
  - pattern: "signUserOp("
    in: ["test/accounts/mldsa-failures.test.ts"]
  - pattern: "sigBytes[5] ^="
    in: ["test/accounts/mldsa-failures.test.ts"]
  - pattern: "new Uint8Array(100)"
    in: ["test/accounts/mldsa-failures.test.ts"]
  - pattern: "errorName === \"SignatureMalformed\""
    in: ["test/accounts/mldsa-failures.test.ts"]

## Dev Notes (advisory)

- **Single network connection per test:** mirror `setup()` at `test/accounts/mldsa.test.ts:36-78` — pass the connection's `viem` to `deployDilithiumVerifier(viem)` so EntryPoint, verifier, proxy, and account all land on one chain. A second `hre.network.connect()` inside the same test would produce a fresh chain with no deployed verifier; the staticcall returns empty data, decode fails, and `SignatureMalformed` fires spuriously. Documented explicitly at `test/fixtures/mldsa.ts:17-23`.
- **`simulate.validateUserOp`, not `write`:** the account's `validateUserOp` return value is only observable via `simulate` (with `{ account: entryPoint.address }` impersonation). `write` propagates through `FailedOp` reverts rather than the raw return. Established Story 2-1, reused Story 3-1/3-2/4-1.
- **Timeout budget:** ML-DSA on-chain verification under HH3 EDR runs slow — `{ timeout: 120_000 }` per test is the proven ceiling from `test/accounts/mldsa.test.ts:135`. Three tests × ~120s worst-case = 6 minutes wall-clock for this file; still well under the Story 5-1 NFR-4 suite-total budget.
- **Bob's keypair seeding:** no explicit seeding required. noble's `ml_dsa44.keygen()` draws from `crypto.getRandomValues`; collision with Alice is negligible.
- **Why Story 4-1 already ensured AC-3's revert path works:** Story 4-1 AC-4's structural assertion at `test/accounts/mldsa.test.ts:160-187` statically guarantees `try dilithiumVerifier.verify(...)` is wrapped in a `catch` that reverts `SignatureMalformed()`. Trust the structural guard; this story adds the runtime.
- **File placement:** new test file lives at `test/accounts/mldsa-failures.test.ts` alongside `mldsa.test.ts`. Do not add to `mldsa.test.ts` itself — the PD-2 wave-isolation principle keeps happy-path and failure-class in separate files so future parallelism isn't blocked by intra-file merge pressure.
- **AC-3 signing-efficiency note (informational, per C-010.1):** AC-3 signs a valid UserOp with Alice's key to obtain `userOpHash`, then discards the signature. The sign step is dead work (~signing time per AC-3 run) since `canonicalUserOpHash` hashes only non-signature fields. The Falcon sibling left this as-is to stay within Story 3-2's scope (C-010.1 Fix-when-touched); Story 4-2 follows the same decision — the natural place to optimize PQC test setup is Story 5-1, which will profile the whole path anyway. If the implementer wants to eliminate it, replace the sign step with `{ ...userOp, signature: "0x" } as unknown as PackedUserOperation` before calling `canonicalUserOpHash`. Purely optional.

> Ref: test/accounts/falcon-failures.test.ts#AC-3 — dual-path ContractFunctionRevertedError predicate with origin-contract binding (reused verbatim, errorName unchanged)
> Ref: test/accounts/mldsa.test.ts#setup — helper shape copied into the new failure-class file

## Detected Patterns

| Pattern | Value | Sampled from | Established? |
|---------|-------|--------------|-------------|
| Test framework | `node:test` + `node:assert/strict` | `test/accounts/ecdsa.test.ts`, `test/accounts/falcon.test.ts`, `test/accounts/mldsa.test.ts`, `test/accounts/falcon-failures.test.ts` | ✅ Established (A-001) |
| Failure-class test file naming | `{scheme}-failures.test.ts` | `test/accounts/falcon-failures.test.ts` (Story 3-2 introduced the convention) | ✅ Established |
| Account deploy | `ERC1967Proxy` over implementation (A-002) | `test/accounts/ecdsa.test.ts`, `test/accounts/falcon.test.ts:65-77`, `test/accounts/mldsa.test.ts:54-67`, `test/accounts/falcon-failures.test.ts:65-78` | ✅ Established |
| EntryPoint impersonation | `testClient.impersonateAccount` + `setBalance(parseEther("1"))` + `simulate.validateUserOp(..., { account: entryPoint.address })` | `test/accounts/mldsa.test.ts:69-110`, `test/accounts/falcon-failures.test.ts:80-122` | ✅ Established |
| Revert extraction (dual-path) | `err.walk(...ContractFunctionRevertedError)` → `errorName` check, plus HH3 EDR message-regex fallback bound to origin `account.address` | `test/accounts/falcon-failures.test.ts:221-250` | ✅ Established (Story 3-2 under code review hardening) |
| Bit-flip locus for "still parseable" | `sigBytes[5] ^= 0x01` inside hash-input region (salt for Falcon, cTilde for ML-DSA) | `test/accounts/falcon-failures.test.ts:179`, `test/accounts/ecdsa.test.ts:195` | ✅ Established |
| Per-test `{ timeout: 120_000 }` for PQC | 120s ceiling on any AC that runs on-chain PQC verification | `test/accounts/falcon.test.ts:132`, `test/accounts/mldsa.test.ts:135`, `test/accounts/falcon-failures.test.ts:127` | ✅ Established |
| Fresh verifier per `setup()` | `await deployDilithiumVerifier(viem)` inside setup, never hoisted | `test/fixtures/mldsa.ts:35-43`, `test/accounts/mldsa.test.ts:49` | ✅ Established (DD-9 LOCKED) |
| Fixture `registerPublicKey` signature | ⚠ Falcon is 3-arg `(verifier, rawKey, publicClient)`; ML-DSA is 2-arg `(verifier, rawKey)` | `test/fixtures/falcon.ts:31-61` vs `test/fixtures/mldsa.ts:45-69` | ⚠ Conflicting — divergence predates this story (C-008.1/C-008.2). Implementer chooses option (a) mirror or (b) leave; see Verified Interfaces for both approaches. |

## Wave Structure

Single wave (3 tasks, strict sequence):

- **Task 1** — author the test file (authoring work, no dependencies).
- **Task 2** — run the new file against current `MlDsaAccount.sol` (depends on Task 1's output file).
- **Task 3** — full compile + full `npm test` gate (depends on Task 2 passing).

No parallelism opportunity — the three tasks are linear. This story is small (one new file, three tests) and does not warrant sub-task fan-out.

## Inlined-vs-Referenced quality signal

Inlined (rules 1-2 of the Inline Decision List — correctness-critical):
- "byte 0 is bit-flipped" plan phrasing clarified to byte 5 inside cTilde with the parseability rationale (without this, a literal byte-0 reading is still correct but the implementer might pick an unsafe offset under "byte 0 is bit-flipped" if they misread it as an offset range).
- ML-DSA-44 signature layout table (`cTilde[0,32) | z[32,2336) | h[2336,2420)`) — the whole bit-flip safety argument depends on this and it is nowhere else in the story chain outside A-004's compact mention.
- Bit-flip locus constraint (AC-2): cTilde vs z vs h with per-region consequences — mis-locating the flip either collapses AC-2 into AC-3 (bad) or produces a soft-fail that still returns 1n (accidentally fine, but the locus choice should be principled).
- Malformed choice (AC-3): 100-zero-bytes truncation chosen over full-length all-zeros, with the decisive evidence that an all-zeros 2,420-byte blob actually returns `1n` (via `unpackH` soft-fail) rather than reverting — i.e. would collapse AC-3 into AC-2.
- AC-1 setup detail: second `keygen("mldsa")` call for Bob with the account registered under Alice's pointer — exact shape of "crypto failure against a different key".
- `SignatureMalformed` semantic boundary (crypto fail → 1n vs slice/decode fail → revert) — the whole story hinges on this distinction.
- `registerPublicKey` 2-argument signature (ML-DSA fixture) vs Falcon's 3-argument form — flagged explicitly because an implementer coming directly from Story 3-2 will expect the 3-arg shape and be silently confused when the type checker accepts the 2-arg call.
- Dual-path rejection-extraction snippet (canonical `ContractFunctionRevertedError.data.errorName` path + HH3 EDR message-regex fallback + origin-contract binding) — reproduced inline because both paths are load-bearing under HH3's error chain and the origin-binding is specifically necessary here given Falcon and ML-DSA both declare `SignatureMalformed()` with identical selectors.
- AC-4 absence note (plan has no AC-4 for 4-2 unlike 3-2) and A-001 assertion-framework binding — so the implementer doesn't look for a missing AC.

Referenced via `> Ref:` (rules 3-5 — discoverable):
- MlDsaAccount contract shape (lives in 4-1's Architecture Guardrails and the source itself).
- SimpleAccount proxy patterns (inherited from A-002).
- `ZKNOX_dilithium.verify` assembly-level behavior (upstream submodule).
- Compile-warnings gate (Story 1-1 convention).
- Shared test helpers' internals (`computeUserOpHash`, `preparePublicKeyForDeployment`) — consumed, not analyzed.
- Pattern precedents: single-connection invariant, impersonation, per-test timeouts — all live in sibling test files and are Codebase Scan "✅ Established".

## Quality self-check

| # | Check | Result |
|---|-------|--------|
| 1 | Self-containment — no vague refs | ✅ All cross-references use `> Ref: {path}#{section} — {why}` format |
| 2 | AC fidelity | ✅ ACs copied verbatim from `docs/plan.md:114-116`; clarification that "byte 0" maps to byte-5-in-cTilde flagged explicitly |
| 3 | Version verification | ✅ No new library introductions; inherited noble / viem / HH3 versions from Story 4-1 lockfile |
| 4 | Task ↔ AC coverage | ✅ Task 1 covers AC-1/2/3; Task 2 runtime-verifies all three; Task 3 full gate |
| 5 | must_haves precision | ✅ Artifacts have .ts extension; key_links are grep-able literals |
| 6 | Amendment integration | ✅ A-001, A-002, A-003, A-004 all applied |
| 7 | Wave independence | ✅ Tasks are strictly linear (no parallel lanes) |
| 8 | Previous intelligence | ✅ Story 3-2 (dual-path predicate, byte-5 locus), Story 4-1 (setup, fixture), Story 2-1 (impersonation) each cited with file paths |
| 9 | Interface verification | ✅ Six interfaces verified against source with SHA-256 hashes; one divergence (`registerPublicKey` arg count) called out explicitly |
| 10 | Inline/Reference audit | ✅ Correctness-critical → inlined (layout table, locus, malformed choice, predicate); conventions → `> Ref:` |
| 11 | Story size budget | ✅ ~260 lines; at the top of the S-size range (60-120 is the target but the bit-flip-locus table + dual-path predicate reasoning justify the expansion — same as Story 3-2 at ~260 lines) |
| 12 | must_haves count | ✅ 7 truths (S budget: 5-8) |
| 13 | Derivable content | ✅ No library versions, tsconfig, or test-runner commands inlined — all derivable from package.json / prior stories |
| 14 | Structural evaluation | ✅ Single new file ≤ ~250 lines; no god component; no implementation-detail prescription beyond AC-3 predicate which is LOCKED; no UI; no migration; not micro-eligible (3 ACs, ~200 LOC test file) |
