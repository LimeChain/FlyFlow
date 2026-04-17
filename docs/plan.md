---
status: complete
feature: mldsa-eth
phase: 4
created: 2026-04-17
brief: docs/research.md
spec: docs/spec.md
architecture: docs/architecture.md
---

# Plan: ML-DSA-ETH — Keccak-Based ML-DSA for ERC-4337

## Decomposition Strategy

**Strategy A-extended (5 stories, 5 waves, serial with fixture-gen CLI as Story 1 foundation).** Dependency chain: Fixture-gen CLI → Keccak-PRG port → XOF refactor + keygen → Signer → pk-transform + account + verifier + benchmark. Each story owns exactly one (or one pair of) test gates. Fixture-gen lands first so every downstream KAT has authoritative vectors to assert against; FR-7 (regenerate fixtures) is satisfied on day one.

Alternatives considered (PD-1 LOCKED rationale): original 4-story Strategy A with CLI folded into Story 2 (rejected — fixtures are prerequisite for G0 KAT); Strategy B with Wave-3 parallelism (rejected); 6-story atomic (rejected — low signal-to-ceremony for G0-prime as own story).

---

## Epic 1: Foundation

Goal: Fixture infrastructure + Keccak-PRG primitive. Gates G0 and G0-prime.

### Story 1: Fixture-gen CLI + submodule compile path + KAT loader [M]

**User Story:** As a test author, I want a fixture-gen CLI that produces byte-accurate KAT fixtures from the pinned ZKNox reference implementations, so that all downstream KAT tests have authoritative vectors to assert against and can be regenerated deterministically when the submodule bumps.

**Dependencies:** none
**Wave:** 1

**Acceptance Criteria:**
- **AC-1-1** (CLI regeneration — FR-7): Given the ETHDILITHIUM submodule at its pinned commit, when `npx tsx scripts/generate-kat-fixtures.ts` runs, then `test/fixtures/kat/mldsa-eth/vectors.json` contains ≥100 vectors with fields `(id, drbgSeed, zeta, rnd, publicKey, secretKey, reshapedPublicKey, message, signature)` + embedded `submoduleSha` matching HEAD, and `test/fixtures/kat/keccak-prg/vectors.json` contains 4 `source: "zhenfei-canonical"` vectors (hex literals from `ETHDILITHIUM/test/keccak_prng.t.sol`) + ≥3 `source: "python-ref-extended"` boundary vectors.
- **AC-1-2** (Determinism): Given identical submodule state, when the CLI runs twice, then `git diff test/fixtures/kat/` produces zero output.
- **AC-1-3** (pk_for_eth invocation): Given each `.rsp` vector's raw pk, when `Dilithium2.pk_for_eth(pk, _xof=Keccak256PRNG, _xof2=Keccak256PRNG)` is invoked from the submodule's Python module, then the resulting `abi.encode(aHatEncoded, tr, t1Encoded)` bytes land in the `reshapedPublicKey` field.
- **AC-1-4** (Submodule pin mismatch — AC-NFR-4): Given `.gitmodules` records the pinned ETHDILITHIUM SHA, when the CLI is invoked with submodule HEAD at a different SHA, then the CLI refuses to run and prints both expected + actual SHAs plus the reset-to-pin command.
- **AC-1-5** (AC-U-2 diagnostic — uninit'd submodule): Given ETHDILITHIUM submodule is uninitialized, when CLI is invoked, then it exits with `code "SUBMODULE_UNINIT"` and message containing `git submodule update --init --recursive`.
- **AC-1-6** (AC-U-2 diagnostic — Python version): Given detected `python3 --version` does not satisfy the required version, when CLI is invoked, then it exits with error naming required + detected versions.
- **AC-1-7** (AC-U-2 diagnostic — pip deps): Given pip dependencies in the submodule's `requirements.txt` are missing, when CLI is invoked, then it exits with the pinned requirements path + exact `pip install -r ...` command.
- **AC-1-8** (Loader SHA check at import): Given a committed `vectors.json.submoduleSha` differs from current submodule HEAD, when any KAT test file imports via `loadPrgVectors()` or `loadKatVectors("mldsa-eth")`, then a `KatFixtureError` with `code: "KAT_SUBMODULE_SHA_MISMATCH"` is thrown at import time with the regeneration command.
- **AC-1-9** (Submodule compile path): Given `hardhat.config.ts` includes `ETHDILITHIUM/src/` in Solidity source paths, when `npx hardhat compile` runs, then `ZKNOX_keccak_prng.sol`, `ZKNOX_ethdilithium.sol`, and their dependencies compile without warnings using the existing Solidity compiler version.
- **AC-1-10** (No new runtime deps): Given `package.json` + `package-lock.json`, when Story 1 commit diff is inspected, then no new runtime dependencies are introduced.

**FR Coverage:** FR-7
**NFR Coverage:** NFR-3 (cross-cutting), NFR-4 (AC-1-9+1-10), NFR-5 (AC-1-4+1-8)

**Size:** M (~200 LOC).

---

### Story 2: Keccak-PRG port + G0 KAT + G0-prime [M]

**User Story:** As a signer engineer, I want a byte-compatible JS port of ZKNox's Keccak-PRG primitive validated against both the canonical C/Solidity vectors and the Python reference, so that downstream crypto ports have a byte-identity-verified primitive to build on.

**Dependencies:** Story 1
**Wave:** 2

**Acceptance Criteria:**
- **AC-2-1** (G0 Layer 1 canonical — NFR-9): Given a `createKeccakPrg()` instance and the 4 Zhenfei-canonical PRG fixtures, when each fixture's scripted `inject`/`flip`/`extract` sequence runs, then every output matches the committed hex-literal expected bytes byte-for-byte.
- **AC-2-2** (G0 Layer 2 cross-extract): Given `inject(seed); flip()` on one instance, when `extract(5)` then `extract(27)` is called, then the concatenated output equals `extract(32)` from a fresh identically-seeded instance.
- **AC-2-3** (G0 Layer 2 absorb concatenation): Given `inject(a); inject(b); flip(); extract(64)` vs `inject(concat(a,b)); flip(); extract(64)`, then outputs are byte-identical.
- **AC-2-4** (Lifecycle — inject after flip): Given a `KeccakPrg` with `flip()` called, when `inject(data)` is called, then `PrgLifecycleError` with `code: "PRG_INJECT_AFTER_FLIP"` is thrown.
- **AC-2-5** (Lifecycle — extract before flip): Given a `KeccakPrg` with no prior `flip()`, when `extract(32)` is called, then `PrgLifecycleError` with `code: "PRG_EXTRACT_BEFORE_FLIP"` is thrown.
- **AC-2-6** (G0-prime Solidity cross-check — required): Given `ZKNOX_keccak_prng.sol` deployed on Hardhat, when each Layer-2 fixture's scripted operations are driven through the Solidity API (`initPrng` + `refill` + `prng.pool`), then Solidity outputs match JS `extract()` outputs byte-for-byte.

**FR Coverage:** FR-8 (PRG subset)
**NFR Coverage:** NFR-9 (direct)

**Size:** M (~160 LOC).

---

## Epic 2: Crypto & Integration

Goal: XOF refactor + keygen + signer + pk-transform + account + benchmark. Gates G1, G2, G3, G4.

### Story 3: XOF refactor + keygen port + G1 KAT + NIST regression [M]

**User Story:** As a wallet engineer, I want `mldsa-encoding.ts` refactored to accept an XOF factory + a Keccak-based keygen port that passes byte-identity against `.rsp`, so that the shared encoding module and keygen serve both NIST and ETH code paths without module-level state.

**Dependencies:** Story 1, Story 2
**Wave:** 3

**Acceptance Criteria:**
- **AC-3-1** (G1 KAT — FR-2 byte-identity): Given a `.rsp` vector N's `zeta`, when `keygenInternal(zeta)` is called, then `(publicKey, secretKey)` matches the fixture's `pk` and `sk` byte-for-byte, iterated across all ~100 vectors.
- **AC-3-2** (No module-level XOF state — AC-A-1 HIGH): Given the refactored `mldsa-encoding.ts` + new `ml-dsa-eth.ts`, when source-level grep runs for `let _xof` / `var _xof` / module-scoped factory assignments, then zero matches are found.
- **AC-3-3** (AC-D-2 NIST regression — 100-vector): Given a frozen 100-vector NIST pre-refactor golden fixture captured from `PQCsignKAT_Dilithium2.rsp`, when post-refactor code runs against all 100 vectors, then outputs match byte-for-byte per vector. Any mismatch → HALT per refactor-rollback protocol.
- **AC-3-4** (XofReader `id` discriminant): Given `assertBytesEqual(actual, expected, label, xofId?)`, when divergence occurs and `xofId` is provided, then the error message includes `(factory=<xofId>)`.
- **AC-3-5** (Interleaved XOF-isolation — AC-A-1 HIGH): Given one test reshapes the same pk with SHAKE → Keccak → SHAKE factories interleaved in one process, then each reshape output matches its own golden; no cross-contamination.
- **AC-3-6** (Module-header `@delta-from-ml-dsa`): Given `test/signers/ml-dsa-eth.ts` and `test/signers/ml-dsa-eth.kat-internal.ts`, when a maintainer reads the top-of-file JSDoc, then a `@delta-from-ml-dsa` section enumerates byte-level differences from `ml-dsa.ts`.
- **AC-3-7** (ESLint `no-restricted-imports`): Given the `.eslintrc` rule, when `test/signers/index.ts` or any file under `test/bench/**` imports from `ml-dsa-eth.kat-internal.ts`, then lint fails.
- **AC-3-8** (AC-NFR-5 ML-DSA-44 params): Given keygen's parameter constants, when asserted against (k=4, l=4, η=2, γ₁=2¹⁷, γ₂=95232, τ=39, ω=80, β=78), then all match by named constant.

**FR Coverage:** FR-1 (keygen), FR-2 (keygen), FR-8 (keygen)
**NFR Coverage:** NFR-2 (direct), NFR-6 (direct)

**Size:** M (~230 LOC).

---

### Story 4: Signer port + G2 KAT [L]

**User Story:** As a wallet engineer, I want a JS ML-DSA-ETH signer that produces signatures byte-identical to the Python reference, so that signatures over userOps verify on-chain against the external ZKNox verifier.

**Dependencies:** Story 1, Story 2, Story 3
**Wave:** 4

**Acceptance Criteria:**
- **AC-4-1** (G2 KAT — FR-2/FR-8 byte-identity): Given a `.rsp` vector N's `sk`, `msg`, `rnd`, when `signWithRnd(sk, msg, rnd, ctx=0x)` is called, then output matches `sig = sm[:-mlen]` byte-for-byte across all ~100 vectors.
- **AC-4-2** (Production sign path — FR-1): Given a keypair from `keygen()` + a valid `UnsignedUserOp`, when `signUserOp(sk, userOp, entryPointAddress, chainId)` is called, then a `PackedUserOperation` with a signature of exactly 2420 bytes (32 cTilde + 2304 z + 84 h) is returned.
- **AC-4-3** (Input error — SK length): Given `signWithRnd(sk, ...)` called with `sk.length !== 2560`, then `SignerInputError` with `code: "INVALID_SECRET_KEY_LENGTH"` is thrown.
- **AC-4-4** (Input error — message type): Given `signWithRnd(sk, msg, rnd)` called with `msg` neither `Uint8Array` nor `0x`-hex, then `SignerInputError` with `code: "INVALID_MESSAGE"` is thrown.
- **AC-4-5** (Rejection loop exercised): Given the signer's ExpandMask → norm-check loop, when `signWithRnd` runs across ~100 `.rsp` vectors, then ≥1 vector observably requires more than one rejection iteration (instrumented counter > 0).
- **AC-4-6** (Hedged production path): Given `signUserOp` called twice with identical inputs, when the two signatures are compared, then they differ (probabilistic; rnd from `crypto.getRandomValues(32)`).

**FR Coverage:** FR-1 (signUserOp), FR-2 (signer), FR-8 (signer), FR-13 (signer)
**NFR Coverage:** NFR-2 (direct)

**Size:** L (~300 LOC). Justified: rejection-loop state machine + SampleInBall + MakeHint + ExpandMask + signer encoding + error taxonomy. Architecture-endorsed. Splitting into internal vs production surfaces creates a story with no observable deliverable at G2.

---

### Story 5: pk-transform + MlDsaEthAccount + G3 + G4 + benchmark + rename [L]

**User Story:** As a PQC researcher, I want ML-DSA-ETH fully integrated as a 4th scheme — account contract, benchmark, report, documentation — so that `npx hardhat test` reports a full 4-scheme suite and `npx tsx scripts/generate-report.ts` writes a 4-row gas comparison.

**Dependencies:** Story 1, Story 2, Story 3, Story 4
**Wave:** 5

**Acceptance Criteria:**
- **AC-5-1** (Rename pre-task — A-001 amendment): Given `MlDsaAccount.sol`, `FalconAccount.sol`, their tests, and all callers, when `publicKey` is renamed to `publicKeyPointer` and `_publicKey` param to `_publicKeyPointer`, then the full existing NIST + Falcon test suites pass byte-for-byte AND `docs/amendments.md` contains the A-001 amendment logged per code-standards.md Rule 3.
- **AC-5-2** (G3 pk-transform KAT — FR-6): Given a `.rsp` vector N's raw `pk`, when `preparePublicKeyForDeployment(pk, keccakXofFactory)` is called, then output equals the fixture's `reshapedPublicKey` byte-for-byte (~100 vectors).
- **AC-5-3** (G4 happy path — FR-3, AC-FR-1, AC-NFR-1): Given `MlDsaEthAccount` initialized with `publicKeyPointer = verifier.setKey(reshapedPk)` for `.rsp` vector N, when a userOp signed via `signWithRnd(sk, userOpHash, rnd, ctx=0x)` is submitted through EntryPoint's `validateUserOp`, then EntryPoint observes `SIG_VALIDATION_SUCCESS` (uint256 0) for all ~100 vectors.
- **AC-5-4** (G4 rejection — crypto-invalid — FR-4, AC-A-2): Given a signature constructed with `signWithRnd(wrongSk, msg, rnd)` or a single bit-flipped byte, when submitted through `validateUserOp`, then EntryPoint observes `SIG_VALIDATION_FAILED` (uint256 1); no revert; no state change.
- **AC-5-5** (G4 rejection — malformed — FR-5, AC-A-2): Given a truncated, over-length, or structurally-unparseable signature blob, when submitted through `validateUserOp`, then `MlDsaEthAccount._validateSignature` catches the verifier's internal revert and re-reverts with `SignatureMalformed()`.
- **AC-5-6** (4-scheme benchmark — FR-9/10/11, AC-NFR-6): Given the benchmark harness iterates `SCHEMES` (4 items), when `npx hardhat test test/bench/gas-benchmark.test.ts` runs, then per-scheme gas measurements emit for ECDSA, Falcon, MLDSA, MLDSA-ETH using identical workload; `npx tsx scripts/generate-report.ts` renders a Markdown report with 4 rows under identical column headers.
- **AC-5-7** (Deterministic report — AC-U-4): Given two consecutive runs of `scripts/generate-report.ts` with no code changes, when `git diff docs/gas-report.md` runs, then only gas-cost deltas appear.
- **AC-5-8** (Per-scheme failure isolation — AC-A-3): Given a deliberate failure injected for one scheme's measurement, when the benchmark runs, then the other three rows render with gas numbers; the failed row renders the human-readable reason.
- **AC-5-9** (SCHEMES.length derivation — AC-D-1): Given `test/bench/gas-benchmark.test.ts` and `scripts/generate-report.ts`, when grep'd, then no literal `=== 3`/`!== 3`/`.length === 3` remains; all guards derive from `SCHEMES.length`; adding a 5th scheme produces TypeScript compile errors at every site that needs edits.
- **AC-5-10** (README attribution — FR-12, AC-U-5): Given top-level `README.md`, when a reader reaches the "Supported schemes" section, then ML-DSA-ETH is listed alongside ECDSA, Falcon, NIST ML-DSA; ZKNox credited as origin of the ETHDilithium design + `ZKNOX_ethdilithium.sol`; the Python dev-oracle isolation note is present.
- **AC-FLOW-1** (End-to-end cross-story — AC-NFR-1): Given a production flow `keygen()` (Story 3) + `preparePublicKeyForDeployment(pk, keccakFactory)` (Story 5) + `verifier.setKey(reshapedPk)` (Story 5) + `signUserOp(sk, userOp, ...)` (Story 4) + `validateUserOp` (Story 5), when a freshly-generated keypair signs and submits a userOp, then EntryPoint observes `SIG_VALIDATION_SUCCESS`. Exercised by a ≥5-iteration test per AC-NFR-1.

**FR Coverage:** FR-3, FR-4, FR-5, FR-6, FR-9, FR-10, FR-11, FR-12, FR-13
**NFR Coverage:** NFR-1 (direct), NFR-7 (direct)

**Size:** L (~350 LOC). Justified: Strategy A-extended intentionally bundles rename + pk-transform + account + G3 + G4 + benchmark + README to minimize story count. Splitting reintroduces Strategy B.

---

## FR Coverage Map

| FR | Stories | Status |
|---|---|---|
| FR-1 | 3, 4 | ✅ |
| FR-2 | 3, 4 | ✅ |
| FR-3 | 5 | ✅ |
| FR-4 | 5 | ✅ |
| FR-5 | 5 | ✅ |
| FR-6 | 5 | ✅ |
| FR-7 | 1 | ✅ |
| FR-8 | 2, 3, 4, 5 | ✅ |
| FR-9 | 5 | ✅ |
| FR-10 | 5 | ✅ |
| FR-11 | 5 | ✅ |
| FR-12 | 5 | ✅ |
| FR-13 | 4, 5 | ✅ |

**Coverage: 13/13 (100%)**.

## NFR Coverage Strategy

| NFR | Path | Story / Note |
|---|---|---|
| NFR-1 | Direct | Story 5 (AC-5-3, AC-FLOW-1) |
| NFR-2 | Direct | Stories 2, 3, 4, 5 (G0/G1/G2/G3 — ~100 vectors each) |
| NFR-3 | Cross-cutting | Story 1 commits zero Python files; Story 5 README documents. Code-review discipline per spec (user-accepted deferral) |
| NFR-4 | Cross-cutting | Story 1 AC-1-9+1-10; lockfile spot-check at every Gate 5 |
| NFR-5 | Direct | Story 1 (AC-1-4, AC-1-8) |
| NFR-6 | Direct | Story 3 (AC-3-8) |
| NFR-7 | Direct | Story 5 (AC-5-6) |
| NFR-8 | Post-Launch Verification | Deferred per spec — post-merge read of `docs/gas-report.md` |
| NFR-9 | Direct | Story 2 (AC-2-1 through AC-2-6) |

## Dependency Graph

```
Story 1 (Fixture-gen CLI + loader + compile path)
    │
    ▼
Story 2 (Keccak-PRG port + G0 + G0-prime)
    │
    ▼
Story 3 (XOF refactor + keygen + G1 + NIST regression)
    │
    ▼
Story 4 (Signer port + G2)
    │
    ▼
Story 5 (pk-transform + account + G3 + G4 + benchmark + rename)
```

Linear chain. DAG validated. No cycles.

## Wave Assignments

| Wave | Stories | Rationale |
|---|---|---|
| 1 | Story 1 | Foundation — no deps; produces fixtures + compile path |
| 2 | Story 2 | Story 1 complete — PRG fixtures exist; Solidity compilable for G0-prime |
| 3 | Story 3 | Story 2 complete — `createKeccakPrg` for Keccak XofFactory; fixtures for G1 |
| 4 | Story 4 | Story 3 complete — XofFactory + keygen ready; fixtures for G2 |
| 5 | Story 5 | Story 4 complete — signer produces sigs for G4; pk-transform uses refactored encoding module |

## Interface Contracts

### `KeccakPrg`
- **Defined by:** Story 2
- **Consumed by:** Story 3 (Keccak XOF adapter), Story 4 (via adapter), Story 5 (via adapter)
- **Signature:** `interface KeccakPrg { inject(Uint8Array): void; flip(): void; extract(number): Uint8Array; update(Uint8Array): void; read(number): Uint8Array; }` and `function createKeccakPrg(seed?: Uint8Array): KeccakPrg`
- **Location:** `test/signers/keccak-prg.ts`

### `XofFactory` / `XofReader`
- **Defined by:** Story 3
- **Consumed by:** Story 4 (signer), Story 5 (pk-transform)
- **Signature:** `interface XofReader { readonly id: "shake128" | "shake256" | "keccak-prg"; xof(length: number): Uint8Array; }` and `type XofFactory = (seed: Uint8Array) => XofReader`
- **Location:** `test/signers/mldsa-encoding.ts`

### `keygen` / `keygenInternal`
- **Defined by:** Story 3
- **Consumed by:** Story 5 (AC-FLOW-1 fresh-keypair test)
- **Signature:** `function keygen(): Keypair` (production) in `test/signers/ml-dsa-eth.ts`; `function keygenInternal(zeta: Uint8Array): Keypair` (KAT) in `test/signers/ml-dsa-eth.kat-internal.ts`

### `signUserOp` / `signWithRnd`
- **Defined by:** Story 4
- **Consumed by:** Story 5 (G4 integration + AC-FLOW-1)
- **Signature:** `async function signUserOp(secretKey: Uint8Array, userOp: UnsignedUserOp, entryPointAddress: string, chainId: bigint): Promise<PackedUserOperation>` (production) in `test/signers/ml-dsa-eth.ts`; `function signWithRnd(sk: Uint8Array, msg: Uint8Array, rnd: Uint8Array, ctx?: Uint8Array): Uint8Array` (KAT) in `test/signers/ml-dsa-eth.kat-internal.ts`

### `preparePublicKeyForDeployment` (refactored)
- **Defined by:** Story 3 (XOF-factory refactor)
- **Consumed by:** Story 5 (G3 KAT + account init pipeline)
- **Signature:** `function preparePublicKeyForDeployment(rawPk: Uint8Array, xofFactory: XofFactory): Uint8Array`
- **Location:** `test/signers/mldsa-encoding.ts`

### `IZKNOXEthDilithium` (external — from submodule)
- **Defined by:** `ETHDILITHIUM/src/ZKNOX_ethdilithium.sol` (verified against lines 81 + 29 of the pinned commit)
- **Consumed by:** Story 5 (`MlDsaEthAccount._validateSignature` + deployment harness)
- **Signature:** `function verify(bytes calldata pk, bytes32 m, bytes calldata signature) external view returns (bytes4); function setKey(bytes calldata reshapedPk) external returns (bytes memory);`
- **Location:** `ETHDILITHIUM/src/ZKNOX_ethdilithium.sol`

### `MlDsaEthAccount`
- **Defined by:** Story 5
- **Consumed by:** Benchmark harness (Story 5) + integration tests (Story 5)
- **Signature:** `contract MlDsaEthAccount is SimpleAccount { bytes public publicKeyPointer; function initialize(address, bytes calldata _publicKeyPointer) public initializer; function _validateSignature(PackedUserOperation calldata, bytes32) internal view override returns (uint256); error SignatureMalformed(); }`
- **Location:** `contracts/MlDsaEthAccount.sol`

### KAT loaders
- **Defined by:** Story 1
- **Consumed by:** Stories 2, 3, 4, 5 (every KAT test file)
- **Signature:** `function loadPrgVectors(): PrgVector[]; function loadKatVectors(scheme: "mldsa-eth"): KatVector[];` — both run `assertSubmoduleShaMatches()` at import time, throwing `KatFixtureError` with `code: "KAT_SUBMODULE_SHA_MISMATCH"` on drift
- **Location:** `test/fixtures/kat/index.ts`

## Plan Decisions

- **PD-1** Decomposition Strategy = Strategy A-extended (5 stories, 5 waves, serial with fixture-gen CLI as Story 1 foundation). **LOCKED.**
  - Alternatives considered: original 4-story Strategy A with CLI folded into Story 2 (rejected — fixtures are prerequisite for G0 KAT); Strategy B with Wave-3 parallelism (rejected); 6-story atomic with G0-prime as separate story (rejected — low signal-to-ceremony).
  - Rationale: CLI-first honors the "fixtures are foundational" observation while keeping story count within Medium tier budget (5 vs 6+). Serial wave execution trades parallelism for simplicity.

- **PD-2** AC amplification 1.95x **justified not trimmed**. **LOCKED.**
  - Alternatives: trim to 1.7x by merging related lifecycle/diagnostic ACs (rejected — loses specificity that downstream implement phase needs).
  - Rationale: All 20 extra ACs trace directly to persona-resolution obligations surfaced at architecture Gate 3 (M-1 KAT boundary, M-2 G0-prime required, M-3 XofReader discriminant + delta JSDoc, A-2 loader SHA at import, A-3 DD-11 Python source, AC-U-2 four-mode diagnostics, DD-11 lifecycle error taxonomy, AC-D-1 SCHEMES.length derivation, AC-U-4 deterministic report, AC-A-3 per-scheme failure isolation). Trimming would reintroduce concerns already resolved upstream.

## Flagged for awareness

- **Sizing:** 3M + 2L stories (40% L — at advisory threshold, not over). Strategy A trade-off accepted.
- **Wave depth:** 5 waves serial (at advisory threshold). Strategy A trade-off accepted; strict dependency chain precludes parallelism without restructuring.
- **AC amplification:** 1.95x (PD-2 justified).
