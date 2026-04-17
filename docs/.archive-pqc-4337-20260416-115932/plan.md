---
status: complete
feature: pqc-4337
phase: 4
created: 2026-04-13
---

# Plan: PQC-4337

## Decomposition Strategy

**Scheme-first vertical slices** (PD-1 LOCKED). Each signature scheme is its own epic with an end-to-end slice (contract + off-chain signer + validation tests). Foundation epic establishes shared infrastructure; benchmark epic consumes the three accounts.

---

## Epic 1: Foundation

### Story 1-1: Project scaffold + submodules + signer harness [M]

**User Story:** As an engineer, I want a Hardhat project with PQC submodules and a shared signing harness ready to go, so that scheme-specific stories can plug in without reinventing setup.
**Dependencies:** none
**Wave:** 1

**Acceptance Criteria:**

- AC-1: Given a fresh clone, When running `npm install && git submodule update --init`, Then `ETHFALCON/src/ZKNOX_falcon.sol` and `ETHDILITHIUM/src/ZKNOX_dilithium.sol` exist at expected paths pinned to specific commit SHAs.
- AC-2: Given submodules initialized, When running `npx hardhat compile`, Then all submodule verifiers and project contracts compile with zero warnings treated as errors.
- AC-3: Given the EntryPoint fixture, When calling `deployEntryPoint()`, Then a deployed eth-infinitism `EntryPoint` instance is returned for reuse across tests.
- AC-4: Given the signer module at `test/signers/`, When inspected, Then it contains `index.ts` (exports `Scheme`, `Keypair`, `keygen`, `signUserOp`), `ecdsa.ts` (complete implementation), `falcon.ts` (stub throwing `NotImplementedError`), and `ml-dsa.ts` (stub throwing `NotImplementedError`). `index.ts` dispatches on the `scheme` parameter.
- AC-5: Given submodule directories, When running `git diff` inside either submodule, Then output is empty (NFR-5).

**FR Coverage:** (enabling) · **NFR Coverage:** NFR-5 (direct)

---

## Epic 2: ECDSA Baseline

### Story 2-1: EcdsaAccount + acceptance/rejection tests [S]

**User Story:** As an engineer, I want an ECDSA baseline smart account that passes the standard 4337 validation path, so that PQC schemes have a reference to compare against.
**Dependencies:** 1-1
**Wave:** 2

**Acceptance Criteria:**

- AC-1: Given a deployed `EcdsaAccount` with `owner` set to Alice's address, When Alice signs a UserOp with her ECDSA private key and it is submitted to `validateUserOp`, Then it returns `SIG_VALIDATION_SUCCESS` (`0`).
- AC-2: Given the same account (owned by Alice), When Bob signs the UserOp with his own ECDSA keypair, Then `validateUserOp` returns `SIG_VALIDATION_FAILED` (`1`) because `ecrecover` returns Bob's address, not Alice's.
- AC-3: Given Alice's valid signature, When byte 0 of the signature is bit-flipped, Then `ecrecover` returns `address(0)` or an unrelated address and `validateUserOp` returns `SIG_VALIDATION_FAILED`.
- AC-4: Given the `EcdsaAccount` source, When inspected, Then it contains no `_validateSignature` override (inherits SimpleAccount directly — DD-10).

**FR Coverage:** FR-1, FR-4 (ECDSA), FR-7 (ECDSA) · **NFR Coverage:** NFR-2 (cross-cutting via AC-4)

---

## Epic 3: Falcon Account

### Story 3-1: Falcon signer + FalconAccount + happy-path acceptance [M]

**User Story:** As an engineer, I want a Falcon-signing smart account that validates a correctly-signed UserOp on-chain, so that Falcon is integrated end-to-end.
**Dependencies:** 1-1
**Wave:** 2

**Acceptance Criteria:**

- AC-1: Given `SigningUtils.keygen('falcon')`, When called, Then returns Alice's Falcon-512 keypair via `@noble/post-quantum/falcon` with a 897-byte public key.
- AC-2: Given Alice's Falcon keypair, When calling `signUserOp('falcon', aliceSecretKey, userOp)`, Then returns a `PackedUserOperation` whose `signature` field decodes via `ZKNOX_falcon`'s expected format.
- AC-3: Given a deployed `FalconAccount` initialized with Alice's 897-byte public key and a `ZKNOX_falcon` verifier reference, When Alice's Falcon-signed UserOp is submitted to `validateUserOp`, Then it returns `SIG_VALIDATION_SUCCESS`.
- AC-4: Given `FalconAccount._validateSignature`, When inspected, Then it calls `falconVerifier.verify(publicKey, userOpHash, userOp.signature)` wrapped in try/catch per architecture.

**FR Coverage:** FR-2, FR-4 (Falcon) · **NFR Coverage:** NFR-1 (cross-cutting), NFR-2 (cross-cutting via AC-4)

### Story 3-2: Falcon failure-class tests [S]

**User Story:** As an engineer, I want Falcon to distinguish malformed from crypto-invalid signatures, so that debugging signature failures is tractable.
**Dependencies:** 3-1
**Wave:** 3

**Acceptance Criteria:**

- AC-1: Given a `FalconAccount` owned by Alice, When Bob signs with his own Falcon keypair, Then `validateUserOp` returns `SIG_VALIDATION_FAILED` (crypto failure against Alice's public key).
- AC-2: Given Alice's valid Falcon signature, When one bit of the signature bytes is flipped (signature remains parseable), Then `validateUserOp` returns `SIG_VALIDATION_FAILED`.
- AC-3: Given a malformed Falcon signature (truncated to 100 bytes or filled with zeros such that `ZKNOX_falcon` decode reverts), When submitted, Then the call reverts with `SignatureMalformed()`.
- AC-4: Test assertions use `expect(...).to.be.revertedWithCustomError(account, 'SignatureMalformed')` for AC-3 and `expect(returnValue).to.equal(1)` for AC-1/AC-2.

**FR Coverage:** FR-7 (Falcon)

---

## Epic 4: ML-DSA Account

### Story 4-1: ML-DSA signer + MlDsaAccount + happy-path acceptance [M]

**User Story:** As an engineer, I want an ML-DSA-signing smart account that validates a correctly-signed UserOp on-chain, so that ML-DSA is integrated end-to-end.
**Dependencies:** 1-1
**Wave:** 2

**Acceptance Criteria:**

- AC-1: Given `SigningUtils.keygen('mldsa')`, When called, Then returns Alice's ML-DSA-65 keypair via `@noble/post-quantum/ml-dsa` with a 1,952-byte public key.
- AC-2: Given Alice's ML-DSA keypair, When calling `signUserOp('mldsa', aliceSecretKey, userOp)`, Then returns a `PackedUserOperation` whose `signature` field is a 3,309-byte ML-DSA-65 blob.
- AC-3: Given a deployed `MlDsaAccount` initialized with Alice's 1,952-byte public key and a `ZKNOX_dilithium` verifier reference, When Alice's ML-DSA-signed UserOp is submitted to `validateUserOp`, Then it returns `SIG_VALIDATION_SUCCESS`.
- AC-4: Given `MlDsaAccount._validateSignature`, When inspected, Then it calls `dilithiumVerifier.verify(publicKey, userOpHash, userOp.signature)` wrapped in try/catch.

**FR Coverage:** FR-3, FR-4 (ML-DSA) · **NFR Coverage:** NFR-1 (cross-cutting), NFR-2 (cross-cutting via AC-4)

### Story 4-2: ML-DSA failure-class tests [S]

**User Story:** As an engineer, I want ML-DSA to distinguish malformed from crypto-invalid signatures.
**Dependencies:** 4-1
**Wave:** 3

**Acceptance Criteria:**

- AC-1: Given an `MlDsaAccount` owned by Alice, When Bob signs with his own ML-DSA keypair, Then `validateUserOp` returns `SIG_VALIDATION_FAILED`.
- AC-2: Given Alice's valid ML-DSA signature, When byte 0 is bit-flipped, Then `validateUserOp` returns `SIG_VALIDATION_FAILED`.
- AC-3: Given a malformed ML-DSA signature (truncated or bad encoding), When submitted, Then the call reverts with `SignatureMalformed()`.

**FR Coverage:** FR-7 (ML-DSA)

---

## Epic 5: Benchmark & Report

### Story 5-1: Gas benchmark + variance test + calldata decomposition [M]

**User Story:** As an engineer, I want gas consumed per scheme captured deterministically across 3 runs, so that overhead numbers are trustworthy.
**Dependencies:** 2-1, 3-1, 4-1
**Wave:** 3

**Acceptance Criteria:**

- AC-1: Given all three deployed accounts, When the benchmark test runs `entryPoint.handleOps([signedUserOp])` for each scheme, Then `hardhat-gas-reporter` captures per-scheme gas used.
- AC-2: Given 3 repeated benchmark runs on the same devnet state, When gas values are collected per scheme, Then `(max - min) / mean < 0.01` for each scheme (NFR-3).
- AC-3: Given gas per scheme, When computing calldata cost from `userOp.signature` bytes (16 gas/non-zero byte, 4 gas/zero byte) and subtracting from total, Then both calldata cost and execution cost are reported separately (AC-A-1).
- AC-4: Given a partial failure where one scheme fails validation, When the benchmark completes, Then the failing scheme is recorded with its failure reason and remaining schemes still produce valid gas data (AC-U-1).
- AC-5: Given the full benchmark suite, When measured wall-clock, Then total elapsed time is ≤ 5 minutes (NFR-4).

**FR Coverage:** FR-5 · **NFR Coverage:** NFR-3 (direct), NFR-4 (direct)

### Story 5-2: Report generator + README run instructions [M]

**User Story:** As an engineer, I want a markdown report and README that let anyone reproduce the numbers and read them without running the suite.
**Dependencies:** 5-1
**Wave:** 4

**Acceptance Criteria:**

- AC-1: Given captured gas data from 5-1, When running the report generator, Then `docs/gas-report.md` is written with: (a) absolute gas per scheme, (b) relative overhead of Falcon and ML-DSA vs ECDSA baseline (percentage), (c) calldata vs execution breakdown per scheme (AC-FR-3, AC-A-1).
- AC-2: Given any scheme marked failed in 5-1 data, When generating the report, Then that scheme's row shows the failure reason and remaining schemes show valid gas data (AC-U-1).
- AC-3: Given the project README, When reading it, Then it contains exact commands for: `git submodule update --init`, `npm install`, running the validation suite, running the benchmark, and locating the report output (AC-U-2).

**FR Coverage:** FR-6

---

## FR Coverage Map

| FR   | Requirement                   | Stories       | Status |
| ---- | ----------------------------- | ------------- | ------ |
| FR-1 | ECDSA UserOp validation       | 2-1           | ✅     |
| FR-2 | Falcon UserOp validation      | 3-1           | ✅     |
| FR-3 | ML-DSA UserOp validation      | 4-1           | ✅     |
| FR-4 | Off-chain signing each scheme | 1-1, 3-1, 4-1 | ✅     |
| FR-5 | Gas benchmark suite           | 5-1           | ✅     |
| FR-6 | Markdown comparison report    | 5-2           | ✅     |
| FR-7 | Invalid/malformed rejection   | 2-1, 3-2, 4-2 | ✅     |

**Coverage: 7/7 (100%)**

## NFR Coverage Strategy

| NFR   | Path          | Story / Note                                                                                         |
| ----- | ------------- | ---------------------------------------------------------------------------------------------------- |
| NFR-1 | Cross-cutting | Account stories 2-1, 3-1, 4-1 use identical `validateUserOp` entry; verified across all three in 5-1 |
| NFR-2 | Cross-cutting | Per-story source-inspection ACs: 2-1 AC-4, 3-1 AC-4, 4-1 AC-4                                        |
| NFR-3 | Direct        | Story 5-1 AC-2 (variance assertion)                                                                  |
| NFR-4 | Direct        | Story 5-1 AC-5 (wall-clock assertion)                                                                |
| NFR-5 | Direct        | Story 1-1 AC-5 (submodule git diff empty)                                                            |

## Dependency Graph

```
1-1 (Foundation)
  ├─→ 2-1 (ECDSA)  ──────────────────┐
  ├─→ 3-1 (Falcon) ──→ 3-2 (fail)    │
  └─→ 4-1 (ML-DSA) ──→ 4-2 (fail)    │
                                      ↓
                       5-1 (bench) ──→ 5-2 (report)
```

## Wave Assignments

| Wave | Stories       | Rationale                                                                                       |
| ---- | ------------- | ----------------------------------------------------------------------------------------------- |
| 1    | 1-1           | Foundation — no deps                                                                            |
| 2    | 2-1, 3-1, 4-1 | Each scheme end-to-end; depend only on 1-1; disjoint files (signer file split prevents overlap) |
| 3    | 3-2, 4-2, 5-1 | PQC failure classes + benchmark; independent test files                                         |
| 4    | 5-2           | Report generator consumes 5-1's gas data                                                        |

## Interface Contracts

### `SigningUtils` TypeScript API

- **Defined by:** Story 1-1
- **Consumed by:** Stories 2-1, 3-1, 4-1, 5-1, 3-2, 4-2
- **Signature:**

```typescript
type Scheme = "ecdsa" | "falcon" | "mldsa";
type Keypair = { publicKey: Uint8Array; secretKey: Uint8Array };

export function keygen(scheme: Scheme): Keypair;
export function signUserOp(
  scheme: Scheme,
  secretKey: Uint8Array,
  userOp: UnsignedUserOp,
  entryPointAddress: string,
  chainId: bigint,
): Promise<PackedUserOperation>;
```

- **Location:** `test/signers/index.ts` (dispatches to `ecdsa.ts`, `falcon.ts`, `ml-dsa.ts`)

### `FalconAccount` constructor

- **Defined by:** Story 3-1
- **Consumed by:** Stories 3-2, 5-1
- **Signature:** `constructor(IEntryPoint entryPoint, ZKNOX_falcon _verifier)` + `function initialize(address owner, bytes calldata _publicKey)`
- **Location:** `contracts/FalconAccount.sol`

### `MlDsaAccount` constructor

- **Defined by:** Story 4-1
- **Consumed by:** Stories 4-2, 5-1
- **Signature:** `constructor(IEntryPoint entryPoint, ZKNOX_dilithium _verifier)` + `function initialize(address owner, bytes calldata _publicKey)`
- **Location:** `contracts/MlDsaAccount.sol`

## Plan Decisions

**PD-1:** Decomposition Strategy — Scheme-first vertical slices [LOCKED]

- Alternatives: consolidated PQC epic (uneven balance, couples Falcon/ML-DSA into one wave), flat single-epic (no epic grouping, less clear review boundaries)
- Rationale: spec treats ECDSA/Falcon/ML-DSA symmetrically (FR-1/2/3 identical modulo scheme); matching that in epic structure keeps stories predictable and makes Epic 3 and 4 genuinely wave-parallelizable

**PD-2:** Signer module file layout — `test/signers/{index,ecdsa,falcon,ml-dsa}.ts` split [LOCKED]

- Alternatives: single `SigningUtils.ts` with scheme dispatch inline
- Rationale: per-scheme files give Story 3-1 and Story 4-1 disjoint source files, enabling true Wave 2 parallelism

## Advisory Flags

- **Epic balance:** Epics 1 and 2 have 1 story each. Justified: Epic 1 is a single M-sized enabling foundation; Epic 2 is intentionally minimal since ECDSA inherits SimpleAccount unmodified (DD-10) — one story covers the entire baseline.
- **AC amplification:** 2.75× (33 story ACs / 12 spec ACs after AC-D-2 removal). Justified: symmetric per-scheme × per-failure-class expansion is mechanical, not bloat.
