---
status: complete
feature: falcon-eth
created: 2026-04-19
phase: 4
brief: docs/research.md
spec: docs/spec.md
architecture: docs/architecture.md
---
# Plan: Falcon-ETH

## Decomposition Strategy

**PD-1 [LOCKED]: Strategy C — 6-story plan with G2/G4 isolation**

6 stories across 2 epics, 5 waves. HashToPoint G2 lands in its own small Story 2-2 parallel with Story 1-2 (G1 PRG verification); signer G4 in Story 2-3 consumes both.

**Alternatives considered:**
- **Strategy A (5-story):** Ships G2 HashToPoint + G4 signer in a single story (`hashtopoint + signer port`). Weaker bug localization — a G4 failure requires bisecting between HashToPoint adapter code and the sign state machine; G2 has no dedicated commit surface. Rejected.
- **Strategy B (4-story):** Collapses G1 PRG verification into the keygen story as Task 0. Commits to "G1 is trivially identical" before verifying. If ETHFALCON's `Keccak256PRNG(a, b)` wrapper [**A-004**: the actual ETHFALCON class is `KeccakPRNG()` (0-arg); `Keccak256PRNG(a, b)` is the ETHDILITHIUM wrapper — see `docs/amendments.md` A-004] diverges from our `keccak-prg.ts`, Story 2-1 would reopen mid-stream with a `falconKeccakXofFactory` port. Rejected — DD-13 says the verification is non-skippable, so a dedicated small story is the right shape.

**Rationale for Strategy C:** G2 HashToPoint's bug classes (chunk endianness, rejection threshold, mod-q reduction, absorb order, coefficient-order) are distinct from the signer's state machine. A ~20-LOC test isolating HashToPoint pays for itself in diagnostic speed when G4 fails.

---

## Epic 1: Fixtures + Loader foundation

### Story 1-1: `falcon-eth-fixtures` [M]

**User Story:** As a signer-catalogue maintainer, I want the falcon-eth KAT corpus captured and loadable through a scheme-typed API, so that every downstream oracle gate has a ground-truth dataset and a type-safe loader.

**Dependencies:** None (Wave 1 foundation)
**Wave:** 1 · **Gate:** — (scaffolding)

**Tasks:**
1. **T0 — PRE_G4_DRBG_PROBE** (lesson 5.2 A-005 audit). Blocks all downstream tasks.
2. **T1 — `.rsp` transcription** + Python batch subprocess for `reshapedPk`.
3. **T2 — `FalconRef.sol` extension + Hardhat HashToPoint generator** (DD-25 Option C).
4. **T3 — Pure rename** `KatVector` → `MlDsaEthKatVector` across 8 files (DD-26).
5. **T4 — Multi-submodule loader + discriminated overload + `submoduleSource` backfill** on ml-dsa-eth fixtures.

**Acceptance Criteria (BDD):**
- **AC-1:** Given a fresh checkout with pinned ETHFALCON submodule, When maintainer runs `npm run kat:regen -- --scheme falcon-eth`, Then `test/fixtures/kat/falcon-eth/vectors.json` is written with 100 vectors — each containing `drbgSeed` (48 B), `publicKey` (897 B raw), `secretKey`, `reshapedPublicKey` (abi-encoded `uint256[]`), `message`, `signature` (1064 B), `submoduleSource: "ethfalcon"`, `submoduleSha` matching `git submodule status ETHFALCON`.
- **AC-2:** Given `ZKNOX_HashToPointExposed` contract deployed in Hardhat, When the fixture generator calls `.compute(salt, msg)` for 6 `(salt, msg)` pairs, Then `test/fixtures/kat/falcon-eth/hashtopoint-vectors.json` is emitted with 6 vectors — each `salt` (40 B), `message`, `expectedHash` (512 uint16 coefficients, all `< 12289`).
- **AC-3:** Given PRE_G4_DRBG_PROBE is run on vec 0 from `.rsp`, When Python ref signs `(sk, msg)` with the same AES256_CTR_DRBG-derived entropy order as the captured signature, Then the re-computed signature byte-equals `sm[:-mlen]` from the `.rsp`; probe failure HALTS the fixture-gen pipeline.
- **AC-4:** Given an ML-DSA-ETH fixture missing the `submoduleSource` field, When the refactored loader is invoked, Then the loader throws `KatFixtureError { code: "KAT_SCHEMA_MISMATCH" }`. Given `submoduleSource: "unknown"`, Then throws `KAT_UNKNOWN_SUBMODULE_SOURCE`.
- **AC-5:** Given fixture `submoduleSource: "ethfalcon"` with a stale `submoduleSha`, When `loadKatVectors("falcon-eth")` is called, Then loader throws `KAT_SUBMODULE_SHA_MISMATCH` with expected + actual SHAs + regeneration command.
- **AC-6 (Interface):** `loadKatVectors` is a TypeScript discriminated overload. Given a Falcon test file accesses `vec.cTilde` (ML-DSA-only), When compiled, Then `tsc` fails.
- **AC-7 (Commit discipline, DD-26):** Given Task 3 (pure rename) is committed before Task 4 (loader feature), When `git log` is inspected, Then the rename commit touches ≥7 files with no behavior change; the subsequent Task 4 commit adds the multi-submodule probe + discriminated overload without any rename-only edits.

**FR Coverage:** FR-16, FR-17
**NFR Coverage:** NFR-9 (direct — override safety), NFR-12 (direct — commit discipline), NFR-1 (cross-cutting)
**Persona ACs realized:** AC-A-1, AC-D-1, AC-A-4 (partial, HashToPoint wrapper lands here), AC-NFR-9, AC-NFR-10, AC-NFR-12

---

### Story 1-2: `keccak-prg-verification` [S-M]

**User Story:** As a signer-catalogue maintainer, I want confirmation that the shared `keccakXofFactory` produces byte-identical output to ETHFALCON's `Keccak256PRNG(a, b)` Python wrapper [**A-004**: the actual ETHFALCON class is `KeccakPRNG()` (0-arg); `Keccak256PRNG(a, b)` is the ETHDILITHIUM wrapper — see `docs/amendments.md` A-004], so that the XOF primitive is trusted for keygen, HashToPoint, signer, and pk-transform gates.

**Dependencies:** `1-1`
**Wave:** 2 · **Gate:** **G1**

**Tasks:**
1. **T1 — Capture G1 vectors** from ETHFALCON's `Keccak256PRNG` Python wrapper. [**A-004**: target class is actually `KeccakPRNG()` (0-arg) — see `docs/amendments.md` A-004]
2. **T2 — Assert byte-identity** via `assertBytesEqual` with factory-id discriminant in divergence messages.

**Acceptance Criteria (BDD):**
- **AC-1 (amended by A-004):** Given a fresh `KeccakPrg` seeded with G1 vector inputs, When scripted `inject`/`flip`/`extract` is applied per vector, Then output byte-equals ETHFALCON's Python `Keccak256PRNG(a, b)` output for the same seed + call sequence; divergence prints first-differing byte ±8 B context plus `(factory=keccak-prg)` discriminant. [**A-004**: target class is actually `KeccakPRNG()` (0-arg); `Keccak256PRNG(a, b)` is the ETHDILITHIUM wrapper — see `docs/amendments.md` A-004 for the authoritative class-name correction.]
- **AC-2 (Error path):** Given divergence is detected, When the G1 KAT test runs, Then the test fails with byte-offset + factory-id context AND a reminder that DD-13 requires porting a `falconKeccakXofFactory` adapter before proceeding to Story 2-1 / 2-2.

**FR Coverage:** FR-11
**NFR Coverage:** NFR-3 (direct — G1 single-pass primitive)
**Persona ACs realized:** AC-FR-11

---

## Epic 2: TS Port + Signer + Integration

### Story 2-1: `core + keygen port` [L] [**A-005**: resized L → S; see `docs/amendments.md` §A-005. This entire section is superseded by A-005's "Impact on Story 2-1" block — tasks, ACs, and the "XOF-factory abstraction" framing all change. Story 2-1 is a thin wrapper around `@noble/post-quantum/falcon.js#falcon512.keygen(innerSeed)`, where `innerSeed` is derived at test time via `@noble/ciphers/aes.js#rngAesCtrDrbg256(hexToBytes(v.drbgSeed)).randomBytes(48)`. No NTRU fork, no XOF factory, no `falcon-eth.core.ts`, no fixture schema additions. See the amended story file at `docs/stories/2-1.md` for the binding shape.]

**User Story:** As a signer-catalogue maintainer, I want Falcon-ETH keygen ported to TypeScript with the XOF-factory abstraction, so that G3 passes byte-identity against the NIST-KAT `.rsp` over ≥100 vectors.

**Dependencies:** `1-2`
**Wave:** 3 · **Gate:** **G3**

**Tasks:**
1. **T1 — Core module skeleton** (`falcon-eth.core.ts`) + `@delta-from-falcon` header with 6 `FALCON_DELTA_HEADINGS` + structural test.
2. **T2 — Sampler fork** from `@noble/post-quantum/falcon` with `XofFactory` parameterization.
3. **T3 — `keygenInternal(drbgSeed): Keypair`** (KAT surface) + `keygen(): Keypair` (production surface).
4. **T4 — G3 KAT** over 100 `.rsp` vectors.

**Acceptance Criteria (BDD):**
- **AC-1 (G3 KAT):** Given vec N's `drbgSeed` from `.rsp`, When `keygenInternal(drbgSeed)` runs, Then returned `{publicKey, secretKey}` byte-equals `.rsp`'s `pk` + `sk` for that vector — over 100 vectors.
- **AC-2 (Production surface hedging):** Given production `keygen()` is called twice, When outputs are compared, Then the two keys differ with overwhelming probability (entropy-sourced from `crypto.getRandomValues`).
- **AC-3 (Input validation):** Given `keygenInternal(seed)` where `seed.length !== 48`, When invoked, Then throws `SignerInputError { code: "INVALID_DRBG_SEED_LENGTH" }`.
- **AC-4 (Module header structural check):** Given `falcon-eth.core.ts` + `falcon-eth.ts` + `falcon-eth.kat-internal.ts`, When `test/signers/falcon-eth.test.ts` greps each file's JSDoc, Then all 6 `FALCON_DELTA_HEADINGS` substrings appear in each module header, AND no stray `ml-dsa`/`mldsa`/`dilithium` substrings appear unprefixed by `@cross-ref:`.
- **AC-5 (Grep gates, AC-D-2 + AC-A-5):** Given `falcon-eth.*.ts` source files, When test runs `^(let|var) _?xof` grep, Then zero hits returned; Given `test/signers/index.ts` + `test/bench/**/*.ts`, When `KAT_INTERNAL_MODULES` grep runs, Then zero hits for `falcon-eth.kat-internal` imports from these files.
- **AC-6 (Interface):** `falcon-eth.core.ts` exports `keygenInternal(drbgSeed: Uint8Array): Keypair` and consumes `XofFactory` from `mldsa-encoding.ts`. `falcon-eth.ts` exports `keygen(): Keypair`. Neither imports the other.

**FR Coverage:** FR-2, FR-3, FR-12, FR-18 (keygen fields)
**NFR Coverage:** NFR-3 (direct — G3 ≥100), NFR-6 (direct — grep gates land), NFR-11 (cross-cutting)
**Persona ACs realized:** AC-FR-2, AC-FR-3, AC-FR-12, AC-FR-18 (keygen portion), AC-D-2, AC-D-3, AC-A-5, AC-NFR-3, AC-NFR-6, AC-NFR-11

---

### Story 2-2: `hashtopoint-port` [S]

**User Story:** As a signer-catalogue maintainer, I want `hashToPointEVM(salt, msg)` ported to TypeScript as a standalone shared-core export, so that G2 passes byte-identity against the pinned on-chain `ZKNOX_HashToPoint.sol` over the 6 Hardhat-captured vectors — BEFORE the signer port consumes it.

**Dependencies:** `1-1`
**Wave:** 2 · **Gate:** **G2**

**Tasks:**
1. **T1 — Port `hashToPointEVM`** as standalone shared-core export using `keccak-prg.ts` internally.
2. **T2 — G2 KAT** against 6 vectors with first-differing-coefficient ±4 context on mismatch.

**Acceptance Criteria (BDD):**
- **AC-1 (G2 KAT):** Given vec N's `(salt, message)` from `hashtopoint-vectors.json`, When TS `hashToPointEVM(salt, message)` is invoked, Then output byte-equals the 512 uint16 `expectedHash` — for each of the 6 vectors.
- **AC-2 (Error path):** Given a coefficient mismatch at index K, When the G2 test fails, Then failure message includes first-differing-coefficient index ±4 context + rejection-threshold hint ("check chunk endianness, 61445 threshold, mod-q reduction").
- **AC-3 (Output constraints):** Given any valid `(salt, msg)`, When `hashToPointEVM` runs, Then output has length 512 AND every coefficient is `< 12289`.
- **AC-4 (Interface):** `falcon-eth.core.ts` exports `hashToPointEVM(salt: Uint8Array, msg: Uint8Array): Uint16Array` as a pure function.
- **AC-5 (Trust anchor):** Given the submodule SHA pin changes, When `npm run kat:regen` is re-run for falcon-eth, Then `hashtopoint-vectors.json` is regenerated from the new pinned `ZKNOX_HashToPoint.sol` automatically.

**FR Coverage:** (derived from FR-11 family; HashToPoint is an architecture-phase refinement per DD-25)
**NFR Coverage:** NFR-3 (direct — G2 corpus 6 vectors), NFR-1 (cross-cutting)

---

### Story 2-3: `signer port + G4` [L] [**A-005**: surface-shape superseded; see `docs/amendments.md` §A-005 "Forward contract for Story 2-3". The KAT signer takes a `BytesReader` whose `.read(n)` is driven by `@noble/ciphers/aes.js#rngAesCtrDrbg256(hexToBytes(v.drbgSeed))` (DRBG state advanced past the 48 B keygen draw before reading), NOT a raw `drbgSeed` replayed inline in the signer. Signer forks noble's `signRaw` + `FFSampler` + `HashToPoint` (~285 LOC transplant) with ONE algorithmic change: HashToPoint call-site swaps noble's SHAKE256 → Story 2-2's `hashToPointEVM` (KeccakPRNG). Function-name suggestions + error-code shape + fork inventory documented in A-005. Story 2-3 likely sizes M, not L. Tasks, ACs referencing `signWithDrbgRnd(drbgSeed)` + `INVALID_DRBG_SEED_LENGTH` below are stale; story-creator for 2-3 (wave 4) must treat A-005 as the binding interpretation.] [**A-006 SUPERSEDES**: A-005's 285-LOC source-transplant is DROPPED in favour of Strategy E — fork-side HashToPoint injection at `github.com/LimeChain/noble-post-quantum-eth#falcon-eth-hashtopoint-injection`. Our repo adds `~10 LOC`: `falcon512paddedEth = genFalcon({ ...falcon512paddedOpts, hashToPoint: hashToPointEVM })`. Final size: **S** (4 tasks). AC-4 / `signWithXofInstrumented` DROPPED (G4 byte-identity subsumes rejection-loop predicate; fork diff kept minimal). Tasks + ACs + DD-10 XofFactory parameterization stance below are ALL superseded; see `docs/amendments.md` §A-006 for Strategy E design, fork branch-pin, two-repo commit cadence, AC-4 drop rationale, and Story-2-4 forward contract. `docs/stories/2-3.md` is the binding task spec.]

**User Story:** As a signer-catalogue maintainer, I want Falcon-ETH signing ported to TypeScript using the hybrid-fork approach (noble math + Keccak-PRG samplers + G2 HashToPoint), so that G4 passes byte-identity over ≥100 `.rsp` vectors for the 1064-byte `salt‖s2_compact` layout.

**Dependencies:** `2-1`, `2-2`
**Wave:** 4 · **Gate:** **G4**

**Tasks:**
1. **T1 — Hybrid-fork sign state machine** — reuse noble's `ffSampling`/`splitFFT`/`mergeFFT`, fork sampler to Keccak-PRG.
2. **T2 — `signWithDrbgRnd` KAT surface** + `signWithXofInstrumented` sibling (DD-10).
3. **T3 — `signUserOp` production** + hedged sign via `crypto.getRandomValues`.
4. **T4 — G4 KAT** + input validation + hedged/deterministic tests.

**Acceptance Criteria (BDD):**
- **AC-1 (G4 KAT):** Given vec N's `(drbgSeed, sk, msg)` from `.rsp`, When `signWithDrbgRnd(sk, msg, drbgSeed)` runs, Then output 1064-byte `salt‖s2_compact` byte-equals `.rsp`'s `sm[:-mlen]` for that vector — over 100 vectors.
- **AC-2 (Hedged production sign):** Given two `signUserOp` calls with identical `(sk, userOp, entryPoint, chainId)`, When outputs are compared, Then the first 40 bytes (salt) differ; verifying both signatures against the same pk + userOp succeeds.
- **AC-3 (Deterministic KAT sign):** Given two `signWithDrbgRnd` calls with identical inputs, When outputs compared, Then they byte-equal.
- **AC-4 (Rejection counter instrumentation, DD-10):** Given `signWithXofInstrumented(sk, msg, salt, xof)`, When called on any vector, Then returns `{ signature, iterations }` where `iterations >= 1` AND no module-level XOF state is mutated (verified by AC-A-5 grep).
- **AC-5 (Input validation):** Given wrong-length `sk`, `msg`, or `drbgSeed`, When called, Then throws `SignerInputError` with code `INVALID_SECRET_KEY_LENGTH` / `INVALID_MESSAGE` / `INVALID_DRBG_SEED_LENGTH` respectively. One test per field per surface.
- **AC-6 (PRE_G4_DRBG_PROBE composition):** Given the PRE_G4_DRBG_PROBE from Story 1-1 passed, When Story 2-3 G4 bulk test runs, Then bulk test expects all 100 vectors to pass; if >1 vector fails, the test output suggests A-005-equivalent DRBG state-advancement bug + points to `docs/amendments.md` for logging.
- **AC-7 (Interface):** `falcon-eth.core.ts` exports `signWithXof(sk, msg, salt, xof): Uint8Array` (1064 bytes) and `signWithXofInstrumented(...): { signature: Uint8Array; iterations: number }`. `falcon-eth.kat-internal.ts` exports `signWithDrbgRnd(sk, msg, drbgSeed, ctx?): Uint8Array`. `falcon-eth.ts` exports `signUserOp(...): Promise<PackedUserOperation>`.

**FR Coverage:** FR-4, FR-5, FR-6, FR-13, FR-18 (signer fields)
**NFR Coverage:** NFR-3 (direct — G4 ≥100), NFR-6 (direct — grep gates extended), NFR-11 (cross-cutting)
**Persona ACs realized:** AC-FR-4, AC-FR-5, AC-FR-6, AC-FR-13, AC-FR-18 (full), AC-NFR-3, AC-NFR-6, AC-NFR-11

---

### Story 2-4: `integration + benchmark + README` [L]

**User Story:** As a smart-wallet operator, I want Falcon-ETH available as the 5th signer with working on-chain validateUserOp, a side-by-side 5-scheme benchmark surfacing the ML-DSA-ETH ↔ Falcon-ETH pairwise delta, and README attribution, so that I can evaluate lattice PQC tradeoffs on the ETH path.

**Dependencies:** `2-3`
**Wave:** 5 · **Gates:** **G5 + G6**

**Tasks:**
1. **T1 — `pkToNttCompact` + `preparePublicKeyForDeployment` + G5 KAT.**
2. **T2 — `FalconEthAccount.sol`** + NatSpec + `@custom:experimental` posture.
3. **T3 — `test/fixtures/falcon-eth.ts`** factory deploying fresh verifier + account.
4. **T4 — G6 happy-path `validateUserOp`** + gas-cap assertion.
5. **T5 — G6 failure paths** with dual-path walker + accountAddress bind.
6. **T6 — `SCHEMES` → 5** + `SCHEME_DEPLOYERS` registry + AC-A-3 calldata asymmetry + AC-U-1 pairwise delta + naming grep test + refresh `gas-data.json`.
7. **T7 — README 5-scheme attribution** + `@custom:experimental` warning + NFR-5 gas-cap runbook (AC-U-2).

**Acceptance Criteria (BDD):**
- **AC-1 (G5 pk-transform) [amended by A-007]:** Given vec N's `publicKey` from `.rsp`, When `preparePublicKeyForDeployment(rawPk, keccakXofFactory)` runs, Then output `Hex` byte-equals `reshapedPublicKey` for that vector — over 100 vectors. [**A-007**: oracle superseded — fixture uses `uint256[32]` (1024 B), `preparePublicKeyForDeployment` emits `uint256[]` (1088 B, required by on-chain `ZKNOX_ethfalcon.setKey`). The 64 B delta is the dynamic-array prefix; same 32 coefficients on both sides. Test uses `decodeAbiParameters` on both and compares element-wise. See `docs/amendments.md` §A-007 for root cause + precedent (`test/signers/mldsa-encoding.pk-transform.kat.test.ts:146-204`).]
- **AC-2 (G5 structural sub-check):** Given the same input, When `pkToNttCompact` is called, Then returns `bigint[]` of length 32, every element `< 2^256`.
- **AC-3 (G6 happy path):** Given a `FalconEthAccount` deployed with a valid `publicKeyPointer`, When a user-op signed with the matching sk is submitted via `validateUserOp`, Then EntryPoint accepts with `SIG_VALIDATION_SUCCESS`; `verifyGas < 16_777_216`.
- **AC-4 (G6 wrong-key reject):** Given a user-op signed with a DIFFERENT Falcon-ETH key, When `validateUserOp` runs, Then returns `SIG_VALIDATION_FAILED` (no revert).
- **AC-5 (G6 bit-flip reject):** Given a valid signature with one byte flipped in the salt region AND one byte flipped in the s2 region (2 sub-cases), When `validateUserOp` runs, Then returns `SIG_VALIDATION_FAILED` OR reverts `SignatureMalformed()` — EntryPoint does not accept.
- **AC-6 (G6 malformed reject):** Given a user-op with a zero-byte or wrong-length signature, When `validateUserOp` runs, Then reverts with `SignatureMalformed()`; dual-path walker binds to `accountAddress.toLowerCase()` on BOTH canonical `errorName` path AND HH3 EDR message-regex fallback path.
- **AC-7 (Bench — AC-A-3):** Given the 5-scheme bench test runs, When calldata assertions execute, Then length-ordering `ecdsa < falcon == falconEth < mldsa == mldsaEth` passes; within-pair gas-delta `|mldsa - mldsaEth| <= 5%` passes; within-pair `|falcon - falconEth| <= 25%` passes.
- **AC-8 (Bench — AC-U-1 pairwise delta):** Given `gas-report.md` is regenerated, When the report is inspected, Then it contains a labeled section comparing `ML-DSA-ETH ↔ Falcon-ETH` on (verify gas, calldata bytes) as named deltas.
- **AC-9 (Deployer registry — AC-A-2):** Given `SCHEMES` contains 5 entries, When `deployAccount(scheme, ctx)` dispatches via `SCHEME_DEPLOYERS: Record<Scheme, Deployer>`, Then every scheme gets its deployer from the registry; `tsc` fails at compile time if any `Scheme` union member lacks a registry entry. Test asserts `Object.keys(SCHEME_DEPLOYERS).length === SCHEMES.length`.
- **AC-10 (Naming discipline — AC-D-4):** Given the naming table is documented in `docs/`, When the unit test greps `src/ test/ contracts/ scripts/` for literal `falcon_eth` (snake), Then zero hits returned.
- **AC-11 (License header — AC-NFR-10):** Given `contracts/imports/FalconRef.sol` is extended, When the wrapper-header test runs, Then the first-N-lines byte-equal the upstream ETHFALCON MIT header verbatim.
- **AC-12 (Gas-cap README runbook — AC-U-2):** Given the README file, When `test/docs/readme-runbook.test.ts` runs, Then README contains a named runbook entry mapping "OOG during validation" → NFR-5 gas-cap explanation.
- **AC-13 (Deterministic bench — NFR-8):** Given a no-op test run (no `UPDATE_BENCH=1`), When `npm run report` executes, Then `gas-report.md` byte-equals the prior rendering; Given `UPDATE_BENCH=1` is set, When bench runs, Then `gas-data.json` snapshot is rewritten with timestamp from the snapshot file, not wall clock.
- **AC-14 (FalconRef doc note — AC-A-4):** Given `contracts/imports/FalconRef.sol`, When its contents are inspected, Then the file contains both the existing `ZKNOX_ethfalcon is _ZKNOX_ethfalcon {}` wrapper AND the new `ZKNOX_HashToPointExposed` contract (added in Story 1-1); a doc comment records that no new RefShim file was created.
- **AC-FLOW-1 (End-to-end):** Given a fresh Falcon-ETH account is deployed, When the operator calls `keygen("falcon-eth")` → `preparePublicKeyForDeployment` → `setKey` → `initialize` → `signUserOp` → submits to EntryPoint, Then the EntryPoint accepts and executes the user-op AND the bench entry in `gas-report.md` records the verify gas.

**FR Coverage:** FR-1, FR-7, FR-8, FR-9, FR-10, FR-14, FR-15, FR-19, FR-20
**NFR Coverage:** NFR-1 (final CI check), NFR-2 (final test count), NFR-3 (direct — G5 + G6), NFR-4 (final solc check), NFR-5 (direct — gas cap), NFR-7 (direct — measured), NFR-8 (direct — deterministic bench), NFR-10 (direct — MIT header), NFR-11 (cross-cutting — try/catch SignatureMalformed)
**Persona ACs realized:** AC-U-1, AC-U-2, AC-A-2, AC-A-3, AC-A-4, AC-D-4, AC-FR-1, AC-FR-7–10, AC-FR-14, AC-FR-15, AC-FR-19, AC-FR-20, AC-NFR-1, AC-NFR-5, AC-NFR-7, AC-NFR-8, AC-NFR-10, AC-NFR-11

---

## FR Coverage Map

| FR | Requirement summary | Story | Status |
|---|---|---|---|
| FR-1 | Select Falcon-ETH as 5th scheme | 2-4 | ✅ |
| FR-2 | Production keygen (fresh entropy) | 2-1 | ✅ |
| FR-3 | KAT keygen (deterministic) | 2-1 | ✅ |
| FR-4 | Hedged sign | 2-3 | ✅ |
| FR-5 | Deterministic sign | 2-3 | ✅ |
| FR-6 | Rejection-iteration observable | 2-3 | ✅ |
| FR-7 | pk → ntt-compact pure transform | 2-4 | ✅ |
| FR-8 | Register pk at deployment (20-byte pointer) | 2-4 | ✅ |
| FR-9 | Valid user-op accepted | 2-4 | ✅ |
| FR-10 | Invalid/malformed/wrong-key rejected | 2-4 | ✅ |
| FR-11 | G1 XOF byte-identity | 1-2 | ✅ |
| FR-12 | G3 keygen byte-identity | 2-1 | ✅ |
| FR-13 | G4 signer byte-identity | 2-3 | ✅ |
| FR-14 | G5 pk-transform byte-identity | 2-4 | ✅ |
| FR-15 | G6 on-chain validate | 2-4 | ✅ |
| FR-16 | Fixture pipeline | 1-1 | ✅ |
| FR-17 | Fixture loader with Falcon-typed schema | 1-1 | ✅ |
| FR-18 | SignerInputError stable codes | 2-1, 2-3 | ✅ |
| FR-19 | 5-scheme bench report | 2-4 | ✅ |
| FR-20 | README attribution | 2-4 | ✅ |

**Coverage: 20/20 (100%) — zero gaps.**

## NFR Coverage Strategy

| NFR | Path | Story / Coverage Method |
|---|---|---|
| NFR-1 Submodule immutability | Direct + Cross-cutting | CI gate at every story commit; final check at Story 2-4 AC-NFR-1 |
| NFR-2 97-test baseline | Cross-cutting | Every story's Gate 5 runs `npx hardhat test` |
| NFR-3 Oracle gates ≥100 vectors | Direct (multi-story) | G1→1-2, G2→2-2, G3→2-1, G4→2-3, G5+G6→2-4 |
| NFR-4 Zero solc warnings | Cross-cutting | Every Solidity commit runs `npm run compile` |
| NFR-5 On-chain verify < 2²⁴ gas | Direct | Story 2-4 AC-3 |
| NFR-6 Grep gates zero hits | Direct (multi-story) | Story 2-1 lands grep tests; Story 2-4 extends to final file set |
| NFR-7 Falcon-ETH verify gas recorded | Direct | Story 2-4 AC-7, AC-8 |
| NFR-8 Deterministic bench | Direct | Story 2-4 AC-13 |
| NFR-9 Test-override safety | Direct | Story 1-1 AC-3 + NFR-9 tests |
| NFR-10 MIT header byte-equal | Direct | Story 2-4 AC-11 |
| NFR-11 Cross-scheme symmetry | Cross-cutting | Stories 2-1, 2-3, 2-4 |
| NFR-12 One commit per task | Cross-cutting | All 6 stories |

**NFR classification: 7 direct + 5 cross-cutting + 0 deferred. Every NFR has a coverage path.**

## Dependency Graph

```
           1-1 (fixtures + loader)
          /   \
       1-2   2-2            ← Wave 2 fork: G1 ‖ G2 (independent oracles)
       (G1)  (G2)
          \    \
          2-1   \           ← Wave 3: keygen (G3)
          (G3)   \
              \   \
                \   \
                 2-3         ← Wave 4: signer (G4)
                (G4)
                  │
                 2-4         ← Wave 5: integration (G5 + G6)
                (G5+G6)
```

DAG validated (topological sort): 1-1 → {1-2, 2-2} → 2-1 → 2-3 → 2-4. No cycles.

## Wave Assignments

| Wave | Stories | Rationale |
|---|---|---|
| 1 | 1-1 | Foundation: fixtures + loader are prereqs for every gate |
| 2 | 1-2, 2-2 | G1 PRG verification + G2 HashToPoint port — independent oracles (DD-25 Option C anchors G2 to Solidity, not Python) |
| 3 | 2-1 | Keygen port needs G1-verified XOF (DD-13) |
| 4 | 2-3 | Signer consumes G3 keygen output + G2 HashToPoint |
| 5 | 2-4 | Integration composes G4 signer for G5 pk-transform + G6 on-chain |

**Total: 5 waves · 6 stories.**

## Interface Contracts

| Interface | Defined by | Consumed by | Signature | Location |
|---|---|---|---|---|
| `loadKatVectors` (discriminated overload) | 1-1 | 1-2, 2-1, 2-3, 2-4 | `loadKatVectors("mldsa-eth"): MlDsaEthKatVector[]` · `loadKatVectors("falcon-eth"): FalconKatVector[]` | `test/fixtures/kat/index.ts` |
| `loadHashToPointVectors` | 1-1 | 2-2 | `loadHashToPointVectors(): HashToPointVector[]` | `test/fixtures/kat/index.ts` |
| `hashToPointEVM` | 2-2 | 2-3, 2-4 | `hashToPointEVM(salt: Uint8Array, msg: Uint8Array): Uint16Array` | `test/signers/falcon-eth.core.ts` |
| `keygenInternal` | 2-1 | 2-3 | `keygenInternal(drbgSeed: Uint8Array): Keypair` | `test/signers/falcon-eth.kat-internal.ts` |
| `keygen` (production) | 2-1 | 2-4, dispatcher | `keygen(): Keypair` | `test/signers/falcon-eth.ts` |
| `signWithXof` | 2-3 | 2-4 | `signWithXof(sk, msg, salt, xof): Uint8Array` (1064 B) | `test/signers/falcon-eth.core.ts` |
| `signWithXofInstrumented` | 2-3 | 2-3 test suite | `signWithXofInstrumented(...): { signature: Uint8Array; iterations: number }` | `test/signers/falcon-eth.core.ts` |
| `signWithDrbgRnd` (KAT) | 2-3 | G4 KAT test | `signWithDrbgRnd(sk, msg, drbgSeed, ctx?): Uint8Array` | `test/signers/falcon-eth.kat-internal.ts` |
| `signUserOp` (production) | 2-3 | 2-4, dispatcher | `signUserOp(sk, userOp, entryPoint, chainId): Promise<PackedUserOperation>` | `test/signers/falcon-eth.ts` |
| `preparePublicKeyForDeployment` | 2-4 | Fixture factory, account init | `preparePublicKeyForDeployment(rawPk, xof): Hex` | `test/signers/falcon-eth.core.ts` |
| `pkToNttCompact` (internal helper) | 2-4 | G5 structural sub-test | `pkToNttCompact(rawPk, xof): bigint[]` (length 32) | `test/signers/falcon-eth.core.ts` |
| `SCHEME_DEPLOYERS` | 2-4 | Bench harness | `Record<Scheme, Deployer>` (compile-time exhaustive) | `test/signers/deployers.ts` (or collocated sibling files) |
| `Scheme` union extended | 2-4 | Every dispatcher call-site | `"ecdsa" \| "falcon" \| "mldsa" \| "mldsa-eth" \| "falcon-eth"` | `test/signers/schemes.ts` or `test/signers/index.ts` |
| `ZKNOX_HashToPointExposed.compute` (Solidity) | 1-1 | Hardhat fixture-gen (1-1 T2), also future G2 regeneration | `compute(bytes salt, bytes msgHash) external pure returns (uint256[] memory)` | `contracts/imports/FalconRef.sol` (extended) |
| `FalconEthAccount` | 2-4 | EntryPoint flow + fixture factory | `initialize(address, bytes _publicKeyPointer)` · `_validateSignature(...)` override | `contracts/FalconEthAccount.sol` |

## Plan Decisions

- **PD-1 [LOCKED]: Strategy C — 6-story with G2/G4 isolation.** Alternatives: Strategy A (5-story, G2+G4 bundled) rejected for weaker bug localization; Strategy B (4-story with G1 pre-collapse) rejected as committing to G1 identicality before verifying. Rationale: G2 HashToPoint has a distinct bug-class surface (chunk endianness, rejection threshold, mod-q reduction, absorb order, coefficient-order) — a ~20-LOC isolated test pays for itself in diagnostic speed at G4 failures.
