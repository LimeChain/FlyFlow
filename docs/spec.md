---
status: complete
created: 2026-04-18
feature: falcon-eth
brief: docs/research.md
complexityTier: medium
---
# Specification: Falcon-ETH

## Overview
Port ETHFALCON (Keccak-CTR-PRNG variant of Falcon-512) as the 5th ERC-4337 signer in the existing signer catalogue alongside ECDSA, NIST Falcon, NIST ML-DSA, and ML-DSA-ETH. Delivers a production + KAT signing surface pair backed by a shared core, a parallel account contract storing a 20-byte `publicKeyPointer` to the verifier-held public key, a 6-stage oracle chain (G1–G6) proving byte-identity to the ZKNoxHQ Python reference, and extensions to the benchmark + report harness for 5-scheme coverage. Secondary deliverable: the first and only JavaScript/TypeScript implementation of ETHFALCON — `@noble/post-quantum/falcon` ships only NIST Falcon (SHAKE).

## Use Cases

UC-1: Select Falcon-ETH as the signer scheme for a smart-wallet account — A wallet operator chooses Falcon-ETH from the five-scheme catalogue and obtains a working keypair and account.
  Primary actor: Smart-wallet operator
  Precondition: The signer catalogue exposes five schemes; the Falcon-ETH production surface is available.
  Main flow:
    1. The operator selects Falcon-ETH from the catalogue.
    2. The operator requests a fresh Falcon-ETH keypair from the production surface.
    3. The catalogue returns secret-key and public-key bytes.
    4. The operator deploys a smart-wallet account, registering the public key at initialization.
    5. The catalogue confirms successful deployment and returns the deployed account address.
  Alternative flows:
    - The chosen scheme name is misspelled or unknown: the catalogue rejects the request with a scheme-not-found error and lists supported schemes.
    - On-chain registration of the public key fails (e.g., EVM revert): no account is deployed and the failure is surfaced to the operator without leaving partial state.
  Postcondition: A new account exists on-chain whose state references the Falcon-ETH public key via a single 20-byte pointer; the operator holds the corresponding secret key.

UC-2: Submit a Falcon-ETH-signed user operation — A wallet operator authorizes an ERC-4337 user operation with a Falcon-ETH signature and observes acceptance on-chain.
  Primary actor: Smart-wallet operator
  Precondition: A Falcon-ETH-backed account is deployed; the operator holds the matching secret key; the operator has constructed a valid user operation.
  Main flow:
    1. The operator requests a hedged Falcon-ETH signature over the user operation.
    2. The catalogue returns a single signature byte-string (salt followed by the compacted second polynomial).
    3. The operator submits the signed user operation to the EntryPoint flow.
    4. The on-chain verifier validates the signature against the registered public key.
    5. The EntryPoint accepts the operation and proceeds with execution.
  Alternative flows:
    - The signature is invalid for the registered key: the on-chain verifier rejects the operation with a structured signature-validation failure and the EntryPoint does not execute it.
    - The signature byte-string is malformed (wrong length, garbage payload): the verifier rejects with the same structured malformed-signature failure rather than an arbitrary revert.
    - The user operation was signed by a Falcon-ETH key that does not match the account's registered key: the verifier rejects and the failure is observable to the operator/bundler.
  Postcondition: A valid signature results in execution and observable state change; an invalid signature results in rejection with no execution and no key/account state change.

UC-3: Verify byte-identity of a TypeScript Falcon-ETH port against the Python reference — A maintainer runs the oracle-chain test suite and confirms every gate passes.
  Primary actor: Signer-catalogue maintainer
  Precondition: The Falcon-ETH KAT corpus has been captured from the Python reference; the TypeScript port is implemented; the on-chain verifier wrapper is in the compile graph.
  Main flow:
    1. The maintainer triggers the oracle-chain test suite.
    2. The suite executes G1 (XOF byte-identity), G2 (HashToPoint byte-identity), G3 (keygen byte-identity), G4 (sign byte-identity), G5 (public-key transform byte-identity), and G6 (on-chain validate happy + rejection paths) against the captured corpus.
    3. Each gate compares TypeScript output to the captured Python reference output byte-for-byte.
    4. The suite reports pass/fail per gate with first-differing-byte context on any mismatch.
  Alternative flows:
    - A gate fails byte-identity: the assertion prints the first differing byte ±8 bytes of context plus the XOF discriminant, and the maintainer halts and investigates rather than relaxing the gate.
    - The Python reference subprocess is unavailable (e.g., missing interpreter, missing submodule): fixture capture refuses to run and the maintainer is told which prerequisite is missing.
  Postcondition: Either all five gates report pass at byte-identity over the corpus, or the failing gate is identified with sufficient context for diagnosis; in no case is a "close enough" pass recorded.

UC-4: Refresh the Falcon-ETH KAT corpus from the Python reference — A maintainer regenerates fixture vectors when the upstream reference or capture parameters change.
  Primary actor: Signer-catalogue maintainer
  Precondition: The Python reference is reachable; the fixture-capture pipeline supports the falcon-eth scheme target.
  Main flow:
    1. The maintainer invokes the fixture-capture pipeline targeting Falcon-ETH.
    2. The pipeline executes the Python reference for the configured number of vectors (~100).
    3. For each vector, the pipeline records secret key, public key, message, salt, signature, and any reshaped-public-key payload.
    4. The pipeline writes a single fixture file under the Falcon-ETH KAT corpus directory and updates the submodule SHA pin.
    5. The loader validates the SHA pin at next test import.
  Alternative flows:
    - A test-only override environment variable is supplied with an unexpected value: the pipeline rejects it at ingest with a regex-validation failure rather than passing it to the subprocess.
    - The pipeline is invoked without the off-by-default sentinel variable while overrides are set: the pipeline refuses to apply the overrides and runs in default mode (or aborts with a clear message).
    - The recorded submodule SHA does not match the loader's pinned SHA on next test run: the loader fails at import time with a pin-mismatch error.
  Postcondition: A new fixture file exists with ~100 captured vectors and the SHA pin matches; or the run is aborted with a structured error and no partial fixture file is left behind.

UC-5: Read the five-scheme benchmark report — A wallet developer compares signature size, verify gas, and signer runtime across all five schemes.
  Primary actor: Smart-wallet operator
  Precondition: The bench harness has been run and a snapshot is committed.
  Main flow:
    1. The developer opens the published benchmark report.
    2. The report lists all five schemes (ECDSA, NIST Falcon, NIST ML-DSA, ML-DSA-ETH, Falcon-ETH) in deterministic order.
    3. For each scheme, the report shows verify gas, calldata size, and any cross-scheme deltas.
    4. The developer uses the comparison to choose a scheme for their evaluation.
  Alternative flows:
    - The snapshot is stale or missing an entry: a routine test run flags the inconsistency without overwriting the snapshot, and the maintainer regenerates it via the explicit refresh flag.
    - The snapshot timestamp drifts on a no-op rerun: the report renderer treats this as a non-deterministic-rendering failure rather than silently writing.
  Postcondition: The developer has a single, deterministic, side-by-side comparison of the five schemes that matches the on-disk snapshot.

## Functional Requirements (Capability Contract)

FR-1: [Smart-wallet operator] can [select Falcon-ETH (Keccak-CTR-PRNG Falcon-512) as a fifth signer scheme] [from the existing signer catalogue alongside ECDSA, NIST Falcon, NIST ML-DSA, and ML-DSA-ETH] (Source: FI-5)

FR-2: [Signer-catalogue maintainer] can [generate a Falcon-ETH key pair from a fresh entropy source on the production surface] [with the secret and public key returned as byte arrays suitable for downstream signing and on-chain registration] (Source: FI-3)

FR-3: [Signer-catalogue maintainer] can [generate a Falcon-ETH key pair deterministically from an explicit seed on the KAT-only surface] [so that fixture vectors captured from the Python reference can be reproduced byte-for-byte in TypeScript] (Source: FI-3)

FR-4: [Smart-wallet operator] can [produce a Falcon-ETH signature over an ERC-4337 user operation hedged with fresh randomness] [via the production signing surface, without supplying any explicit nonce or salt] (Source: FI-4)

FR-5: [Signer-catalogue maintainer] can [produce a Falcon-ETH signature deterministically from an explicit randomness/salt input on the KAT-only surface] [so that captured fixture vectors are reproducible byte-for-byte from TypeScript against the Python reference] (Source: FI-4)

FR-6: [Signer-catalogue maintainer] can [observe the rejection-loop iteration count from a Falcon-ETH sign call without mutating any shared module state] [so that hedged-vs-deterministic and rejection-counter behaviour can be asserted in tests] (Source: FI-4)

FR-7: [Signer-catalogue maintainer] can [transform a raw Falcon-ETH public key into the on-chain compacted NTT-domain representation expected by the on-chain verifier] [as a pure function over the raw key bytes prior to deployment] (Source: FI-5)

FR-8: [Smart-wallet operator] can [register a Falcon-ETH public key with their account at deployment time] [so that the account stores a single 20-byte pointer to the verifier-held key rather than the raw key bytes] (Source: FI-5)

FR-9: [Smart-wallet operator] can [submit a Falcon-ETH-signed user operation to the bundler/EntryPoint flow and have it accepted on-chain when the signature is valid for the registered key] (Source: FI-5)

FR-10: [Smart-wallet operator] can [have a Falcon-ETH-signed user operation rejected on-chain when the signature is invalid, malformed, or signed by the wrong key] [with the rejection surfacing as a structured signature-validation failure rather than an arbitrary revert] (Source: FI-5)

FR-11: [Signer-catalogue maintainer] can [confirm that the shared Keccak-CTR-PRNG XOF used on the ETH path produces byte-identical output to ETHFALCON's Python Keccak-PRNG wrapper] [as a fixture-driven oracle (G1) prior to relying on it for keygen and signing] (Source: FI-2)

FR-12: [Signer-catalogue maintainer] can [confirm Falcon-ETH keygen output is byte-identical to the Python reference] [as a fixture-driven oracle (G3) over a corpus of captured vectors] (Source: FI-3)

FR-13: [Signer-catalogue maintainer] can [confirm Falcon-ETH signature output is byte-identical to the Python reference for the same secret-key/message/salt inputs] [as a fixture-driven oracle (G4) over a corpus of captured vectors] (Source: FI-4)

FR-14: [Signer-catalogue maintainer] can [confirm the raw-public-key to compacted-NTT-domain transform is byte-identical to the Python reference's encoded payload] [as a fixture-driven oracle (G5) prior to on-chain registration] (Source: FI-5)

FR-15: [Signer-catalogue maintainer] can [confirm a Falcon-ETH-signed user operation validated end-to-end against an on-chain account is accepted on the happy path and rejected on the wrong-key/bit-flip/malformed paths] [as a fixture-driven oracle (G6) over a corpus of captured vectors] (Source: FI-5)

FR-16: [Signer-catalogue maintainer] can [generate and refresh the Falcon-ETH KAT corpus on demand from the Python reference] [via a fixture-capture pipeline that records secret key, public key, message, salt, signature, and any reshaped-public-key payload per vector] (Source: FI-1)

FR-17: [Signer-catalogue maintainer] can [load the Falcon-ETH KAT corpus into TypeScript tests through the existing fixture loader] [with a typed vector schema specific to Falcon-ETH (salt + s2 layout) distinct from the ML-DSA-ETH schema] (Source: FI-1)

FR-18: [Signer-catalogue maintainer] can [reject Falcon-ETH inputs of the wrong byte length on both surfaces] [with a structured signer-input error carrying a stable error code identifying the failing field (secret key, message, randomness, salt)] (Source: FI-3, FI-4)

FR-19: [Signer-catalogue maintainer] can [view a single benchmark report covering all five signer schemes side-by-side] [with deterministic ordering, calldata-delta assertions covering the Falcon-ETH entry, and snapshot regeneration gated behind an explicit refresh flag] (Source: FI-5)

FR-20: [Smart-wallet operator] can [read in the project README which of the five schemes are NIST-variant versus ETH-variant and which are appropriate for which evaluation question] [with attribution to upstream references for each scheme] (Source: FI-5)

## Non-Functional Requirements (measurable targets)

NFR-1: Maintainability (submodule immutability) — `git status ETHFALCON/` and `git status ETHDILITHIUM/` MUST report zero modifications across the entire feature; verified as a hard gate.

NFR-2: Compatibility (test baseline) — The pre-feature baseline of 97 passing Hardhat tests MUST remain green throughout the feature, and the post-feature total MUST equal 97 plus the falcon-eth additions (target: 15–25 new tests, in line with mldsa-eth's per-story adds).

NFR-3: Correctness (oracle chain coverage) — Each of the four oracle gates G3, G4, G5, G6 MUST pass at byte-identity over ≥100 captured KAT vectors (G1 byte-identity passes once over the XOF primitive). G6 MAY land at smoke size N=5 during initial development and tune up to N=100 at story Gate 5 if runtime budget allows.

NFR-4: Compatibility (build hygiene) — Solidity compilation MUST emit zero solc warnings; warnings-as-errors gate is enforced by the existing compile wrapper script.

NFR-5: Maintainability (gas cap) — On-chain Falcon-ETH user-operation verification MUST fit under the EDR `tx_gas_limit_cap = 2^24 = 16,777,216 gas` ceiling, consistent with the existing `VERIFICATION_GAS_LIMIT = 15_000_000` and `TX_GAS_OVERRIDE = 16,777,215` workaround.

NFR-6: Maintainability (test-architecture invariants) — The runtime grep gate on `*.kat-internal.*` imports (AC-3-7 boundary) MUST report zero hits when scanning the dispatcher and bench harness for Falcon-ETH KAT-internal imports. The runtime grep gate on `^(let|var) _?xof` (AC-A-1) MUST report zero hits across falcon-eth source files.

NFR-7: Performance (signer + verifier runtime) — Falcon-ETH verify gas SHOULD be lower than ML-DSA-ETH verify gas (Falcon signatures are smaller than ML-DSA's); exact target deferred to architecture phase but MUST be measured and recorded in the 5-scheme bench report.

NFR-8: Compatibility (deterministic bench/report) — The bench report MUST render deterministically with the timestamp sourced from the snapshot file rather than wall-clock time, and the snapshot MUST only be rewritten when an explicit refresh flag is set.

NFR-9: Security (test-override safety) — Test-only environment-variable overrides in the fixture-generation pipeline MUST be regex-validated at ingest and gated behind an off-by-default sentinel variable, never accepted on documentation alone.

NFR-10: Maintainability (license/attribution) — Every wrapper contract pulled into the compile graph MUST carry the upstream MIT copyright/license header verbatim.

NFR-11: Maintainability (cross-scheme symmetry) — Falcon-ETH MUST follow the same production/KAT split, shared-core, sibling-export instrumentation, per-account-verifier, and `try/catch SignatureMalformed()` patterns as ML-DSA-ETH, so the dispatcher's exhaustive switches catch any missing branch at compile time.

NFR-12: Maintainability (commit traceability) — One commit per task, story file tracked from Task 1, story-file checkbox advancement committed in the same commit as the work it describes.

## Constraints & Assumptions

### Constraints
- C-1: Submodule immutability — `ETHFALCON/**` and `ETHDILITHIUM/**` MUST NOT be modified; all integration occurs via wrappers under `contracts/imports/` and TS ports under `test/signers/`. (Source: research Constraints + DD-6 LOCKED + NFR-5)
- C-2: XOF swap is total — every SHAKE-128/256 role from NIST Falcon (including HashToPoint) collapses to a single Keccak-CTR-PRNG factory call on the ETH path; NIST Falcon and Falcon-ETH keys/signatures are NOT interchangeable. (Source: DD-1 LOCKED)
- C-3: The Falcon-ETH account inherits from the existing `SimpleAccount` base, overrides `_validateSignature`, and uses an `initialize(address, bytes calldata _publicKeyPointer)` shape with the same shadowing discipline as ML-DSA-ETH. (Source: DD-5 LOCKED)
- C-4: Wrapper contracts for the on-chain verifier go under `contracts/imports/FalconRef.sol` mirroring `contracts/imports/DilithiumRef.sol:37`; the submodule source is never edited to satisfy the compile graph. (Source: DD-6 LOCKED)
- C-5: The on-chain public-key shape is the NTT-domain compacted form (`32 × uint256` for Falcon-512); a TS pre-deployment transform converts the raw public key into this shape before registration. (Source: DD-7 LOCKED)
- C-6: The on-chain Falcon-ETH signature ABI is `salt(40 bytes) || s2_compact(32 × uint256 = 1024 bytes) = 1064 bytes` total; TypeScript signing emits a single byte-string in this layout. (Source: DD-8 LOCKED)
- C-7: Each Falcon-ETH-backed account carries its own immutable on-chain verifier reference; verifiers are not shared across accounts. (Source: DD-9 LOCKED)
- C-8: Rejection-loop instrumentation is delivered via a sibling export returning `{ signature, iterations }`; no module-level XOF state is permitted, and the AC-A-1 grep gate enforces this. (Source: DD-10 LOCKED + NFR-6)
- C-9: Oracle-chain discipline is byte-identity at every segment (G1–G6); "close enough" is not acceptable. (Source: DD-11 LOCKED + NFR-3)
- C-10: Story 2 (Keccak-PRG byte-identity verification, G1) is REQUIRED, not skippable, because ETHFALCON's `Keccak256PRNG(a=None, b=None)` wrapper diverges from ETHDILITHIUM's `KeccakPRNG()` even if internal mechanics match. (Source: DD-13 LOCKED)
- C-11: No pre-existing KAT corpus exists for ETHFALCON; vectors MUST be generated on demand from `generate_falcon_test_vectors.py` in the Python reference. (Source: DD-14 LOCKED)
- C-12: NIST-variant signers (ECDSA, NIST Falcon, NIST ML-DSA) and existing account contracts (`MlDsaAccount`, `FalconAccount`, `MlDsaEthAccount`) remain verbatim; falcon-eth work is purely additive. (Source: research Out of Scope)
- C-13: License/attribution preservation — ZKNoxHQ MIT copyright/license headers are kept verbatim on every wrapper contract. (Source: research Constraints + NFR-10)
- C-14: Commit granularity — one commit per task, story file tracked from Task 1 with `status: ready-for-dev`, checkboxes advanced in the task's own commit. (Source: research Constraints + NFR-12)
- C-15: The on-chain verifier carries an `@custom:experimental` "not audited yet, do not use in production" posture; production deployment of Falcon-ETH-backed accounts is out of scope for this feature. (Source: research Out of Scope)

### Assumptions
- A-1: `@noble/post-quantum/falcon` exposes enough of the NIST Falcon math (keygen, internal sampling, polynomial helpers) to be leveraged as a NIST-side reference, with the ETH-variant XOF swap delta-diffed on top — mirroring how ML-DSA-ETH leveraged `ml_dsa44`. Risk if wrong: `ffSampling` and other Falcon-internal primitives must be ported ground-up from Python, increasing Story 4 cost and amendment risk. (Source: DD-12 DISCRETION + DD-15 DEFERRED)
- A-2: The shared `keccakXofFactory` shipped with ML-DSA-ETH produces byte-identical output to ETHFALCON's `Keccak256PRNG` Python wrapper. Risk if wrong: a Falcon-specific XOF adapter must be ported, expanding Story 2 from verification-only into a port. (Source: DD-13 LOCKED + research Reusable infrastructure)
- A-3: `ffSampling` is portable to TypeScript without unbounded numerical-precision issues (or noble exposes a usable equivalent). Risk if wrong: client-side sampling must be reformulated, potentially affecting G4 byte-identity and the signing-API shape. (Source: DD-15 DEFERRED)
- A-4: The on-chain verifier's exact `verify()` signature is `verify(h, salt, s2, ntth)` with no additional hint field; full re-reading at architecture time confirms this. Risk if wrong: the `_validateSignature` decode path and the signature-ABI constraint (C-6) need to be revised. (Source: DD-16 DEFERRED)
- A-5: The total feature size is ~5 stories at M/L, comparable to ML-DSA-ETH's 2–3 day end-to-end duration; if Story 2 concludes "Keccak-PRG matches, nothing to port," it can merge into Story 3 for a 4-story plan. Risk if wrong: timeline and story count both grow; replan at Gate 5 of an early story. (Source: research Success Metrics + suggested decomposition)
- A-6: 3–5 amendments are expected during implementation (Falcon has more moving parts than ML-DSA). Risk if wrong: more amendments imply higher review overhead and possible architectural drift; mitigated by amendment-doc-sweep discipline (universal rule [2026-04-18]). (Source: research Additional Context A-N amendments)
- A-7: Falcon-ETH verify gas is below the EDR cap (Falcon is cheaper than NIST ML-DSA which already fits with the workaround). Risk if wrong: the verification-gas-limit / tx-gas-override workaround needs further tuning, possibly affecting bench numbers. (Source: NFR-5 + research Lessons)
- A-8: The Falcon-ETH KAT vector schema (salt + s2 layout) can coexist with the ML-DSA-ETH schema (cTilde + z + h) under a single fixture-loader entry point by parameterizing the per-scheme vector type. Risk if wrong: loader needs a structural refactor or a separate code path, increasing Story 1 scope. (Source: research Reusable infrastructure)

## Open Questions
None — all open architectural items (DD-15 ffSampling port strategy, DD-16 exact `verify()` signature) are flagged as DEFERRED design decisions for the architecture phase rather than business decisions requiring stakeholder input.

## Quality Perspectives

### End User (2 concerns)
| # | Concern | Priority | AC |
|---|---------|----------|-----|
| 1 | 5-scheme bench lacks labeled ML-DSA-ETH ↔ Falcon-ETH pairwise delta; evaluator subtracts absolute numbers mentally | MED | AC-U-1 |
| 2 | Gas-cap-breach UX undefined — OOG revert indistinguishable from SignatureMalformed rejection | MED | AC-U-2 |

### Architect (3 concerns + 2 LOW gaps)
| # | Concern | Priority | AC |
|---|---------|----------|-----|
| 1 | KAT loader SHA oracle is single-submodule; Falcon fixtures sourced from ETHFALCON would compare against ETHDILITHIUM HEAD → tautological match or always-mismatch; breaks DD-13 at loader boundary | **HIGH** | AC-A-1 |
| 2 | Bench `deployAccount` accumulates O(N) inline scheme-branches; 5th makes it 5, 6th crosses size thresholds | MED | AC-A-2 |
| 3 | Calldata-delta assertion clone-risk: mldsa pair shares DD-8 layout (5% window), falcon pair shares byte length but differs in distribution (NTT-compact vs Algorithm-17 compress) | MED | AC-A-3 |
| 4 | Gap: `contracts/imports/FalconRef.sol` already exposes `ZKNOX_ethfalcon` — arch doc must record unchanged to prevent redundant RefShim | LOW | AC-A-4 |
| 5 | Gap: AC-A-1 grep enforcement test glob must include `falcon-eth.*` | LOW | AC-A-5 |

### Maintainer (3 concerns + naming gap)
| # | Concern | Priority | AC |
|---|---------|----------|-----|
| 1 | `KatVector` type is ML-DSA-shaped (cTilde/z/h); `loadKatVectors` returns hard-coded `KatVector[]`. Falcon needs salt+s2. Naive union leaves callers with `vec.cTilde` → `undefined` at runtime | **HIGH** | AC-D-1 |
| 2 | Grep gates hardcode regex literals (AC-3-7, AC-A-1) — copy-paste for falcon risks silent miss for 6th scheme | MED | AC-D-2 |
| 3 | `@delta-from-falcon` JSDoc needs enumerated-deltas structure check, not literal-string copy from `@delta-from-ml-dsa` | MED | AC-D-3 |
| 4 | Gap: 4 casings (`falcon-eth`/`falconEth`/`FalconEthAccount`/`Falcon512_ETH`); `falcon_eth` (snake) typo risk in env vars | LOW | AC-D-4 |

**Total: 8 substantive concerns + 3 gap-ACs = 11 persona-sourced ACs. 2 HIGH concerns resolved structurally.**

## Acceptance Criteria

### AC-U: End User Criteria

AC-U-1: The 5-scheme bench report explicitly surfaces the ML-DSA-ETH ↔ Falcon-ETH pairwise delta (verify gas, calldata bytes) as a labeled row or section — not only as raw absolute numbers per scheme. Snapshot test asserts the labeled delta line exists and names both schemes in the pair (covers UC-5, FR-19).

AC-U-2: When a Falcon-ETH user-op is rejected due to verify gas exceeding the NFR-5 cap (versus signature invalidity), the failure mode is distinguishable from `SignatureMalformed`: either via a pre-flight static gas estimate against the cap surfacing a structured `VerifyGasCapExceeded` error, OR via a documented README runbook entry mapping "OOG during validation" to "check NFR-5 cap, not your signature bytes." A test asserts the chosen mechanism is in place (covers UC-2 alt-flow, FR-10).

### AC-FR: Functional Completeness

AC-FR-1: The signer catalogue exposes Falcon-ETH alongside the four prior schemes; an unknown/misspelled scheme name is rejected with a `scheme-not-found` error that lists all five supported schemes (covers FR-1, UC-1 alt-flow).

AC-FR-2: The Falcon-ETH production keygen surface returns `{secretKey, publicKey}` byte arrays sourced from a fresh entropy source on every call; two consecutive calls produce different keys with overwhelming probability (covers FR-2).

AC-FR-3: The Falcon-ETH KAT keygen surface accepts an explicit seed and returns `{secretKey, publicKey}` byte arrays that are byte-identical across repeated calls with the same seed (covers FR-3).

AC-FR-4: The hedged sign surface accepts only `(secretKey, message)` — no nonce/salt parameter — and returns a single 1064-byte signature `salt(40) || s2_compact(1024)`; two consecutive signatures over the same message differ in the salt prefix (covers FR-4, C-6).

AC-FR-5: The deterministic sign surface accepts `(secretKey, message, salt|randomness)` and returns byte-identical signatures across repeated calls with the same inputs (covers FR-5).

AC-FR-6: A sibling sign export returns `{ signature, iterations }` exposing the rejection-loop iteration count without mutating any module-level state; iteration count is a positive integer for every successful sign (covers FR-6, C-8).

AC-FR-7: A pure function `pkToNttCompact(rawPublicKey): Uint8Array` (or equivalent) transforms the raw Falcon-ETH public key into the on-chain `32 × uint256` NTT-domain compacted shape; calling it twice with the same input yields identical bytes and does not touch any external state (covers FR-7, C-5).

AC-FR-8: `FalconEthAccount.initialize(address, bytes calldata _publicKeyPointer)` registers a 20-byte pointer to the verifier-held public key; the deployed account's storage references the pointer, not the raw key bytes (covers FR-8, UC-1).

AC-FR-9: A user-op signed with a valid Falcon-ETH signature for the registered key is accepted by the on-chain verifier and proceeds through the EntryPoint flow; integration test asserts state change (covers FR-9, UC-2).

AC-FR-10: User-ops with (a) a valid signature over the wrong message, (b) a malformed/wrong-length signature, or (c) a valid signature from a key that does not match the registered pointer are ALL rejected via `try/catch SignatureMalformed()` — never an arbitrary revert. Three integration tests, one per case (covers FR-10, UC-2 alt-flows, NFR-11).

AC-FR-11: G1 oracle test asserts the shared Keccak-CTR-PRNG XOF used by the falcon-eth ETH-path produces byte-identical output to ETHFALCON's `Keccak256PRNG(a, b)` Python wrapper across the captured G1 vector(s); first-differing-byte ±8 bytes context is printed on mismatch (covers FR-11, UC-3, C-10).

AC-FR-12: G3 oracle test passes byte-identity over ≥100 captured KAT vectors comparing TS keygen output (sk, pk) to the Python reference for the same seed (covers FR-12, NFR-3).

AC-FR-13: G4 oracle test passes byte-identity over ≥100 captured KAT vectors comparing TS sign output (1064-byte signature) to the Python reference for the same `(sk, message, salt)` (covers FR-13, NFR-3).

AC-FR-14: G5 oracle test passes byte-identity over ≥100 captured KAT vectors comparing TS `pkToNttCompact` output to the Python reference's encoded payload (covers FR-14, NFR-3).

AC-FR-15: G6 oracle test runs end-to-end on-chain validation on the happy path and on wrong-key/bit-flip/malformed paths over the captured corpus; happy-path accepts; all three failure paths reject as `SignatureMalformed`. May land at smoke N=5 in initial development; tunes to N=100 by Gate 5 if runtime budget allows (covers FR-15, NFR-3).

AC-FR-16: The fixture-capture pipeline targets falcon-eth, captures ~100 vectors recording `{sk, pk, message, salt, signature, reshapedPk}`, writes a single fixture file under the falcon-eth KAT corpus directory, and updates the submodule SHA pin in the same operation (covers FR-16, UC-4).

AC-FR-17: The fixture loader exposes a discriminated overload `loadKatVectors("falcon-eth"): FalconKatVector[]` returning vectors with the Falcon-typed schema (salt + s2 fields); the Falcon vector type is distinct from the ML-DSA-ETH vector type (covers FR-17, A-8). [See AC-D-1 for cross-scheme tsc enforcement.]

AC-FR-18: Wrong-byte-length inputs on both production and KAT surfaces (sk, pk, message, randomness, salt) are rejected with a `SignerInputError` carrying a stable error code identifying the failing field; one test per field per surface (covers FR-18).

AC-FR-19: The bench harness produces a single report covering all five schemes (ECDSA, NIST Falcon, NIST ML-DSA, ML-DSA-ETH, Falcon-ETH) in deterministic order, with calldata-delta assertions covering the Falcon-ETH entry; snapshot regeneration is gated behind an explicit refresh flag (covers FR-19, UC-5, NFR-8). [See AC-A-3 for the calldata-assertion policy.]

AC-FR-20: README documents which of the five schemes are NIST-variant versus ETH-variant and which evaluation question each is suited for, with attribution to upstream references (ZKNoxHQ ETHFALCON for falcon-eth) (covers FR-20).

### AC-A: Architecture Criteria

AC-A-1: The KAT loader probes BOTH `ETHDILITHIUM` and `ETHFALCON` submodule HEADs. Each fixture file declares `submoduleSource: "ethfalcon" | "ethdilithium"` and the SHA-mismatch check resolves the correct submodule per fixture. The Falcon-ETH fixture is rejected on ETHFALCON drift; the ML-DSA-ETH fixture continues to reject on ETHDILITHIUM drift. Both checks fire at module-evaluation time (resolves architect HIGH concern; covers DD-13, NFR-1).

AC-A-2: The bench harness `deployAccount` dispatches via a per-scheme deployer registry (or per-signer-module export) typed as `Record<Scheme, Deployer>` — not an inline if-cascade. Adding the falcon-eth scheme adds exactly one registry entry plus one collocated deployer function; the registry's exhaustiveness is enforced at TypeScript compile time (covers FR-19, NFR-11; complements AC-D-2 — AC-A-2 governs runtime dispatch, AC-D-2 governs compile-time grep registries).

AC-A-3: The 5-scheme bench asserts calldata orderings explicitly: `ecdsa < falcon == falconEth < mldsa == mldsaEth` BY BYTE LENGTH. Within-pair calldata-gas equivalence at the 5% basis-point window is asserted ONLY for the mldsa pair (which shares the DD-8 layout). For falcon vs falcon-eth the assertion is (a) equal signature length (1064 bytes per C-6) and (b) same-order-of-magnitude calldata gas at a looser 25% bound. Spec records the rationale inline in the test file (covers FR-19, NFR-7).

AC-A-4: The architecture decision log / docs record explicitly that `contracts/imports/FalconRef.sol` is unchanged from the mldsa-eth-era work (it already exposes the `ZKNOX_ethfalcon` wrapper); no new RefShim is introduced for falcon-eth (covers C-4, NFR-1).

AC-A-5: The xof-lifecycle (DD-10) grep enforcement test glob includes `falcon-eth.*` files in addition to `mldsa-eth.*` files; module-level XOF state prohibition is enforced at runtime against the new signer files (covers C-8, NFR-6).

### AC-D: Developer/Maintainer Criteria

AC-D-1: `loadKatVectors` is a discriminated overload — `loadKatVectors("mldsa-eth"): MlDsaEthKatVector[]` and `loadKatVectors("falcon-eth"): FalconKatVector[]`. The legacy `KatVector` symbol is RENAMED to `MlDsaEthKatVector` in the same commit (no aliased re-export). `tsc` fails if a Falcon test file accesses an ML-DSA-only field (e.g., `vec.cTilde`) or vice versa (resolves maintainer HIGH concern; covers FR-17).

AC-D-2: The KAT-internal boundary grep iterates a shared `KAT_INTERNAL_MODULES = ["ml-dsa-eth.kat-internal", "falcon-eth.kat-internal"] as const` array consumed by both `ml-dsa-eth.test.ts` and `falcon-eth.test.ts`. The xof-lifecycle grep walks `test/signers/{mldsa,falcon}-eth*.ts` via glob, not a literal file list. Both gates fail-closed when a new scheme module is added without registering it (covers NFR-6).

AC-D-3: `falcon-eth.test.ts` defines a `FALCON_DELTA_HEADINGS` enumeration covering: HashToPoint domain swap, salt+s2 layout, Algorithm-17 compression, ctx handling, signature layout, and fork scope. The test asserts each substring appears in both module headers (`falcon-eth.ts` + `falcon-eth.kat-internal.ts`); it greps for stray `ml-dsa` / `mldsa` / `dilithium` substrings in those files and fails on any hit not prefixed with `@cross-ref:` (covers C-2, NFR-11; addresses universal rule [2026-04-18] amendment-doc-sweep).

AC-D-4: A naming-consistency mapping table in `docs/` enumerates the four canonical casings — `falcon-eth` (kebab, file paths), `falconEth` (camel, TS identifiers), `FalconEthAccount` (Pascal, contract names), `Falcon512_ETH` (docstring/scheme-tag) — and a unit test greps for the disallowed casing `falcon_eth` (snake) across `src/`, `test/`, `contracts/`, and `scripts/`, failing on any hit (covers FR-1, NFR-12).

### AC-NFR: Non-Functional Criteria

AC-NFR-1: After every commit in the falcon-eth feature, `git status ETHFALCON/` and `git status ETHDILITHIUM/` report zero modifications; CI gate enforces this (covers NFR-1, C-1).

AC-NFR-2: At Gate 5 of every story, the Hardhat test runner reports `97 + N` passing tests where N is the falcon-eth additions for stories landed so far; final feature total is `97 + (15 to 25)` passing with zero failures and zero skips lacking tracking references (covers NFR-2).

AC-NFR-3: G3, G4, G5 oracle suites each execute against ≥100 captured KAT vectors at byte-identity by feature Gate 5; G6 lands at ≥5 vectors during initial development and tunes to ≥100 by feature Gate 5 if runtime budget allows. Test reporter prints the executed vector count per gate (covers NFR-3, FR-12, FR-13, FR-14, FR-15).

AC-NFR-4: `solc` compilation of all falcon-eth contracts emits zero warnings; the existing compile wrapper script enforces warnings-as-errors and the build fails on any warning (covers NFR-4).

AC-NFR-5: Falcon-ETH on-chain user-op verification fits under `tx_gas_limit_cap = 2^24 = 16,777,216` gas. A bench-harness assertion records `verifyGas < 16_777_216` for every G6 happy-path vector and fails the test on breach (covers NFR-5, A-7).

AC-NFR-6: Runtime grep gates report zero hits: (a) `*.kat-internal.*` imports from the dispatcher and bench harness, (b) `^(let|var) _?xof` across falcon-eth source files. Both gates run as test cases in CI (covers NFR-6; implementation enforced by AC-D-2 and AC-A-5).

AC-NFR-7: Falcon-ETH verify gas is measured and recorded in the 5-scheme bench report snapshot. A regression assertion fails if Falcon-ETH verify gas ≥ ML-DSA-ETH verify gas (Falcon should be cheaper — smaller signatures); deviation is recorded as a SHOULD-not-MUST observation in the bench report comments (covers NFR-7, FR-19).

AC-NFR-8: The bench report renders deterministically: timestamp is sourced from the snapshot file (not wall clock); a no-op rerun produces a byte-identical render; snapshot is rewritten ONLY when an explicit refresh flag is set; routine runs that detect drift FAIL rather than silently overwrite (covers NFR-8, UC-5 alt-flows).

AC-NFR-9: Test-only environment-variable overrides in the fixture-generation pipeline are (a) regex-validated at ingest with the validation pattern recorded in code, AND (b) gated behind an off-by-default sentinel env var (e.g., `ALLOW_TEST_OVERRIDES=1`) that the test harness sets and production never sets. Pipeline rejects overrides absent the sentinel; rejects malformed override values per regex; both rejections are tested (covers NFR-9, UC-4 alt-flows; addresses universal rule [2026-04-18] security-relevant test overrides).

AC-NFR-10: Every wrapper contract under `contracts/imports/` pulled into the falcon-eth compile graph carries the upstream MIT copyright/license header verbatim (byte-equal to the upstream source's header). A test greps each wrapper's first lines for the canonical header and fails on drift (covers NFR-10, C-13).

AC-NFR-11: Falcon-ETH follows ML-DSA-ETH structural patterns: production/KAT split (separate surface modules), shared core, sibling-export rejection-iteration instrumentation, per-account immutable verifier (no shared verifiers per C-7), `try/catch SignatureMalformed()` failure path. The dispatcher's exhaustive switches over `Scheme` cover all five schemes; tsc fails on a missing branch (covers NFR-11, C-7, C-8).

AC-NFR-12: One commit per task; the story file is tracked from Task 1 with `status: ready-for-dev`; the story file checkbox advancement for each task is committed in the same commit as the work it describes. CI/review checks `git log` granularity (covers NFR-12, C-14).

## Traceability Matrix

| Requirement | Covered By |
|---|---|
| FR-1 | AC-FR-1, AC-D-4 |
| FR-2 | AC-FR-2 |
| FR-3 | AC-FR-3 |
| FR-4 | AC-FR-4 |
| FR-5 | AC-FR-5 |
| FR-6 | AC-FR-6 |
| FR-7 | AC-FR-7 |
| FR-8 | AC-FR-8 |
| FR-9 | AC-FR-9 |
| FR-10 | AC-FR-10, AC-U-2 |
| FR-11 | AC-FR-11 |
| FR-12 | AC-FR-12, AC-NFR-3 |
| FR-13 | AC-FR-13, AC-NFR-3 |
| FR-14 | AC-FR-14, AC-NFR-3 |
| FR-15 | AC-FR-15, AC-NFR-3 |
| FR-16 | AC-FR-16 |
| FR-17 | AC-FR-17, AC-D-1 |
| FR-18 | AC-FR-18 |
| FR-19 | AC-FR-19, AC-U-1, AC-A-2, AC-A-3, AC-NFR-7 |
| FR-20 | AC-FR-20 |
| NFR-1 | AC-NFR-1, AC-A-4 |
| NFR-2 | AC-NFR-2 |
| NFR-3 | AC-NFR-3 |
| NFR-4 | AC-NFR-4 |
| NFR-5 | AC-NFR-5, AC-U-2 |
| NFR-6 | AC-NFR-6, AC-D-2, AC-A-5 |
| NFR-7 | AC-NFR-7, AC-A-3 |
| NFR-8 | AC-NFR-8 |
| NFR-9 | AC-NFR-9 |
| NFR-10 | AC-NFR-10 |
| NFR-11 | AC-NFR-11, AC-FR-10, AC-D-3 |
| NFR-12 | AC-NFR-12, AC-D-4 |
| UC-1 | AC-FR-1, AC-FR-8 |
| UC-2 | AC-FR-9, AC-FR-10, AC-U-2 |
| UC-3 | AC-FR-11 through AC-FR-15 |
| UC-4 | AC-FR-16, AC-NFR-9 |
| UC-5 | AC-FR-19, AC-U-1, AC-NFR-8 |
| FI-1 | FR-16, FR-17 |
| FI-2 | FR-11 |
| FI-3 | FR-2, FR-3, FR-12, FR-18 |
| FI-4 | FR-4, FR-5, FR-6, FR-13, FR-18 |
| FI-5 | FR-1, FR-7, FR-8, FR-9, FR-10, FR-14, FR-15, FR-19, FR-20 |

## Content Quality

| Check | Status | Notes |
|---|---|---|
| CQ-1 Density | PASS | Zero filler ("It is important", "In order to", vague intensifiers). |
| CQ-2 Implementation Leakage | PASS | FR capability text uses domain terminology (Falcon-ETH, user operation, on-chain verifier, smart-wallet operator, NTT-domain compacted, salt+s2). G1–G6 are feature-defined oracle labels. Tech-specific symbols (`FalconEthAccount`, `ZKNOX_ethfalcon`, `SignerInputError`, `SimpleAccount`) appear only in Constraints/Assumptions. |
| CQ-3 Measurability | PASS (BLOCKING) | All 12 NFRs have numeric or boolean-measurable targets. |
| CQ-4 Traceability | PASS (BLOCKING) | 20/20 FRs → ≥1 AC; 12/12 NFRs → ≥1 AC-NFR; 5/5 UCs → ≥1 AC; zero orphan ACs. |
| CQ-5 Source Completeness | PASS (BLOCKING) | 5/5 FI-* items from research.md map to ≥1 FR. |

## Risk Register

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|-----------|
| R-1 | `ffSampling` port complexity exceeds estimate (A-3 risk-if-wrong) | MED | HIGH | DD-15 DEFERRED to arch phase; architecture phase reads `node_modules/@noble/post-quantum/src/falcon.ts` to decide direct-port vs leverage-noble before story planning. |
| R-2 | `keccakXofFactory` diverges byte-for-byte from ETHFALCON's `Keccak256PRNG` (A-2 risk-if-wrong) | MED | MED | Story 2 (G1 verification) is non-skippable per DD-13 LOCKED. If divergent, Story 2 expands to port a falcon-specific adapter; timeline grows but contained. |
| R-3 | Python-format vs TS-format pk fixture divergence (A-004 equivalent from mldsa-eth) | MED | LOW | Spot-check vec 0 `reshapedPk` byte length before writing G5; structural-decode oracle fallback at `test/signers/mldsa-encoding.pk-transform.kat.test.ts` (~200 LOC template). |
| R-4 | DRBG state advancement pattern wrong across `random_bytes()` calls (A-005 equivalent) | LOW | HIGH | Pre-G4 smoke-test: sign vec 0 inputs with Python ref directly; confirm byte-identity before full G4. Catches captured-pattern bugs immediately. |
| R-5 | Multi-submodule SHA loader regression if AC-A-1 not landed in Story 1 | MED | HIGH | AC-A-1 is structural, must land in Story 1 alongside the fixture pipeline (FR-16, FR-17). Cannot be deferred — silent oracle break otherwise. |
| R-6 | Code-review-agent truncation (mldsa-eth §5.12) | HIGH | LOW | Budget one `SendMessage` resume per code-review per story; known-good resume prompt documented in research.md §Additional Context. |
| R-7 | Bench calldata-delta assertion flakes if mldsa 5%-bound cloned to falcon pair | MED | LOW | AC-A-3 explicitly splits the assertion policy: mldsa pair tight, falcon pair loose (length-equal + 25% gas bound). Rationale inline. |
| R-8 | Amendment count exceeds expectation (A-6 risk-if-wrong, Falcon has more moving parts than ML-DSA) | MED | MED | Amendment-doc-sweep discipline per universal rule [2026-04-18]; AC-D-3 operationalizes stray-substring grep. If >6 amendments, escalate at Gate 5 of any story. |

## Persona Budget & Confidence

- **Complexity tier:** MEDIUM · **Concern budget per persona:** 0-3 · **Confidence Statement threshold:** <1 concern (none required — all 3 personas returned ≥2 concerns).
- **Persona-sourced AC count:** 11 (AC-U: 2 · AC-A: 5 · AC-D: 4). Within typical guidance for MEDIUM tier when counting only persona-driven ACs. Structural AC-FR (20) and AC-NFR (12) are 1:1 with FRs/NFRs and exempt from persona budget.

## Out of Scope
- Epervier variant (`ZKNOX_epervier.sol`, `ZKNOX_ethepervier.sol`, `falcon_epervier.py`) — different account architecture (pk-recovered via `recover()` rather than pk-stored via pointer), different signature ABI, larger signatures. Deferred to a future feature that would reuse ~80% of this work.
- Editing the ETHFALCON or ETHDILITHIUM submodule sources — hard NFR-1 gate.
- Modifying the NIST-variant signers (ECDSA, NIST Falcon, NIST ML-DSA) — verbatim.
- Modifying the existing `MlDsaAccount`, `FalconAccount`, or `MlDsaEthAccount` contracts — falcon-eth work is purely additive.
- Production deployment of Falcon-ETH-backed accounts — `@custom:experimental` posture.
- Audit of the on-chain verifier.
- Cross-account verifier sharing — each account carries its own immutable verifier reference (DD-9 LOCKED).
- A separate JS/TS distribution package for the Falcon-ETH port — TypeScript port lives under `test/signers/` for now; packaging is a future decision.
