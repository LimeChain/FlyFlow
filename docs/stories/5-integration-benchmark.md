---
story_id: "5"
title: "pk-transform + MlDsaEthAccount + G3 + G4 + benchmark + rename"
size: "L"
status: "ready-for-dev"
wave: 5
feature: mldsa-eth
created: 2026-04-18
---

# Story 5: pk-transform + MlDsaEthAccount + G3 + G4 + benchmark + rename

> Ref: `docs/plan.md` §"Story 5: pk-transform + MlDsaEthAccount + G3 + G4 + benchmark + rename [L]" — authoritative AC text, FR/NFR coverage, wave assignment, dependency chain (Stories 1, 2, 3, 4).
> Ref: `docs/plan.md` §"Interface Contracts" §"`IZKNOXEthDilithium`" + §"`MlDsaEthAccount`" + §"`preparePublicKeyForDeployment`" — the signatures Story 5 produces or consumes.
> Ref: `docs/architecture.md` §"Smart Contract Interfaces" §"`MlDsaEthAccount` (new)" + §"`IZKNOXEthDilithium`" — the on-chain surfaces Story 5 authors.
> Ref: `docs/architecture.md` §"Smart Contract Interfaces" §"Naming normalization" — `publicKey` → `publicKeyPointer` Rule 3 rename (AC-5-1).
> Ref: `docs/architecture.md` §"Design Rationale" DD-5 (MlDsaEthAccount : SimpleAccount, LOCKED), DD-6 (submodule compile path, LOCKED), DD-8 (signature ABI `abi.encode(cTilde, z, h)`, LOCKED), DD-9 (SCHEMES const + exhaustive-never switch, LOCKED), DD-10 (parameterize-by-factory, LOCKED).
> Ref: `docs/architecture.md` §"Data Models" §"ETHDilithium public key (reshaped — DD-2 LOCKED)" + `docs/amendments.md` §A-001 — reshaped pk tuple shape `(bytes aHatEncoded, bytes tr, bytes t1Encoded)`.
> Ref: `docs/architecture.md` §"Testing Strategy" rows "G3 — PK-transform KAT" + "G4 — Verifier integration" + "Benchmark" — per-gate test-file placement, coverage targets, mocking stance.
> Ref: `docs/architecture.md` §"Key Workflows" §UC-1 (happy-path sign & verify), §UC-4 (4-way benchmark), §UC-5 (reject invalid signature).
> Ref: `docs/amendments.md` §A-001 — DD-7 `reshapedPublicKey` ABI is `(bytes, bytes, bytes)` with `tr` 64 B via Keccak-PRG stream; DIRECTLY consumed by AC-5-2 (G3 byte-identity) and by `MlDsaEthAccount.initialize`'s SSTORE2 payload.
> Ref: `docs/amendments.md` §A-002 — refactored `preparePublicKeyForDeployment(rawPk, xofFactoryH, xofFactoryExpandA)` takes TWO factories; Story 5 calls it with `(keccakXofFactory, keccakXofFactory)` on the ETH path per DD-1 collapse.
> Ref: `docs/amendments.md` §A-003 — AC-3-7 runtime grep boundary at `test/signers/ml-dsa-eth.test.ts`. Story 5 MUST NOT add `kat-internal` imports to `test/signers/index.ts` or anything under `test/bench/**`; the production `signUserOp` dispatch entry routes to `ml-dsa-eth.ts`, never `ml-dsa-eth.kat-internal.ts`.
> Ref: `docs/amendments.md` §A-004 — mldsa-eth fixture `reshapedPublicKey` field is Python-format (`aHat` as 16384 B flat 4B-BE; `tr` 64 B; `t1` as 4096 B flat 4B-BE). TS `preparePublicKeyForDeployment` emits a DIFFERENT byte layout (inner `abi.encode(uint256[][][], ...)` wrappers). **Story 5 G3 oracle reconciles this** — see Dev Notes §"G3 oracle — TS vs Python format reconciliation" for the chosen resolution.
> Ref: `docs/amendments.md` §A-005 — fixture `rnd` is two `random_bytes(32)` calls; consumed by Story 4 G2 and by AC-FLOW-1's end-to-end path (freshly generated keypair, NOT a `.rsp` vector — so A-005 flows through transparently).
> Ref: `docs/stories/1-fixture-gen-cli.md` — upstream; `KatVector.reshapedPublicKey` (Python-format per A-004) + `KatVector.signature` (2420 B hex) are the G3 + G4 oracles; `Detected Patterns` table applies.
> Ref: `docs/stories/2-keccak-prg-port.md` — upstream; `createKeccakPrg` + `KeccakPrg` primitive, consumed transitively via `keccakXofFactory` (no direct import from Story 5).
> Ref: `docs/stories/3-xof-refactor-keygen.md` — upstream; `keccakXofFactory`, refactored `preparePublicKeyForDeployment`, `shake128XofFactory`/`shake256XofFactory`, `@delta-from-ml-dsa` JSDoc convention, AC-3-7 grep boundary at `test/signers/ml-dsa-eth.test.ts`, `assertBytesEqual` helper with `xofId`.
> Ref: `docs/stories/4-signer-port.md` — upstream; `signUserOp` (production, `ml-dsa-eth.ts`), `signWithRnd` (KAT, `ml-dsa-eth.kat-internal.ts`), `SignerInputError` with 4 codes, `signWithXofInstrumented` core (NOT consumed by Story 5 — KAT-only).

## User Story

As a PQC researcher, I want ML-DSA-ETH fully integrated as a 4th scheme — account contract, benchmark, report, documentation — so that `npx hardhat test` reports a full 4-scheme suite and `npx tsx scripts/generate-report.ts` writes a 4-row gas comparison.

## Acceptance Criteria

> All ACs copied verbatim from `docs/plan.md` §"Story 5: pk-transform + MlDsaEthAccount + G3 + G4 + benchmark + rename [L]". Never paraphrase.

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

**FR Coverage:** FR-3, FR-4, FR-5, FR-6, FR-9, FR-10, FR-11, FR-12, FR-13. **NFR Coverage:** NFR-1 (direct), NFR-7 (direct).

## Verified Interfaces

### Consumed by this story (VERIFIED against source at story-creation time)

- **`preparePublicKeyForDeployment(rawPk, xofFactory, xofFactory2): Hex`** — Story 3 refactored pk-transform; Story 5's G3 oracle + Account init pipeline
  - Source: `test/signers/mldsa-encoding.ts:281`
  - File hash (sha256): `d41bfc950d85f79c11cb941954304ce4725c52c0c7e2ebb5983f77689282de2e`
  - Signature (verbatim lines 281-285):
    ```ts
    export function preparePublicKeyForDeployment(
      rawPublicKey: Uint8Array,
      xofFactory: XofFactory,
      xofFactory2: XofFactory,
    ): Hex
    ```
  - NIST call pattern (existing — DO NOT BREAK per AC-D-1): `preparePublicKeyForDeployment(rawPk, shake256XofFactory, shake128XofFactory)` — used at `test/fixtures/mldsa.ts:55-59`.
  - ETH call pattern (new — Story 5 Task 2 + 3 use this): `preparePublicKeyForDeployment(rawPk, keccakXofFactory, keccakXofFactory)` — same factory twice, per DD-1 XOF collapse + A-002 two-factory API shape.
  - **Return type note:** returns `Hex` (0x-prefixed hex string), NOT `Uint8Array`. ETH account fixture must `hexToBytes` if byte-level ops are needed; `verifier.setKey` accepts `Hex` directly (viem auto-encodes `bytes` calldata from hex).
  - Plan match: ✓ matches `docs/plan.md` §"Interface Contracts" §"`preparePublicKeyForDeployment` (refactored)" with the A-002 two-factory correction applied.

- **`keccakXofFactory: XofFactory`** — Story 3 Keccak-PRG adapter; the sole XOF source for the ETH pk-transform path
  - Source: `test/signers/mldsa-encoding.ts:92`
  - File hash (sha256): `d41bfc950d85f79c11cb941954304ce4725c52c0c7e2ebb5983f77689282de2e`
  - Signature (verbatim): `export const keccakXofFactory: XofFactory = (seed) => { ... };` (wraps `createKeccakPrg(seed); p.flip()`; returns `{ id: "keccak-prg", xof: (n) => p.extract(n) }`).
  - Plan match: ✓.

- **`shake256XofFactory`, `shake128XofFactory`** — Story 3 NIST adapters; consumed by the rename-impact test (Task 1) to confirm existing NIST `MlDsaAccount` path survives
  - Source: `test/signers/mldsa-encoding.ts:60` (shake128) + `:73` (shake256)
  - File hash (sha256): `d41bfc950d85f79c11cb941954304ce4725c52c0c7e2ebb5983f77689282de2e`
  - Story 5 Task 1 does NOT change these; Task 2/3 does NOT use these.

- **`keygen(): Keypair`** — Story 3 ETH-path production keygen; consumed by AC-FLOW-1 end-to-end test
  - Source: `test/signers/ml-dsa-eth.ts:75`
  - File hash (sha256): `8d177d0c9cee6734ab12472ca1516f5c8f849d11856b5745658ace9b75bda8c5`
  - Signature (verbatim line 75-79):
    ```ts
    export function keygen(): Keypair {
      const zeta = new Uint8Array(32);
      globalThis.crypto.getRandomValues(zeta);
      return keygenWithXof(zeta, keccakXofFactory);
    }
    ```
  - Returns `{ publicKey: Uint8Array(1312), secretKey: Uint8Array(2560) }`.
  - Plan match: ✓.

- **`signUserOp(secretKey, userOp, entryPointAddress, chainId): Promise<PackedUserOperation>`** — Story 4 production signer; consumed by AC-5-3 happy-path test + AC-FLOW-1 + benchmark harness
  - Source: `test/signers/ml-dsa-eth.ts:99`
  - File hash (sha256): `8d177d0c9cee6734ab12472ca1516f5c8f849d11856b5745658ace9b75bda8c5`
  - Signature (verbatim lines 99-104):
    ```ts
    export async function signUserOp(
      secretKey: Uint8Array,
      userOp: UnsignedUserOp,
      entryPointAddress: string,
      chainId: bigint,
    ): Promise<PackedUserOperation>
    ```
  - Internally: computes `userOpHash`, sources fresh `rnd` via `crypto.getRandomValues(32)`, passes `(sk, userOpHash, rnd, new Uint8Array(0), keccakXofFactory)` to `signWithXof`, returns `{...userOp, signature: bytesToHex(sig)}`. Signature is exactly 2420 B raw (cTilde 32 ‖ z 2304 ‖ h 84) — the Solidity verifier's slice offsets at `ZKNOX_ethdilithium.sol:95-96` expect this exact layout.

- **`signWithRnd(sk, msg, rnd, ctx?): Hex`** — Story 4 KAT signer; consumed ONLY by G4 per-vector happy-path test (AC-5-3) — NOT the production benchmark/flow tests
  - Source: `test/signers/ml-dsa-eth.kat-internal.ts:120`
  - File hash (sha256): `72c1f97a4ad5b0eeff18a33bb076ea5b2c9837240d9aeea5e19ac7d98ff690d9`
  - Signature (verbatim):
    ```ts
    export function signWithRnd(
      sk: Uint8Array,
      msg: Uint8Array | Hex,
      rnd: Uint8Array,
      ctx: Uint8Array = new Uint8Array(0),
    ): Hex
    ```
  - **Import boundary:** MUST be imported ONLY by G4 KAT test files (`test/accounts/mldsa-eth.test.ts` and kin). MUST NOT be imported from `test/signers/index.ts` or anything under `test/bench/**` — the runtime grep at `test/signers/ml-dsa-eth.test.ts` (hash `e826f4af950320d98a2370a4e67fa282b90a163dfd77d6220ff67b24c98d1c4e`) asserts this at every test run (AC-3-7, `docs/amendments.md` §A-003). G4 test files are OUTSIDE the forbidden grep scope — `test/accounts/**` is permitted.

- **`SignerInputError`** — Story 4 typed error with 4-code taxonomy; consumed by AC-5-5 malformed-path assertions
  - Source: `test/signers/errors.ts:46`
  - File hash (sha256): `94cf9c1e2cd12baeeffe5c61e22adbe6cec0f2510d07e7c0bbc46f7b37ce1b1f`
  - `SignerInputErrorCode = "INVALID_SECRET_KEY_LENGTH" | "INVALID_MESSAGE" | "INVALID_CTX_LENGTH" | "INVALID_RND_LENGTH"` (line 33-37). Story 5 does NOT extend this taxonomy — the rejection paths in AC-5-5 are Solidity-side (`SignatureMalformed()` custom error on `MlDsaEthAccount`), not JS-side.

- **`loadKatVectors(scheme: "mldsa-eth"): KatVector[]`** — Story 1 KAT loader; consumed by AC-5-2 (G3) + AC-5-3 (G4 happy path) + AC-5-4 (G4 crypto-reject bit-flip)
  - Source: `test/fixtures/kat/index.ts:344`
  - File hash (sha256): `ca8c32db82d0d082efc53cfa92526d94f7f4d2a0e9c0d4376c7e63b4e406d4f0`
  - `KatVector` shape (lines 83-101) — Story 5 consumes: `{id, zeta, rnd, publicKey, secretKey, reshapedPublicKey, message, signature}`. Note `reshapedPublicKey` is **Python-format** per A-004 (see Dev Notes §"G3 oracle — TS vs Python format reconciliation").
  - Side effect at import: `assertSubmoduleShaMatches()` runs — G3/G4 tests get submodule-pin validation for free.

- **`assertBytesEqual(actual, expected, label, xofId?): void`** — Story 3 byte-comparison helper; consumed by AC-5-2 G3 KAT (divergence messages include `(factory=keccak-prg)`)
  - Source: `test/utils/assert-bytes.ts:15`
  - File hash (sha256): `7bb2bc6449549cebe4b2f90988e1b07198bc32088d56ba1b41b9b408be9765ef`
  - Signature (verbatim): `export function assertBytesEqual(actual: Uint8Array, expected: Uint8Array, label: string, xofId?: string): void`.

- **`computeUserOpHash(userOp, entryPointAddress, chainId): Hex`** — shared ERC-4337 v0.7 hash helper; consumed transitively via `signUserOp` (Story 5 does not call directly). Kept in Verified Interfaces because the G4 integration test may need to compute the hash independently when feeding `signWithRnd(sk, userOpHash, rnd, 0x)` from a fixture vector.
  - Source: `test/signers/userOpHash.ts:20`
  - File hash (sha256): `b1903d7438791be3ef810a37ecd336d9f9f9c1d2f2baf612b598355d36a21501`
  - Signature (verbatim): `export function computeUserOpHash(userOp: UnsignedUserOp, entryPointAddress: string, chainId: bigint): \`0x${string}\``.

- **`UnsignedUserOp`, `PackedUserOperation`, `Keypair`, `Scheme`** — shared dispatch types
  - Source: `test/signers/index.ts:14` / `:16` / `:26` / `:41`
  - File hash (sha256): `5f571b4ecbe7d6a709d45df187320a5641c94aa5e2695be649170f6fc1189238`
  - **Current `Scheme` union:** `"ecdsa" | "falcon" | "mldsa"` (line 14). Story 5 Task 6 ADDS `"mldsa-eth"` to this union per DD-9/AC-5-9 — 4-entry tuple `["ecdsa", "falcon", "mldsa", "mldsa-eth"]`. Current dispatch uses `switch` exhaustive-never discipline (lines 45-54, 62-71); adding `"mldsa-eth"` without a case causes TS `never`-assignability errors → compile fails → AC-5-9's "adding a 5th scheme produces TypeScript compile errors at every site that needs edits" guarantee holds transitively.

- **`MlDsaAccount`** (existing NIST account — **RENAMED by Task 1**)
  - Source: `contracts/MlDsaAccount.sol`
  - File hash (sha256): `69618d4b80cac77e4d15118a3f9c1917afa29a3e6cdb251370e3888b84802edf`
  - Current state value name: `bytes public publicKey;` (line 46) — misleading per architecture §"Naming normalization". Task 1 renames to `bytes public publicKeyPointer;`. Solidity is NOT currently referenced as a public getter in tests (inspected `test/accounts/mldsa*.ts` + `test/bench/gas-benchmark.test.ts` — no `.read.publicKey!` or similar), so rename surface is contained to: contract member + `initialize(address, bytes calldata _publicKey)` param name at line 68 + doc block at lines 41-46 + lines 66-72. Tests reference Account via `viem.getContractAt("MlDsaAccount", ...)` — no ABI member name pinning beyond the immutables.
  - Rename scope: `publicKey` → `publicKeyPointer` AND `_publicKey` → `_publicKeyPointer` in both member declaration AND `initialize(...)` parameter AND every occurrence of the NatSpec doc reference.

- **`FalconAccount`** (existing — **RENAMED by Task 1**, parity with `MlDsaAccount`)
  - Source: `contracts/FalconAccount.sol`
  - File hash (sha256): `c9008de9281faa0362c9e15cd1ffec45983566f0604f3f33f44d436d3829f725`
  - Identical rename surface to `MlDsaAccount` — `bytes public publicKey` (line 43), `initialize(address, bytes calldata _publicKey)` (line 65), and the NatSpec comment on line 63. Story 5 keeps contract shape byte-for-byte otherwise.

- **`ZKNOX_ethdilithium` (submodule verifier) — verified against pinned submodule SHA `b9ca7f72526ecc696230d3c774a6e2c12c9b37c2`**
  - Source: `ETHDILITHIUM/src/ZKNOX_ethdilithium.sol:23` (contract) + `:29` (setKey) + `:81` (3-arg verify overload)
  - Signatures (verbatim from source):
    ```solidity
    function setKey(bytes memory pubkey) external returns (bytes memory) { /* abi.encodePacked(pointer) */ }
    function verify(bytes calldata pk, bytes32 m, bytes calldata signature) external view returns (bytes4);
    ```
  - The `verify` overload returns `ISigVerifier.verify.selector` on success, `0xFFFFFFFF` on crypto-invalid — matches the `MlDsaAccount` `_VERIFY_SELECTOR` pattern at `contracts/MlDsaAccount.sol:31-32` exactly.
  - The contract slices signature as `cTilde = bytes[0:32]`, `z = bytes[32:2336]`, `h = bytes[2336:2420]` (lines 95-96) — matches Story 4's DD-8 layout exactly. Malformed blobs trigger `slice(...)` OOB revert (`ZKNOX_dilithium_utils.sol`'s `slice` function), which Story 5's `MlDsaEthAccount._validateSignature` must catch (AC-5-5).
  - Plan match: ✓ matches `docs/plan.md` §"Interface Contracts" §"`IZKNOXEthDilithium`" verbatim.

- **`ZKNOX_ethdilithium` artifact-emission wrapper**
  - Source: `contracts/imports/DilithiumRef.sol:37` — `contract ZKNOX_ethdilithium is _ZKNOX_ethdilithium {}`
  - Already exists (wrapped at Story 1 AC-1-9 time). Story 5 does NOT need to edit `DilithiumRef.sol`; the empty wrapper inherits from the submodule contract and Hardhat emits an artifact at this path. Test fixtures deploy `"ZKNOX_ethdilithium"` by name (same pattern as `"ZKNOX_dilithium"` at `test/fixtures/mldsa.ts:44`).

- **Existing benchmark harness** — modified by Story 5 Task 5
  - Source: `test/bench/gas-benchmark.test.ts`
  - File hash (sha256): `e772e36e4ea891593f1b4a82295051e9d4108d7fa508236d89ec68fa2245858b`
  - Current `SCHEMES` const at line 57: `["ecdsa", "falcon", "mldsa"] as const satisfies readonly Scheme[]` (3 schemes). Task 5 extends to 4 entries.
  - `UPDATE_BENCH` gate at lines 428-437: committed `gas-data.json` is rewritten ONLY when `process.env.UPDATE_BENCH` is truthy. Routine `npm test` runs preserve the committed baseline. Commit `326d559` (chore) introduced this gate; Story 5's `bench:update` script path is `UPDATE_BENCH=1 hardhat test` (already in `package.json` at line 7).
  - `assert.equal(results.length, 3, ...)` at line 355 — **HARDCODED LITERAL 3** that Task 5 MUST replace with `SCHEMES.length` per AC-5-9.
  - `benchScheme` switch cases at lines 157, 174, 197 — 3-branch dispatch. Task 5 adds a 4th branch for `"mldsa-eth"`.

- **Existing report generator**
  - Source: `scripts/generate-report.ts:44` + `:101`
  - File hash (sha256): recomputed at Task 5 kickoff.
  - Current SCHEMES tuple at line 44: `const SCHEMES: readonly Scheme[] = ["ecdsa", "falcon", "mldsa"] as const;` (3 schemes). Task 5 extends to 4.
  - **HARDCODED `results.length !== 3` at line 101** — the exact string AC-5-9 greps forbids. Task 5 replaces with `results.length !== SCHEMES.length` + error message interpolating `SCHEMES.length`.

- **Existing README.md**
  - Source: `README.md`
  - File hash (sha256): recomputed at Task 7 kickoff.
  - Line 53 mentions "ECDSA, Falcon, and ML-DSA acceptance"; line 76 lists "ecdsa, falcon, mldsa". Task 7 updates these + adds a dedicated "Supported schemes" section if not present.

### Produced by this story (⚠ UNVERIFIED — signatures from plan + architecture contracts)

> Marked ⚠ UNVERIFIED — source not yet implemented, using plan contract + architecture §"Smart Contract Interfaces" + DD-5 parity with `MlDsaAccount`.

- **`MlDsaEthAccount` Solidity contract** — ⚠ UNVERIFIED
  - Target location: `contracts/MlDsaEthAccount.sol` (new)
  - Contract-level shape (from architecture §"Smart Contract Interfaces" §"`MlDsaEthAccount` (new)" — DD-5 LOCKED parity with existing `MlDsaAccount.sol`, post-AC-5-1 rename):
    ```solidity
    // SPDX-License-Identifier: GPL-3.0
    pragma solidity 0.8.34;

    import {SimpleAccount} from "@account-abstraction/contracts/samples/SimpleAccount.sol";
    import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
    import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
    import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "@account-abstraction/contracts/core/Helpers.sol";
    import {ZKNOX_ethdilithium} from "../ETHDILITHIUM/src/ZKNOX_ethdilithium.sol";

    contract MlDsaEthAccount is SimpleAccount {
        error SignatureMalformed();
        bytes4 private constant _VERIFY_SELECTOR =
            bytes4(keccak256("verify(bytes,bytes32,bytes)"));
        ZKNOX_ethdilithium public immutable dilithiumEthVerifier;
        bytes public publicKeyPointer;  // 20 B SSTORE2 pointer from setKey()

        constructor(IEntryPoint anEntryPoint, ZKNOX_ethdilithium _verifier)
            SimpleAccount(anEntryPoint)
        { dilithiumEthVerifier = _verifier; }

        function initialize(address, bytes calldata _publicKeyPointer)
            public initializer { publicKeyPointer = _publicKeyPointer; }

        function _validateSignature(
            PackedUserOperation calldata userOp,
            bytes32 userOpHash
        ) internal view override returns (uint256) {
            try dilithiumEthVerifier.verify(publicKeyPointer, userOpHash, userOp.signature)
                returns (bytes4 result)
            {
                return result == _VERIFY_SELECTOR
                    ? SIG_VALIDATION_SUCCESS
                    : SIG_VALIDATION_FAILED;
            } catch { revert SignatureMalformed(); }
        }
    }
    ```
  - **NatSpec requirement** — per `.claude/rules/solidity.md`: every contract + public/external function + custom error must have NatSpec (`@title`, `@author`, `@notice`, `@param`, `@return`). Follow the existing `contracts/MlDsaAccount.sol` doc-block pattern verbatim — copy its NatSpec shape, swap references from "ML-DSA" to "ML-DSA-ETH (Keccak-PRG variant)" and from "ZKNox ETHDILITHIUM verifier" to "ZKNox ETHDILITHIUM Ethereum-compatible verifier (Keccak-PRG XOF)". Reference `docs/amendments.md` §A-001 where the sibling contract does.
  - **Interface-first design** (`.claude/rules/solidity.md`): consider whether `contracts/IMlDsaEthAccount.sol` is warranted. The sibling `MlDsaAccount` + `FalconAccount` do NOT have dedicated interface files — they define `SignatureMalformed()` as a contract-level error consumed by tests via the contract ABI. Parity path = no separate interface file. If the implementer prefers to add one for the solidity.md rule, do so consistently (add sibling interfaces for `MlDsaAccount`/`FalconAccount` too — out of Story 5 scope). **Decision: no separate interface file** — keep parity with existing account contracts; document this as an accepted solidity.md deviation in the NatSpec doc block.

- **`deployDilithiumEthVerifier` + `registerPublicKey` fixture helpers** — ⚠ UNVERIFIED
  - Target location: `test/fixtures/mldsa-eth.ts` (new — sibling of `test/fixtures/mldsa.ts`)
  - Plan signatures (shape mirrored from `test/fixtures/mldsa.ts` hash `d5c7c8807952791a49af442c889681475a3a27222f5eaa00661736dd09a9a270`):
    ```ts
    export async function deployDilithiumEthVerifier(viem?: ViemConnection):
      Promise<{ dilithiumEthVerifier, publicClient, walletClients }>;
    export async function registerPublicKey(
      dilithiumEthVerifier: Awaited<ReturnType<typeof deployDilithiumEthVerifier>>["dilithiumEthVerifier"],
      rawPublicKey: Uint8Array,
    ): Promise<Hex>;  // 20 B SSTORE2 pointer
    ```
  - **Critical difference from `test/fixtures/mldsa.ts:55-59`**: the call is `preparePublicKeyForDeployment(rawPublicKey, keccakXofFactory, keccakXofFactory)` — same factory twice per DD-1 collapse + A-002 signature. NOT the NIST `(shake256, shake128)` pair.
  - Returns the 20-byte SSTORE2 pointer hex (identical shape to `test/fixtures/mldsa.ts` post-`setKey` capture — the ZKNox ethdilithium verifier's `setKey` at `ZKNOX_ethdilithium.sol:29-32` returns `abi.encodePacked(pointer)` = 20 bytes, same as `ZKNOX_dilithium`).

- **`preparePublicKeyForDeploymentBytes` helper (OPTIONAL — ⚠ UNVERIFIED)**
  - Target location: `test/signers/mldsa-encoding.ts` (extend) OR new helper module
  - If the G3 KAT test needs byte-level comparison against fixture `reshapedPublicKey`, it can either `hexToBytes(preparePublicKeyForDeployment(...))` inline OR a sibling export `preparePublicKeyForDeploymentBytes(pk, f1, f2): Uint8Array` can be added to avoid repeated hex-conversion. Implementer discretion — inline `hexToBytes` is lighter and keeps the encoding module's surface area minimal. **Recommended: inline `hexToBytes`; no new export.**

- **`SCHEMES` const + `Scheme` union extension** — ⚠ UNVERIFIED (mutation, not new export)
  - Target location: `test/signers/index.ts:14` (Scheme union, add `"mldsa-eth"`) + explicit `SCHEMES` tuple export — currently the tuple lives only inline in `test/bench/gas-benchmark.test.ts:57` and `scripts/generate-report.ts:44`. Per architecture §"Component Decomposition" row "Shared schemes const" + DD-9, Story 5 EXTRACTS the tuple to `test/signers/schemes.ts` (new):
    ```ts
    // test/signers/schemes.ts — DD-9 single source of truth
    export type Scheme = "ecdsa" | "falcon" | "mldsa" | "mldsa-eth";
    export const SCHEMES = ["ecdsa", "falcon", "mldsa", "mldsa-eth"] as const
      satisfies readonly Scheme[];
    ```
    `test/signers/index.ts` re-exports `Scheme` + `SCHEMES` for backward compatibility; benchmark + report import from either location. **Alternative**: leave `Scheme` in `test/signers/index.ts` and add `SCHEMES` as a new named export from the same file — less churn. Implementer discretion; prefer the alternative unless a third consumer materialises.
  - Adding `"mldsa-eth"` to `Scheme` triggers TypeScript `never`-assignability errors at all three `switch(scheme)` sites in `test/signers/index.ts` (lines 46-54 `keygen` + 63-71 `signUserOp`) plus the benchmark's `deployAccount` switch — AC-5-9's "adding a 5th scheme produces TypeScript compile errors at every site that needs edits" guarantee. Story 5 adds the 4th case at each site; the guarantee remains intact for any 5th scheme.

- **`test/accounts/mldsa-eth.test.ts`** — ⚠ UNVERIFIED (G4 happy path + AC-FLOW-1)
  - Target location: NEW file under `test/accounts/` (permitted kat-internal importer per `docs/amendments.md` §A-003).
  - Shape mirrored from `test/accounts/mldsa.test.ts` hash `/* recompute at Task 4 kickoff */` — single-connection setup, EntryPoint + verifier + account + proxy deployment, impersonate EntryPoint, `validateUserOp` assertion. Adjustments:
    - Use `deployDilithiumEthVerifier` + `registerPublicKey` from `test/fixtures/mldsa-eth.ts`.
    - Use `MlDsaEthAccount` (not `MlDsaAccount`).
    - Import `signWithRnd` from `test/signers/ml-dsa-eth.kat-internal.js` for the `.rsp`-vector iteration (AC-5-3) — kat-internal import is PERMITTED in `test/accounts/**`.
    - Import `signUserOp` from `test/signers/ml-dsa-eth.js` (NOT via `test/signers/index.js` — the dispatcher scheme is "mldsa-eth" post-Task 6; either import works, but direct module import sidesteps any ordering concern with the dispatcher update).

- **`test/accounts/mldsa-eth-failures.test.ts`** — ⚠ UNVERIFIED (AC-5-4 + AC-5-5)
  - Target location: NEW file under `test/accounts/` (sibling of `mldsa-failures.test.ts` hash `/* existing */`).
  - Shape mirrored verbatim from `test/accounts/mldsa-failures.test.ts` — three rejection ACs per scheme. Byte-5-in-cTilde bit-flip for AC-5-4; 100-zero-byte truncation for AC-5-5. Swap the fixture path to `test/fixtures/mldsa-eth.js` and the account contract to `MlDsaEthAccount`.

- **`test/signers/mldsa-encoding.pk-transform.kat.test.ts`** — ⚠ UNVERIFIED (AC-5-2 G3)
  - Target location: NEW file.
  - Shape: iterate `loadKatVectors("mldsa-eth")`; for each vector `v`, compute `actual = preparePublicKeyForDeployment(hexToBytes(v.publicKey), keccakXofFactory, keccakXofFactory)`; assert via the G3 oracle (see Dev Notes §"G3 oracle — TS vs Python format reconciliation" — the direct `hexToBytes(actual) === hexToBytes(v.reshapedPublicKey)` path is NOT byte-achievable per A-004).

### Smoke-check — 5 tests already exercise the end-state (NOT produced by Story 5, but guard the rename)

- **`test/accounts/mldsa.test.ts`** — must continue to pass post-rename (AC-5-1 blocking post-condition).
- **`test/accounts/falcon.test.ts`** — same.
- **`test/accounts/mldsa-failures.test.ts`** — same.
- **`test/accounts/falcon-failures.test.ts`** — same.
- **`test/bench/gas-benchmark.test.ts`** — post Task 5 runs with 4 schemes; snapshot preserved unless `UPDATE_BENCH=1` is set.

## Dev Notes

### Architecture context (inlined — correctness-critical)

**DD-5 LOCKED — `MlDsaEthAccount : SimpleAccount`, structural parity with `MlDsaAccount`.** The contract overrides only `_validateSignature`, stores a bytes SSTORE2 pointer identical in layout to `MlDsaAccount.publicKeyPointer` (post-Task-1 rename), and uses the same `_VERIFY_SELECTOR` constant computed via `keccak256("verify(bytes,bytes32,bytes)")` since the verifier exposes multiple overloads. Do NOT monkey-patch or extend beyond `_validateSignature`; do NOT add custom fallback or receive functions; do NOT hold the raw 1312 B pk.

**DD-6 LOCKED — submodule compile path via `DilithiumRef.sol`.** `ZKNOX_ethdilithium` is already declared at `contracts/imports/DilithiumRef.sol:37` (wrapped for artifact emission). Hardhat emits an artifact at that path; tests deploy via `viem.deployContract("ZKNOX_ethdilithium")` (same pattern as `"ZKNOX_dilithium"` at `test/fixtures/mldsa.ts:44`). **No `hardhat.config.ts` change required for Story 5** — the ref-wrapper already exists.

**DD-8 LOCKED — signature ABI `abi.encode(cTilde, z, h)` at the Solidity boundary.** Story 4's `signWithXof` + `signUserOp` + `signWithRnd` return a RAW 2420 B concat (`cTilde‖z‖h`); the Solidity verifier at `ZKNOX_ethdilithium.sol:95-96` slices directly from the raw concat — NO abi-encoding happens at the JS/Solidity boundary. Story 5's `PackedUserOperation.signature` is exactly `bytesToHex(rawConcat)` — a 0x-prefixed hex string of 4842 characters (2 prefix + 2420 × 2 = 4842). This matches the existing `MlDsaAccount` → `ZKNOX_dilithium` wire format — no new marshalling logic.

**DD-9 LOCKED — `SCHEMES` const + exhaustive-never switch.** `Scheme` union must list all 4 variants; `switch(scheme)` on a `Scheme` value without a case for `"mldsa-eth"` fails at compile time (`never`-assignment). Every dispatcher (`test/signers/index.ts:46-54` keygen, `:63-71` signUserOp, plus `test/bench/gas-benchmark.test.ts:157/174/197` deployAccount branching, plus any future consumer) gains a 4th case. Deleting the literal `3`-comparisons at `test/bench/gas-benchmark.test.ts:355` + `scripts/generate-report.ts:101` replaces them with `SCHEMES.length`.

**DD-10 LOCKED — parameterize-by-factory, single factory on ETH path.** Story 5's `preparePublicKeyForDeployment(rawPk, keccakXofFactory, keccakXofFactory)` passes the SAME factory twice to the two-factory Story 3 signature (A-002). The factory is invoked fresh at each call-site inside the encoding module (once for `_xof` / mu-style H role producing 64 B `tr`, once for `_xof2` / ExpandA role producing A_hat). Passing the same factory twice is byte-correct on the ETH path per DD-1 (Python ref `pk_for_eth` passes `_xof=Keccak256PRNG, _xof2=Keccak256PRNG`).

**`@delta-from-ml-dsa` JSDoc — preserve, do not re-author.** Story 3 + 4 already landed the `@delta-from-ml-dsa` JSDoc in `test/signers/ml-dsa-eth.ts` + `test/signers/ml-dsa-eth.kat-internal.ts` (see `test/signers/ml-dsa-eth.ts:17-50` hash `8d177d0c9cee6734ab12472ca1516f5c8f849d11856b5745658ace9b75bda8c5`). Story 5 does NOT modify these blocks — items 3 (pk-transform factory argument, "ETH path passes `(keccakXofFactory, keccakXofFactory)`") and 4 (ctx handling) are already accurate for Story 5's scope. The `@delta-from-ml-dsa` grep discipline (via `test/signers/ml-dsa-eth.test.ts`) continues to guard both files.

**AC-3-7 runtime grep boundary (`docs/amendments.md` §A-003).** The grep at `test/signers/ml-dsa-eth.test.ts` (hash `e826f4af950320d98a2370a4e67fa282b90a163dfd77d6220ff67b24c98d1c4e`) scans:
- `test/signers/index.ts` — MUST NOT import from `ml-dsa-eth.kat-internal`.
- Every file under `test/bench/**` — MUST NOT import from `ml-dsa-eth.kat-internal`.

Story 5's dispatcher extension (Task 6) in `test/signers/index.ts` MUST import the production surface via `import * as mldsaEth from "./ml-dsa-eth.js";` — **never** `"./ml-dsa-eth.kat-internal.js"`. Story 5's benchmark extension (Task 5) similarly goes through `test/signers/index.ts`'s dispatcher, not the kat-internal module. Story 5's G4 test files under `test/accounts/**` ARE PERMITTED to import `signWithRnd` from `ml-dsa-eth.kat-internal.js` — the grep scope does NOT include `test/accounts/**` (confirmed at `test/signers/ml-dsa-eth.test.ts:46-52` + hash).

### G3 oracle — TS vs Python format reconciliation (A-004 implication)

**The problem.** Per `docs/amendments.md` §A-004, the fixture's `reshapedPublicKey` field is Python-format: `eth_abi.encode(['bytes','bytes','bytes'], [aHatFlatBE, tr, t1FlatBE])` where `aHatFlatBE`/`t1FlatBE` are row-major 4-byte big-endian uint32 flattenings of each polynomial's 256 coefficients. TS `preparePublicKeyForDeployment` produces `abi.encode(bytes aHatEncoded, bytes tr, bytes t1Encoded)` where `aHatEncoded = abi.encode(uint256[][][])` and `t1Encoded = abi.encode(uint256[][])` — SAME coefficient data, DIFFERENT inner ABI wrapper. Byte-identity of the top-level output against the fixture's hex string is NOT achievable.

**The Solidity verifier's expectation is the TS format**, not the Python format. `ZKNOX_ethdilithium.sol:182-188` (the `_readPubKey` SSTORE2 reader) decodes the outer tuple as `(bytes, bytes, bytes)` then inner-decodes the first blob as `uint256[][][]` and the third as `uint256[][]` — the TS wrapping shape. The Python format in the fixture is CANONICAL for the off-chain Python reference (a fixture-storage convention), NOT the on-chain wire format.

**Three possible G3 oracles — pick ONE per implementer discretion:**

1. **Structural decode + compare** (recommended — byte-correctness guaranteed via downstream consumer). G3 test iterates the ~100 vectors and for each vector:
   - Compute `actual = hexToBytes(preparePublicKeyForDeployment(hexToBytes(v.publicKey), keccakXofFactory, keccakXofFactory))`.
   - Decode `actual` as `(bytes, bytes, bytes)` via viem `decodeAbiParameters`.
   - Decode `actualAHat = decodeAbiParameters([{type:'uint256[][][]'}], actualAHatBytes)[0]`; same for `actualT1`.
   - Decode the fixture's Python-format `reshapedPublicKey` as `(bytes, bytes, bytes)` → inner blobs are flat 4-byte BE uint32 arrays; manually unpack to the same `uint256[][][]` / `uint256[][]` structural shape.
   - Assert `actualAHat` deep-equals reconstructed `expectedAHat` (coefficient-by-coefficient), `actualTr` byte-equals `expectedTr` (both 64 B Keccak-PRG output), `actualT1` deep-equals reconstructed `expectedT1`.
   - This oracle proves the TS output is **equivalent** to the fixture's Python format under ABI-reshape — AC-5-2's "equals the fixture's `reshapedPublicKey` byte-for-byte" intent is honored at the coefficient level (the only level that matters for on-chain consumption); the byte-level hex-string comparison the AC literally states is NOT byte-achievable and the amendment explains why.

2. **Regenerate fixture in TS format** (Story 1 fixture-gen CLI rerun). Would require re-running `generate-kat-fixtures.ts` with a modified `encode_matrix_bytes` / `encode_vector_bytes` Python batch that wraps `uint256[][][]` + `uint256[][]` ABI-encoding before the outer `(bytes,bytes,bytes)` tuple. Post-regen, the G3 oracle becomes direct `hexToBytes(actual) === hexToBytes(v.reshapedPublicKey)`. **Cost**: Story 1 fixture regeneration (76→91 test suite reverification), downstream Stories 2-4 reverification (the `reshapedPublicKey` field is not consumed by any of them — G1 uses `publicKey`+`secretKey`, G2 uses `secretKey`+`message`+`rnd`+`signature`, but the file hash changes). A-004 explicitly calls this option "out of Story 3 scope" and defers to Story 5.

3. **End-to-end via G4** (implicit oracle). Skip a standalone G3 byte-identity test; rely on G4's on-chain verification as the aggregate byte-identity check (if TS pk-transform output decodes correctly in `ZKNOX_ethdilithium._readPubKey` + feeds a verify-success path, the coefficient data is correct). **Rejected** — breaks the G0–G4 per-gate decomposition (DD-11 / architecture §"Key Workflows" §UC-3), obscures where a future bug regresses.

**Recommended resolution: Option 1** — structural decode + coefficient-wise assert. It is the closest achievable approximation of AC-5-2's literal wording while respecting A-004's byte-level divergence. The `assertBytesEqual` helper's `xofId` discriminant still fires for the `tr` field comparison (the one of the three triples that IS byte-comparable). Document the choice at the top of `mldsa-encoding.pk-transform.kat.test.ts` and cross-reference `docs/amendments.md` §A-004.

Alternatively, if the user approves Option 2 during Task 2 kickoff, log it as **A-006 (Rule 3 — fixture regeneration)** in `docs/amendments.md` and regenerate. Implementer should ask at Task 2 kickoff which option to take; default to Option 1 if no instruction.

### Rename direction (AC-5-1) — `publicKey` → `publicKeyPointer`

The architecture's "Naming normalization (Rule 3 amendment)" paragraph specifies the rename direction: `publicKey` (the member name today) → `publicKeyPointer` (post-rename). Affects `MlDsaAccount.sol` + `FalconAccount.sol` AND their `initialize(address, bytes calldata _publicKey)` parameter name → `_publicKeyPointer`. The architecture declares this as a Story 4 Task 1 amendment ("A-001" in architecture's terms) but Story 4 landed without this work (see commit `243395c` "feat(signers): Story 4 Task 2" + review-fix `bc1936c` — no account-contract changes). Story 5 absorbs this as its AC-5-1 "pre-task".

**Critical consumer check (pre-rename audit):**
- Tests reference these accounts ONLY via `viem.getContractAt("MlDsaAccount", ...)` / `viem.getContractAt("FalconAccount", ...)` — ABI inferred at call time. No `.read.publicKey()` / `.read.publicKeyPointer()` accessor calls exist today (confirmed via `grep -rn '\.read\.publicKey' test/`). Rename is structurally safe.
- Fixture helpers `test/fixtures/mldsa.ts:registerPublicKey` + `test/fixtures/falcon.ts:registerPublicKey` return the pointer `Hex` — no rename coupling there.
- Account `initialize(...)` is invoked via `encodeFunctionData({ abi, functionName: "initialize", args: [ZERO_ADDRESS, pointerHex] })` — positional args, NOT parameter-name dependent. The `_publicKey` → `_publicKeyPointer` param rename does NOT require any test update.
- `docs/amendments.md` already carries A-001 through A-005; the rename amendment will be **A-006** (next sequential number) and logs the rename itself + cross-references architecture §"Smart Contract Interfaces" §"Naming normalization".

**NatSpec update scope per `.claude/rules/solidity.md`:** both contracts' doc blocks at lines 41-46 (`MlDsaAccount`) / 38-42 (`FalconAccount`) mention "publicKey" in the `@notice` comment — update accordingly.

### UPDATE_BENCH gate (commit `326d559` chore)

`test/bench/gas-benchmark.test.ts:428-437` gates the `gas-data.json` write behind `process.env.UPDATE_BENCH`. Routine `npm test` runs leave the committed snapshot untouched; the operator-initiated `npm run bench:update` (which is `UPDATE_BENCH=1 hardhat test` per `package.json:7`) rewrites it.

**Story 5 implication:** after Task 5 extends `SCHEMES` to 4 entries and `benchScheme` handles `"mldsa-eth"`, the committed `gas-data.json` becomes STALE — it has 3 entries; the new test expects `SCHEMES.length` = 4 entries in each run. Options:

1. **Run `npm run bench:update` as part of Task 5's landing**, commit the refreshed `gas-data.json` with its 4th row. This is a deliberate snapshot refresh; the commit message should cross-reference Story 5 Task 5 and AC-5-6/AC-5-7.
2. **Leave `gas-data.json` at 3 rows and update `scripts/generate-report.ts` to tolerate partial data** — rejected; defeats AC-5-6/AC-5-7's "4 rows" guarantee at report-render time.

**Recommended: Option 1** — Task 5's Gate 5 includes `UPDATE_BENCH=1 npx hardhat test test/bench/gas-benchmark.test.ts` followed by committing the refreshed `gas-data.json` + `docs/gas-report.md`. The commit is atomic with Task 5's code changes.

**AC-5-7 (deterministic report — USER DECISION 2026-04-18: STRICT):** the AC's "only gas-cost deltas appear" is interpreted literally — two consecutive `npm run report` runs on an UNCHANGED `gas-data.json` MUST produce a byte-identical `gas-report.md`, including the `_Generated:` header line. Task 6 achieves this by sourcing the timestamp from `gas-data.json.generatedAt` (written by the bench test at `UPDATE_BENCH=1` invocation time) rather than from `new Date().toISOString()` at render time. Concretely:

1. **Bench test** (`test/bench/gas-benchmark.test.ts`): instead of writing a flat `results: BenchResult[]` to `gas-data.json`, wrap as `{ generatedAt: new Date().toISOString(), results: [...] }`. This is a one-time schema bump; log as a Rule 1 deviation inline (schema change is additive — the loader bump in `generate-report.ts` lands in the same commit, preserving atomicity).
2. **Report generator** (`scripts/generate-report.ts`): loader reads `gas-data.json.generatedAt` and `gas-data.json.results`; renderer interpolates `generatedAt` into the `_Generated:` line. The `new Date().toISOString()` call at render time is DELETED.
3. **Verification:** at Gate 5, run `npm run report` twice back-to-back with no file changes between invocations; `git diff docs/gas-report.md` must produce zero output. If the diff is non-empty, AC-5-7 fails.

### `test/accounts/**` is NOT in the AC-3-7 grep scope (kat-internal import permitted)

Confirmed by inspection of `test/signers/ml-dsa-eth.test.ts:46-52` hash `e826f4af...` (reproduced here inlined because correctness-critical):

```ts
const ML_DSA_ETH_KAT_FILE = path.join(SIGNERS_DIR, "ml-dsa-eth.kat-internal.ts");
const KAT_INTERNAL_PATTERN =
  /from\s+["'][^"']*ml-dsa-eth\.kat-internal[^"']*["']/;
// Grep scope (verified from test body): test/signers/index.ts + all files under test/bench/
// NOT scanned: test/accounts/**
```

Story 5's `test/accounts/mldsa-eth.test.ts` MAY `import { signWithRnd } from "../signers/ml-dsa-eth.kat-internal.js"` — this import is OUTSIDE the forbidden scope. The grep test continues to pass.

### Structural evaluation (from story-creator protocol §Structural Evaluation)

1. **File size prediction** — `MlDsaEthAccount.sol` will be ~90 LOC (parity with `MlDsaAccount.sol:89`); `test/fixtures/mldsa-eth.ts` ~80 LOC; `test/accounts/mldsa-eth.test.ts` ~150 LOC; `test/accounts/mldsa-eth-failures.test.ts` ~200 LOC; bench harness extension ~50 LOC; report generator ~20 LOC; README ~40 LOC added. No single file crosses 500 lines. ✅ PASS.
2. **God component detection** — Story 5 spans multiple responsibilities (account + G3 + G4 + benchmark + rename + docs). The tasks are decomposed into 7 atomic units (Tasks 1-7 below), not a single multi-responsibility component. ✅ PASS.
3. **Implementation detail density** — Error taxonomy is pre-existing (`SignerInputError`, `SignatureMalformed`), NOT re-prescribed. Transaction patterns follow existing `test/fixtures/mldsa.ts` + `test/accounts/mldsa.test.ts` shapes (single-connection, impersonate EntryPoint, staticcall verify). Internal helpers are left to implementer per the Inline Decision List's rule-3 (codebase establishes patterns — this is the exact domain). ✅ PASS.
4. **UI decomposition** — N/A (no UI in this story). ✅ PASS.
5. **Migration/seed/schema execution** — No DB migrations. The "benchmark snapshot refresh" is analogous (fixture rebuild) — Task 5's Gate 5 criterion explicitly requires running `UPDATE_BENCH=1 hardhat test` + committing the result. ✅ PASS.
6. **Micro-story eligibility** — Story spans 7 tasks, ~500 LOC total, multiple new files. NOT micro. ✅ PASS (uses full template).

### Behavioral requirements (inlined from plan + architecture)

- **AC-5-1 sequencing** — rename is the FIRST task, lands before any Story 5 mldsa-eth work. The rationale (existing architecture §"Naming normalization"): `MlDsaEthAccount` will use the post-rename name `publicKeyPointer` from its first commit; renaming the sibling `MlDsaAccount` + `FalconAccount` to match MUST happen strictly before any test file references the new name across all 4 accounts (would otherwise produce a confusing mixed state).
- **AC-5-2 oracle resolution** — see Dev Notes §"G3 oracle — TS vs Python format reconciliation". Default to Option 1 (structural decode + coefficient-wise compare); escalate to user at Task 2 kickoff if Option 2 regeneration is preferred.
- **AC-5-3 scope** — ~100 `.rsp` vectors, each runs through `MlDsaEthAccount.validateUserOp` with `v.reshapedPublicKey` → `setKey` → pointer → account init → `signWithRnd(sk, userOpHash, v.rnd, 0x)` → submit via EntryPoint. The vector's `signature` field is NOT used directly (Story 4 G2 already proved it matches `signWithRnd` output byte-for-byte); here we recompute via `signWithRnd` and feed the result to `validateUserOp`. Cost estimate: 100 × (deploy + setKey + validateUserOp) ≈ EVM-heavy; budget 2-3 minutes. Mitigation: share a single verifier+account deployment across all 100 vectors — re-initialize the account per vector by rotating the `publicKeyPointer` via a fresh proxy proxy-per-vector (each `initialize` is one-shot per proxy). Recommended: deploy 100 proxies in a loop, then `validateUserOp` 100 times; OR deploy 1 proxy and iterate a helper `testRotateKey` — whichever keeps test body cleaner.
- **AC-5-4 bit-flip strategy** — mirror the existing `test/accounts/mldsa-failures.test.ts:4-20` body verbatim: flip byte 5 inside cTilde (safe zone) to induce a crypto-invalid but structurally-parseable signature. Verifier returns `0xFFFFFFFF`; `MlDsaEthAccount._validateSignature` returns `SIG_VALIDATION_FAILED = 1n`. Also cover the wrong-key path: sign with `wrongSk` where `wrongSk` comes from a second `keygen()` call; assert `SIG_VALIDATION_FAILED`.
- **AC-5-5 malformed strategy** — 100 zero bytes as the signature (same as `mldsa-failures.test.ts`). `ZKNOX_ethdilithium.verify` does `slice(signature, 32, 2304)` which reverts OOB when `signature.length < 2336`; `_validateSignature`'s `try/catch` catches and re-reverts with `SignatureMalformed()`. Assertion: `assert.rejects(...)` + the dual-path viem-walker pattern at `mldsa-failures.test.ts:29-33`.
- **AC-FLOW-1** — at least 5 iterations of the full production flow (keygen + preparePublicKeyForDeployment + setKey + signUserOp + validateUserOp), all producing `SIG_VALIDATION_SUCCESS = 0n`. NOT the KAT `.rsp` vectors — freshly-generated keypairs per iteration. Concrete shape: loop 5 times, `keygen()` + `preparePublicKeyForDeployment(alice.publicKey, keccakXofFactory, keccakXofFactory)` + `setKey` + deploy proxy + `signUserOp(alice.secretKey, userOp, entryPoint, chainId)` + `validateUserOp` via impersonated EntryPoint. Probabilistic coverage (5 runs × ~50% rejection-loop cost) ≈ 5-10 rejection iterations total; enough to exercise a non-trivial code path without blowing the test budget.
- **AC-5-6 benchmark shape** — add `"mldsa-eth"` to `SCHEMES` tuple; add the 4th `benchScheme` branch (mirror `"mldsa"` branch at `test/bench/gas-benchmark.test.ts:197-214` but swap `deployDilithiumVerifier` → `deployDilithiumEthVerifier`, `registerMldsaKey` → the new ETH fixture's `registerPublicKey`, `"MlDsaAccount"` → `"MlDsaEthAccount"`). The test asserts `results.length === SCHEMES.length` (AC-5-9 derivation).
- **AC-5-8 injection already exists** — `test/bench/gas-benchmark.test.ts:441-510` has an AC-4 (benchmark AC-4 in that file, = architecture AC-A-3) per-scheme failure isolation test. Task 5 extends the `corruptedOptions: Record<Scheme, BenchOptions>` map (line 467) with an `"mldsa-eth": {}` entry; the existing test body already iterates `SCHEMES` and proves the 4-scheme record isolation.
- **AC-5-9 grep gate** — at Gate 5, run `grep -nE '\\b(===?|!==?)\\s*3\\b|\\.length\\s*(===?|!==?)\\s*3' test/bench/gas-benchmark.test.ts scripts/generate-report.ts`. Must return zero hits. The TypeScript compile-error guarantee is validated by inspection: every `switch(scheme)` site must have exactly 4 cases; removing any case causes `never`-assignment failure at `tsc --noEmit`.
- **AC-5-10 README scope** — add a "Supported schemes" section (if not present) listing all 4 schemes with 1-line descriptions; credit ZKNox for the ETHDilithium design + `ZKNOX_ethdilithium.sol`; Python dev-oracle isolation note (already a tradition in the repo per Story 1's fixture-gen intro; copy that phrasing). Update lines 53 + 76 to mention all 4 schemes.
- **Test runner** — `node:test` + `node:assert/strict` (project A-001 convention, applies throughout). Hardhat required for G4 + benchmark (EVM state). G3 KAT is pure-JS `node:test`.
- **Hex / byte I/O** — viem `hexToBytes` / `bytesToHex`, established project convention.
- **No `!` non-null assertions in production code** — allowed in test files only (`.claude/rules/nodejs.md`). The `MlDsaEthAccount.sol` contract has no JS analogue.
- **No silenced tests** — `.claude/rules/test-integrity.md` §2 prohibits test-disable annotations. Story 5 adds tests; never disables existing ones.
- **No new runtime dependencies** — all Solidity deps (`@account-abstraction/contracts`, ZKNox submodule) already present at `package.json:14-17`; all JS deps (`viem`, `@noble/post-quantum`, `hardhat`) already present. Zero new entries.

### File-tree effects (expected — non-binding)

New files:
- `contracts/MlDsaEthAccount.sol` (~90 LOC — DD-5 parity shape + NatSpec)
- `test/fixtures/mldsa-eth.ts` (~80 LOC — mirror `test/fixtures/mldsa.ts` with `(keccakXofFactory, keccakXofFactory)` pk-transform + `ZKNOX_ethdilithium` verifier)
- `test/signers/mldsa-encoding.pk-transform.kat.test.ts` (~80 LOC — AC-5-2 G3 KAT with structural coefficient oracle)
- `test/accounts/mldsa-eth.test.ts` (~150 LOC — AC-5-3 happy path + AC-FLOW-1 5-iteration end-to-end)
- `test/accounts/mldsa-eth-failures.test.ts` (~200 LOC — AC-5-4 crypto-reject + AC-5-5 malformed)
- (Optional) `test/signers/schemes.ts` (~10 LOC — extract SCHEMES tuple; only if implementer prefers — see §Produced)

Modified files:
- `contracts/MlDsaAccount.sol` (Task 1: rename `publicKey` → `publicKeyPointer`, `_publicKey` → `_publicKeyPointer`, update NatSpec)
- `contracts/FalconAccount.sol` (Task 1: same rename)
- `test/signers/index.ts` (Task 6: add `"mldsa-eth"` to `Scheme` union at line 14, add 4th `switch` cases at lines 45-54 + 62-71, import `* as mldsaEth from "./ml-dsa-eth.js"`)
- `test/bench/gas-benchmark.test.ts` (Task 5: extend `SCHEMES` at line 57 to 4 entries, extend `deployAccount` with `"mldsa-eth"` branch at ~line 197, swap `assert.equal(results.length, 3)` → `assert.equal(results.length, SCHEMES.length)` at line 355, extend `corruptedOptions` at line 467)
- `scripts/generate-report.ts` (Task 6: extend `SCHEMES` at line 44, replace `results.length !== 3` at line 101 with `results.length !== SCHEMES.length` + interpolate `SCHEMES.length` into the error message)
- `README.md` (Task 7: Supported schemes section; lines 53 + 76 mention 4 schemes; ZKNox + Python isolation attribution)
- `docs/amendments.md` (Task 1 adds A-006 for the `publicKey` → `publicKeyPointer` rename; Task 2 MAY add A-007 if Option 2 fixture regeneration is chosen)
- `test/bench/gas-data.json` (Task 5: refresh via `UPDATE_BENCH=1 hardhat test` — 4-row snapshot)
- `docs/gas-report.md` (Task 6: regenerate via `npm run report` to reflect 4 rows)

Package files: no additions to `dependencies` OR `devDependencies`.

### Library versions (verified at story creation, 2026-04-18; unchanged from Stories 1-4)

- `@account-abstraction/contracts@^0.7.0` — verified at `package.json:14` + `node_modules/@account-abstraction/contracts/package.json` version field = `0.7.0`. `SimpleAccount`, `IEntryPoint`, `PackedUserOperation`, `SIG_VALIDATION_SUCCESS`/`SIG_VALIDATION_FAILED` imports at `MlDsaAccount.sol:4-7` + `FalconAccount.sol:4-7` prove the package exports these symbols at v0.7. **No version bump.**
- `viem@^2.43.0`, `hardhat@^3.3.0`, `typescript@^5.9.3`, Solidity `0.8.34`, Node `v24.13.1`.
- `@noble/post-quantum@^0.6.1` — consumed transitively via Story 3/4; Story 5 does not import directly.
- `@openzeppelin/contracts` (transitive via `@account-abstraction/contracts` + `npmFilesToBuild` at `hardhat.config.ts:45`).
- Pinned ETHDILITHIUM submodule SHA: `b9ca7f72526ecc696230d3c774a6e2c12c9b37c2` (per `README.md:12`). `ZKNOX_ethdilithium.sol` signatures verified against this SHA.

## Tasks

- [x] **Task 1: Rename `publicKey` → `publicKeyPointer` in `MlDsaAccount.sol` + `FalconAccount.sol` + log A-006 amendment**
  - AC: AC-5-1 (rename + NIST + Falcon suites pass byte-for-byte + amendment logged)
  - Files: `contracts/MlDsaAccount.sol` (member + initialize param + NatSpec), `contracts/FalconAccount.sol` (same three surfaces), `docs/amendments.md` (add A-006 per Rule 3)
  - Dependencies: none — this is the pre-task per AC-5-1 sequencing
  - Why: The existing state variable name `publicKey` is semantically misleading (it stores a pointer, not a key — see architecture §"Naming normalization"). Renaming BEFORE Story 5's mldsa-eth work lands keeps the three account contracts naming-consistent from the first Story 5 commit forward. Pre-audit confirmed (Dev Notes §"Rename direction"): no test references `.read.publicKey()` or `.read.publicKeyPointer()`; `initialize(...)` args are positional. Gate 5 verification: `npm test` passes all 4 pre-Story-5 test files (mldsa.test.ts + mldsa-failures.test.ts + falcon.test.ts + falcon-failures.test.ts) byte-for-byte. Log A-006 in `docs/amendments.md` with the evidence scope (line numbers renamed in each contract + NatSpec updates).

- [x] **Task 2: G3 pk-transform KAT (AC-5-2) with structural coefficient oracle**
  - AC: AC-5-2 (pk-transform byte-identity against ~100 vectors, reconciled per A-004)
  - Files: `test/signers/mldsa-encoding.pk-transform.kat.test.ts` (new; ~80 LOC)
  - Dependencies: Task 1 (cosmetic — Task 2 does not touch Solidity but we want Task 1 to land first so all commits thereafter reference the new name). Stories 1/3 must be complete (loader + `keccakXofFactory` + refactored `preparePublicKeyForDeployment`).
  - Why: G3 proves `preparePublicKeyForDeployment(pk, keccakXofFactory, keccakXofFactory)` produces the correct coefficient data across all ~100 `.rsp` vectors. Per Dev Notes §"G3 oracle — TS vs Python format reconciliation", the default oracle is structural decode + coefficient-wise compare (Option 1). Concrete shape:
    - `import { loadKatVectors } from "../fixtures/kat/index.js";`
    - `import { preparePublicKeyForDeployment, keccakXofFactory } from "../signers/mldsa-encoding.js";`
    - `import { decodeAbiParameters, hexToBytes } from "viem";`
    - `import { assertBytesEqual } from "../utils/assert-bytes.js";`
    - For each vector: compute `actualHex = preparePublicKeyForDeployment(hexToBytes(v.publicKey), keccakXofFactory, keccakXofFactory)`; decode `(actualAHatBytes, actualTrBytes, actualT1Bytes) = decodeAbiParameters([{type:"bytes"},{type:"bytes"},{type:"bytes"}], actualHex)`; decode `actualAHat: bigint[][][] = decodeAbiParameters([{type:"uint256[][][]"}], actualAHatBytes)[0]`; same for `actualT1: bigint[][]`.
    - Decode fixture `(expectedAHatBytes, expectedTrBytes, expectedT1Bytes) = decodeAbiParameters(...)(v.reshapedPublicKey)`. For the `aHat`/`t1` inner blobs (Python-format 4-byte BE flat), unpack into `bigint[][][]` / `bigint[][]` structurally matching the TS decoded shape (each 256-coefficient poly is a Uint8Array of 1024 B → 256 × uint32 BE → bigint[256]).
    - Assert `actualAHat` deep-equals `expectedAHatReconstructed` (coefficient-wise); `assertBytesEqual(actualTrBytes, expectedTrBytes, \`vec ${v.id} tr\`, "keccak-prg")`; `actualT1` deep-equals `expectedT1Reconstructed`.
    - Document the Option 1 choice at top-of-file JSDoc; cross-reference `docs/amendments.md` §A-004.
    - Iterate all ~100 vectors in a single `describe`; cost ~5-10 s (pure-JS, no EVM).
  - **Escalation point:** at kickoff, surface both Option 1 (default) and Option 2 (fixture regeneration → adds A-007 amendment, Story 1 fixture diff) to the user; proceed with user-approved oracle.

- [x] **Task 3: `contracts/MlDsaEthAccount.sol` + `test/fixtures/mldsa-eth.ts` helper**
  - AC: AC-5-3 prerequisite (the account + fixture are what the G4 test deploys); AC-5-5 (the contract defines `SignatureMalformed()` custom error + try/catch in `_validateSignature`)
  - Files: `contracts/MlDsaEthAccount.sol` (new; ~90 LOC per §Verified Interfaces "Produced"), `test/fixtures/mldsa-eth.ts` (new; ~80 LOC)
  - Dependencies: Task 1 (`publicKeyPointer` naming must match across all 4 PQC account contracts)
  - Why: The on-chain account that delegates `_validateSignature` to `ZKNOX_ethdilithium.verify(...)`. Concrete shape per §Verified Interfaces "Produced":
    - Author `MlDsaEthAccount.sol` with full NatSpec (`@title`, `@author pqc-4337-laim`, `@notice`, `@dev`, `@param`, `@return` where applicable) per `.claude/rules/solidity.md`; mirror `contracts/MlDsaAccount.sol`'s doc-block conventions verbatim.
    - `import {ZKNOX_ethdilithium} from "../ETHDILITHIUM/src/ZKNOX_ethdilithium.sol";` — the submodule path is compile-path-correct (already in the compile graph via `contracts/imports/DilithiumRef.sol:34`). `contracts/imports/DilithiumRef.sol:37` already exposes `contract ZKNOX_ethdilithium is _ZKNOX_ethdilithium {}` as an artifact-emitted wrapper — tests deploy via `viem.deployContract("ZKNOX_ethdilithium")`.
    - Storage: `ZKNOX_ethdilithium public immutable dilithiumEthVerifier;` + `bytes public publicKeyPointer;`. Constant: `bytes4 private constant _VERIFY_SELECTOR = bytes4(keccak256("verify(bytes,bytes32,bytes)"));` — the verifier has overloads (3-arg + 4-arg) so `.selector` is ambiguous; use the keccak256 literal.
    - Author `test/fixtures/mldsa-eth.ts` mirroring `test/fixtures/mldsa.ts` hash `d5c7c8807952791a49af442c889681475a3a27222f5eaa00661736dd09a9a270`. Swap `"ZKNOX_dilithium"` → `"ZKNOX_ethdilithium"`; swap the `preparePublicKeyForDeployment(rawPublicKey, shake256XofFactory, shake128XofFactory)` call to `preparePublicKeyForDeployment(rawPublicKey, keccakXofFactory, keccakXofFactory)`. Preserve the simulate-then-write two-step capture pattern exactly.
    - Gate 5 criterion: `npm run compile` succeeds with zero warnings (`check-compile-warnings.cjs` enforces this across the ETHDILITHIUM transitive compile graph).

- [x] **Task 4: G4 happy path + AC-FLOW-1 end-to-end test (`test/accounts/mldsa-eth.test.ts`)**
  - AC: AC-5-3 (G4 happy path, ~100 `.rsp` vectors → SIG_VALIDATION_SUCCESS), AC-FLOW-1 (≥5-iteration fresh-keypair end-to-end)
  - Files: `test/accounts/mldsa-eth.test.ts` (new; ~150 LOC)
  - Dependencies: Task 3 (`MlDsaEthAccount` + `test/fixtures/mldsa-eth.ts`)
  - Why: G4 composes G0-G3 into on-chain verification — `(reshapedPublicKey, userOpHash, signature)` survives the full ERC-4337 validation chain. Concrete shape:
    - Mirror `test/accounts/mldsa.test.ts` setup (single `hre.network.connect()`, EntryPoint + verifier + account + proxy deployment, impersonate EntryPoint, `chainId` capture).
    - **AC-5-3 loop**: **USER DECISION (2026-04-18): smoke-first approach.** Start with `N = 5` (`loadKatVectors("mldsa-eth").slice(0, 5)`) to validate the on-chain scaffolding end-to-end; measure runtime; at Gate 5 tune `N` upward (toward 100) if the full corpus fits inside a ≤3 min budget, or stay at 5 with an explicit concern logged if it does not. Define `N` as a top-of-file constant with a JSDoc note so Gate-5 tuning is a one-line edit. Per vector: `setKey(reshapedPk from v.reshapedPublicKey)` → deploy proxy (or rotate via a fresh proxy) → init with `publicKeyPointer` → build `userOp` with sender = proxy address, nonce 0 → compute `userOpHash` via `computeUserOpHash(userOp, entryPoint.address, chainId)` → `sig = signWithRnd(hexToBytes(v.secretKey), hexToBytes(userOpHash), hexToBytes(v.rnd), new Uint8Array(0))` → submit via impersonated EntryPoint `validateUserOp(signed, userOpHash, 0)` simulate → assert `result === SIG_VALIDATION_SUCCESS` (0n).
    - **AC-FLOW-1 loop**: separate `it` block iterating 5 times: `const alice = keygen()` from `ml-dsa-eth.ts` → `preparePublicKeyForDeployment(alice.publicKey, keccakXofFactory, keccakXofFactory)` → `registerPublicKey(...)` → deploy proxy + init → `signUserOp(alice.secretKey, userOp, entryPoint, chainId)` → `validateUserOp` simulate → assert `SIG_VALIDATION_SUCCESS`. Uses production `signUserOp` (NOT `signWithRnd`), proving the end-to-end freshness path.
    - **Import boundary**: `import { signWithRnd } from "../signers/ml-dsa-eth.kat-internal.js"` PERMITTED (outside AC-3-7 grep scope per Dev Notes). `import { signUserOp, keygen } from "../signers/ml-dsa-eth.js"` — direct module import (sidesteps dispatcher ordering with Task 6).
    - `assert.rejects` + viem error walker NOT required here (happy paths only — rejection-class tests live in Task 5's failure file).

- [x] **Task 5: G4 rejection tests (`test/accounts/mldsa-eth-failures.test.ts`)**
  - AC: AC-5-4 (crypto-invalid → SIG_VALIDATION_FAILED, no revert), AC-5-5 (malformed → `SignatureMalformed()` revert)
  - Files: `test/accounts/mldsa-eth-failures.test.ts` (new; ~200 LOC)
  - Dependencies: Task 3 (`MlDsaEthAccount` + fixture); can run in parallel with Task 4 but sits logically after
  - Why: AC-5-4 + AC-5-5 exercise the two `_validateSignature` branches (return `SIG_VALIDATION_FAILED` vs revert with `SignatureMalformed`). Mirror `test/accounts/mldsa-failures.test.ts` structure verbatim (the three-AC decomposition: wrong-key, bit-flip cTilde byte 5, 100-zero-byte truncated), swapping fixture + account identifiers. Concrete shape:
    - `describe("MlDsaEthAccount failure classes")` with three `it` blocks.
    - **AC-5-4a (wrong key)**: `const alice = keygen(); const bob = keygen();` — register Alice's pk with the verifier; sign with Bob's sk; assert validation returns `1n`.
    - **AC-5-4b (bit-flip in cTilde)**: sign with Alice's sk; flip `signature[5]` (inside 32-byte cTilde region — safe zone per `mldsa-failures.test.ts:11-19`); assert `1n`. Comment at top of block cites the 2420 B layout (32 cTilde + 2304 z + 84 h) and byte-5 rationale.
    - **AC-5-5 (malformed)**: 100 zero bytes as `signature`; assert `assert.rejects(..., errorWalker)` — walker checks either `ContractFunctionRevertedError.data.errorName === "SignatureMalformed"` OR HH3 EDR message-regex fallback matching `/0x2c3c2fe1/` (the keccak selector of `SignatureMalformed()`). Both `MlDsaAccount` and `MlDsaEthAccount` declare the same selector; bind the walker to the account's origin address for disambiguation (per `mldsa-failures.test.ts:29-33` pattern).
    - No chai; no hardhat-chai-matchers — node-native `assert` only (A-001 convention).

- [x] **Task 6: Extend `SCHEMES` to 4 entries + benchmark harness + report generator + refresh snapshots**
  - AC: AC-5-6 (4-scheme benchmark runs), AC-5-7 (deterministic report), AC-5-8 (per-scheme failure isolation extended), AC-5-9 (SCHEMES.length derivation — zero literal `3`s)
  - Files: `test/signers/index.ts` (extend `Scheme` union + dispatch switches), `test/bench/gas-benchmark.test.ts` (extend `SCHEMES` + `deployAccount` branch + swap `length === 3` for `length === SCHEMES.length`), `scripts/generate-report.ts` (extend `SCHEMES` + swap `length !== 3` for `length !== SCHEMES.length`), `test/bench/gas-data.json` (refresh via `UPDATE_BENCH=1`), `docs/gas-report.md` (regen via `npm run report`)
  - Dependencies: Tasks 3 + 4 (`MlDsaEthAccount` + fixture must exist for the benchmark's `"mldsa-eth"` branch to deploy)
  - Why: The 4-scheme guarantee per DD-9 + AC-5-9 + AC-NFR-6. Concrete shape:
    - In `test/signers/index.ts`: add `| "mldsa-eth"` to `Scheme` at line 14; `import * as mldsaEth from "./ml-dsa-eth.js";` at the top; add `case "mldsa-eth": return mldsaEth.keygen();` + `case "mldsa-eth": return mldsaEth.signUserOp(secretKey, userOp, entryPointAddress, chainId);` branches. `never`-assignment compile check confirms every switch is exhaustive.
    - In `test/bench/gas-benchmark.test.ts`: extend `SCHEMES` at line 57 to `["ecdsa", "falcon", "mldsa", "mldsa-eth"] as const satisfies readonly Scheme[]`. Add a 4th `benchScheme`-dispatch branch for `"mldsa-eth"` at ~line 197 (mirror the `"mldsa"` branch: `deployDilithiumEthVerifier` → `registerKey` → `"MlDsaEthAccount"` deploy + proxy + initData). Swap `assert.equal(results.length, 3, ...)` at line 355 to `assert.equal(results.length, SCHEMES.length, ...)`. Extend `corruptedOptions: Record<Scheme, BenchOptions>` at line 467 with `"mldsa-eth": {}` and ensure AC-5-8's result-row iteration covers 4 schemes.
    - In `scripts/generate-report.ts`: extend `SCHEMES` at line 44 to 4 entries; replace `if (results.length !== 3) throw new Error(\`expected 3 BenchResult records, got ${results.length}\`)` at line 101 with `if (results.length !== SCHEMES.length) throw new Error(\`expected ${SCHEMES.length} BenchResult records, got ${results.length}\`)`.
    - **AC-5-7 strict determinism (USER DECISION 2026-04-18):** the report's `_Generated:` timestamp line MUST be sourced from `gas-data.json.generatedAt` (written by the bench test), NOT from `new Date().toISOString()` at render time. Two consecutive `npm run report` runs on an unchanged `gas-data.json` produce a byte-identical `gas-report.md`. Concretely: (a) the bench test writes `{ generatedAt: new Date().toISOString(), results: [...] }` to `gas-data.json` (current shape is a flat array — Task 6 wraps it in an object with a `generatedAt` field AND updates the loader in `generate-report.ts`; this is a one-time schema bump, logged inline as a Rule 1 deviation); (b) `generate-report.ts` reads `generatedAt` from the loaded JSON and interpolates it into the `_Generated:` line; (c) `git diff docs/gas-report.md` between two consecutive runs with the same `gas-data.json` produces zero output. ~10 LOC touched across both files.
    - **Refresh snapshots as part of this task's commit:** `UPDATE_BENCH=1 npx hardhat test test/bench/gas-benchmark.test.ts` (writes a 4-row `gas-data.json` with the new `generatedAt` schema); `npm run report` (regens `docs/gas-report.md` — 4 rows, deterministic timestamp). Commit `gas-data.json` + `gas-report.md` atomically with this task's code changes. The commit message references AC-5-6 + AC-5-7 + the deliberate snapshot refresh.
    - **Gate 5 AC-5-9 grep gate**: `grep -nE '\\b(===?|!==?)\\s*3\\b|\\.length\\s*(===?|!==?)\\s*3' test/bench/gas-benchmark.test.ts scripts/generate-report.ts` returns zero hits.

- [x] **Task 7: README attribution (AC-5-10)**
  - AC: AC-5-10 (README lists all 4 schemes + ZKNox credit + Python dev-oracle isolation note)
  - Files: `README.md` (add "Supported schemes" section OR extend existing list at lines 53 + 76; add ZKNox attribution paragraph + Python dev-oracle isolation note)
  - Dependencies: Task 6 (scheme list stabilizes at 4 entries)
  - Why: Per FR-12 + AC-U-5, the README surface must document ML-DSA-ETH alongside the other three schemes, credit ZKNox as the origin of the ETHDilithium design and `ZKNOX_ethdilithium.sol`, and preserve the Python dev-oracle isolation note (Python interpreter invoked ONLY by `scripts/generate-kat-fixtures.ts`, NEVER at `npm test` time). Concrete shape:
    - Under "Running the suite" §4 (line 53): change "ECDSA, Falcon, and ML-DSA acceptance + rejection tests" to "ECDSA, Falcon, ML-DSA (NIST), and ML-DSA-ETH (Keccak-PRG variant) acceptance + rejection tests".
    - Under "Read the report" §7 (line 76): change "ecdsa, falcon, mldsa" to "ecdsa, falcon, mldsa, mldsa-eth".
    - **Add a new "Supported schemes" section** above or below "Pinned Dependencies":
      ```markdown
      ## Supported schemes

      | Scheme | Algorithm | Signature size | Verifier origin |
      |---|---|---|---|
      | `ecdsa` | secp256k1 ECDSA | 65 B | Ethereum-native |
      | `falcon` | Falcon-512 | 1064 B | [ZKNoxHQ/ETHFALCON](https://github.com/ZKNoxHQ/ETHFALCON) |
      | `mldsa` | ML-DSA-44 (NIST) | 2420 B | [ZKNoxHQ/ETHDILITHIUM](https://github.com/ZKNoxHQ/ETHDILITHIUM) |
      | `mldsa-eth` | ML-DSA-44 (Keccak-PRG variant) | 2420 B | [ZKNoxHQ/ETHDILITHIUM](https://github.com/ZKNoxHQ/ETHDILITHIUM) — `ZKNOX_ethdilithium.sol` |

      ZKNoxHQ authored the ETHDilithium design and the ETH-variant Solidity verifier (`ZKNOX_ethdilithium.sol`). This repository integrates their audited implementations as ERC-4337 account modules without modifying submodule sources (NFR-5).

      **Python dev-oracle isolation (NFR-3):** the Python reference in `ETHDILITHIUM/pythonref/` is invoked exclusively by `scripts/generate-kat-fixtures.ts` at fixture-regeneration time. `npm test` never spawns a Python interpreter — all runtime crypto is TypeScript + Solidity.
      ```
    - Preserve existing README content; this is additive.

## Definition of Done (Gate 5 criteria — Story 5)

Beyond standard Gate 5 (format + lint + build + test + test integrity + security — `.claude/rules/code-standards.md` §2 "Verification Loop"):

1. **AC-5-1 rename + A-006 amendment landed.** `contracts/MlDsaAccount.sol` + `contracts/FalconAccount.sol` rename `publicKey` → `publicKeyPointer` + `_publicKey` → `_publicKeyPointer` on all three surfaces (member + initialize param + NatSpec). Existing `test/accounts/mldsa*.ts` + `test/accounts/falcon*.ts` continue to pass byte-for-byte. `docs/amendments.md` contains A-006 per Rule 3.
2. **G3 KAT passes — structural coefficient oracle across all ~100 vectors.** `npx hardhat test test/signers/mldsa-encoding.pk-transform.kat.test.ts` — for every `.rsp` vector, `preparePublicKeyForDeployment(pk, keccakXofFactory, keccakXofFactory)` decoded structurally matches the fixture's `reshapedPublicKey` decoded structurally (coefficient-wise `aHat` + `t1` + byte-identity `tr`). AC-5-2 honored per A-004 reconciliation.
3. **G4 happy path passes — full 100 vectors return SIG_VALIDATION_SUCCESS.** `npx hardhat test test/accounts/mldsa-eth.test.ts` — AC-5-3 validated across the full KAT corpus. Per user decision (2026-04-18), Task 4 initially landed at `N = 5` (smoke first). Gate 5 empirical measurement showed ~80 ms/vector (full 100 ≈ 8 s total — well under the 3 min budget), so `AC_5_3_VECTOR_COUNT` was tuned up to 100 during Story 5 code-review followups to cover the AC's "all ~100 vectors" literal wording.
4. **AC-FLOW-1 ≥5-iteration fresh-keypair path passes.** Same test file, separate `it` block: 5 independent `keygen()` + `preparePublicKeyForDeployment` + `setKey` + `signUserOp` + `validateUserOp` cycles all return `SIG_VALIDATION_SUCCESS`.
5. **G4 rejection tests pass.** `npx hardhat test test/accounts/mldsa-eth-failures.test.ts` — wrong-key → `1n`; bit-flipped cTilde byte 5 → `1n`; 100-zero-byte malformed signature → `SignatureMalformed()` revert caught by the dual-path viem-walker. AC-5-4 + AC-5-5.
6. **4-scheme benchmark passes.** `npx hardhat test test/bench/gas-benchmark.test.ts` — `SCHEMES.length === 4` in the assertion; all 4 rows produced; variance thresholds unchanged from pre-Story-5 (0.01 ECDSA / 0.10 PQC); `gas-data.json` refreshed via `UPDATE_BENCH=1` + committed.
7. **4-scheme report renders + strict determinism.** `npm run report` produces `docs/gas-report.md` with 4 rows (ecdsa, falcon, mldsa, mldsa-eth) and a `_Generated:` header timestamp sourced from `gas-data.json.generatedAt`. Gate-5 verification: run `npm run report` twice back-to-back on an unchanged `gas-data.json`; `git diff docs/gas-report.md` produces zero output. AC-5-6 + AC-5-7 (strict interpretation per user decision).
8. **AC-5-8 per-scheme failure isolation — 4 rows with deliberate injection.** Same test file, second `it` block with `corruptedOptions` map covers 4 entries; deliberately-corrupted scheme's row is `status: "failed"` with human-readable `reason`; other 3 rows remain `status: "ok"`.
9. **AC-5-9 grep gate — zero literal `3`-comparisons.** `grep -nE '\\b(===?|!==?)\\s*3\\b|\\.length\\s*(===?|!==?)\\s*3' test/bench/gas-benchmark.test.ts scripts/generate-report.ts` returns zero hits.
10. **Adding a 5th scheme causes TypeScript compile errors.** Inspection-verified at Gate 5: every `switch(scheme)` site handles all 4 cases exhaustively (no `default` fallthrough); `never`-assignability catches a hypothetical 5th addition.
11. **AC-5-10 README attribution.** `README.md` contains a "Supported schemes" section listing all 4 schemes; ZKNoxHQ credited as origin of ETHDilithium + `ZKNOX_ethdilithium.sol`; Python dev-oracle isolation note present.
12. **`npm run compile` succeeds with zero warnings.** `MlDsaEthAccount.sol` compiles cleanly via the existing `DilithiumRef.sol` transitive compile path (no `hardhat.config.ts` change needed).
13. **AC-3-7 runtime grep continues to pass.** `test/signers/ml-dsa-eth.test.ts` grep scope (scanning `test/signers/index.ts` + `test/bench/**`) reports zero `ml-dsa-eth.kat-internal` import matches; `test/accounts/**` is outside this scope and Story 5's `test/accounts/mldsa-eth.test.ts` + kin are permitted to import from kat-internal.
14. **No new dependencies in `package.json`.** `git diff package.json package-lock.json` — `dependencies` + `devDependencies` unchanged. All new capability is composed from existing dev-deps.
15. **No silenced tests, no assertion-free new tests.** Per `.claude/rules/test-integrity.md` §5 — `VERIFY.md` §4 grep audit at Gate 5. Every new test file has at least one `assert.*` call per `describe`/`it` block.
16. **Task-atomic commits per `.claude/rules/code-standards.md` §1.** Minimum 7 commits matching Tasks 1-7. Pre-tag `pre-mldsa-eth-5` before Task 1's first commit; post-tag `post-mldsa-eth-5` after Gate 5 passes. Rule 1 allows minor rider commits when trivial.
17. **NatSpec coverage on `MlDsaEthAccount.sol`.** Every public/external function + custom error + state variable has the required NatSpec tags per `.claude/rules/solidity.md`. No bare `@inheritdoc` on `_validateSignature` unless the override adds nothing beyond the parent — given the try/catch + custom revert, an explicit `@dev` block is warranted.
18. **Snapshot commits (`gas-data.json`, `gas-report.md`) atomic with Task 6 code changes.** Not scattered across multiple commits; one commit per snapshot refresh, cross-referenced to Task 6 in the commit message.

## must_haves

truths:
  - "`contracts/MlDsaAccount.sol` + `contracts/FalconAccount.sol` store `bytes public publicKeyPointer` (renamed from `publicKey`) and accept `initialize(address, bytes calldata _publicKeyPointer)` (renamed from `_publicKey`) after Task 1; existing `test/accounts/mldsa.test.ts` + `test/accounts/mldsa-failures.test.ts` + `test/accounts/falcon.test.ts` + `test/accounts/falcon-failures.test.ts` all pass byte-for-byte post-rename; `docs/amendments.md` contains A-006 entry logging the rename per Rule 3 — AC-5-1."
  - "`test/signers/mldsa-encoding.pk-transform.kat.test.ts` iterates `loadKatVectors('mldsa-eth')` (~100 vectors); for each vector `v`, `preparePublicKeyForDeployment(hexToBytes(v.publicKey), keccakXofFactory, keccakXofFactory)` decoded structurally (outer `(bytes,bytes,bytes)` → inner `uint256[][][]` + 64 B bytes + `uint256[][]`) matches `v.reshapedPublicKey` decoded structurally (outer `(bytes,bytes,bytes)` → inner Python-format flat 4B-BE reconstructed to the same shape); the `tr` 64-byte field is byte-identical via `assertBytesEqual(..., 'keccak-prg')` — AC-5-2 per `docs/amendments.md` §A-004 reconciliation."
  - "`contracts/MlDsaEthAccount.sol` exists as a `SimpleAccount`-subclass with `bytes public publicKeyPointer`, `ZKNOX_ethdilithium public immutable dilithiumEthVerifier`, `_VERIFY_SELECTOR = bytes4(keccak256(\"verify(bytes,bytes32,bytes)\"))`, `initialize(address, bytes calldata _publicKeyPointer) public initializer`, and `_validateSignature(PackedUserOperation calldata, bytes32) internal view override returns (uint256)` that wraps `verifier.verify(publicKeyPointer, userOpHash, userOp.signature)` in a try/catch — success returns `SIG_VALIDATION_SUCCESS` when result matches selector, `SIG_VALIDATION_FAILED` otherwise; catch branch reverts with `SignatureMalformed()`. Full NatSpec on every public/external surface."
  - "`test/fixtures/mldsa-eth.ts` exports `deployDilithiumEthVerifier(viem?)` and `registerPublicKey(verifier, rawPublicKey): Promise<Hex>` mirroring `test/fixtures/mldsa.ts` with the sole behavioral change: the pk-transform invocation is `preparePublicKeyForDeployment(rawPublicKey, keccakXofFactory, keccakXofFactory)` (both factories Keccak, per DD-1 collapse) — never the NIST `(shake256XofFactory, shake128XofFactory)` pair."
  - "`test/accounts/mldsa-eth.test.ts` contains an AC-5-3 `describe` iterating `.rsp` vectors: for each, `setKey(reshapedPk from v.reshapedPublicKey)` + `MlDsaEthAccount.initialize(ZERO_ADDRESS, pointerHex)` + `signWithRnd(hexToBytes(v.secretKey), hexToBytes(userOpHash), hexToBytes(v.rnd), new Uint8Array(0))` → `EntryPoint.validateUserOp` simulate returns `SIG_VALIDATION_SUCCESS = 0n`. Separate `it` block for AC-FLOW-1: 5 iterations of `keygen()` + full end-to-end production path → `SIG_VALIDATION_SUCCESS`."
  - "`test/accounts/mldsa-eth-failures.test.ts` covers three rejection ACs: wrong-key + bit-flip (byte 5 inside cTilde) → `SIG_VALIDATION_FAILED = 1n`; 100-zero-byte signature → `assert.rejects` with the dual-path viem walker matching `SignatureMalformed()` custom error — AC-5-4 + AC-5-5."
  - "`test/signers/index.ts` exports `Scheme = \"ecdsa\" | \"falcon\" | \"mldsa\" | \"mldsa-eth\"` (4-variant union); `keygen(scheme)` + `signUserOp(scheme, ...)` dispatch switches have exactly 4 cases each (no `default`); `import * as mldsaEth from \"./ml-dsa-eth.js\"` at the top (never `ml-dsa-eth.kat-internal.js`)."
  - "`test/bench/gas-benchmark.test.ts` declares `const SCHEMES = [\"ecdsa\", \"falcon\", \"mldsa\", \"mldsa-eth\"] as const satisfies readonly Scheme[]` (4 entries); `benchScheme` / `deployAccount` has a 4th branch for `\"mldsa-eth\"` using `deployDilithiumEthVerifier` + `MlDsaEthAccount`; any literal `results.length === 3` / `results.length !== 3` is replaced with `SCHEMES.length`; `corruptedOptions: Record<Scheme, BenchOptions>` covers all 4 entries."
  - "`scripts/generate-report.ts` declares `SCHEMES: readonly Scheme[] = [\"ecdsa\", \"falcon\", \"mldsa\", \"mldsa-eth\"]` (4 entries); the guard at line 101 reads `if (results.length !== SCHEMES.length) throw new Error(\`expected ${SCHEMES.length} BenchResult records, got ${results.length}\`)` — no literal `3` remains."
  - "`test/bench/gas-data.json` has been refreshed via `UPDATE_BENCH=1 npx hardhat test test/bench/gas-benchmark.test.ts` as part of Task 6's landing; `docs/gas-report.md` has been regenerated via `npm run report`; both 4-row artifacts are committed atomically with Task 6 — AC-5-6 + AC-5-7."
  - "`test/bench/gas-data.json` now has schema `{ generatedAt: string, results: BenchResult[] }` (Task 6 schema bump — previously flat `BenchResult[]`); `scripts/generate-report.ts` reads the `generatedAt` from the JSON and renders the `_Generated:` header from that field (no `new Date().toISOString()` at render time); two consecutive `npm run report` runs on an unchanged `gas-data.json` produce a byte-identical `docs/gas-report.md` — AC-5-7 strict determinism."
  - "`grep -nE '\\b(===?|!==?)\\s*3\\b|\\.length\\s*(===?|!==?)\\s*3' test/bench/gas-benchmark.test.ts scripts/generate-report.ts` returns zero hits — AC-5-9 literal-3 prohibition."
  - "`README.md` contains a 'Supported schemes' section listing all 4 schemes with a short-label description for each; ZKNoxHQ credited as origin of the ETHDilithium design + `ZKNOX_ethdilithium.sol`; Python dev-oracle isolation note (NFR-3) present stating the Python interpreter is invoked ONLY by `scripts/generate-kat-fixtures.ts` and never by `npm test` — AC-5-10."
  - "`test/signers/ml-dsa-eth.test.ts`'s AC-3-7 runtime grep continues to pass post-Story-5 — `test/signers/index.ts` + all files under `test/bench/**` contain zero `/from\\s+[\"'][^\"']*ml-dsa-eth\\.kat-internal[^\"']*[\"']/` matches. `test/accounts/mldsa-eth.test.ts`'s kat-internal import is outside the grep scope and therefore permitted."
  - "`npm run compile` succeeds with zero warnings. `MlDsaEthAccount.sol` compiles via the existing `contracts/imports/DilithiumRef.sol:37` ref-wrapper; no `hardhat.config.ts` edit is required."
  - "`docs/amendments.md` contains A-006 (rename `publicKey` → `publicKeyPointer`) as a new entry appended after A-005; if the G3 oracle implementer chose Option 2 (fixture regeneration), A-007 is also present — otherwise the default Option 1 structural oracle is cross-referenced in the test file's JSDoc."

artifacts:
  - path: "contracts/MlDsaEthAccount.sol"
    contains: ["MlDsaEthAccount", "SimpleAccount", "publicKeyPointer", "dilithiumEthVerifier", "SignatureMalformed", "_VERIFY_SELECTOR", "ZKNOX_ethdilithium", "SIG_VALIDATION_SUCCESS", "SIG_VALIDATION_FAILED", "@title", "@author"]
  - path: "contracts/MlDsaAccount.sol"
    contains: ["publicKeyPointer", "_publicKeyPointer"]
  - path: "contracts/FalconAccount.sol"
    contains: ["publicKeyPointer", "_publicKeyPointer"]
  - path: "test/fixtures/mldsa-eth.ts"
    contains: ["deployDilithiumEthVerifier", "registerPublicKey", "keccakXofFactory", "preparePublicKeyForDeployment", "ZKNOX_ethdilithium"]
  - path: "test/signers/mldsa-encoding.pk-transform.kat.test.ts"
    contains: ["loadKatVectors", "mldsa-eth", "preparePublicKeyForDeployment", "keccakXofFactory", "decodeAbiParameters", "assertBytesEqual", "A-004"]
  - path: "test/accounts/mldsa-eth.test.ts"
    contains: ["MlDsaEthAccount", "deployDilithiumEthVerifier", "signWithRnd", "signUserOp", "keygen", "validateUserOp", "SIG_VALIDATION_SUCCESS", "AC-FLOW-1"]
  - path: "test/accounts/mldsa-eth-failures.test.ts"
    contains: ["MlDsaEthAccount", "SignatureMalformed", "SIG_VALIDATION_FAILED", "assert.rejects", "cTilde"]
  - path: "test/signers/index.ts"
    contains: ["\"mldsa-eth\"", "mldsaEth", "ecdsa", "falcon", "mldsa"]
  - path: "test/bench/gas-benchmark.test.ts"
    contains: ["mldsa-eth", "SCHEMES.length", "deployDilithiumEthVerifier", "MlDsaEthAccount"]
  - path: "scripts/generate-report.ts"
    contains: ["mldsa-eth", "SCHEMES.length"]
  - path: "test/bench/gas-data.json"
    contains: ["mldsa-eth"]
  - path: "docs/gas-report.md"
    contains: ["mldsa-eth"]
  - path: "README.md"
    contains: ["mldsa-eth", "ZKNox", "ZKNOX_ethdilithium", "Supported schemes"]
  - path: "docs/amendments.md"
    contains: ["A-006", "publicKeyPointer"]

key_links:
  - pattern: "MlDsaEthAccount"
    in: ["contracts/MlDsaEthAccount.sol", "test/fixtures/mldsa-eth.ts", "test/accounts/mldsa-eth.test.ts", "test/accounts/mldsa-eth-failures.test.ts", "test/bench/gas-benchmark.test.ts"]
  - pattern: "deployDilithiumEthVerifier"
    in: ["test/fixtures/mldsa-eth.ts", "test/accounts/mldsa-eth.test.ts", "test/accounts/mldsa-eth-failures.test.ts", "test/bench/gas-benchmark.test.ts"]
  - pattern: "keccakXofFactory, keccakXofFactory"
    in: ["test/fixtures/mldsa-eth.ts", "test/signers/mldsa-encoding.pk-transform.kat.test.ts", "test/accounts/mldsa-eth.test.ts"]
  - pattern: "publicKeyPointer"
    in: ["contracts/MlDsaAccount.sol", "contracts/FalconAccount.sol", "contracts/MlDsaEthAccount.sol"]
  - pattern: "SCHEMES.length"
    in: ["test/bench/gas-benchmark.test.ts", "scripts/generate-report.ts"]
  - pattern: "\"mldsa-eth\""
    in: ["test/signers/index.ts", "test/bench/gas-benchmark.test.ts", "scripts/generate-report.ts", "test/fixtures/kat/index.ts"]

## Detected Patterns

Scanned from Stories 1/2/3/4 + existing `MlDsaAccount`/`FalconAccount`/`ecdsa.test.ts` + `gas-benchmark.test.ts` + `mldsa.ts` signer + `mldsa.test.ts`/`mldsa-failures.test.ts` accounts.

| Pattern | Value | Sampled from | Established? |
|---------|-------|-------------|-------------|
| Test framework | `node:test` + `node:assert/strict` (A-001 LOCKED) | `test/accounts/mldsa.test.ts:17-18`, `test/bench/gas-benchmark.test.ts:30-33`, `test/signers/ml-dsa-eth.test.ts` | ✅ Established |
| Hex I/O | viem `hexToBytes` + `bytesToHex` — never `Buffer.from(..., 'hex')` | `test/signers/ml-dsa-eth.ts:52`, `test/fixtures/mldsa.ts:29`, `test/accounts/mldsa.test.ts:22` | ✅ Established |
| Account contract shape | `MlDsaEthAccount is SimpleAccount`, override ONLY `_validateSignature`, `bytes4 private constant _VERIFY_SELECTOR = keccak256("verify(bytes,bytes32,bytes)")`, `try ... catch { revert SignatureMalformed(); }` | `contracts/MlDsaAccount.sol:19-88`, `contracts/FalconAccount.sol:18-85` | ✅ Established |
| Fixture helper shape | `deploy*Verifier(viem?) + registerPublicKey(verifier, rawPublicKey): Promise<Hex>` (20-byte SSTORE2 pointer); single-connection discipline; simulate-then-write two-step setKey | `test/fixtures/mldsa.ts:39-79`, `test/fixtures/falcon.ts` | ✅ Established |
| G4 test setup | single `hre.network.connect()` for ALL contracts; impersonate EntryPoint via `testClient.impersonateAccount` + `setBalance`; chainId from `publicClient.getChainId` | `test/accounts/mldsa.test.ts:36-77`, `test/accounts/falcon.test.ts` | ✅ Established |
| Rejection-class test body | 3-AC decomposition (wrong key + bit-flip + truncated blob); dual-path viem walker (ContractFunctionRevertedError.data.errorName OR HH3 EDR message-regex fallback) bound to account origin | `test/accounts/mldsa-failures.test.ts:1-80` | ✅ Established |
| Bit-flip locus | byte 5 inside 32-byte cTilde region; 100-zero-byte for malformed | `test/accounts/mldsa-failures.test.ts:11-19, 20-27` | ✅ Established |
| Dispatcher discipline | exhaustive-never switch on `Scheme`; one case per scheme; NO `default` fallthrough — relies on TS `never`-assignment for compile-time check | `test/signers/index.ts:45-71` | ✅ Established |
| Benchmark harness shape | `try/catch` per scheme; `BenchResult = {scheme, status: "ok" | "failed", ...}`; warm-up rounds nonces 0/1; measurement rounds 2/3/4; `UPDATE_BENCH`-gated snapshot | `test/bench/gas-benchmark.test.ts:106-328` | ✅ Established |
| Report generator shape | RawOk/RawFailed → BenchResult hydration; renderReport returns Markdown; stable timestamp + deterministic formatting | `scripts/generate-report.ts:31-200` | ✅ Established |
| Import style (TS) | ESM `.js` extensions in imports (`import ... from "./foo.js"` even when source is `.ts`) | all `test/**/*.ts` | ✅ Established |
| Error discriminant | `readonly code: "..." as const` on error subclasses; tests assert `err instanceof Class && err.code === "..."`, never message strings | `test/signers/errors.ts:33-54`, `test/fixtures/kat/index.ts:49` (KatFixtureError) | ✅ Established |
| `@delta-from-ml-dsa` JSDoc | required on `test/signers/ml-dsa-eth.ts` + `test/signers/ml-dsa-eth.kat-internal.ts`; enforced by grep at `test/signers/ml-dsa-eth.test.ts` | Stories 3/4 landed; Story 5 preserves | ✅ Established |
| AC-3-7 grep boundary | runtime grep at `test/signers/ml-dsa-eth.test.ts` scans `test/signers/index.ts` + `test/bench/**`; does NOT scan `test/accounts/**` | `test/signers/ml-dsa-eth.test.ts:46-90` (hash `e826f4af...`) | ✅ Established |
| Solidity NatSpec | every public/external function + custom error + state variable has `@notice`/`@param`/`@return`; reference `docs/amendments.md` in-contract where relevant | `contracts/MlDsaAccount.sol`, `contracts/FalconAccount.sol` (esp. doc blocks at 10-46 / 10-42) | ✅ Established |
| Submodule compile path | ref-wrapper pattern in `contracts/imports/DilithiumRef.sol`, `contracts/imports/FalconRef.sol` — empty contract inherits submodule contract → Hardhat emits artifact under ref-wrapper path → tests deploy by string name | `contracts/imports/DilithiumRef.sol:33-37`, `hardhat.config.ts:5-31` | ✅ Established |
| Commit atomicity | Task-atomic commits; pre-`pre-{feature}-{story}` tag before first commit; post-`post-{feature}-{story}` tag after Gate 5; never `git add .`/`git add -A` | all Story 1-4 commits visible in `git log` | ✅ Established |

No ⚠ conflicting patterns detected — codebase is internally consistent across 4 completed stories.

## Wave Structure

Story 5 is **Wave 5** in the serial decomposition (per `docs/plan.md` §"Wave Assignments"). All 7 tasks run within this single wave; no parallelism across waves.

**Intra-story task dependencies (DAG):**

```
Task 1 (rename)
    │
    ├──► Task 2 (G3 KAT — only cosmetic dependency: post-rename all commits reference publicKeyPointer)
    │
    └──► Task 3 (MlDsaEthAccount + fixture — uses publicKeyPointer from day one)
              │
              ├──► Task 4 (G4 happy path — uses Task 3's account + fixture)
              ├──► Task 5 (G4 rejections — uses Task 3's account + fixture)
              └──► Task 6 (benchmark extension — uses Task 3's account + fixture in the 4th branch)
                         │
                         └──► Task 7 (README — scheme list stable at 4 entries)
```

Task 2 can run in parallel with Tasks 3+ (no code-overlap; both depend only on Task 1's cosmetic naming). Tasks 4 and 5 can run in parallel after Task 3 (no shared file writes — different test files). Task 6 waits for Task 3 (needs `MlDsaEthAccount` artifact for the 4th benchmark branch). Task 7 waits for Task 6 (scheme list must stabilize before documenting).

**Single-wave execution:** all 7 tasks land in `wave: 5`. Within the wave, implementer may choose a strict linear order (Task 1 → 2 → 3 → 4 → 5 → 6 → 7) or parallelize Tasks 4/5 after Task 3. No cross-wave dependencies.
