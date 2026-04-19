---
status: complete
created: 2026-04-18
feature: falcon-eth
---
# Brief: Falcon-ETH

## Problem
The pqc-4337-laim signer catalogue currently exposes four ERC-4337 signers: `ecdsa`, `falcon` (NIST-SHAKE Falcon-512), `mldsa` (NIST-SHAKE ML-DSA-44), and the just-landed `mldsa-eth` (Keccak-CTR-PRNG ML-DSA). Operators evaluating PQC on Ethereum want symmetric coverage — both ML-DSA and Falcon available in the gas-optimized ETH variant — so that lattice-scheme tradeoffs (ML-DSA's larger signatures vs Falcon's smaller signatures and more complex signer) can be measured head-to-head on-chain. ETHFALCON (ZKNoxHQ's Keccak-CTR-PRNG Falcon-512) is the missing 5th entry.

## Vision
Land `falcon-eth` as a 5th ERC-4337 signer integrated into the same framework as `mldsa-eth`: production surface + KAT surface + shared core, per-account verifier contract, 4-gate oracle chain (G1–G6), bench coverage, and a parallel Account contract storing the SSTORE2 pointer. When complete, the benchmark table shows 5 schemes side-by-side with byte-identity proofs to the ZKNoxHQ Python reference, ETHFALCON source unchanged (NFR-5), and the same hedged/deterministic signing discipline as mldsa-eth. As a secondary deliverable, the feature produces the **first and only JavaScript/TypeScript implementation of ETHFALCON** (Keccak-CTR-PRNG Falcon-512) — a reusable artifact for the broader AA + PQC ecosystem, since `@noble/post-quantum/falcon` only covers NIST Falcon (SHAKE) and the ETHFALCON submodule ships no JS port.

## Users
- **Smart wallet / account-abstraction developer evaluating PQC**: Goals — pick a lattice signature scheme to integrate into their AA wallet that balances signature size, verify gas cost, and signer runtime. Pain points today — only one ETH-variant PQC signer (`mldsa-eth`) is available, so tradeoffs between Falcon and ML-DSA on the ETH path can't be measured empirically.
- **Internal maintainer / auditor of this repo**: Goals — extend the signer dispatcher symmetrically (ecdsa + 2 NIST + 2 ETH variants), keep the oracle-chain methodology uniform across schemes, preserve the `mldsa-eth` architectural decisions where they transfer. Pain point — drift between schemes' test/fixture/bench patterns would fragment the codebase.

## Success Metrics
- **Test coverage**: G1–G6 oracles each pass ≥100 KAT vectors for falcon-eth at byte-identity with the Python reference (same bar as mldsa-eth).
- **First JavaScript/TypeScript ETHFALCON implementation**: `test/signers/falcon-eth.{core.ts, ts, kat-internal.ts}` is the first and only JS/TS port of ETHFALCON (Keccak-CTR-PRNG Falcon-512). `ETHFALCON/js/` does not exist in the submodule; `@noble/post-quantum/falcon` ships only NIST Falcon (SHAKE). Measurable: files exist, exports `keygen` + `sign(User)` + `signWithRnd`, pass all G3/G4 byte-identity oracles against ETHFALCON Python ref.
- **Zero regressions**: existing 97-test baseline stays green throughout, and post-feature total is 97 + falcon-eth additions (≥ mldsa-eth's per-story test adds: ~15–25 new tests).
- **Bench schema extended to 5 schemes**: `gas-data.json`/`gas-report.md` deterministically renders all 5 entries (ecdsa, falcon, mldsa, mldsa-eth, falcon-eth) with cross-scheme ordering + calldata-delta assertions covering the new entry.
- **Submodule untouched**: `git status ETHFALCON/` shows zero modifications across the full feature (NFR-5 hard gate).
- **Story count**: 5 stories at M/L size, matching mldsa-eth's shape (2–3 day duration expected).

## Feature Inventory
- FI-1: Fixture-gen pipeline for falcon-eth — extend `scripts/generate-kat-fixtures.ts` to capture ~100 Falcon-ETH vectors (`sk`, `pk`, `msg`, `salt`, `signature`, `reshapedPublicKey` if applicable) from ETHFALCON's Python reference into `test/fixtures/kat/falcon-eth/vectors.json`, with loader + type extensions.
- FI-2: Keccak-CTR-PRNG verification for ETHFALCON — G1 oracle confirming that `keccakXofFactory` (already shipped for mldsa-eth) produces byte-identical output to ETHFALCON's `Keccak256PRNG` Python wrapper. If the two wrappers diverge, port a falcon-specific adapter.
- FI-3: Falcon-ETH keygen port + HashToPoint — TS port of ETHFALCON's keygen and `HashToPoint` primitive with XOF-factory abstraction (DD-10), G3 byte-identity KAT, leveraging `@noble/post-quantum/falcon` where applicable.
- FI-4: Falcon-ETH signer port + G4 KAT — TS port of Falcon signing (including `ffSampling` if client-side), production + KAT surfaces, hedged/deterministic RND discipline, G4 byte-identity over ~100 vectors with rejection-counter instrumentation via sibling export (DD-10 LOCKED — no module-level XOF state).
- FI-5: Integration + benchmark + rename — `contracts/FalconEthAccount.sol` (extends SimpleAccount, stores `publicKeyPointer` from day one), `test/fixtures/falcon-eth.ts`, G5 pk-transform KAT (raw pk → ntt-domain compacted), G6 on-chain validateUserOp happy+rejection paths, extend `SCHEMES` to 5 entries in bench + report, refresh `gas-data.json`/`gas-report.md`/README.

## Scope
### In Scope
- Port ETHFALCON (Keccak-CTR-PRNG variant of Falcon-512) as the 5th ERC-4337 signer.
- All five above feature-inventory items.
- Reuse + extend: `keccak-prg.ts`, `keccakXofFactory`, `assert-bytes.ts`, `SignerInputError`, `test/fixtures/kat/index.ts`, bench harness, report renderer, submodule-import wrapper pattern.
- `FalconEthAccount.sol` mirroring `MlDsaEthAccount.sol` structure (SimpleAccount inheritance, `publicKeyPointer` state var, per-account verifier, `try/catch SignatureMalformed()`, `_VERIFY_SELECTOR`).
- Bench + report extended to 5 schemes with updated cross-scheme assertions.

### Out of Scope
- **Epervier variant** (`ZKNOX_epervier.sol`, `ZKNOX_ethepervier.sol`, `falcon_epervier.py`): different account architecture (pk-recovered via `recover()` instead of pk-stored via `publicKeyPointer`), different signature ABI (`salt || cs1 || cs2 || hint || s_1_inv_ntt` vs `salt || s2`), larger signatures. Deferred to a future feature that would reuse ~80% of this work (Keccak-PRG primitive, HashToPoint, fixture pipeline, Falcon signing core).
- **Editing ETHFALCON submodule source** (`ETHFALCON/**`) — NFR-5 hard gate.
- **Editing ETHDILITHIUM submodule source** — NFR-5 applies equally.
- **Modifying NIST-variant signers** (`test/signers/ecdsa.ts`, `test/signers/falcon.ts`, `test/signers/ml-dsa.ts`): stay verbatim.
- **Modifying existing Account contracts** (`MlDsaAccount.sol`, `FalconAccount.sol`, `MlDsaEthAccount.sol`): untouched — only additive work.
- **Production deployment of FalconEthAccount**: the on-chain verifier is `@custom:experimental This library is not audited yet, do not use in production` — same posture as mldsa-eth.

## Constraints
- **Technical — submodule immutability**: `ETHFALCON/` and `ETHDILITHIUM/` never modified. All integration via wrappers under `contracts/imports/` and TS ports under `test/signers/`.
- **Technical — warnings-as-errors compile gate**: `npm run compile` pipes through `scripts/check-compile-warnings.cjs`; zero solc warnings tolerated.
- **Technical — HH3 EDR `tx_gas_limit_cap = 2^24`**: existing `VERIFICATION_GAS_LIMIT = 15_000_000n` + `TX_GAS_OVERRIDE = 16_777_215n` workaround already baked in; confirm falcon-eth verify fits under the cap.
- **Technical — oracle chain discipline**: G1–G6 byte-identity at every segment; no "close enough" — failures must be tracked to the bit.
- **Technical — AC-3-7 grep boundary**: `test/signers/index.ts` + `test/bench/**/*.ts` must never import `*.kat-internal.*` modules; runtime test enforces this.
- **Technical — AC-A-1 HIGH grep gate**: `^(let|var) _?xof` must return zero hits across `{scheme}-eth.*` files. DD-10 LOCKED — XOF must be parameter-threaded, not module-level.
- **Business — MIT license preservation**: ZKNoxHQ copyright/license headers on every wrapper contract.
- **Timeline**: L × ~5 stories; mldsa-eth took ~2d 9h end-to-end — expect similar minus Story-2 (Keccak-PRG primitive already shipped).
- **Process — commit granularity**: one commit per task, story file tracked from Task 1 (corrective lesson from mldsa-eth §5.9).

## Design Decisions
Decisions that transfer LOCKED from mldsa-eth (re-state in architecture phase):

- DD-1 [LOCKED]: **XOF swap** — every SHAKE-128/256 role in NIST Falcon (including `HashToPoint`) collapses to a single `keccakXofFactory` call on the ETH path. Keys + signatures are NOT interchangeable between NIST Falcon and ETH-Falcon. (Source: `docs/user-context/falcon-eth.md` §4)
- DD-5 [LOCKED]: **Account extends SimpleAccount** — `FalconEthAccount` inherits from `@account-abstraction/contracts/samples/SimpleAccount.sol` and overrides `_validateSignature`. Uses `initialize(address, bytes calldata _publicKeyPointer)` with matching shadowing discipline. (Source: §4)
- DD-6 [LOCKED]: **Submodule compile path** — do not edit `ETHFALCON/**`. Compile-graph wrapper contracts go under `contracts/imports/FalconRef.sol` mirroring `contracts/imports/DilithiumRef.sol:37`. (Source: §4)
- DD-7 [LOCKED]: **Reshaped-pk on-chain shape** — `ZKNOX_ethfalcon`'s `setKey(bytes)` does raw `SSTORE2.write`; but the verifier's `CheckParameters` expects `ntth` (ntt-domain compacted, 32 × uint256 for Falcon-512). The TS `preparePublicKeyForDeployment` must transform raw pk → ntt-domain-compacted bytes before calling setKey. **G5 applies.** (Source: §4 + probe of `ETHFALCON/src/ZKNOX_ethfalcon.sol`)
- DD-8 [LOCKED]: **Signature ABI** — Solidity boundary for ETHFALCON is `salt(40) || s2_compact(32 × uint256 = 1024 bytes)`. TS `signWithXof` emits a single `Uint8Array` per this layout; on-chain decoding is the verifier's concern. (Source: §4 + `ZKNOX_ethfalcon.sol:23-34`)
- DD-9 [LOCKED]: **Per-account verifier** — each `FalconEthAccount` carries its own immutable `ZKNOX_ethfalcon` reference; no cross-account verifier reuse. (Source: §4)
- DD-10 [LOCKED]: **Parameterize-by-factory** — instrumentation for rejection-counters uses a sibling export `signWithXofInstrumented` returning `{ signature, iterations }`. Zero module-level XOF state. AC-A-1 grep pattern extends to falcon-eth files. (Source: §4)
- DD-11 [LOCKED]: **Four-implementation oracle chain** — Python ref ↔ JSON fixture ↔ TS fork ↔ Solidity verifier, G1–G6 byte-identity at every segment. (Source: §4)

New decisions derived from probes:

- DD-12 [DISCRETION]: **Use `@noble/post-quantum/falcon` where possible** — probe confirmed `@noble/post-quantum@0.6.1` exports a Falcon submodule; use it as the NIST-side reference for keygen/sign math that maps cleanly, then delta-diff the ETHFALCON-specific XOF swap (same pattern as mldsa-eth leveraging `ml_dsa44`). Architecture phase to confirm feasibility vs a full ground-up port.
- DD-13 [LOCKED]: **Story 2 (Keccak-PRG verification) is REQUIRED, not skippable** — probe of `ETHFALCON/pythonref/keccak_prng.py` vs `ETHDILITHIUM/pythonref/dilithium_py/keccak_prng/keccak_prng_wrapper.py` shows the class names differ (`Keccak256PRNG(a=None, b=None)` vs `KeccakPRNG()`) and ETHFALCON's header explicitly says "This file is copied from ETHFALCON" → ETHFALCON is the upstream origin. Core Keccak mechanics may be byte-identical, but the wrapper API diverges enough that G1 must confirm byte-identity of `keccakXofFactory` against ETHFALCON's `Keccak256PRNG` before trusting it for G3/G4. (Source: probe at /research time)
- DD-14 [LOCKED]: **No existing KAT corpus** — `ETHFALCON/pythonref/assets/` does not exist; vectors must be generated on-demand via `generate_falcon_test_vectors.py`. Story 1 is the fixture-gen pipeline (higher cost than mldsa-eth Story 1 which had a pre-existing `.rsp` file to port). (Source: probe at /research time)
- DD-15 [DEFERRED]: **Falcon client-side `ffSampling` port strategy** — whether to port `ffSampling` (recursive Fast Fourier sampling) directly from Python or leverage noble's implementation depends on what noble's falcon submodule exposes. Architecture phase decides after reading `node_modules/@noble/post-quantum/src/falcon.ts`.
- DD-16 [DEFERRED]: **Solidity-side `verify()` signature exact shape** — current probe shows `verify(h, salt, s2, ntth)` but the full signature (including any hint field) needs full re-reading of `ZKNOX_falcon_core.sol` + `ZKNOX_HashToPoint.sol` during architecture phase. Related to DD-8 but specifies the exact `_validateSignature` decode path.

## Additional Context

### Vocabulary (load this into context before architecture phase)

| Term | Meaning in this codebase |
|---|---|
| **NIST variant** | The FIPS-204 spec algorithm. Drives `falcon` / `mldsa` signers. Uses SHAKE-128/256 for every XOF role. Keys generated under NIST are NOT interchangeable with ETH keys. |
| **ETH variant** | The ZKNoxHQ gas-optimized variant where every XOF role is swapped for Keccak-CTR-PRNG. Drives `mldsa-eth` (done) and `falcon-eth` (this feature). |
| **Keccak-PRG** | The XOF primitive implemented in `test/signers/keccak-prg.ts`. `createKeccakPrg(seed?); prg.inject(data)*; prg.flip(); prg.extract(n)*`. Lifecycle-guarded (inject-after-flip throws `PrgLifecycleError`). The SOLE XOF primitive on the ETH path. |
| **XofFactory** | `(seed: Uint8Array) => XofReader`. Each scheme/path passes one (or two) factories to the shared core. For ETH paths the factory is `keccakXofFactory`; for NIST it's `shake256XofFactory` / `shake128XofFactory`. |
| **XofReader** | `{ id: "shake128" \| "shake256" \| "keccak-prg"; xof(length: number): Uint8Array }`. The `id` discriminant surfaces in `assertBytesEqual` failure messages as `(factory=<id>)` — useful for grepping when a byte-identity test fails. |
| **Production/KAT split** | Production surface (`{scheme}.ts`) exposes entropy-sourcing keygen + hedged-rnd signUserOp. KAT surface (`{scheme}.kat-internal.ts`) exposes explicit-zeta keygen + explicit-rnd signWithRnd for deterministic tests. Both route through shared `{scheme}.core.ts`. Neither imports the other. |
| **AC-3-7 grep boundary** | Runtime test pattern at `test/signers/ml-dsa-eth.test.ts` that greps `test/signers/index.ts` + `test/bench/**/*.ts` to confirm they NEVER import the `kat-internal` module. A parallel test `test/signers/falcon-eth.test.ts` will enforce the same for falcon-eth. |
| **Oracle chain (DD-11)** | Four implementations in a byte-identity chain: Python ref (truth) ↔ fixture JSON (captured from Python) ↔ TypeScript fork (our code) ↔ Solidity verifier (ZKNoxHQ submodule). Gates G1-G6 check byte-identity at each stage. |
| **G1 / G2 / G3 / G4 / G5 / G6** | Gate labels for the oracle chain. G1 = Keccak-CTR-PRNG primitive byte-identity (single-pass); G2 = HashToPoint byte-identity (≥6 vectors from `HashToPointEVMVectors.t.sol`, Hardhat-generated per DD-25 Option C); G3 = keygen byte-identity; G4 = signer byte-identity; G5 = pk-transform byte-identity; G6 = on-chain validateUserOp. G3–G6 each run over ~100 KAT vectors. |
| **publicKeyPointer** | State variable on `MlDsaEthAccount` / `MlDsaAccount` / `FalconAccount` that stores the 20-byte SSTORE2 pointer returned by `verifier.setKey(encodedPayload)`. NOT the raw public key. `FalconEthAccount` must use this name from day one (lesson from mldsa-eth Story 5 Task 1 / A-006 rename). |
| **A-N amendments** | Amendments to frozen architecture discovered during implementation. See `docs/amendments.md` once new ones land. mldsa-eth produced A-001 through A-006; expect 3-5 new amendments in falcon-eth (Falcon has more moving parts than ML-DSA). |

### Reusable infrastructure (carries over from mldsa-eth — cite in plan phase)

**Already works — extend, don't touch:**

| Path | Purpose | Falcon-eth reuse |
|---|---|---|
| `test/signers/keccak-prg.ts` | Story 2 (mldsa-eth) Keccak-CTR-PRNG primitive. Lifecycle guards, inject/flip/extract, aliases for update/read. | Verify G1 byte-identity against ETHFALCON's `Keccak256PRNG` Python wrapper. If matches, reuse as-is. If not, port a falcon-specific adapter. DD-13. |
| `test/signers/mldsa-encoding.ts` — `keccakXofFactory` | The XofFactory wrapping the Keccak-PRG primitive. | Directly reusable as the XOF for falcon-eth IF DD-13 confirms byte-identity. Same `id: "keccak-prg"` discriminant. |
| `test/utils/assert-bytes.ts` | `assertBytesEqual(actual, expected, label, xofId?)`. Prints first differing byte ±8 bytes of context. | Use verbatim for every falcon-eth KAT assertion. |
| `test/fixtures/kat/index.ts` | KAT JSON loader; `KatVector` type; `loadKatVectors("mldsa-eth" \| "nist-regression")`. Validates submodule SHA pin at import time. | Extend `Scheme` literal to include `"falcon-eth"`; add `falcon-eth/vectors.json` fixture file. Create parallel `FalconKatVector` type (fields differ: Falcon has salt + s2, not cTilde + z + h). |
| `test/signers/errors.ts` | `SignerInputError` with codes (`INVALID_SECRET_KEY_LENGTH`, `INVALID_MESSAGE`, `INVALID_CTX_LENGTH`, `INVALID_RND_LENGTH`). | Reuse; add falcon-specific codes if needed (e.g. `INVALID_NONCE_LENGTH`, `INVALID_SALT_LENGTH`). |
| `scripts/generate-kat-fixtures.ts` | Python-subprocess CLI that captures fixtures. Supports `mldsa-eth` + `nist-regression`. | Extend to a `falcon-eth` scheme target. Swap Python module to `ETHFALCON/pythonref/falcon.py` and use `generate_falcon_test_vectors.py` entry-point. Apply `retrospect/universal.md [2026-04-18]` security rules for test-override env vars (regex-validate, sentinel gates). |
| `test/bench/gas-benchmark.test.ts` | 4-scheme bench harness. `SCHEMES` literal; `deployAccount` branches per scheme; `SCHEMES.length` derivation (AC-5-9 literal-3 prohibition). | Extend to 5 entries. Add `case scheme === "falcon-eth"` branch with `deployFalconEthVerifier` + `FalconEthAccount`. Extend cross-scheme ordering + calldata-delta assertions. |
| `scripts/generate-report.ts` | 4-scheme report renderer. Reads `{ generatedAt, results }` snapshot. AC-5-7 strict determinism (timestamp from snapshot, not `new Date()`). | Extend `SCHEMES` to 5. Same deterministic rendering. |
| `test/signers/index.ts` | Dispatcher. `Scheme = "ecdsa" \| "falcon" \| "mldsa" \| "mldsa-eth"`. Exhaustive-never switches (keygen, signUserOp). | Extend `Scheme` union to add `"falcon-eth"`; add two `case "falcon-eth":` branches. TS's exhaustiveness will flag every missing switch case at compile time. |
| `contracts/imports/DilithiumRef.sol:37` | Artifact-emission wrapper: `contract ZKNOX_ethdilithium is _ZKNOX_ethdilithium {}`. | Mirror in new `contracts/imports/FalconRef.sol` with `contract ZKNOX_ethfalcon is _ZKNOX_ethfalcon {}` so the Solidity compile graph pulls in the verifier. |

**Templates to copy for new files:**

| Source template | Target new file | Notes |
|---|---|---|
| `contracts/MlDsaEthAccount.sol` | `contracts/FalconEthAccount.sol` | 3 swaps: verifier type (`ZKNOX_ethdilithium` → `ZKNOX_ethfalcon`), state-variable name, NatSpec. Use `publicKeyPointer` from day one. Keep `try/catch SignatureMalformed()` + `_VERIFY_SELECTOR` pattern. |
| `test/fixtures/mldsa-eth.ts` | `test/fixtures/falcon-eth.ts` | Swap deployed contract name + fixture factory pair. Falcon pk is simpler (raw NTT coeffs, no aHat matrix) — `preparePublicKeyForDeployment` may need fewer factories. |
| `test/signers/ml-dsa-eth.core.ts` | `test/signers/falcon-eth.core.ts` | Shared core exporting `signWithXof` + `signWithXofInstrumented` (sibling-export pattern for AC-X-5 rejection-counter instrumentation — DD-10 LOCKED means NO module-level XOF state). `HashToPoint` lives here; `ffSampling` if client-side. Keep `@delta-from-falcon` JSDoc mirroring `@delta-from-ml-dsa` convention. |
| `test/signers/ml-dsa-eth.ts` | `test/signers/falcon-eth.ts` | Production surface. `keygen()` with `crypto.getRandomValues`-seeded entropy; `signUserOp(sk, userOp, entryPoint, chainId)`. |
| `test/signers/ml-dsa-eth.kat-internal.ts` | `test/signers/falcon-eth.kat-internal.ts` | KAT surface. `keygenInternal(zeta)` + `signWithRnd(sk, msg, rnd, ctx?)`. Falcon may need `signWithSalt(sk, msg, salt)` depending on its deterministic-test API. Validate sk length with `SignerInputError{code}`. |
| `test/signers/ml-dsa-eth.sign.kat.test.ts` | `test/signers/falcon-eth.sign.kat.test.ts` | G4 KAT test. Instrumented pass for rejection-counter check (HashToPoint has a rejection loop). |
| `test/signers/ml-dsa-eth.sign.test.ts` | `test/signers/falcon-eth.sign.test.ts` | Input-validation + production-path + hedged-sign tests. |
| `test/signers/mldsa-encoding.pk-transform.kat.test.ts` | `test/signers/falcon-encoding.pk-transform.kat.test.ts` | G5 KAT for raw pk → ntt-domain-compacted transform. DD-7 confirms this is required. |
| `test/accounts/mldsa-eth.test.ts` | `test/accounts/falcon-eth.test.ts` | G6 happy path + AC-FLOW-1 end-to-end. Smoke-first (N=5) then tune up at Gate 5 review if runtime allows. |
| `test/accounts/mldsa-eth-failures.test.ts` | `test/accounts/falcon-eth-failures.test.ts` | G6 rejection suite: wrong key, bit-flip, malformed. Walker disambiguation is now 4-contract-strong (`MlDsaAccount` + `FalconAccount` + `MlDsaEthAccount` + `FalconEthAccount` share `SignatureMalformed()` selector `0x2c3c2fe1`) — AND both walker paths with `message.includes(accountAddress)` per AC-X-5 walker lesson. |

**Don't rewrite:**

- `test/signers/ecdsa.ts`, `test/signers/falcon.ts`, `test/signers/ml-dsa.ts` — NIST variants stay verbatim.
- `test/fixtures/mldsa.ts`, `test/fixtures/falcon.ts` — NIST fixtures unchanged.
- `contracts/MlDsaAccount.sol`, `contracts/FalconAccount.sol`, `contracts/MlDsaEthAccount.sol` — untouched.
- `ETHDILITHIUM/`, `ETHFALCON/` submodule sources — NEVER (NFR-5).

### Lessons from mldsa-eth to carry into falcon-eth (avoid these class-of-bug)

Ordered by blast-radius impact:

1. **Python-format vs TS-format fixture divergence** (A-004 equivalent): Python captures `reshapedPublicKey` via `eth_abi.encode(...)` with inner blobs as raw BE concats; TS produces the same numeric data under a different ABI wrapper. Spot-check vec 0's byte length against TS transform output BEFORE writing G5 — if they diverge, pick Option 1 structural-decode up front.
2. **DRBG state advancement between calls** (A-005 equivalent): NIST `AES256_CTR_DRBG.random_bytes` runs `__ctr_drbg_update` at the END of every call. Naively slicing `random_bytes(64)` into `[0:32]` + `[32:64]` ≠ `random_bytes(32); random_bytes(32)`. Before writing G4, extract ONE vector's (sk, msg, salt) triple from the fixture, sign it in the Python ref with those exact inputs, confirm byte-for-byte equality. Catches captured-DRBG-consumption-pattern bugs immediately.
3. **Amendment doc sweep** (universal rule [2026-04-18]): when an amendment lands, `grep -rn 'amendment A-XXX'` across `{scripts, src, test, contracts, docs/stories}` and verify every hit — including TSDoc, Python docstrings in embedded templates, block comments, story examples. Stale docs cause the next maintainer to reintroduce the exact bug the amendment corrected.
4. **Test source-string assertions depend on exact contract text**: if a story renames anything in a production contract, `grep -rn '"{old-name}"' test/` for QUOTED usages, not just property-access usages. Source-string assertions (`source.includes("verify(publicKey, ...)")`) are a real pattern in this codebase.
5. **hintCoder.decode phrasing is load-bearing**: if a shared core has an unreachable-by-design code path (splitCoder parity, unused enum branch), annotate with a `@verify-ignore:reason` JSDoc from day one. Don't wait for the stub-detection grep to flag it. Phrasing constraints live in `.claude/hooks/laim-verify-checks.sh`.
6. **HH3 EDR `tx_gas_limit_cap = 2^24 = 16,777,216 gas`**: bench harness has the workaround baked in (`VERIFICATION_GAS_LIMIT = 15_000_000n`, `TX_GAS_OVERRIDE = 16_777_215n`). Falcon verify is cheaper than ML-DSA (~4M NIST) — probably won't hit, but confirm.
7. **EntryPoint address literal EIP-55 strictness**: viem's `encodeAddress` rejects invalid checksums. Use all-zeros-plus-N (`0x0000000000000000000000000000000000000002`) for dummy addresses, don't hand-type mixed-case.
8. **`gas-data.json` write gated behind `UPDATE_BENCH=1`**: already in place post-mldsa-eth Story 5. Routine test runs leave snapshot alone; refresh via `npm run bench:update`.
9. **Story file checkbox commits**: commit story file with `status: ready-for-dev` during Task 1, then tick each checkbox in the task's own commit (preserves per-commit progression trace in git).
10. **Bench ordering assertion extension**: when extending SCHEMES to 5, extend every cross-scheme assertion — ordering, destructure, calldata comparisons. Use `byScheme.get(...)` name-based lookup instead of position destructure.
11. **AC-X-5 walker's canonical path must bind to account address**: with `FalconEthAccount` as the 4th contract declaring `SignatureMalformed()`, AND both walker paths with `message.includes(accountAddress)` to prevent spurious pass if test-setup routes to wrong account contract.
12. **Code-review-agent truncation**: budget one `SendMessage` resume per review. Resume prompt pattern: "Your previous turn ended mid-investigation. Please complete the review now — no further investigation, deliver final output as a markdown table of findings + a Confidence Statement if findings < 3."

### Suggested story decomposition (for architecture/plan phase consideration)

| # | Slug | Size | Focus | Depends on |
|---|------|------|-------|-----------|
| 1 | `falcon-eth-fixtures` | M | Extend `scripts/generate-kat-fixtures.ts` to produce `falcon-eth/vectors.json`; extend loader + types; capture ~100 vectors. DD-14. | none |
| 2 | `keccak-prg-verification` | S-M | G1: verify `keccakXofFactory` matches ETHFALCON's `Keccak256PRNG` byte-for-byte. If divergent, port adapter. DD-13. | Story 1 |
| 3 | `hash-to-point + keygen port` | M-L | Port ETHFALCON keygen + HashToPoint to TS with XOF-factory abstraction. G3 KAT. | Stories 1, 2 |
| 4 | `signer port + G4 KAT` | L | Port Falcon sign (including `ffSampling` if client-side) to TS. G4 KAT over ~100 vectors. Production + KAT surfaces. | Stories 1, 2, 3 |
| 5 | `integration + benchmark` | L | `FalconEthAccount.sol` + `test/fixtures/falcon-eth.ts` + G5 + G6 + extend SCHEMES to 5 + refresh snapshots + README. | Stories 1, 2, 3, 4 |

Mirrors mldsa-eth's plan structure. If Story 2 concludes "Keccak-PRG matches, nothing to do", merge into Story 3 → 4-story plan. Architecture phase to confirm.

### Pre-kickoff probe results (ran at /research time)

- **ETHFALCON KAT corpus**: `ETHFALCON/pythonref/assets/` does not exist (unlike ETHDILITHIUM's pre-populated `.rsp` file). `generate_falcon_test_vectors.py` exists and produces vectors on-demand.
- **ETHFALCON submodule pin**: `03ed0d60c67087527de7c4a3c1c469b89611bd68` at `heads/main`.
- **Keccak-PRG wrapper divergence**: ETHFALCON's class is `Keccak256PRNG(a=None, b=None)`; ETHDILITHIUM's is `KeccakPRNG()`. ETHFALCON's file header declares it as the upstream origin ("This file is copied from ETHFALCON"). Internal mechanics likely byte-identical but wrappers require G1 verification.
- **noble-post-quantum Falcon**: `@noble/post-quantum/falcon` submodule exists (`node_modules/@noble/post-quantum/falcon.{js,d.ts}`) → can leverage as NIST-side reference, mirroring how mldsa-eth used `ml_dsa44`.
- **`ZKNOX_ethfalcon.setKey()` transform**: raw `SSTORE2.write(pubkey)`, no on-chain transform. `CheckParameters` expects `ntth` (ntt-domain compacted, `falcon_S256 = 32 × uint256 = 1024 bytes`). TS `preparePublicKeyForDeployment` must produce this shape before calling setKey. G5 applies.
- **Solidity verifier boundary**: `verify()` per `ZKNOX_ethfalcon.sol:28-34` expects `(hash, salt[40], s2[32 × u256], ntth[32 × u256])`. Signature ABI (DD-8) = `salt || s2_compact = 40 + 1024 = 1064 bytes`.
- **Epervier present but out of scope**: `ZKNOX_epervier.sol`, `ZKNOX_ethepervier.sol`, `falcon_epervier.py` exist (different account arch — `recover()` flow, no `publicKeyPointer`). Deferred — would be a future feature reusing ~80% of falcon-eth's work.
- **Baseline test state**: `npx hardhat test` → 97 passing, zero failures.
- **Solidity compile graph**: no existing `contracts/imports/FalconRef.sol` — Story 5 (or earlier, depending on when verifier is first deployed) adds one mirroring `DilithiumRef.sol:37`.

### Operational tips from mldsa-eth process

- **Commit one task per commit**; use `git add {specific-files}` not `git add .` or `-A`.
- **Story file tracked from Task 1** (corrective lesson §5.9) — commit with `status: ready-for-dev`, tick checkboxes per commit.
- **`npx hardhat test`** is the final regression word (~30s for current 97 tests, higher post-falcon-eth).
- **`npm run compile`** is the Solidity build with warnings-as-errors via `scripts/check-compile-warnings.cjs`.
- **Resume protocol**: `docs/.lock` is session marker; stale (>4h) triggers takeover; always re-read `docs/stories/{id}-{slug}.md` from disk on resume (implement skill's task compaction strips earlier task detail).
- **Amendments** go in `docs/amendments.md`, one entry per Rule-3+ deviation. Template: `## A-NNN: title` + Story/Task/Date/Classification/Affects/Original/Actual/Rationale/Resolution sections.
- **Code review at end of every story**: spawn `code-review-agent` via Task tool with ONLY story file + `git diff pre-{feature}-{N}..HEAD` + state.json. Adversarial, zero implementation context. Expect ≤5 findings per story.
- **Bench/report snapshot refresh**: `UPDATE_BENCH=1 npx hardhat test test/bench/gas-benchmark.test.ts && npm run report && git add test/bench/gas-data.json docs/gas-report.md {code-files} && git commit`.
- **N=5 smoke-first for on-chain KAT loops**: land at `VECTOR_COUNT = 5`, tune up to 100 at Gate 5 review if budget allows. Saves 35-55s per failed iteration during initial development.

### Archived mldsa-eth references

`docs/.archive-mldsa-eth/{research,spec,architecture,plan,sprint-status,amendments,concerns}.md` + `stories/{1..5}-*.md`. Re-read these as the architecture phase's primary structural reference alongside this document and `docs/user-context/falcon-eth.md`.
