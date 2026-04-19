---
status: complete
created: 2026-04-18
completed: 2026-04-19
feature: falcon-eth
phase: 3
brief: docs/research.md
spec: docs/spec.md
---

# Architecture: Falcon-ETH — Keccak-CTR-PRNG Falcon-512 for ERC-4337

## Goals & Constraints

**Drivers (from spec):** byte-compatibility with ETHFALCON Python reference across G1–G6 (NFR-3, AC-FR-11..15), zero submodule modification (NFR-1, AC-NFR-1), submodule-SHA oracle that resolves per fixture (AC-A-1 HIGH — loader must probe both `ETHFALCON` and `ETHDILITHIUM` HEADs), XOF isolation across NIST and ETH paths in one process (NFR-6, AC-A-5 extending the existing xof-lifecycle grep glob), 5-scheme dispatcher symmetry without literal-`=== 5` constants (NFR-11, AC-A-2), calldata-delta assertion asymmetry between mldsa-pair and falcon-pair (AC-A-3), discriminated-overload `loadKatVectors` returning per-scheme typed arrays (AC-D-1 HIGH), table-driven grep gates across 5+ schemes (AC-D-2), structural `@delta-from-falcon` module-header assertion with stray-`ml-dsa` substring guard (AC-D-3), naming-consistency mapping + snake-case `falcon_eth` prohibition (AC-D-4).

**Non-negotiable boundaries:** ETHFALCON submodule is external — no re-authoring or auditing its Solidity. Falcon-512 parameters are fixed (n=512, q=12289, sig_bound=34034726). The only XOF substitution point is Keccak-CTR-PRNG (DD-1 LOCKED). Archived `mldsa-eth` artifacts under `docs/.archive-mldsa-eth/` are frozen (precedent source, not editable). NIST-variant signers (`ecdsa.ts`, `falcon.ts`, `ml-dsa.ts`) and existing account contracts (`MlDsaAccount.sol`, `FalconAccount.sol`, `MlDsaEthAccount.sol`) are verbatim — falcon-eth is purely additive.

## Component Decomposition

| Component | Responsibility | Module / File | Dependencies |
|---|---|---|---|
| `FalconEthAccount.sol` | ERC-4337 account delegating signature verification to ZKNOX_ethfalcon. Stores 20-byte SSTORE2 pointer via `publicKeyPointer`. | `contracts/FalconEthAccount.sol` (new) | `SimpleAccount`, `ISigVerifier`, `_VERIFY_SELECTOR` |
| ZKNOX verifier (external) | On-chain Falcon-ETH signature verification with Keccak-PRG-based HashToPoint | `ETHFALCON/src/ZKNOX_ethfalcon.sol` (submodule, pinned at `03ed0d60c6...`) | `ZKNOX_falcon_core.sol`, `ZKNOX_HashToPoint.sol`, `SSTORE2` |
| Compile-graph wrapper | Artifact-emission shim so Hardhat emits `ZKNOX_ethfalcon` artifact — **already exists** in `contracts/imports/FalconRef.sol` from mldsa-eth era. **Extended this feature** with a `ZKNOX_HashToPointExposed` contract that exposes the free function `hashToPointEVM(salt, msgHash)` as an external-callable method, so the Hardhat-driven G2 fixture generator (DD-25 Option C) can call on-chain HashToPoint directly. ~10 LOC addition; no new file. | `contracts/imports/FalconRef.sol` (extended) | ETHFALCON submodule source |
| JS signer (production surface) | Hedged keygen + sign over a userOp hash under Falcon-ETH. Exposes `keygen(): Keypair` and `signUserOp(sk, userOp, entryPoint, chainId)` with fresh entropy via `crypto.getRandomValues`. | `test/signers/falcon-eth.ts` (new) | `falcon-eth.core.ts`, `keccak-prg.ts`, `mldsa-encoding.ts` (shared `keccakXofFactory`) |
| JS signer (KAT surface) | Deterministic keygen + sign with explicit seed/salt for byte-identity tests. Imported ONLY by G3 (keygen) + G4 (signer) byte-identity test files. Grep-boundary enforced by AC-3-7. | `test/signers/falcon-eth.kat-internal.ts` (new) | `falcon-eth.core.ts` |
| Falcon-ETH shared core | Forked math from `@noble/post-quantum/src/falcon.ts` — reuses `ffSampling`, `splitFFT`, `mergeFFT`, NTT, `Float`, `BNORM_MAX`, `SIGMA_MIN`, `INV_SIGMA`, `COMPLEX_ROOTS` verbatim. Forks `HashToPoint` and sampler classes to accept an `XofFactory` (DD-10). Exposes `signWithXof(sk, msg, salt, xofFactory)` + `signWithXofInstrumented(...)` (sibling export per C-8, no module-level XOF state). Module header carries `@delta-from-falcon` JSDoc enumerating byte-level differences from NIST (AC-D-3). | `test/signers/falcon-eth.core.ts` (new) | `@noble/post-quantum/src/falcon.ts` (source copy of math-only subset), `@noble/curves/abstract/fft.js`, `keccak-prg.ts` |
| Keccak-CTR-PRNG primitive | **Reused as-is from mldsa-eth.** Stateful `inject`/`flip`/`extract` construction. Lifecycle guards (inject-after-flip throws `PrgLifecycleError`). Byte-compatibility with ETHFALCON's `Keccak256PRNG(a, b)` must be verified by **G1** per DD-13 before trusting for G3 (keygen) / G4 (signer) / G5 (pk-transform). | `test/signers/keccak-prg.ts` (existing, unchanged) | viem `keccak256` |
| HashToPoint primitive (shared core export) | **Adapter on top of the Keccak-CTR-PRNG primitive.** Ports ETHFALCON's EVM-optimized `hashToPointEVM(salt, msg)` construction: `state = keccak256(salt‖msg)` (single-shot absorb — equivalent to `inject(salt); inject(msg); flip()` on the PRG), then loop `keccak256(state‖counter_u64)` producing the same counter-mode stream the PRG's `extract()` produces. On top of that stream, HashToPoint-specific logic: parse 2-byte chunks big-endian, reject `≥ kq=61445`, accepted chunk `mod q=12289`, collect 512 coefficients. **Implementation can reuse `keccak-prg.ts` internally** or inline the counter loop — both produce identical output because the underlying primitive is the same. Pure function: same `(salt, msg)` → same 512-coefficient polynomial. Consumed by signer + verifier. G2 validates the HashToPoint-specific parameters (absorb order, chunk endianness, rejection threshold, mod-q, coefficient-order) independently of G1's XOF-primitive verification. | `test/signers/falcon-eth.core.ts` exports `hashToPointEVM(salt, msg): Uint16Array(512)` or equivalent typed output | viem `keccak256`, optionally `keccak-prg.ts` |
| XOF factory (Keccak variant) | **Reused as-is from mldsa-eth.** `keccakXofFactory: (seed) => XofReader` with `id: "keccak-prg"` discriminant. Called at every falcon-eth call-site; never stored in module-level state. | `test/signers/mldsa-encoding.ts:keccakXofFactory` (existing, unchanged) | `keccak-prg.ts` |
| pk-transform (public + internal) | **Public (NFR-11 parity with mldsa-eth):** `preparePublicKeyForDeployment(rawPk, xofFactory): Hex` — same naming + same return-type convention as `test/signers/mldsa-encoding.ts:preparePublicKeyForDeployment`. Returns already-abi-encoded bytes (`Hex = \`0x${string}\`` per viem) directly passable to `verifier.setKey()`. **Internal/test helper:** `pkToNttCompact(rawPk, xofFactory): bigint[]` — returns the intermediate NTT-compact array (length 32, each element a `bigint` for one `uint256` word — 16 Falcon coefficients × 16 bits per word). Exposed for G5's structural test + debugging (mirrors mldsa-eth's `compactModule256` precedent). `preparePublicKeyForDeployment` composes: `encodeAbiParameters([{type:"uint256[]"}], [pkToNttCompact(rawPk, xof)])`. | `test/signers/falcon-eth.core.ts` exports both | viem (`encodeAbiParameters`, `Hex`), shared NTT primitives |
| Fixture-gen CLI extension | Extends existing `scripts/generate-kat-fixtures.ts` with `scheme === "falcon-eth"` target. **Parses the pre-existing NIST-standard `.rsp` corpus at `ETHFALCON/test/ethfalcon512-KAT.rsp` (100 vectors — DD-14 resolved this phase)** using the same `.rsp` parser pattern mldsa-eth already ships. For each `count`: extracts `(seed, msg, pk, sk, sm)`, derives `sig = sm[:-mlen]`, replays `AES256_CTR_DRBG(seed).random_bytes(N)` for any keygen/sign entropy the Python ref consumes, spawns one `python3 -c "..."` to compute `reshapedPk` via `pk_for_eth`-equivalent transform (NTT-compact + abi.encode). Writes `test/fixtures/kat/falcon-eth/vectors.json` with embedded `submoduleSha` + `submoduleSource: "ethfalcon"` discriminator (AC-A-1). Env-var overrides regex-validated + sentinel-gated (AC-NFR-9). | `scripts/generate-kat-fixtures.ts` (modified) | child_process, `.rsp` parser (reused from mldsa-eth Story 1), regex validator, `ALLOW_TEST_OVERRIDES` sentinel |
| KAT loader (multi-submodule) | Extends `test/fixtures/kat/index.ts` to probe BOTH `ETHDILITHIUM` and `ETHFALCON` submodule HEADs. Each fixture declares `submoduleSource: "ethfalcon" \| "ethdilithium"`; SHA-mismatch check resolves the correct submodule per fixture. Discriminated overload: `loadKatVectors("mldsa-eth"): MlDsaEthKatVector[]`, `loadKatVectors("falcon-eth"): FalconKatVector[]`. Legacy `KatVector` renamed to `MlDsaEthKatVector` in the same commit — no aliased re-export (AC-D-1). | `test/fixtures/kat/index.ts` (refactored) | node:child_process (`git submodule status`), node:fs |
| Signer dispatcher | Extends `Scheme` union from 4 to 5. Two exhaustive-never switches (keygen, signUserOp) with added `case "falcon-eth":` branches. TS catches missing cases at compile time. | `test/signers/index.ts` (modified) | per-scheme signer modules |
| Per-scheme deployer registry | `SCHEME_DEPLOYERS: Record<Scheme, Deployer>` — compile-time exhaustive registry for `deployAccount` in the bench harness (AC-A-2). Replaces the inline if-cascade. Each signer module exports its deployer fn collocated. Adding falcon-eth adds 1 registry entry + 1 collocated deployer fn; no `deployAccount` body edit. | `test/signers/deployers.ts` (new — extracted from `gas-benchmark.test.ts`) OR `test/signers/{scheme}.deployer.ts` siblings | `Scheme` type, per-scheme fixture modules |
| Bench harness | 5-scheme gas measurement, `SCHEMES.length` derivation everywhere, per-scheme failure isolation, calldata orderings enforced (ecdsa < falcon == falconEth < mldsa == mldsaEth BY LENGTH), within-pair 5% bound ONLY for mldsa pair, falcon-pair uses 25% looser bound (AC-A-3). Snapshot-refresh gated by `UPDATE_BENCH=1`. Surfaces labeled `mldsa-eth ↔ falcon-eth` pairwise delta row (AC-U-1). | `test/bench/gas-benchmark.test.ts` (modified) | `SCHEMES` const, deployer registry |
| Report generator | 5-scheme report renderer, strict determinism (timestamp from snapshot, not `new Date()`), explicit delta section for mldsa-eth ↔ falcon-eth pair. | `scripts/generate-report.ts` (modified) | bench snapshot JSON |
| Falcon fixtures wrapper | Test fixture factory `test/fixtures/falcon-eth.ts` deploying a fresh `ZKNOX_ethfalcon` verifier + `FalconEthAccount` per test instance (DD-9 per-account verifier). `preparePublicKeyForDeployment(rawPk, keccakXofFactory)` → `abi.encode(uint256[32])` → `setKey(encodedPayload)` → 20-byte SSTORE2 pointer stored as `publicKeyPointer`. | `test/fixtures/falcon-eth.ts` (new) | `FalconEthAccount`, `ZKNOX_ethfalcon`, viem |

**Boundaries:**
- `falcon-eth.core.ts` is ONLY imported by `falcon-eth.ts` (production) and `falcon-eth.kat-internal.ts` (KAT). Neither imports the other. Grep boundary at AC-3-7.
- `XofFactory` is passed as a **function parameter at every call-site** — no module-level mutable state. AC-A-5 extends the existing xof-lifecycle grep glob (`^(let|var) _?xof`) to `test/signers/{mldsa,falcon}-eth*.ts`.
- Python code lives exclusively under `ETHFALCON/pythonref/` (submodule). NFR-9 sentinel + regex gate applies.
- No new wrapper file under `contracts/imports/` — `FalconRef.sol` already exposes `ZKNOX_ethfalcon` from mldsa-eth era. Feature **extends** it with `ZKNOX_HashToPointExposed` (~10 LOC) for DD-25 Option C fresh-generation (AC-A-4).

## Data Models

Crypto types + fixture schemas only — no database entities.

### `Scheme` union + `SCHEMES` const (extended from 4 to 5 per DD-9)
```ts
// test/signers/schemes.ts
export type Scheme = "ecdsa" | "falcon" | "mldsa" | "mldsa-eth" | "falcon-eth";
export const SCHEMES = ["ecdsa", "falcon", "mldsa", "mldsa-eth", "falcon-eth"] as const
  satisfies readonly Scheme[];
```

### Falcon-ETH signature payload at Solidity boundary (DD-8 LOCKED)
```
Uint8Array([
  salt:  40 bytes,
  s2:    32 uint256s * 32 bytes = 1024 bytes (big-endian, sequentially packed)
]) // total 1064 bytes
```
No framing, no abi.encode wrapper at the signature level. The 3-arg boundary `verify(bytes pk, bytes32 m, bytes sig)` reads bytes directly via inline assembly (confirmed at `ETHFALCON/src/ZKNOX_ethfalcon.sol:79-130`). TS signer emits this layout verbatim from `signWithXof`.

### Falcon-ETH public-key reshape (DD-7 refined this phase)
Raw Falcon-512 public key: **897 bytes** (header byte + 896 encoded coefficient bytes) — consumed by `preparePublicKeyForDeployment`.

Transform chain:
1. `pkToNttCompact(rawPk, keccakXofFactory): bigint[]` — internal/test helper returning `bigint[]` of length 32, each element a `bigint` for one `uint256` word. NTT-domain polynomial (512 coefficients) compacted into 32 words (16 coefficients × 16 bits per word). Driven by XofFactory (shared with keygen per DD-1). Consumed directly by G5's structural test when fine-grained debugging is needed.
2. `preparePublicKeyForDeployment(rawPk, xofFactory): Hex` — **public surface, mirrors mldsa-eth's `preparePublicKeyForDeployment` shape exactly (NFR-11 cross-scheme symmetry)**. Composes `encodeAbiParameters([{type:"uint256[]"}], [pkToNttCompact(rawPk, xofFactory)])` internally and returns already-abi-encoded viem `Hex`. Caller pattern is identical to mldsa-eth: `const payload = preparePublicKeyForDeployment(rawPk, factory); await verifier.write.setKey([payload]);`. This refinement addresses DD-16's insight that `SSTORE2.read` inside the verifier does `abi.decode(..., (uint256[]))`, so `setKey` expects the ABI-encoded `uint256[]` form; Solidity ABI type `uint256[]` ↔ TS `bigint[]` is viem's standard mapping.
3. `verifier.setKey(encoded) → bytes` — returns 20-byte `abi.encodePacked(address)` of SSTORE2 pointer.
4. `publicKeyPointer = setKeyResult` — Account stores the pointer bytes directly, not decoded.

### KAT fixture JSON — Falcon-ETH (DD-7 new, DD-14 flipped this phase)
Location: `test/fixtures/kat/falcon-eth/vectors.json`
Source: transcribed from `ETHFALCON/test/ethfalcon512-KAT.rsp` (100 canonical NIST-format vectors — pre-existing).

```jsonc
{
  "scheme": "falcon-eth",
  "params": "falcon-512-keccak",
  "submoduleSource": "ethfalcon",       // AC-A-1 discriminator
  "submoduleSha": "<40-hex>",            // ETHFALCON HEAD at capture time
  "generatedAt": "<ISO 8601>",
  "source": {
    "rspFile": "ETHFALCON/test/ethfalcon512-KAT.rsp",
    "drbgDerivation": "AES256_CTR_DRBG(drbgSeed).random_bytes(N) — N TBD by Python-ref audit (PRE_G4_DRBG_PROBE)",
    "ctx": "0x"                          // empty — matches ETHFALCON ref default
  },
  "vectors": [
    {
      "id":                "vec-000",
      "drbgSeed":          "0x…(48B)",   // NIST AES256_CTR_DRBG seed — audit trail + replay input
      "publicKey":         "0x…(897B)",  // G3 expected + G5 input
      "secretKey":         "0x…",        // G3 expected + G4 input
      "reshapedPublicKey": "0x…",        // G5 expected (= abi.encode(uint256[32])) + G6 setKey input
      "message":           "0x…",        // G4 input (+ G2 input if reused for HashToPoint cross-check)
      "signature":         "0x…(1064B)"  // G4 expected + G6 input (salt(40) || s2_compact(1024) concat, extracted as sm[:-mlen])
    }
  ]
}
```

Hex-encoded with `0x` prefix. `reshapedPublicKey` is pre-`abi.encode`d (G3 asserts this byte layout directly). `signature` is raw `salt || s2` concat (not abi-encoded); extracted at fixture-gen time from `.rsp` via `sig = sm[:-mlen]`. `drbgSeed` retained in fixture for independent audit — anyone can re-derive downstream entropy by running the same DRBG. **Salt is embedded inside the 1064-byte signature at offset 0..40** — not a separate top-level field (contrast with my earlier draft that proposed a separate `salt` field; the `.rsp` doesn't expose salt separately because the `sm` field packs it inside the signature). Mldsa-eth A-005 DRBG-state-advancement lesson DOES apply — `AES256_CTR_DRBG.random_bytes(N)` runs `__ctr_drbg_update` at the END of every call, so naive slicing of a single `random_bytes(64)` ≠ two `random_bytes(32)` calls. PRE_G4_DRBG_PROBE audit is load-bearing.

### KAT fixture JSON — HashToPoint (new — DD-25 G2 gate, fresh-generated per DD-25 Option C)
Location: `test/fixtures/kat/falcon-eth/hashtopoint-vectors.json`
Source: **generated fresh by deploying `ZKNOX_HashToPointExposed` in Hardhat and calling `.compute(salt, msg)` on the pinned on-chain implementation** — NOT transcribed from literal arrays. This makes the trust anchor the current pinned `ZKNOX_HashToPoint.sol` itself; transcription-layer bugs are eliminated by construction, and a submodule-SHA bump forces regeneration.

```jsonc
{
  "scheme": "falcon-eth",
  "gate": "G2-hashtopoint",
  "submoduleSource": "ethfalcon",
  "submoduleSha": "<40-hex>",
  "generatedAt": "<ISO 8601>",
  "source": {
    "solContract": "ZKNOX_HashToPointExposed",
    "solFile": "contracts/imports/FalconRef.sol",
    "upstreamFile": "ETHFALCON/src/ZKNOX_HashToPoint.sol",
    "algorithm": "keccak256(salt‖msg) then keccak256(state‖counter_u64) with 16-bit rejection at kq=61445, mod q=12289, n=512",
    "generator": "scripts/generate-kat-fixtures.ts --scheme falcon-eth --target hashtopoint"
  },
  "vectors": [
    {
      "id":            "vec-000",
      "salt":          "0x…(40B hex)",             // chosen by generator (fixed or seeded)
      "message":       "0x…(variable)",
      "expectedHash":  [<512 uint16 coefficients>]  // captured from ZKNOX_HashToPointExposed.compute()
    }
    // ... N more vectors (≥6 minimum, parameterizable)
  ]
}
```

Generation task (Story 1 Task 1b — **replaces the earlier "parse .t.sol literals" plan**):
1. Extend `FalconRef.sol` with a `ZKNOX_HashToPointExposed { function compute(bytes salt, bytes msg) external pure returns (uint256[] memory) { return hashToPointEVM(salt, msg); } }` contract (~10 LOC).
2. Extend `scripts/generate-kat-fixtures.ts` with a `--target hashtopoint` branch that: deploys `ZKNOX_HashToPointExposed` in Hardhat, picks N `(salt, msg)` pairs (hardcoded test corpus OR seeded from a fixed deterministic source), calls `.compute()` for each, captures the 512-uint16 output, emits JSON with `submoduleSource: "ethfalcon"` + `submoduleSha` at generation time.
3. Fixture refresh is automatic: any submodule SHA bump that changes `ZKNOX_HashToPoint.sol` invalidates AC-A-1 pin probe, forcing re-run of the generator → fresh JSON captured against the new Solidity → G2 test re-runs against the refreshed JSON. No "did we remember to regenerate?" gap.

### KAT fixture JSON — ML-DSA-ETH (legacy — LOCKED from mldsa-eth, extended with `submoduleSource`)
Existing `test/fixtures/kat/mldsa-eth/vectors.json` gets an added `"submoduleSource": "ethdilithium"` field in the same commit that lands AC-A-1's multi-submodule loader. Fixture-gen CLI writes this field for both schemes going forward.

### TypeScript vector types (AC-D-1 HIGH)
```ts
// test/fixtures/kat/index.ts
export interface MlDsaEthKatVector {            // RENAMED from KatVector (no re-export alias)
  readonly id: string;
  readonly drbgSeed: `0x${string}`;
  readonly zeta: `0x${string}`;
  readonly rnd: `0x${string}`;
  readonly publicKey: `0x${string}`;
  readonly secretKey: `0x${string}`;
  readonly reshapedPublicKey: `0x${string}`;
  readonly message: `0x${string}`;
  readonly signature: `0x${string}`;
}

export interface FalconKatVector {
  readonly id: string;
  readonly seed: `0x${string}`;
  readonly publicKey: `0x${string}`;     // 897 bytes raw
  readonly secretKey: `0x${string}`;
  readonly reshapedPublicKey: `0x${string}`;  // abi.encode(uint256[32])
  readonly message: `0x${string}`;
  readonly salt: `0x${string}`;          // 40 bytes
  readonly signature: `0x${string}`;     // 1064 bytes (salt || s2_compact)
}

// Discriminated overload — tsc fails on cross-scheme field access
export function loadKatVectors(scheme: "mldsa-eth"): MlDsaEthKatVector[];
export function loadKatVectors(scheme: "falcon-eth"): FalconKatVector[];
```

### Naming table (AC-D-4)
| Form | Casing | Where used |
|---|---|---|
| `falcon-eth` | kebab-case | File paths, `Scheme` literal, fixture directory, CLI target name |
| `falconEth` | camelCase | TS identifier names (`deployFalconEth`, `falconEthVerifier`) |
| `FalconEthAccount`, `FalconEthFixture` | PascalCase | Solidity contract name, TS type aliases |
| `Falcon512_ETH` | docstring/attribution | NatSpec comments, README attribution strings |
| `falcon_eth` | **PROHIBITED** (snake_case) | Forbidden — unit test greps `src/ test/ contracts/ scripts/` and fails on any hit |

## Key Workflows

**UC-1 — Sign & verify Falcon-ETH user-op (happy path).** Engineer calls `keygen("falcon-eth")` via dispatcher → `{ publicKey, secretKey }`. `publicKey` passed to `preparePublicKeyForDeployment(rawPk, keccakXofFactory)` → returns already-abi-encoded `Hex` payload (internal: `pkToNttCompact` → `encodeAbiParameters(["uint256[]"], [...])`) → `setKey(payload)` → 20-byte pointer → stored as `publicKeyPointer` at `FalconEthAccount.initialize`. Same call pattern as mldsa-eth. Engineer calls `signUserOp("falcon-eth", sk, userOp, entryPoint, chainId)` → computes userOpHash (shared `userOpHash.ts`) → core `signWithXof(sk, msg, freshSalt, keccakXofFactory)` → emits 1064-byte `salt || s2_compact`. EntryPoint → `account.validateUserOp` → `_validateSignature` → `verifier.verify(publicKeyPointer, userOpHash, sig)` → `bytes4` selector → `SIG_VALIDATION_SUCCESS`.

**UC-2 — Regenerate Falcon-ETH KAT fixtures.** Engineer runs `npm run kat:regen -- --scheme falcon-eth`. CLI (a) validates any test-override env vars against their regex patterns (fails on malformed), (b) checks `ALLOW_TEST_OVERRIDES=1` sentinel is set if any overrides present, (c) reads pinned submodule SHA from `.gitmodules`, checks `ETHFALCON` HEAD matches pin, (d) **parses `ETHFALCON/test/ethfalcon512-KAT.rsp` line-by-line** using the existing NIST-`.rsp` parser from mldsa-eth's Story 1 Task 3 (same format — `count`/`seed`/`mlen`/`msg`/`pk`/`sk`/`smlen`/`sm` blocks separated by blank lines). For each `count`: extract `(drbgSeed, msg, pk, sk, sm)`; derive `sig = sm[:-mlen]`; (e) spawns ONE `python3 -c "..."` importing `falcon` + `keccak_prng` + `encoding` from `ETHFALCON/pythonref/` that takes the parsed 100 `pk` arrays on stdin and emits 100 `reshapedPk` byte-strings on stdout via `abi.encode([uint256[32]], [falcon_compact(Poly(pk, q).ntt())])`. (f) Writes `test/fixtures/kat/falcon-eth/vectors.json` with `submoduleSource: "ethfalcon"` + `submoduleSha` embedded + 100 vectors. Python invoked ONCE (batched over all 100 vectors) at fixture-gen time only — never at `npm test`. Total runtime: seconds (no live keygen needed, `.rsp` already has precomputed (pk, sk, sig) pairs).

**UC-3 — Oracle chain (G1–G6) byte-identity verification.** Porting chain `PRG → HashToPoint → keygen → signer → pk-transform → verifier`; each gate anchors the next. KAT suite loads fixtures via `loadKatVectors("falcon-eth"): FalconKatVector[]` (signing vectors) and `loadHashToPointVectors(): HashToPointVector[]` (G2 corpus); multi-submodule loader asserts `submoduleSource === "ethfalcon"` → probes `ETHFALCON` HEAD (AC-A-1).

- **G1 (Keccak-PRG byte-identity vs ETHFALCON `Keccak256PRNG`):** Fresh `KeccakPrg` per vector; scripted `inject`/`flip`/`extract` → compare vs captured Python ref output for ETHFALCON's wrapper. Single-pass primitive gate (not a ≥100-vector corpus). If byte-identical to mldsa-eth's keccak stream, DD-13 is satisfied; if divergent, falcon-eth ports a `falconKeccakXofFactory` (Story 2 scope-expand).
- **G2 (HashToPoint byte-identity vs ETHFALCON `hashToPointEVM`):** For each of 6 vectors in `hashtopoint-vectors.json`: `hashToPointEVM(salt, msg) === expectedHash` (512 uint16 coefficients). Same counter-mode Keccak stream as G1's primitive — HashToPoint is an adapter (single-shot absorb `keccak256(salt‖msg)` + rejection-sampled 2-byte chunk consumer). Isolates bugs in the HashToPoint-specific parameters: (a) salt‖msg absorb order (not msg‖salt), (b) 16-bit chunk extraction endianness (big-endian `(b[0]<<8)|b[1]`), (c) rejection threshold `< kq=61445`, (d) mod-q reduction `% 12289`, (e) coefficient fill order + count. A G2 red with G1 green localizes to this adapter, not the underlying keccak primitive. **G2 is cheap insurance** — 6 vectors × 512 coefficients × equality check is ~20-LOC test, catches the exact class of bug that bit mldsa-eth's SampleInBall port (wrong chunk-endianness, off-by-one rejection threshold, etc.).
- **G3 (Falcon-ETH keygen byte-identity):** `keygenInternal(drbgSeed)` → assert `(pk, sk)` vs `.rsp` per vector. Uses G1-verified XOF. ≥100 vectors from `ethfalcon512-KAT.rsp`.
- **G4 (Falcon-ETH signer byte-identity):** `signWithDrbgRnd(sk, msg, drbgSeed)` (KAT surface) → assert 1064-byte `salt || s2` vs `.rsp` `sm[:-mlen]` per vector. Uses G1-verified XOF + G2-verified HashToPoint + G3-verified sk. ≥100 vectors.
- **G5 (pk-transform byte-identity):** Primary — `preparePublicKeyForDeployment(rawPk, keccakXofFactory)` returns `Hex`; assert byte-equality vs fixture `reshapedPublicKey` (also `Hex`). Structural sub-check — `pkToNttCompact(rawPk, keccakXofFactory)` returns `bigint[]` of length 32 for every vector (debug anchor if `Hex` comparison fails). Uses G1-verified XOF + G3-verified pk. ≥100 vectors. **Pk-format divergence probe (lesson 5.1 carry-over):** spot-check vec 0's `reshapedPublicKey.length` against TS output length BEFORE writing the G5 test; if formats diverge, pick structural-decode oracle up front (`test/signers/mldsa-encoding.pk-transform.kat.test.ts` ~200 LOC template).
- **G6 (verifier integration):** Deploy `ZKNOX_ethfalcon` + `FalconEthAccount` via `test/fixtures/falcon-eth.ts`; submit `(publicKeyPointer, userOpHash, signature)` via `validateUserOp`. Composes G1–G5. Rejection classes: wrong-key, bit-flip (target salt byte vs s2 byte for coverage), malformed (zero-byte blob). Walker binds to `accountAddress.toLowerCase()` on BOTH canonical path (`ContractFunctionRevertedError.errorName === "SignatureMalformed"`) AND HH3 EDR message-regex fallback path — per AC-X-5 lesson 5.11. N=5 smoke at landing; tune to 100 by Gate 5.

**Corpus sizes:** G1 is a single-pass XOF primitive check; G2 is ≥6 vectors (ETHFALCON's upstream `HashToPointEVMVectors` corpus via DD-25 Option C fresh-gen); G3–G6 each run over ≥100 vectors per NFR-3. G6 may land at smoke N=5 and tune to 100 at Story 5 Gate 5 per NFR-3.

**UC-4 — 5-scheme benchmark.** Bench iterates `SCHEMES` (5 entries). `deployAccount` uses `SCHEME_DEPLOYERS[scheme]` registry lookup (AC-A-2); no inline branches. Each iteration try/catch-isolated; failed rows record `{scheme, status: "failed", reason}` and continue. Calldata assertions (AC-A-3):
- Length ordering: `ecdsa < falcon == falconEth < mldsa == mldsaEth` (falcon + falcon-eth share 1064 B; mldsa + mldsa-eth share 2420 B).
- Within-pair gas equivalence @ 5% ONLY for `(mldsa, mldsa-eth)`.
- `(falcon, falcon-eth)` asserts equal length + 25% calldata-gas bound (rationale inline: NTT-compact vs Algorithm-17-compress distributions differ).
`results.length === SCHEMES.length` guard (no literal 5). Snapshot write gated by `UPDATE_BENCH=1`. Report renderer includes a labeled `ML-DSA-ETH ↔ Falcon-ETH` pairwise delta section (AC-U-1).

**UC-5 — Reject invalid Falcon-ETH user-op at account boundary (3 paths, AC-FR-10).**
- **Cryptographic reject** (wrong key, bit-flip over valid-length blob): verifier returns `0xFFFFFFFF` → `_validateSignature` returns `SIG_VALIDATION_FAILED` (uint256 1).
- **Malformed** (wrong length, garbage payload): verifier reverts internally → account `catch`es → `revert SignatureMalformed()`.
- **Wrong-key** (valid sig from different key): cryptographic reject path.
Each path exercised by ≥1 test in `test/accounts/falcon-eth-failures.test.ts`.

### Suggested story decomposition (advisory — Plan phase decides)
Five stories, mirroring mldsa-eth structure:

1. **Story 1 — `.rsp` transcription + Hardhat-generated HashToPoint fixtures + loader refactor → multi-submodule SHA oracle.** Extend `scripts/generate-kat-fixtures.ts` with two fixture-emission targets and refactor the loader. **Task-level commit granularity** follows NFR-12; the AC-D-1 rename is further split into its own pure-rename commit to keep bisect surgical (DD-26). Tasks (each its own commit):

   - **Task 0 — PRE_G4_DRBG_PROBE** (lesson 5.2 A-005 audit): pick vec 0 from `.rsp`, derive entropy per the Python ref's `random_bytes(N)` consumption order, confirm 1064-byte sig reconstructs from `sm[:-mlen]` on re-sign. Blocks all downstream tasks.
   - **Task 1 — `.rsp` transcription + Python batch subprocess**: parse `ETHFALCON/test/ethfalcon512-KAT.rsp` (100 NIST-format vectors), one batched `python3 -c` subprocess computes `reshapedPk` per vector, emit `test/fixtures/kat/falcon-eth/vectors.json` (with `submoduleSource: "ethfalcon"` + `submoduleSha`).
   - **Task 2 — `FalconRef.sol` extension + Hardhat HashToPoint generator**: append `ZKNOX_HashToPointExposed` (~10 LOC) to existing `FalconRef.sol` (AC-A-4 extension per Option C), extend `scripts/generate-kat-fixtures.ts` with `--target hashtopoint` branch that deploys the wrapper in Hardhat and captures `.compute(salt, msg)` output for ≥6 pairs, emit `hashtopoint-vectors.json`.
   - **Task 3 — pure rename `KatVector` → `MlDsaEthKatVector`**: mechanical 8-file rename across `scripts/generate-kat-fixtures.ts` + `test/fixtures/kat/index.ts` + all 6 ml-dsa-eth consumer test files. **No behavior change, no new symbols.** Atomically bisectable; any downstream regression in Story 2–5 that points here is unambiguously "the rename broke something" vs "the loader refactor broke something." (DD-26 rationale.)
   - **Task 4 — multi-submodule loader + discriminated overload** (feature-adding commit on top of Task 3's clean rename): add `loadHashToPointVectors()` loader, discriminated `loadKatVectors("mldsa-eth"|"falcon-eth")` overload, multi-submodule HEAD probe (AC-A-1), `submoduleSource` validation + `KAT_UNKNOWN_SUBMODULE_SOURCE` error, backfill `submoduleSource: "ethdilithium"` into existing ml-dsa-eth fixtures.

   AC-A-1 + AC-D-1 ship across Tasks 3+4; both HIGH and structural, blocking Stories 2–5 only after Task 4 lands. **Size: M.** Commit count: 5 (one per task); no commit does more than one logical operation.
2. **Story 2 — G1 Keccak-PRG byte-identity vs ETHFALCON.** Capture G1 Layer-2 vectors from ETHFALCON's `Keccak256PRNG(a, b)`. Compare to existing `keccakXofFactory` output. If identical, ship G1 test as thin assertion; if divergent, port `falconKeccakXofFactory` adapter. **May collapse into Story 3** if G1 is trivially identical (likely — ETHDILITHIUM copied from ETHFALCON verbatim, only wrapper API differs).
3. **Story 3 — Falcon-ETH core + keygen port → G3 PASS.** Fork noble math into `falcon-eth.core.ts`; implement sampler with `XofFactory` parameterization (DD-10); expose `keygenInternal(drbgSeed)` that replays `AES256_CTR_DRBG` to derive internal entropy. **HashToPoint is NOT a keygen dependency** — it's deferred to Story 4. G3 KAT over 100 `.rsp` vectors. Module header `@delta-from-falcon` JSDoc lands with `FALCON_DELTA_HEADINGS` test (AC-D-3).
4. **Story 4 — HashToPoint port + Signer port → G2 + G4 PASS.** **Task 1 (HashToPoint isolated):** port `hashToPointEVM(salt, msg)` as standalone shared-core export; run G2 against 6 transcribed vectors; first-differing-coefficient ±4 context on mismatch. **Tasks 2–5 (Signer port):** implement hybrid fork per DD-15 (reuse noble's `ffSampling`/`splitFFT`/`mergeFFT`, fork sampler to Keccak-PRG), consume Story 4 Task 1's HashToPoint in the sign loop, expose `signWithDrbgRnd(sk, msg, drbgSeed)` for KAT surface + `signWithXofInstrumented` sibling (DD-10). Production `signUserOp` on top. G4 byte-identity over 100 `.rsp` vectors. Hedged-sign, deterministic-sign, SignerInputError validation. **Story 4 ships two gates (G2 + G4) because HashToPoint is cheap isolated + load-bearing for signer debugging.**
5. **Story 5 — pk-transform + account + bench → G5 + G6 + 5-scheme report.** `preparePublicKeyForDeployment` + internal `pkToNttCompact` helper + G5 KAT (mirrors mldsa-eth's G3 test pattern). `FalconEthAccount.sol` + wrapper confirmation (AC-A-4 doc note). G6 happy + rejection paths (smoke N=5 → tune to 100). Extend `SCHEMES` to 5, `SCHEME_DEPLOYERS` registry (AC-A-2), calldata asymmetry (AC-A-3), pairwise delta section (AC-U-1), AC-D-4 naming grep, AC-D-2 table-driven grep gates, AC-A-5 glob extension. Refresh `gas-data.json` + `gas-report.md`. README attribution (FR-20).

Chain is strictly ordered by byte-identity dependency. AC-A-1 + AC-D-1 in Story 1 gate everything downstream. Story 4 ships G2 BEFORE G4 (HashToPoint as Task 1; signer follows as Tasks 2–5) so a G4 red with G2 green localizes to the sign state machine, not HashToPoint. Amendment-doc-sweep discipline (AC-D-3 + universal rule [2026-04-18]) applies at every amendment boundary. **Final plan is likely 4 stories** if Story 2 collapses into Story 3; architecture-phase bet: high probability given ETHDILITHIUM's wrapper was copied from ETHFALCON per DD-13 investigation.

## Error Handling Strategy

### JS signer taxonomy (FR-18, AC-FR-18)
Extend existing `test/signers/errors.ts`. Stable `code` discriminant:

| Code | Class | Condition |
|---|---|---|
| `INVALID_SECRET_KEY_LENGTH` | `SignerInputError` | `sk.length` ≠ expected Falcon-512 sk bytes |
| `INVALID_PUBLIC_KEY_LENGTH` | `SignerInputError` | `pk.length !== 897` |
| `INVALID_MESSAGE` | `SignerInputError` | message not bytes or malformed hex |
| `INVALID_DRBG_SEED_LENGTH` | `SignerInputError` | `drbgSeed.length !== 48` (KAT surface; matches NIST AES256_CTR_DRBG seed size) |
| `KAT_SCHEMA_MISMATCH` | `KatFixtureError` | missing required top-level keys OR missing `submoduleSource` field |
| `KAT_SUBMODULE_SHA_MISMATCH` | `KatFixtureError` | embedded SHA ≠ resolved submodule HEAD (per `submoduleSource` field — AC-A-1) |
| `KAT_UNKNOWN_SUBMODULE_SOURCE` | `KatFixtureError` | `submoduleSource` not in `{"ethfalcon","ethdilithium"}` — protects against typos |
| `PRG_INJECT_AFTER_FLIP` | `PrgLifecycleError` | (inherited from mldsa-eth; unchanged) |
| `PRG_EXTRACT_BEFORE_FLIP` | `PrgLifecycleError` | (inherited) |
| `PRG_DOUBLE_FLIP` | `PrgLifecycleError` | (inherited) |
| `TEST_OVERRIDE_INVALID_FORMAT` | `FixtureGenError` | env-var override fails regex validation (NFR-9) |
| `TEST_OVERRIDE_SENTINEL_MISSING` | `FixtureGenError` | overrides present without `ALLOW_TEST_OVERRIDES=1` sentinel |
| `INTERNAL_SIGNER_ERROR` | `SignerInternalError` | unexpected failure in XOF / NTT / ffSampling / encoding |

Tests assert on `.code`, never on message strings. Error classes extend `SignerError` base with `readonly code` discriminant.

### Account contract reverts
`SignatureMalformed()` custom error — shared selector `0x2c3c2fe1` across MlDsaAccount / FalconAccount / MlDsaEthAccount / **FalconEthAccount** (4-contract club post-feature). Test walker MUST bind to `accountAddress.toLowerCase()` on BOTH canonical path (`ContractFunctionRevertedError.errorName === "SignatureMalformed"`) AND HH3 EDR message-regex fallback path (lesson 5.11 from mldsa-eth). Without the address bind, test-setup-routing-to-wrong-contract passes spuriously.

### Gas-cap-breach UX (AC-U-2)
Falcon-ETH verify is expected to fit under `tx_gas_limit_cap = 2^24 = 16,777,216` (NFR-5, A-7 — Falcon is cheaper than ML-DSA). **Chosen mechanism for distinguishing OOG vs SignatureMalformed:** documented README runbook entry mapping "OOG during validation" → "check NFR-5 cap, not your signature bytes." No new structured `VerifyGasCapExceeded` error is introduced at the contract level — this keeps the Account contract minimal. The bench-harness assertion (`verifyGas < 16_777_216` per G6 happy-path vector) catches cap breaches in test; production-adjacent operators are directed to the README runbook. Test: `test/accounts/falcon-eth.test.ts` asserts the runbook entry exists in README via a text-presence grep.

### Refactor rollback guard (inherited from mldsa-eth)
Any post-refactor byte-identity mismatch against the frozen NIST regression fixture → **HALT**, bisect, or revert-and-retry on fresh branch. Existing NIST ML-DSA + NIST Falcon suites are blocking post-conditions — they MUST remain green after any shared-module change.

## Smart Contract Interfaces

### `FalconEthAccount` (new)
```solidity
// contracts/FalconEthAccount.sol
// NatSpec: @title, @author, @notice, @dev per .claude/rules/solidity.md
// @custom:experimental This library is not audited yet, do not use in production.
contract FalconEthAccount is SimpleAccount {
  error SignatureMalformed();
  ISigVerifier public immutable falconEthVerifier;   // immutable per DD-9 (per-account verifier)
  bytes public publicKeyPointer;                     // 20-byte SSTORE2 pointer (AC-FR-8)
  bytes4 internal constant _VERIFY_SELECTOR = ISigVerifier.verify.selector;

  constructor(IEntryPoint entryPoint_, ISigVerifier falconEthVerifier_) SimpleAccount(entryPoint_) {
    falconEthVerifier = falconEthVerifier_;
  }

  function initialize(address owner_, bytes calldata _publicKeyPointer) public initializer {
    publicKeyPointer = _publicKeyPointer;
    _initialize(owner_);                             // shadow-discipline matches MlDsaEthAccount
  }

  function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
    internal view override returns (uint256)
  {
    try falconEthVerifier.verify(publicKeyPointer, userOpHash, userOp.signature) returns (bytes4 result) {
      return result == _VERIFY_SELECTOR ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    } catch { revert SignatureMalformed(); }
  }
}
```

Structurally identical to `MlDsaEthAccount` (`contracts/MlDsaEthAccount.sol` as reference). State variable name `falconEthVerifier` mirrors `dilithiumEthVerifier` naming. Uses `publicKeyPointer` from day one — no rename amendment like mldsa-eth A-006.

### `ISigVerifier` — unchanged from mldsa-eth era
```solidity
interface ISigVerifier {
  function verify(bytes calldata pk, bytes32 m, bytes calldata signature)
    external view returns (bytes4);
  function setKey(bytes calldata encodedPk) external returns (bytes memory);  // returns abi.encodePacked(address)
}
```

`ZKNOX_ethfalcon` (submodule, pinned) implements both. `setKey(bytes)` does `SSTORE2.write(pubkey)` directly — the `bytes` arg is `abi.encode(uint256[32])` per DD-7 refinement. Consumer passes `publicKeyPointer` bytes back to `verify` unchanged; verifier extracts via `shr(96, calldataload(_pubkey.offset))`.

### Compile-graph wrapper (AC-A-4 — extended, not replaced, this feature)
`contracts/imports/FalconRef.sol` already contains the NIST + ETH verifier wrappers from mldsa-eth era; falcon-eth Story 1 **appends** a `ZKNOX_HashToPointExposed` contract for Hardhat-driven fresh generation of G2 fixtures (DD-25 Option C):

```solidity
// Existing (from mldsa-eth era — unchanged):
contract ZKNOX_falcon is _ZKNOX_falcon {}          // NIST variant wrapper
contract ZKNOX_ethfalcon is _ZKNOX_ethfalcon {}    // ETH variant wrapper

// New this feature (~10 LOC, appended):
import {hashToPointEVM} from "../../ETHFALCON/src/ZKNOX_HashToPoint.sol";
contract ZKNOX_HashToPointExposed {
    function compute(bytes memory salt, bytes memory msgHash)
        external pure returns (uint256[] memory)
    {
        return hashToPointEVM(salt, msgHash);
    }
}
```

**No new wrapper file introduced; all falcon-eth shims consolidated in `FalconRef.sol`.** Architecture doc records the extension scope (NIST/ETH verifier wrappers + new HashToPoint exposure) to prevent RefShim drift. Story 5's first task verifies the file's contents via a doc-comment + grep check; Story 1 adds the `ZKNOX_HashToPointExposed` contract alongside the Hardhat-driven fixture generator. Free function `hashToPointEVM` is `pure` so `.compute()` costs zero gas in read-only calls.

## Library Public API Surface

### `test/signers/falcon-eth.ts` (production surface — same shape as `ml-dsa-eth.ts`)
```ts
/**
 * @delta-from-falcon
 * - HashToPoint XOF swap: SHAKE-256 → Keccak-CTR-PRNG (primitive-level swap; see DD-1)
 * - NTT-compact pk-transform: raw 897-byte pk → 32 × uint256 words → abi.encode(uint256[]) → setKey (NEW gate G5; NOT in NIST Falcon)
 * - signature layout (flat salt‖s2): 40 || 1024 = 1064 bytes flat, NO abi.encode at signature boundary (contrasts with NIST Falcon detached/attached forms)
 * - ctx handling: empty bytes (0x), matches ETHFALCON Python ref default
 * - fork scope (math-only reuse from noble): ffSampling / splitFFT / mergeFFT / NTT / Float primitives reused verbatim from @noble/post-quantum/falcon; HashToPoint + samplers forked to accept XofFactory (DD-10)
 * - rejection-counter via sibling export: signWithXofInstrumented returns { signature, iterations } as a sibling of signWithXof (DD-10 — zero module-level XOF state, enforced by AC-A-5 grep)
 */
export function keygen(): Keypair;                              // Keccak-driven; seed from crypto.getRandomValues
export async function signUserOp(
  secretKey: Uint8Array, userOp: UnsignedUserOp,
  entryPointAddress: string, chainId: bigint,
): Promise<PackedUserOperation>;                                // Keccak-driven; salt from crypto.getRandomValues
```

### `test/signers/falcon-eth.kat-internal.ts` (KAT-only, not imported from production dispatchers)
```ts
/**
 * @delta-from-falcon (same enumeration — AC-D-3 structural check asserts both headers have the same substrings)
 */
export function keygenInternal(drbgSeed: Uint8Array): Keypair;        // 48-byte AES256_CTR_DRBG seed from .rsp
export function signWithDrbgRnd(
  sk: Uint8Array, msg: Uint8Array, drbgSeed: Uint8Array, ctx?: Uint8Array,
): Uint8Array;                                                         // 1064-byte salt || s2_compact
// Salt is DERIVED internally from the DRBG stream — not caller-supplied, matches NIST KAT consumption pattern.
// For unit-testing specific salt values (not KAT byte-identity), use the core's signWithXof directly.
```

AC-3-7 grep boundary enforced via the shared `KAT_INTERNAL_MODULES` array (AC-D-2). Grep gate test case now:
```ts
const KAT_INTERNAL_MODULES = ["ml-dsa-eth.kat-internal", "falcon-eth.kat-internal"] as const;
// scanner builds regex dynamically per entry; iterates all targets; no literal substring
```

### `test/signers/falcon-eth.core.ts` (shared, XOF-parameterized)
```ts
// Copies from @noble/post-quantum/src/falcon.ts: splitFFT, mergeFFT, ffSampling, NTT primitives,
// Float, BNORM_MAX, SIGMA_MIN, INV_SIGMA, COMPLEX_ROOTS. Math only — no shake256 references.

export function signWithXof(
  sk: Uint8Array, msg: Uint8Array, salt: Uint8Array,
  xofFactory: XofFactory, ctx?: Uint8Array,
): Uint8Array;                                                  // 1064-byte output

export function signWithXofInstrumented(
  sk: Uint8Array, msg: Uint8Array, salt: Uint8Array,
  xofFactory: XofFactory, ctx?: Uint8Array,
): { signature: Uint8Array; iterations: number };               // sibling per DD-10

// Public pk-transform — mirrors mldsa-eth's preparePublicKeyForDeployment naming + Hex return convention
// (NFR-11 cross-scheme symmetry). Consumers (fixtures, account init, G5 test happy path) call this.
export function preparePublicKeyForDeployment(rawPk: Uint8Array, xofFactory: XofFactory): Hex;
//   Implementation:
//     const compacted = pkToNttCompact(rawPk, xofFactory);
//     return encodeAbiParameters([{ type: "uint256[]" }], [compacted]);
//   Returns viem `Hex` = `\`0x${string}\`` — directly passable to `verifier.write.setKey([payload])`.

// Internal/test helper — exposed for G5's structural test + debugging. Same precedent as mldsa-eth's
// `compactModule256` export. Returns the intermediate NTT-compact array before abi-encoding.
export function pkToNttCompact(rawPk: Uint8Array, xofFactory: XofFactory): bigint[];
//   Returns bigint[] of length 32, one bigint per uint256 word (each packs 16 Falcon coefficients × 16 bits).
//   Unit test asserts: output.length === 32 && output.every(w => typeof w === "bigint") && output.every(w => w < (1n << 256n)).

export function hashToPointEVM(salt: Uint8Array, msg: Uint8Array): Uint16Array;
// Standalone G2 export — keccak256-counter-mode construction (NOT the Keccak-PRG primitive).
// Returns 512 coefficients, each < q=12289. Pure function — same (salt, msg) → same output.
// Consumed internally by signWithXof at the "c = HashToPoint(r‖m, q, n)" step.
```

`XofFactory` (reused from `mldsa-encoding.ts`, DD-10 LOCKED):
```ts
export interface XofReader {
  readonly id: "shake128" | "shake256" | "keccak-prg";
  xof(length: number): Uint8Array;
}
export type XofFactory = (seed: Uint8Array) => XofReader;
```

Every falcon-eth call-site constructs its own reader via `xofFactory(seed)`. No module-level mutable XOF state; AC-A-5 grep enforces on `test/signers/{mldsa,falcon}-eth*.ts`.

**Module-header Delta requirement (AC-D-3):** Both `falcon-eth.ts` and `falcon-eth.kat-internal.ts` carry `@delta-from-falcon` JSDoc. The test `test/signers/falcon-eth.test.ts` defines:
```ts
const FALCON_DELTA_HEADINGS = [
  "HashToPoint XOF swap",
  "NTT-compact pk-transform",
  "signature layout (flat salt‖s2)",
  "ctx handling",
  "fork scope (math-only reuse from noble)",
  "rejection-counter via sibling export",
] as const;
// Asserts each substring appears in both module headers.
// Rationale for the enumeration (persona-review D-3): "HashToPoint XOF swap" is the SHAKE→Keccak-CTR-PRNG
// substitution point (DD-1). "NTT-compact pk-transform" is the most ETH-divergent delta — raw 897B →
// uint256[32] → abi.encode wrapper — it introduces a NEW gate (G5) that doesn't exist for NIST Falcon.
// "signature layout (flat salt‖s2)" captures that ETHFALCON flattens the sig at the boundary instead of
// using NIST Falcon's detached/attached encoding — this is what makes G4's byte-identity assertion a
// flat-concat compare rather than a parse-and-compare. "ctx handling" captures empty-bytes default per
// ref. "fork scope" names exactly what we reuse from noble vs what we fork. "rejection-counter via
// sibling export" documents the DD-10 instrumentation discipline. "Algorithm-17 compress" was dropped
// — Falcon-ETH REPLACES Algorithm-17 with NTT-compact, so listing it as a delta heading reads as a
// negation, not a positive item; the substantive change is captured under "signature layout" and
// "NTT-compact pk-transform."
//
// Greps for stray `ml-dsa`, `mldsa`, `dilithium` in both files; fails on any hit not prefixed `@cross-ref:`.
```

### `test/signers/deployers.ts` (new — per-scheme deployer registry, AC-A-2)
```ts
type Deployer = (ctx: DeployContext) => Promise<{ proxyAddress: Address; alice: Signer }>;
export const SCHEME_DEPLOYERS: Record<Scheme, Deployer> = {
  ecdsa:        deployEcdsa,
  falcon:       deployFalcon,
  mldsa:        deployMldsa,
  "mldsa-eth":  deployMldsaEth,
  "falcon-eth": deployFalconEth,
};
// TS Record<Scheme, Deployer> catches missing scheme at compile time. Adding 6th scheme = 1 entry.
```

Each `deploy<Scheme>` fn is collocated with its signer module (or in `test/signers/{scheme}.deployer.ts` sibling). Bench harness `deployAccount` becomes:
```ts
async function deployAccount(scheme: Scheme, ctx: DeployContext) {
  return SCHEME_DEPLOYERS[scheme](ctx);
}
```
No if-cascade. Falcon-eth addition is 1 registry entry + 1 sibling file — no `deployAccount` body edit.

## CLI Command Structure

| Command | Purpose | AC |
|---|---|---|
| `npm run kat:regen -- --scheme falcon-eth` | Regenerate Falcon-ETH KAT fixtures (calls Python oracle) | UC-4, FR-16 |
| `npm run kat:regen -- --scheme mldsa-eth` | (unchanged) Regenerate ML-DSA-ETH fixtures | — |
| `npm run report` | Aggregate 5-scheme bench snapshot → Markdown/CSV report, deterministic timestamp | UC-5, FR-19, NFR-8 |
| `UPDATE_BENCH=1 npx hardhat test test/bench/gas-benchmark.test.ts` | Refresh `gas-data.json` snapshot | NFR-8 |
| `npx hardhat test` | Full suite (unit + KAT + integration + grep gates) | NFR-2 |

No new runtime dependencies introduced. `ALLOW_TEST_OVERRIDES=1` sentinel required if any test-only env-var overrides are supplied to `kat:regen` (NFR-9).

## Security

**Tier: Low** (research tool, local Hardhat only, no PII / finance / live deployment; verifier carries `@custom:experimental` posture).

- **Submodule pinning** — `.gitmodules` records `ETHFALCON` SHA at `03ed0d60c6...`; fixture-gen CLI refuses to run when HEAD differs (AC-NFR-1). Loader's multi-submodule probe (AC-A-1) protects against per-scheme drift.
- **Dev-oracle isolation** — no Python interpreter invoked by any shipped test path. Only `scripts/generate-kat-fixtures.ts` spawns Python, and it's not part of `npm test`.
- **Test-override safety (NFR-9)** — env-var overrides in fixture-gen are (a) regex-validated at ingest with pattern recorded in code, (b) gated behind `ALLOW_TEST_OVERRIDES=1` sentinel that production never sets. Operationalizes universal rule [2026-04-18] "security-relevant test overrides need runtime gates, not just docs." Both rejection paths tested.
- **Python subprocess hardening** — CLI constructs subprocess argv explicitly; no shell expansion; env-var override values regex-matched against allowed shape (`/^[0-9a-f]{40}$/` for SHAs, `/^[0-9]+$/` for vector counts, etc.) before embedding in Python `-c` argv.
- **No secrets in fixtures** — Falcon-ETH KAT fixtures include test secret keys by design (research fixtures, not production keys). README attribution (FR-20) states this posture.
- **Input validation** — signer throws structured `SignerInputError` on malformed inputs; account contract reverts `SignatureMalformed()` on malformed signatures. No trust placed in user input at crypto layer.
- **License preservation (NFR-10)** — MIT copyright/license header byte-equal to upstream on `contracts/imports/FalconRef.sol` + any other wrapper; test greps first lines.

**Not in scope (same posture as mldsa-eth):** on-chain verifier audit, threat model, OWASP analysis, formal proof of correctness. Verifier carries explicit `@custom:experimental` posture.

## Testing Strategy

**Framework:** node:test + node:assert/strict (parent project convention). Hardhat v3 for on-chain path. No mocks at crypto layer (real signer vs real verifier).

**Test tiers:**

| Tier | Location | Scope | Representative ACs |
|---|---|---|---|
| Signer unit | `test/signers/falcon-eth.test.ts` (new) | XOF isolation grep, `@delta-from-falcon` structural check (AC-D-3), `FALCON_DELTA_HEADINGS` substring assertion, `KAT_INTERNAL_MODULES` grep | AC-D-2, AC-D-3, AC-A-5, AC-NFR-6 |
| Naming grep | `test/signers/naming.test.ts` (new OR append to existing) | Greps `src/ test/ contracts/ scripts/` for snake-case `falcon_eth` — fails on any hit | AC-D-4 |
| G1 — Keccak-PRG vs ETHFALCON | `test/signers/keccak-prg.falcon.kat.test.ts` (new) | Fresh `KeccakPrg` per fixture; scripted inject/flip/extract vs ETHFALCON Python wrapper output. Anchors G3/G4/G5 (all XOF-dependent). | AC-FR-11, DD-13 |
| **G2 — HashToPoint KAT** (new) | `test/signers/falcon-eth.hashtopoint.kat.test.ts` (new) | `hashToPointEVM(salt, msg) === expectedHash` over 6 vectors from `hashtopoint-vectors.json`. First-differing-coefficient ±4 context on mismatch. Anchors G4 (signer consumes HashToPoint). | DD-25 (new gate), FR-13 implied |
| G3 — Keygen KAT | `test/signers/falcon-eth.keygen.kat.test.ts` (new) | `keygenInternal(drbgSeed)` byte-identity vs `.rsp` ≥100 vectors | AC-FR-12, AC-NFR-3 |
| G4 — Signer KAT | `test/signers/falcon-eth.sign.kat.test.ts` (new) | `signWithDrbgRnd(sk, msg, drbgSeed)` byte-identity over 100 `.rsp` vectors. Instrumented pass asserts rejection-counter positive (HashToPoint rejection loop). | AC-FR-13, AC-FR-6, AC-NFR-3 |
| G4 — Signer non-KAT | `test/signers/falcon-eth.sign.test.ts` (new) | Input validation (SignerInputError per field), production hedged sign (2 calls → different salt prefixes), deterministic sign | AC-FR-4, AC-FR-5, AC-FR-18 |
| G5 — PK-transform KAT | `test/signers/falcon-encoding.pk-transform.kat.test.ts` (new) | Primary assertion: `preparePublicKeyForDeployment(rawPk, keccakXofFactory)` byte-identity vs `reshapedPublicKey` (viem Hex equality) over ≥100 vectors — mirrors mldsa-eth's G3 test pattern exactly. Structural sub-assertion: `pkToNttCompact(rawPk, keccakXofFactory)` returns `bigint[]` of length 32 for every vector (debug anchor if Hex comparison fails). Pk-format divergence probe (vec 0 length check) runs before bulk test. | AC-FR-14, AC-NFR-3 |
| G6 — Verifier integration | `test/accounts/falcon-eth.test.ts` (new) | Deploy verifier + account; submit fixture `(pkPointer, msg, sig)` via `validateUserOp`. Smoke N=5; tune to ≥100 at Gate 5. Gas-cap assertion `verifyGas < 16_777_216` on every vector. | AC-FR-9, AC-FR-15, AC-NFR-5, AC-NFR-3 |
| G6 — Failure paths | `test/accounts/falcon-eth-failures.test.ts` (new) | Wrong-key, bit-flip (salt byte + s2 byte), malformed (zero-byte). Dual-path walker binds to `accountAddress.toLowerCase()` on BOTH paths (lesson 5.11). | AC-FR-10, AC-NFR-11 |
| Bench | `test/bench/gas-benchmark.test.ts` (modified) | 5-scheme gas measurement via `SCHEME_DEPLOYERS` registry. Calldata-asymmetry assertions (mldsa-pair 5%, falcon-pair 25%). Labeled mldsa-eth ↔ falcon-eth delta row. Snapshot gated by `UPDATE_BENCH=1`. | AC-U-1, AC-A-2, AC-A-3, AC-NFR-7 |
| Licence header | `test/contracts/wrapper-headers.test.ts` (new) | Greps first lines of every `contracts/imports/*.sol` wrapper for byte-equal MIT header vs upstream | AC-NFR-10 |
| README runbook presence | `test/docs/readme-runbook.test.ts` (new, small) | Greps README for OOG→NFR-5 runbook entry text | AC-U-2 |

**Shared helpers:**
- `assertBytesEqual(actual, expected, label, xofId?)` — existing, prints first-divergent byte ±8 bytes context plus XOF factory id on divergence.
- `PRE_G5_FORMAT_PROBE` — spot-check vec 0's `reshapedPublicKey.length` against TS output length. Runs as test-setup; fails with structural-decode-fallback guidance if lengths differ (lesson 5.1 carry-over).
- `PRE_G4_DRBG_PROBE` — **load-bearing (DD-14 flip elevated it)**: Falcon-ETH KAT is AES256_CTR_DRBG-driven just like ML-DSA-ETH, so lesson 5.2 (A-005 DRBG state advancement) applies directly. Pick vec 0 from `.rsp`, extract `(drbgSeed, msg, pk, sk, sm)`, run Python ref `sk.sign(msg, ...)` with the same DRBG-derived entropy order, confirm `sm[:-mlen]` byte-identical to freshly-computed signature. Audit the exact `random_bytes(N)` call sequence in `falcon.py` sign path — every `__ctr_drbg_update` boundary matters. Probe MUST pass before bulk G4 runs.

**Coverage baselines:**
- Existing 97-test baseline stays green (AC-NFR-2).
- Post-feature: 97 + ~15–25 new tests (target per mldsa-eth precedent).
- No mocks at crypto layer. EntryPoint impersonation via `testClient.impersonateAccount` (unchanged from mldsa-eth).

## Design Rationale

| DD | Decision | Status | Alternatives / Rationale |
|---|---|---|---|
| DD-1 | XOF swap SHAKE → Keccak-CTR-PRNG at HashToPoint + rejection sampling + internal expansions | **LOCKED** (Research) | ETHFALCON spec — no choice |
| DD-5 | `FalconEthAccount : SimpleAccount`, `_validateSignature` override | **LOCKED** (Research) | Parity with MlDsaEthAccount / FalconAccount |
| DD-6 | ETHFALCON submodule compile path via pre-existing `FalconRef.sol` wrapper | **LOCKED** (Research) | NIST + ETH verifier wrappers untouched; `FalconRef.sol` **extended** with `ZKNOX_HashToPointExposed` (~10 LOC) for DD-25 Option C fresh-generation. No new wrapper file. (AC-A-4) |
| DD-7 | pk reshape exposes **two functions** mirroring mldsa-eth's convention (NFR-11). **Public:** `preparePublicKeyForDeployment(rawPk, xofFactory): Hex` — returns already-abi-encoded `Hex` directly passable to `setKey`; same name + same return-type shape as mldsa-eth's counterpart at `test/signers/mldsa-encoding.ts`. **Internal/test helper:** `pkToNttCompact(rawPk, xofFactory): bigint[]` — returns the NTT-compact array (length 32, each element one `uint256` word) before abi-encoding. `preparePublicKeyForDeployment` composes `encodeAbiParameters([{type:"uint256[]"}], [pkToNttCompact(rawPk, xof)])`. | **LOCKED** (This phase, with post-persona-review cross-scheme alignment) | **Refined from research** — research.md said "NTT-domain compacted bytes"; architecture-phase investigation (DD-16) confirmed `setKey`'s consumer expects `abi.decode(..., (uint256[]))`. Post-persona-review follow-up (user question on mldsa-eth consistency): a single `pkToNttCompact(): bigint[]` surface that made the caller do abi-encode would violate NFR-11 cross-scheme symmetry — mldsa-eth's public pk-transform (`preparePublicKeyForDeployment`) returns already-abi-encoded `Hex` with abi-encode baked in. Two-function shape aligns the public surface with mldsa-eth exactly while keeping the internal helper available for G5's structural test + debugging (same precedent as mldsa-eth exporting `compactModule256` as an internal helper alongside the public function). Rejected alternatives: (a) single `pkToNttCompact(): bigint[]` — NFR-11 violation; (b) single `preparePublicKeyForDeployment(): Hex` with no internal helper — G5 structural debugging loses the fine-grained bigint-array checkpoint; (c) `Uint32Array` — truncates 256-bit words to 32-bit. Two-function is strictly better than any single-function option. |
| DD-8 | Signature ABI = flat `salt(40) \|\| s2_compact(1024) = 1064 bytes`; verifier 3-arg boundary `verify(bytes pk, bytes32 m, bytes sig) returns bytes4` | **LOCKED** (This phase) | Confirmed by DD-16 investigation at `ETHFALCON/src/ZKNOX_ethfalcon.sol:79-130` inline-assembly decode path. |
| DD-9 | Per-account verifier (immutable reference); no cross-account reuse | **LOCKED** (Research) | — |
| DD-10 | Parameterize-by-factory: `XofFactory` passed to every call-site; sibling-export `signWithXofInstrumented` for rejection-counter; zero module-level XOF state | **LOCKED** (Research) | AC-A-5 grep enforces extension to `test/signers/{mldsa,falcon}-eth*.ts` glob |
| DD-11 | Oracle chain PRG → keygen → signer → pk-transform → verifier, each gate byte-identity | **LOCKED** (Research) | — |
| DD-13 | G1 Keccak-PRG byte-identity verification REQUIRED (not skippable) against ETHFALCON's `Keccak256PRNG(a, b)` wrapper | **LOCKED** (Research) | ETHFALCON is upstream origin of keccak_prng.py; ETHDILITHIUM wrapper API diverges (`KeccakPRNG()` vs `Keccak256PRNG(a, b)`); internal mechanics may be identical but verification is cheap-to-land and prevents silent downstream drift |
| DD-14 | Fixture source: **pre-existing `ETHFALCON/test/ethfalcon512-KAT.rsp` (100 NIST-format vectors) transcribed to JSON** — NOT live Python-ref capture | **LOCKED** (Flipped this phase) | **Supersedes research-phase DD-14** which said "no corpus exists." Finding during architecture drafting: `ETHFALCON/test/ethfalcon512-KAT.rsp` is the canonical 100-vector `.rsp` file committed alongside the Solidity tests (same file `ETHFALCON/test/ethfalcon_KAT_file.t.sol` consumes on-chain). Transcription pipeline mirrors mldsa-eth's Story 1 Task 3 verbatim (same NIST schema). `reshapedPk` computed by one batched `python3 -c` subprocess over all 100 pk arrays. Downstream effects: Story 1 size shrinks (M, was M/L), PRE_G4_DRBG_PROBE upgraded to load-bearing (A-005 applies), fixture-gen runtime drops from minutes to seconds, the 3 DD-15-adjacent open questions (keygen RNG seeding, salt capture, live-keygen runtime) all resolve. Research-phase C-11 in spec.md is superseded by this flip. |
| DD-12 | Use `@noble/post-quantum/falcon` math as base reference for fork | **LOCKED** (was DISCRETION — resolved this phase) | DD-15 investigation confirmed math primitives (ffSampling, splitFFT, mergeFFT, NTT, Float) reusable. Source-copy delta-fork is the implementation strategy. |
| DD-15 | `ffSampling` port via hybrid fork — reuse noble's math verbatim; fork `HashToPoint` + samplers to accept `XofFactory` | **LOCKED** (was DEFERRED — resolved this phase) | Alternatives: (a) ground-up port — rejected as ~2500 LOC scope with numerical-precision trap; (b) monkey-patch noble at runtime — rejected as fragile; (c) wait for upstream XOF-pluggability — rejected, no PR exists. |
| DD-16 | Solidity `verify()` boundary = `verify(bytes pk, bytes32 m, bytes sig) returns bytes4`; sig layout flat `salt(40) \|\| s2(1024) = 1064 B`; `pk` = 20-byte SSTORE2 pointer; `setKey(bytes)` consumes `abi.encode(uint256[32])` | **LOCKED** (was DEFERRED — resolved this phase) | Confirmed at `ETHFALCON/src/ZKNOX_ethfalcon.sol:79-130`. Refines DD-7 ABI-wrap detail. |
| DD-17 | Multi-submodule SHA oracle — loader probes both ETHFALCON + ETHDILITHIUM HEADs, per-fixture `submoduleSource` discriminator resolves which submodule to check | **LOCKED** (This phase, AC-A-1 HIGH) | Alternative: single-submodule loader hard-coded — rejected as silent oracle-break risk. Architect HIGH concern: tautological SHA match or always-mismatch with single-submodule loader once Falcon fixtures sourced from ETHFALCON land. |
| DD-18 | Per-scheme deployer registry `SCHEME_DEPLOYERS: Record<Scheme, Deployer>` for bench harness; exhaustive at TS compile time | **LOCKED** (This phase, AC-A-2) | Alternative: inline if-cascade continues — rejected as exceeds 50-line / nested-branch thresholds at 5+ schemes, blocks localized scheme-addition |
| DD-19 | Calldata-assertion asymmetry — 5% within-pair gas bound ONLY for mldsa-pair (shared DD-8 layout); falcon-pair uses equal-length + 25% looser gas bound | **LOCKED** (This phase, AC-A-3) | Alternative: 5% for both pairs — rejected as flake risk (NTT-compact vs Algorithm-17-compress byte distributions differ even at equal length) |
| DD-20 | `loadKatVectors` discriminated overload; rename `KatVector` → `MlDsaEthKatVector` in same commit, no aliased re-export; add `FalconKatVector` | **LOCKED** (This phase, AC-D-1 HIGH) | Alternative: union-extend `KatVector` with optional falcon fields — rejected as `vec.cTilde` would compile but be undefined at runtime for falcon consumers (silent failure mode) |
| DD-21 | `FALCON_DELTA_HEADINGS` enumerated-substring structural assertion + stray-mldsa substring grep. **Enumeration (post persona-review D-3):** `["HashToPoint XOF swap", "NTT-compact pk-transform", "signature layout (flat salt‖s2)", "ctx handling", "fork scope (math-only reuse from noble)", "rejection-counter via sibling export"]`. | **LOCKED** (This phase, AC-D-3) | Alternative A: copy-paste `@delta-from-ml-dsa` literal string check — rejected as either-lies-or-drifts (falcon deltas differ from ml-dsa deltas). Alternative B (initial draft): included "Algorithm-17 compress" as a heading — rejected post-review (D-3 maintainer concern), because Falcon-ETH REPLACES Algorithm-17 rather than using it, so it reads as a negation not a positive delta; the substantive content is captured under "signature layout" and "NTT-compact pk-transform." Alternative B also omitted "NTT-compact pk-transform" and "rejection-counter via sibling export" — both added in the revised list because they are load-bearing deltas (G5 gate + DD-10 instrumentation). |
| DD-22 | Table-driven `KAT_INTERNAL_MODULES` array + xof-lifecycle grep glob extended to `test/signers/{mldsa,falcon}-eth*.ts` | **LOCKED** (This phase, AC-D-2, AC-A-5) | Alternative: regex literal per test file — rejected as silent-miss risk for 6th scheme |
| DD-23 | Naming-consistency doc table + snake-case `falcon_eth` prohibition unit test across `src/ test/ contracts/ scripts/` | **LOCKED** (This phase, AC-D-4) | Alternative: documentation only — rejected as relying on reviewer discipline for a mechanically-checkable constraint |
| DD-24 | Gas-cap-breach UX handled via README runbook entry; no new `VerifyGasCapExceeded` error at contract level | **LOCKED** (This phase, AC-U-2) | Alternative: add structured contract-level error + pre-flight estimator — rejected as increasing Account contract complexity for a failure mode expected to be rare (NFR-7 says Falcon is cheaper than ML-DSA-ETH) |
| DD-26 | **Pure-rename refactors touching >3 files land as their own commit BEFORE the feature-adding commit that depends on the rename.** Applies to AC-D-1's `KatVector` → `MlDsaEthKatVector` rename in Story 1 Task 3, which precedes Task 4's multi-submodule loader + discriminated overload. Each commit is atomically bisectable: downstream regression pointing at Task 3 = rename issue, pointing at Task 4 = loader issue. | **LOCKED** (This phase, persona-review-driven) | Alternative: single commit combining rename + loader refactor + `submoduleSource` backfill — rejected, violates NFR-12 "one commit per task" in spirit and produces a mega-commit that bisects poorly across 8 file rename + 2 new functions + 1 field backfill. Maintainer persona flagged this as a MED concern in Phase-3 review; the cost of splitting is one extra commit in Story 1, the benefit is surgical bisect throughout Stories 2–5. |
| DD-25 | **G2 HashToPoint byte-identity gate inserted between G1 (Keccak-PRG) and G3 (keygen). G2 vectors are fresh-generated from the pinned on-chain impl (Option C), not transcribed from literal arrays.** G2's corpus is captured by deploying `ZKNOX_HashToPointExposed` (contract appended to `FalconRef.sol`) in Hardhat and calling `.compute(salt, msg)` for N≥6 pairs — trust anchor is the current pinned `ZKNOX_HashToPoint.sol`. | **LOCKED** (This phase) | Alternatives considered for gate structure: fold HashToPoint implicitly into G4 signer — rejected, HashToPoint adapter parameters (absorb order, chunk endianness, rejection threshold, mod-q reduction, coefficient-order) are independently testable and exactly the bug class that bit mldsa-eth's SampleInBall. Alternatives considered for G2 vector source: **(A) no cross-validation, transcribe .t.sol literals** — rejected, no anchor to live on-chain behavior; spec-mirrored bug in Python ref + TS port passes G2 spuriously. **(B) transcribe literals + Hardhat cross-validate at transcription time** — rejected as strictly weaker than Option C. **(C, SELECTED) fresh-generate from deployed `ZKNOX_HashToPointExposed`** — trust anchor IS the current pinned on-chain impl; submodule SHA-pin bump via AC-A-1 forces regeneration; no drift possible; no transcription-layer bugs by construction; cost is ~10 LOC wrapper + ~40 LOC generator in Story 1. **(D) make G2 a live Hardhat integration test (no JSON)** — rejected, turns G2 from a fast unit test into an EVM-dependent test, conflicts with G2's bug-localization role. |
