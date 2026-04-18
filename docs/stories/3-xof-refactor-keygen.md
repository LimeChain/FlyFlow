---
story_id: "3"
title: "XOF refactor + keygen port + G1 KAT + NIST regression"
size: "M"
status: "ready-for-dev"
wave: 3
feature: mldsa-eth
created: 2026-04-18
---

# Story 3: XOF refactor + keygen port + G1 KAT + NIST regression

> Ref: `docs/plan.md` §"Story 3: XOF refactor + keygen port + G1 KAT + NIST regression [M]" — authoritative AC text, interface contracts, wave assignment, dependency chain.
> Ref: `docs/architecture.md` §"Library Public API Surface" §"`test/signers/mldsa-encoding.ts` (refactored)" — XofFactory/XofReader contract + factory-vs-one-shot rationale.
> Ref: `docs/architecture.md` §"Library Public API Surface" §"`test/signers/ml-dsa-eth.ts`" + §"`test/signers/ml-dsa-eth.kat-internal.ts`" — production-vs-KAT split (M-1 resolution), fork scope (keygen+sign both XOF-parameterized), module-header `@delta-from-ml-dsa` requirement (M-3).
> Ref: `docs/architecture.md` §"Design Rationale" DD-10 (parameterize-by-factory; one-shot rejected), DD-11 (four-implementation oracle chain — PRG delivered by Story 2).
> Ref: `docs/architecture.md` §"Testing Strategy" row "G1 — Keygen KAT", §"Shared helpers" paragraph (AC-D-2 pre-refactor NIST regression + interleaved XOF-isolation test).
> Ref: `docs/architecture.md` §"Error Handling Strategy" §"Refactor rollback (AC-D-2 pre-refactor NIST regression)" — HALT / bisect / revert protocol on post-refactor byte-identity mismatch.
> Ref: `docs/amendments.md` §A-001 — DD-7 `reshapedPublicKey` ABI is `(bytes, bytes, bytes)` with `tr` 64 B via Keccak-PRG stream, NOT `bytes32`. Story 3's refactored `preparePublicKeyForDeployment` MUST emit the amended tuple shape.
> Ref: `docs/stories/1-fixture-gen-cli.md` — upstream story; `Detected Patterns` table applies unchanged (ESM `.js` imports, `readonly code` error discriminants, viem hex I/O, top-of-file JSDoc). `loadKatVectors("mldsa-eth")` is produced here.
> Ref: `docs/stories/2-keccak-prg-port.md` — upstream story; `createKeccakPrg` + `KeccakPrg` interface are the load-bearing primitive for the `keccakXofFactory` adapter.

## User Story

As a wallet engineer, I want `mldsa-encoding.ts` refactored to accept an XOF factory + a Keccak-based keygen port that passes byte-identity against `.rsp`, so that the shared encoding module and keygen serve both NIST and ETH code paths without module-level state.

## Acceptance Criteria

> All ACs copied verbatim from `docs/plan.md` §"Story 3". Never paraphrase.

- **AC-3-1** (G1 KAT — FR-2 byte-identity): Given a `.rsp` vector N's `zeta`, when `keygenInternal(zeta)` is called, then `(publicKey, secretKey)` matches the fixture's `pk` and `sk` byte-for-byte, iterated across all ~100 vectors.
- **AC-3-2** (No module-level XOF state — AC-A-1 HIGH): Given the refactored `mldsa-encoding.ts` + new `ml-dsa-eth.ts`, when source-level grep runs for `let _xof` / `var _xof` / module-scoped factory assignments, then zero matches are found.
- **AC-3-3** (AC-D-2 NIST regression — 100-vector): Given a frozen 100-vector NIST pre-refactor golden fixture captured from `PQCsignKAT_Dilithium2.rsp`, when post-refactor code runs against all 100 vectors, then outputs match byte-for-byte per vector. Any mismatch → HALT per refactor-rollback protocol.
- **AC-3-4** (XofReader `id` discriminant): Given `assertBytesEqual(actual, expected, label, xofId?)`, when divergence occurs and `xofId` is provided, then the error message includes `(factory=<xofId>)`.
- **AC-3-5** (Interleaved XOF-isolation — AC-A-1 HIGH): Given one test reshapes the same pk with SHAKE → Keccak → SHAKE factories interleaved in one process, then each reshape output matches its own golden; no cross-contamination.
- **AC-3-6** (Module-header `@delta-from-ml-dsa`): Given `test/signers/ml-dsa-eth.ts` and `test/signers/ml-dsa-eth.kat-internal.ts`, when a maintainer reads the top-of-file JSDoc, then a `@delta-from-ml-dsa` section enumerates byte-level differences from `ml-dsa.ts`.
- **AC-3-7** (ESLint `no-restricted-imports`): Given the `.eslintrc` rule, when `test/signers/index.ts` or any file under `test/bench/**` imports from `ml-dsa-eth.kat-internal.ts`, then lint fails.
- **AC-3-8** (AC-NFR-5 ML-DSA-44 params): Given keygen's parameter constants, when asserted against (k=4, l=4, η=2, γ₁=2¹⁷, γ₂=95232, τ=39, ω=80, β=78), then all match by named constant.

**FR Coverage:** FR-1 (keygen), FR-2 (keygen), FR-8 (keygen). **NFR Coverage:** NFR-2 (direct), NFR-6 (direct).

## Verified Interfaces

### Consumed by this story (VERIFIED against source at story-creation time)

- **`createKeccakPrg(seed?: Uint8Array): KeccakPrg`** — Story 2 primitive, wrapped by the Keccak XOF adapter
  - Source: `test/signers/keccak-prg.ts:92`
  - File hash (sha256): `518b57b143280a0053298a561d27eff3be0aa11a83b53b4b18dd64179b7dfa83`
  - Signature (verbatim): `export function createKeccakPrg(seed?: Uint8Array): KeccakPrg`
  - Semantics (from file JSDoc + Story 2 Dev Notes): optional ctor `seed` ≡ immediate `inject(seed)` — NOT auto-flipped. Caller must `flip()` before `extract()`. Empty-seed path valid (`extract(32)` post-flip on an empty buffer returns a defined 32 B stream).
  - Plan match: ✓ matches `docs/plan.md` §"Interface Contracts" §"`KeccakPrg`".

- **`KeccakPrg`** — Story 2 interface, consumed by the Keccak XOF adapter
  - Source: `test/signers/keccak-prg.ts:71`
  - File hash (sha256): `518b57b143280a0053298a561d27eff3be0aa11a83b53b4b18dd64179b7dfa83`
  - Signature (verbatim):
    ```ts
    export interface KeccakPrg {
      inject(data: Uint8Array): void;
      flip(): void;
      extract(length: number): Uint8Array;
      update(data: Uint8Array): void;   // SHAKE-parity alias for inject
      read(length: number): Uint8Array; // SHAKE-parity alias for extract
    }
    ```
  - Plan match: ✓.

- **`loadKatVectors(scheme: "mldsa-eth"): KatVector[]`** — Story 1 loader, consumed by the G1 KAT test
  - Source: `test/fixtures/kat/index.ts:344`
  - File hash (sha256): `ca8c32db82d0d082efc53cfa92526d94f7f4d2a0e9c0d4376c7e63b4e406d4f0`
  - Signature (verbatim): `export function loadKatVectors(scheme: "mldsa-eth"): KatVector[]`
  - `KatVector` (from `test/fixtures/kat/index.ts:83-101`) provides `{ id, drbgSeed, zeta, rnd, publicKey, secretKey, reshapedPublicKey, message, signature }` — G1 consumes `(zeta → keygenInternal → assert (publicKey, secretKey))`.
  - Side effect: module top-level `assertSubmoduleShaMatches()` (line 391) runs at import time — G1 test gets submodule-pin validation for free.
  - Plan match: ✓.

- **EXISTING `test/signers/mldsa-encoding.ts`** — the file being refactored (current pre-refactor shape)
  - Source: `test/signers/mldsa-encoding.ts`
  - File hash (sha256 at story creation): `ec082d16a3fc757737641f3694b2c946305eaf0aaa15664a98fa844ced0dd668`
  - Current signature (verbatim from line 177): `export function preparePublicKeyForDeployment(rawPublicKey: Uint8Array): Hex` — **no xof parameter today.**
  - Current XOF call-sites that must migrate to `xofFactory(seed)`:
    - `mldsa-encoding.ts:45` — `const xof = shake128.create(); xof.update(seed);` inside `rejectionSamplePoly` (used by `recoverAhat` for A_hat). Migrate to `xofFactory(seed)` returning a `XofReader`; replace `xof.xofInto(buf)` with `buf = reader.xof(3 * 64)` (the reader owns buffer allocation). Because `xof` is called in a loop pulling 192-byte chunks until 256 valid coefficients accumulate, the reader is re-invoked repeatedly on the **same** seeded instance — this is why DD-10 LOCKED parameterize-by-factory over one-shot (one-shot forces over-allocation; Python ref `_expand_matrix_from_seed` confirms multi-chunk pull).
    - `mldsa-encoding.ts:103` — `const tr = shake256(new Uint8Array(publicKey), { dkLen: TR_BYTES });` inside `decodePublicKey` (TR_BYTES = 64). **Amendment A-001 applies:** the ETH path computes `tr` as a 64-byte Keccak-PRG stream over the raw pk, not a 32-byte Keccak-256 truncation. The refactor replaces this line with `tr = xofFactory(publicKey).xof(TR_BYTES)` — yields 64 B for both NIST (SHAKE256) and ETH (Keccak-PRG) paths.
  - Current caller (only one — migration surface minimal):
    - `test/fixtures/mldsa.ts:49` — `const encoded = preparePublicKeyForDeployment(rawPublicKey);`. Story 3 must update this call-site to pass the NIST SHAKE XOF factory (either `shake128XofFactory` for `rejectionSamplePoly` / `shake256XofFactory` for `tr` — or a single factory if the refactor consolidates; see Dev Notes §"XOF call-site reconciliation").
  - Refactor commit must be logged as a Rule 3 amendment in `docs/amendments.md` (architecture §"Library Public API Surface" explicitly requires this for the `mldsa-encoding.ts` interface change).

- **`PQCsignKAT_Dilithium2.rsp` (NIST variant, submodule-resident)** — corpus for the AC-3-3 frozen regression fixture
  - Source: `ETHDILITHIUM/pythonref/assets/PQCsignKAT_Dilithium2.rsp`
  - Vector count (verified: `grep -c '^count = '` = 100) — exactly 100 records, matching AC-3-3 wording "100-vector NIST pre-refactor golden fixture".
  - Each record: `count`, `seed` (48 B hex), `mlen`, `msg`, `pk` (1312 B), `sk` (2560 B), `smlen`, `sm`. G1-NIST uses the `pk` field directly; keygen-seed recovery is NOT required (capture script reshapes `pk` via the pre-refactor encoder).

- **Dilithium2 parameter constants (for AC-3-8)** — verified against noble reference
  - Source: `node_modules/@noble/post-quantum/ml-dsa.js:45` (params tuple for ML-DSA-44) and `:149` (derived BETA)
  - Verbatim: `K: 4, L: 4, D, GAMMA1: 2 ** 17, GAMMA2: GAMMA2_1, TAU: 39, ETA: 2, OMEGA: 80` where `GAMMA2_1 = Math.floor((Q - 1) / 88) | 0 = Math.floor(8380416 / 88) = 95232` (`:34`), and `BETA = TAU * ETA = 78` (`:149`). ✓ Matches `docs/plan.md` §AC-3-8 tuple (k=4, l=4, η=2, γ₁=2¹⁷, γ₂=95232, τ=39, ω=80, β=78) exactly.

### Produced by this story (⚠ UNVERIFIED — signatures from plan + architecture contracts)

> Marked ⚠ UNVERIFIED — source not yet implemented, using plan contract + architecture §"Library Public API Surface".

- **`XofReader`** — ⚠ UNVERIFIED
  - Target location: `test/signers/mldsa-encoding.ts` (or sibling export site; implementer discretion so long as the surface is re-exported from `mldsa-encoding.ts`)
  - Plan signature (from architecture §"`test/signers/mldsa-encoding.ts` (refactored)"):
    ```ts
    export interface XofReader {
      readonly id: "shake128" | "shake256" | "keccak-prg";   // named discriminant (M-3)
      xof(length: number): Uint8Array;                        // stateful; may be called repeatedly
    }
    ```

- **`XofFactory`** — ⚠ UNVERIFIED
  - Target location: same as `XofReader`.
  - Plan signature: `export type XofFactory = (seed: Uint8Array) => XofReader;`
  - **No default parameter on `preparePublicKeyForDeployment`** — DD-10 LOCKED: defaults re-introduce hidden XOF state and silently mask AC-A-1 violations. Factory is a **required** parameter.

- **`shake128XofFactory`, `shake256XofFactory`, `keccakXofFactory`** — ⚠ UNVERIFIED
  - Target location: `test/signers/mldsa-encoding.ts` or `test/signers/xof-adapters.ts` (implementer discretion — see Dev Notes §"Adapter location"). Adapters exported from whichever file holds the types so the import graph stays shallow.
  - Plan semantics:
    ```ts
    // NIST adapters — wrap noble `shake{128,256}.create().update(seed)`
    export const shake128XofFactory: XofFactory = (seed) => ({
      id: "shake128",
      xof: /* buf of length n via shake128.create().update(seed).xofInto */,
    });
    export const shake256XofFactory: XofFactory = (seed) => ({
      id: "shake256",
      xof: /* same, shake256 */,
    });
    // ETH adapter — wrap Story 2 Keccak-PRG
    export const keccakXofFactory: XofFactory = (seed) => {
      const p = createKeccakPrg(seed);
      p.flip();
      return { id: "keccak-prg", xof: (n) => p.extract(n) };
    };
    ```
  - Each factory call returns a **fresh** `XofReader` — the SHAKE adapter creates a new noble `shake{128,256}` instance each call; the Keccak adapter constructs a fresh `createKeccakPrg(seed); flip()`. No cached state crosses factory calls.

- **`preparePublicKeyForDeployment(rawPk, xofFactory): Hex`** — ⚠ UNVERIFIED (refactored signature)
  - Target location: `test/signers/mldsa-encoding.ts` (refactored in-place, replacing the current `ec082d1...` version).
  - Plan signature: `function preparePublicKeyForDeployment(rawPk: Uint8Array, xofFactory: XofFactory): Uint8Array` — note the plan says `Uint8Array` return; current implementation returns `Hex`. **Keep `Hex`** — breaking the return-type would cascade into `test/fixtures/mldsa.ts` and defeat AC-D-1 ("existing NIST suite byte-identical"). The plan's `Uint8Array` is advisory-shape; hex vs bytes is the same underlying data, viem idiom is hex. Refactored signature:
    ```ts
    export function preparePublicKeyForDeployment(
      rawPublicKey: Uint8Array,
      xofFactory: XofFactory,
    ): Hex;
    ```

- **`keygen(): Keypair`** (production surface) — ⚠ UNVERIFIED
  - Target location: `test/signers/ml-dsa-eth.ts` (NEW file, same shape as `test/signers/ml-dsa.ts`)
  - Plan signature: `function keygen(): Keypair` where `Keypair = { publicKey: Uint8Array; secretKey: Uint8Array }` (re-exported from `test/signers/index.ts:16`).
  - Behavior: internally generates `ζ` via `crypto.getRandomValues(new Uint8Array(32))` (Node 24 built-in Web Crypto — no polyfill); passes ζ to the forked keygen core driven by `keccakXofFactory`.
  - **Do NOT import from `ml-dsa-eth.kat-internal.ts`** — production and KAT surfaces must share the forked keygen core via a third (implementer-chosen) internal module OR via noble-fork's exported helper. The grep boundary (AC-3-7) forbids `ml-dsa-eth.ts` → `ml-dsa-eth.kat-internal.ts` imports from `test/signers/index.ts` + `test/bench/**`, but architecture §"KAT helpers live in a sibling module" strongly implies `ml-dsa-eth.ts` itself should also avoid the kat-internal dependency to keep the boundary trivially enforceable. The shared core (e.g., `keygenWithXof(zeta, xofFactory)`) lives in the forked noble module or a co-located `ml-dsa-eth.core.ts`.

- **`keygenInternal(zeta: Uint8Array): Keypair`** (KAT-only surface) — ⚠ UNVERIFIED
  - Target location: `test/signers/ml-dsa-eth.kat-internal.ts` (NEW file)
  - Plan signature: `function keygenInternal(zeta: Uint8Array): Keypair` — explicit ζ parameter so KAT tests can replay exact `.rsp` byte sequences.
  - Imported ONLY by `test/signers/ml-dsa-eth.keygen.kat.test.ts` (and any future G1 test variants). Never imported from `test/signers/index.ts` or `test/bench/**` — AC-3-7 grep-enforceable boundary.

- **Frozen NIST regression fixture** — ⚠ UNVERIFIED
  - Target location: `test/fixtures/kat/nist-regression/vectors.json`
  - Format: ~100 records of `{ id, pk: "0x..." (1312 B), expectedReshapedPk: "0x..." }` — captured by running the **pre-refactor** `preparePublicKeyForDeployment(pk)` against every `pk` in `PQCsignKAT_Dilithium2.rsp`. Frozen before Task 2's refactor begins. Schema deliberately minimal (no submodule SHA — this fixture is a local pre-refactor golden, independent of the ZKNox submodule drift check). Post-refactor code asserts `preparePublicKeyForDeployment(pk, shake256XofFactory) === expectedReshapedPk` byte-for-byte; any mismatch triggers the refactor-rollback protocol (architecture §"Error Handling Strategy").

## Dev Notes

### Architecture context (inlined — correctness-critical)

**DD-10 LOCKED — parameterize-by-factory (architecture §"Design Rationale").** Every XOF call-site takes an `XofFactory` and constructs a **fresh** `XofReader` locally via `xofFactory(seed)`. Applies to the noble fork (keygen + sign) AND `mldsa-encoding.ts`.

Rejected alternatives (do not reintroduce):
- **Wrap-and-override with module-level factory state** — violates AC-A-1 HIGH (source-level `let _xof` / `var _xof` → fail).
- **One-shot `(seed, outLen) => bytes` signature** — rejection-sampling call-sites (`rejectionSamplePoly`, noble's `RejNTTPoly`, `RejBoundedPoly`, ExpandMask, SampleInBall) pull bytes in multiple chunks from a single seeded instance with unpredictable total length. One-shot forces over-allocation or semantic divergence. Python ref `_keygen_internal` / `_sign_internal` take `_xof, _xof2` *classes* instantiated per call-site — factory preserves that semantic in TypeScript.

**AC-A-1 enforcement grep (Gate 5 #3):** After refactor lands, `grep -nE '^(let|var) _?xof' test/signers/mldsa-encoding.ts test/signers/ml-dsa-eth.ts test/signers/ml-dsa-eth.kat-internal.ts test/signers/xof-adapters.ts` (and any sibling module introduced by this story) must return zero hits. The grep run from the story's Gate 5 DoD — the AC-3-2 acceptance surface.

**Amendment A-001 applies (LOAD-BEARING for this story).** `docs/amendments.md` §A-001 amends DD-7: `reshapedPublicKey` ABI is `abi.encode(bytes aHatEncoded, bytes tr, bytes t1Encoded)` with `tr` = 64 B (variable-length `bytes`, not `bytes32`). The refactored `preparePublicKeyForDeployment` emits this amended tuple shape. The existing `mldsa-encoding.ts:194-197` already ABI-encodes as `(bytes, bytes, bytes)` with `bytesToHex(tr)` (where `tr` is the 64-byte output of `shake256(publicKey, { dkLen: TR_BYTES=64 })`); Story 3's refactor preserves the amended shape while parameterizing the XOF that produces `tr`.

For the NIST path, `tr` remains 64 B via SHAKE-256 (identical bytes to pre-refactor — AC-D-1 / AC-3-3 guarantee). For the ETH path (downstream Story 5 G3), `tr` is 64 B via Keccak-PRG stream. Both paths produce the same ABI tuple shape; only the `tr` bytes differ between variants.

**M-1 resolution — KAT helpers in a sibling module (architecture §"Library Public API Surface").** Production surface `ml-dsa-eth.ts` exports `keygen()` (and Story 4 adds `signUserOp`). KAT-only helpers `keygenInternal(zeta)` (and Story 4 adds `signWithRnd`) live in `ml-dsa-eth.kat-internal.ts`. This converts the "do not call `signWithRnd`/`keygenInternal` from production" rule from prose discipline into a **grep-enforceable boundary** (AC-3-7).

The boundary:
- `test/signers/index.ts` — MUST NOT import from `ml-dsa-eth.kat-internal.ts`.
- `test/bench/**/*.ts` — MUST NOT import from `ml-dsa-eth.kat-internal.ts`.
- G1/G2 KAT test files — ARE PERMITTED (they are not production dispatchers).

**M-3 resolution — `@delta-from-ml-dsa` module-header JSDoc (AC-3-6).** Both `ml-dsa-eth.ts` and `ml-dsa-eth.kat-internal.ts` MUST begin with a JSDoc block that includes a `@delta-from-ml-dsa` section enumerating byte-level differences from `test/signers/ml-dsa.ts`:

1. **XOF:** Keccak-PRG (this module) vs SHAKE-128 (ExpandA) / SHAKE-256 (ExpandS, ExpandMask, H, G, tr) in `ml-dsa.ts` / `mldsa-encoding.ts`. Byte-identical seeds produce **different** outputs — keys generated under Keccak-PRG are NOT interchangeable with keys generated under SHAKE.
2. **Fork scope:** Noble's `ml_dsa44` is forked at BOTH keygen + sign (Python ref `_keygen_internal` and `_sign_internal` both take `_xof, _xof2` params). Story 3 delivers the keygen side; Story 4 delivers the sign side.
3. **pk-transform factory argument:** `mldsa-encoding.ts#preparePublicKeyForDeployment` is XOF-parameterized post-refactor. ETH path passes `keccakXofFactory`; NIST path passes `shake256XofFactory`.
4. **ctx handling:** ETH path uses `ctx = 0x` (empty bytes) to match `generate_KAT_example.py` and the `.rsp` convention. (Informational for Story 3; exercised by Story 4 sign path.)
5. **Signature layout:** Downstream Story 4 — same 32 cTilde + 2304 z + 84 h = 2420 B as NIST, but cTilde is a Keccak-256 digest, not SHAKE-256. (Informational for Story 3.)

**M-3 resolution (continued) — XofReader `id` discriminant (AC-3-4).** The shared test helper `assertBytesEqual` (architecture §"Shared helpers") accepts an optional `xofId?: string` parameter; on byte divergence, the error message interpolates `(factory=<xofId>)` so interleaved-XOF bugs have a grep-friendly anchor. Implementer action: if `assertBytesEqual` does not yet exist (Story 1 did not introduce it — Story 2 used `assert.equal`), Story 3 Task 2 lands it at `test/utils/assert-bytes.ts` with the signature `(actual: Uint8Array, expected: Uint8Array, label: string, xofId?: string): void`, printing first-divergent byte + ±8 B context + the `(factory=...)` tag when provided. If the helper already exists without `xofId`, extend it.

**XOF call-site reconciliation (refactor surface enumerated from current `mldsa-encoding.ts`).**

Pre-refactor call-sites (current, hash `ec082d1...`):

| Call-site | Line | Current | Post-refactor (NIST caller) | Post-refactor (ETH caller) |
|-----------|------|---------|-----------------------------|----------------------------|
| `rejectionSamplePoly` (A_hat inner loop) | 45-53 | `shake128.create().update(seed); xof.xofInto(buf)` | `const reader = xofFactory(seed); buf = reader.xof(3*64)` (factory = `shake128XofFactory` on NIST path) | factory = `keccakXofFactory` |
| `decodePublicKey` (`tr` 64 B) | 103 | `shake256(publicKey, { dkLen: TR_BYTES })` | `xofFactory(publicKey).xof(TR_BYTES)` (factory = `shake256XofFactory`) | factory = `keccakXofFactory` |

**One factory OR two?** The architecture's NIST adapters provide both `shake128XofFactory` and `shake256XofFactory` — ExpandA (row/col rejection sampling) uses SHAKE-128 per FIPS 204; H / G / tr use SHAKE-256. The refactored `preparePublicKeyForDeployment` accepts a **single** `xofFactory` argument per the plan/architecture signature — meaning for the NIST path, one adapter must serve both shake128 and shake256 call-sites, OR the signature must accept two factories (`xofFactoryForExpandA`, `xofFactoryForH`). Architecture §"Library Public API Surface" shows a single `xofFactory` param. **Resolution:** use one factory for both call-sites in the ETH path (Keccak-PRG is used for every XOF in the ETH variant per DD-1) and rely on the `id` discriminant for divergence diagnostics. For the NIST path, pass `shake256XofFactory` and internally branch: the two NIST call-sites use different SHAKE variants, but since `mldsa-encoding.ts` already hard-codes `shake128` at line 45 and `shake256` at line 103 inside the module body, the factory argument can be **ignored at the `rejectionSamplePoly` SHAKE-128 site for the NIST path** (continue using `shake128.create()`) and **used only at the `tr` site** — with an internal check: if `xofFactory === shake256XofFactory`, use native SHAKE hard-coded; otherwise use the factory. This is ugly; a cleaner alternative is to pass **both** factories to the refactored function (`preparePublicKeyForDeployment(rawPk, xofFactoryA, xofFactoryH)`) matching Python ref's `_xof, _xof2` shape, but that diverges from the plan/architecture single-factory signature.

**DECISION (implementer-facing):** Task 2 implements the single-factory signature per plan/architecture. The factory is invoked at BOTH call-sites (not branched by SHAKE variant). This is byte-semantically correct for the ETH path (one XOF = Keccak-PRG throughout). For the NIST path, it means the `rejectionSamplePoly` call-site switches from `shake128` to `shake256` — which WILL produce different A_hat bytes for the same `rho`, breaking byte-identity of `aHatEncoded` in the reshaped pk. **This is wrong for AC-D-1.** Resolution: accept **two** factories as a Rule 3 amendment to the architecture (`preparePublicKeyForDeployment(rawPk, xofFactoryExpandA, xofFactoryH)`), or equivalently accept an object `{ expandA, h }`. Log this as a Rule 3 amendment in `docs/amendments.md` (Task 2 work) — a second amendment after A-001. Naming suggestion: `A-002: Refactored preparePublicKeyForDeployment takes two XOF factories (ExpandA + H), not one`.

> **Implementer note:** the signature shape is a Rule 3 escalation — coordinate with the user at Task 2 kickoff. Recommended shape: `preparePublicKeyForDeployment(rawPk, xofFactoryExpandA, xofFactoryH): Hex`. The `id`-discriminant surface still works with two factories (both `XofReader`s have `id`). Alternative single-factory with `outLen`-aware internal routing is possible but fragile.

**Adapter location.** Adapters can live in one of three places:
1. Same file (`mldsa-encoding.ts`) — smallest surface; keeps imports shallow. Rec.
2. Sibling file (`xof-adapters.ts`) — cleaner boundary; adds one file.
3. Co-located with primitive (`keccak-prg.ts` exports `keccakXofFactory`, noble-wrapper exports SHAKE adapters) — diffusion; hurts discoverability.

Recommend option 1 unless `mldsa-encoding.ts` crosses 300 lines post-refactor; then option 2. Option 3 is not recommended.

**Refactor rollback protocol (AC-3-3, architecture §"Error Handling Strategy").** On any post-refactor byte-identity mismatch against the frozen 100-vector NIST fixture: **HALT**, bisect (which of the 100 vectors diverged? which XOF call-site?), or revert-and-retry on a fresh branch. AC-D-1 (existing ML-DSA suite byte-identical) is a **blocking post-condition** — the encoding module does NOT land until both (a) the 100-vector NIST regression passes AND (b) the full NIST `MlDsaAccount` test suite passes byte-for-byte. Do not proceed to Task 3 (noble keygen fork) until Task 2 (refactor) is 100-vector-green.

**ESLint / boundary-enforcement strategy (AC-3-7).** The project **has no ESLint configuration today** (no `.eslintrc*`, no `eslint.config.*`, no `eslint` in `package.json` devDependencies). Rather than bootstrapping a full ESLint setup for one rule (incurring Rule 2 config deviation and extending Story 3's scope beyond the plan's ~230 LOC budget), implement AC-3-7 via **belt-and-suspenders runtime grep** as the minimum-viable enforcement:

- A unit test in `test/signers/ml-dsa-eth.test.ts` (or equivalent) reads the source tree at runtime (`node:fs.readdirSync` recursive), filters for `test/signers/index.ts` + files under `test/bench/**/*.ts`, and asserts that no file's content matches `/from\s+["'].*ml-dsa-eth\.kat-internal.*["']/`. Failure = test fail = Gate 5 blocks.
- Additionally, leave a block comment in `ml-dsa-eth.kat-internal.ts` top-of-file warning maintainers: "KAT-only — NEVER import from `test/signers/index.ts` or `test/bench/**`. Boundary asserted by `test/signers/ml-dsa-eth.test.ts`."

If/when ESLint lands in a future story, migrate the assertion to `no-restricted-imports`. Log the deviation in `docs/amendments.md` as a Rule 2 moderate deviation (`A-003: AC-3-7 ESLint substitution — runtime grep assertion in lieu of ESLint config until project-wide ESLint is adopted`). Story 3 Task 3 creates this amendment alongside the test.

### Behavioral requirements (inlined from plan + architecture)

- **Pre-refactor capture MUST commit before Task 2 begins (AC-3-3 sequencing).** The 100-vector NIST fixture is the safety net for the refactor. If the capture script runs AFTER the refactor, the regression is meaningless — the captured outputs would already reflect the refactored code. Task 1 produces + commits the fixture; Task 2 cannot start until that commit lands.
- **No module-level XOF state (AC-3-2 / AC-A-1 HIGH).** Every XOF call-site constructs a fresh `XofReader` via `xofFactory(seed)` at call-time. No cached readers, no module-scoped `let _xof`, no top-level `const _factoryInstance = ...` holding a pre-constructed reader. Grep gate at Gate 5.
- **Interleaved XOF-isolation test (AC-3-5).** Single test that reshapes the SAME `pk` with SHAKE factory → Keccak factory → SHAKE factory in ONE process. Each reshape output must match its own golden (NIST fixture from the AC-3-3 capture for SHAKE; Story 1's `reshapedPublicKey` field for Keccak). Proves no cross-contamination even when both factories are alive in the same V8 instance. Recommended placement: `test/signers/mldsa-encoding.xof-isolation.test.ts` (new).
- **No new runtime dependencies.** `package.json` `dependencies` stays empty. `@noble/post-quantum` and `@noble/hashes` already present (devDependency). If noble's internal `ml-dsa.js` cannot be forked in-tree (e.g., it relies on package-internal `_crystals.js` that's already imported at `mldsa-encoding.ts:2`), copy the relevant keygen function bodies into `test/signers/ml-dsa-eth.core.ts` and replace XOF call-sites with factory invocations — matches Story 2's "port, don't patch" approach.
- **Use `crypto.getRandomValues(new Uint8Array(32))` for production `keygen()` ζ.** Node v24.13.1 exposes Web Crypto API globally (no `import { webcrypto } from 'node:crypto'` needed). Verified: `globalThis.crypto.getRandomValues` is available; matches project convention (no other `keygen` in the repo consumes randomness today — ECDSA uses viem, Falcon uses noble's internal; both obscure the entropy source). The ETH keygen is the first direct `getRandomValues` caller; lock the idiom here.
- **Production `keygen()` MUST NOT import `keygenInternal`.** Both share the forked keygen core (`keygenWithXof(zeta, xofFactory)` or equivalent) living in `ml-dsa-eth.core.ts` or directly inline. This keeps `ml-dsa-eth.kat-internal.ts` importable only by KAT tests, preserving the grep boundary. Alternative shapes are acceptable (e.g., both files re-export from a shared core) so long as the `kat-internal` module is NOT on the import graph of `index.ts` or `test/bench/**`.
- **Test runner.** `node:test` + `node:assert/strict` for the G1 KAT + interleaved-isolation + params-const tests (non-Hardhat tiers). Story 2 Pattern applies — `import hre from "hardhat"; const { viem } = await hre.network.connect();` only if a test requires EVM state (none of Story 3's tests do).
- **Hex / byte I/O.** viem `hexToBytes` / `bytesToHex` — established project convention (Story 2 `Detected Patterns`).
- **No `!` non-null assertions in production code.** Allowed in test files only (`.claude/rules/nodejs.md`).

### File-tree effects (expected — non-binding)

New files:
- `scripts/capture-nist-regression.ts` (pre-refactor capture script; ~60 LOC)
- `test/fixtures/kat/nist-regression/vectors.json` (generated artifact, committed; ~100 vectors × 1312 B + ~20 KB reshaped ≈ large but bounded)
- `test/signers/ml-dsa-eth.ts` (production surface; ~40 LOC — thin wrapper around `keygenWithXof`)
- `test/signers/ml-dsa-eth.kat-internal.ts` (KAT surface; ~20 LOC — thin wrapper)
- `test/signers/ml-dsa-eth.core.ts` OR equivalent shared-core module (forked noble keygen; ~120 LOC)
- `test/signers/xof-adapters.ts` (OR inline in `mldsa-encoding.ts`; ~30 LOC)
- `test/signers/ml-dsa-eth.test.ts` (boundary grep test + params-const test + interleaved-isolation test; ~40 LOC)
- `test/signers/ml-dsa-eth.keygen.kat.test.ts` (G1 byte-identity; ~25 LOC)
- `test/signers/mldsa-encoding.nist-regression.test.ts` (AC-3-3 post-refactor assertion; ~20 LOC)
- `test/utils/assert-bytes.ts` (shared helper if not already present; ~20 LOC)

Modified files:
- `test/signers/mldsa-encoding.ts` (refactor — XOF-factory params, amendment A-001 `tr` shape preserved)
- `test/fixtures/mldsa.ts` (migrate `preparePublicKeyForDeployment(rawPublicKey)` call at line 49 → pass `shake128XofFactory` + `shake256XofFactory` / whatever the amendment A-002 signature is)
- `docs/amendments.md` (add A-002 for refactored signature; add A-003 for ESLint substitution)

Package files: no additions to `dependencies`; `devDependencies` unchanged.

### Library versions (verified at story creation, 2026-04-17; unchanged from Stories 1-2)

- `viem@^2.43.0`, `hardhat@3.3.0`, `typescript@^5.9.3`, Solidity `0.8.34`, Node `v24.13.1`.
- `@noble/post-quantum@^0.6.1` — the fork target; `node_modules/@noble/post-quantum/ml-dsa.js:344` contains the keygen reference flow (lines 344-397).
- `@noble/hashes` — transitive via `@noble/post-quantum`; source of `shake128` / `shake256`. Already imported by `mldsa-encoding.ts:1`.
- No new runtime or dev dependencies introduced.

## Tasks

- [x] **Task 1: Pre-refactor NIST regression capture** (AC-D-2 safety net; MUST commit before Task 2)
  - AC: AC-3-3 (capture half — frozen fixture)
  - Files: `scripts/capture-nist-regression.ts` (new; ~60 LOC), `test/fixtures/kat/nist-regression/vectors.json` (new; ~100 vectors)
  - Dependencies: none — runs against pre-refactor `mldsa-encoding.ts` (hash `ec082d1...`)
  - Why: This task is the safety net for the entire story. The 100-vector NIST fixture captures the pre-refactor byte-level output of `preparePublicKeyForDeployment(pk)` (no factory arg — current signature) for every `pk` in `ETHDILITHIUM/pythonref/assets/PQCsignKAT_Dilithium2.rsp` (100 vectors verified by `grep -c '^count = '`). **If this fixture is not committed before Task 2 starts, the regression is meaningless** (post-refactor captures would reflect the refactored code, not the pre-refactor baseline). Concretely:
    1. Parse `PQCsignKAT_Dilithium2.rsp` (format: `count = N\nseed = 0x...\nmlen = M\nmsg = ...\npk = 0x...\nsk = 0x...\nsmlen = ...\nsm = ...` blocks separated by blank lines). Extract `(count, pk)` pairs. Hex → `Uint8Array` (1312 B per `pk`).
    2. For each `(count, pk)`: invoke the **current** `preparePublicKeyForDeployment(pk)` (no factory arg — pre-refactor signature). Collect `(id: "nist-vec-{count:03d}", pk: "0x...", expectedReshapedPk: "0x...")`.
    3. Serialize deterministically (stable key order, 2-space indent, `\n` line endings, lowercase hex with `0x` prefix; NO `generatedAt` timestamp — it would cause spurious diffs; NO `submoduleSha` — this fixture is a pre-refactor local golden, independent of submodule drift). Top-level shape: `{ "scheme": "nist-dilithium2-pre-refactor", "vectorCount": 100, "vectors": [...] }`.
    4. Commit BOTH the script and the fixture in a single commit titled `chore(story-3): capture pre-refactor NIST regression fixture (AC-3-3)`. Tag `pre-mldsa-eth-3` goes BEFORE this commit per `.claude/rules/code-standards.md` §"Tagging Protocol".

- [x] **Task 2: `mldsa-encoding.ts` XOF-factory refactor + SHAKE/Keccak adapters + post-refactor NIST regression assertion**
  - AC: AC-3-2 (no module-level state — grep gate), AC-3-3 (post-refactor assertion half), AC-3-4 (id discriminant — adapter shape + `assertBytesEqual` helper), AC-3-5 (interleaved XOF-isolation)
  - Files: `test/signers/mldsa-encoding.ts` (refactor in-place), `test/signers/xof-adapters.ts` (new; OR inline in `mldsa-encoding.ts` if shorter — implementer discretion per Dev Notes §"Adapter location"), `test/utils/assert-bytes.ts` (new or extend), `test/fixtures/mldsa.ts` (migrate caller at line 49), `test/signers/mldsa-encoding.nist-regression.test.ts` (new; ~20 LOC), `test/signers/mldsa-encoding.xof-isolation.test.ts` (new; ~30 LOC), `docs/amendments.md` (add A-002 for two-factory signature)
  - Dependencies: Task 1 (frozen fixture must exist on disk before this task's tests run)
  - Why: The load-bearing refactor. Concretely:
    1. **Add `XofReader` + `XofFactory` types** to `mldsa-encoding.ts` (exported). See Verified Interfaces §"Produced" for exact shapes.
    2. **Implement adapters:**
       - `shake128XofFactory: XofFactory` — wraps `shake128.create().update(seed)`. Each `xof(n)` call invokes `xofInto(new Uint8Array(n))` (noble's streaming API — confirm against `@noble/hashes/sha3.js`; the `xofInto` name is used at `mldsa-encoding.ts:53` today).
       - `shake256XofFactory: XofFactory` — same pattern with `shake256`.
       - `keccakXofFactory: XofFactory` — `const p = createKeccakPrg(seed); p.flip(); return { id: "keccak-prg", xof: (n) => p.extract(n) };`.
    3. **Refactor `preparePublicKeyForDeployment` signature.** Per Dev Notes §"XOF call-site reconciliation" DECISION, propose **two-factory signature** to the user and log as amendment A-002: `function preparePublicKeyForDeployment(rawPk: Uint8Array, xofFactoryExpandA: XofFactory, xofFactoryH: XofFactory): Hex`. Migrate `rejectionSamplePoly` (line 45) to use `xofFactoryExpandA`; migrate `decodePublicKey`'s `tr` computation (line 103) to use `xofFactoryH`.
    4. **Migrate the single existing caller** at `test/fixtures/mldsa.ts:49`: `const encoded = preparePublicKeyForDeployment(rawPublicKey, shake256XofFactory, shake128XofFactory);`. After this line is migrated, run `npm test` against the existing NIST `MlDsaAccount` test suite — AC-D-1 requires byte-identical pass.
    5. **Add `test/utils/assert-bytes.ts`** with signature `assertBytesEqual(actual: Uint8Array, expected: Uint8Array, label: string, xofId?: string): void`. On divergence, print first-divergent byte index + ±8 B context; append `(factory=<xofId>)` when `xofId` is provided (AC-3-4 — the `id` discriminant surfaces here).
    6. **Write `mldsa-encoding.nist-regression.test.ts`** that reads `test/fixtures/kat/nist-regression/vectors.json` (the Task 1 artifact) and asserts `preparePublicKeyForDeployment(pk, shake256XofFactory, shake128XofFactory) === expectedReshapedPk` byte-for-byte for all 100 vectors. On mismatch, HALT per refactor-rollback protocol.
    7. **Write `mldsa-encoding.xof-isolation.test.ts`** (AC-3-5) that reshapes the same `pk` (any fixture from `loadKatVectors("mldsa-eth")` — use vector 01) with `(shake128/shake256)` → `(keccak/keccak)` → `(shake128/shake256)` factories in interleaved order within one `it` block. Assert each reshape against its own golden (NIST fixture for SHAKE passes; the fixture's `reshapedPublicKey` field for the Keccak pass). Using the same `pk` input proves no cross-contamination.
    8. **Grep gate (AC-3-2 / AC-A-1 HIGH):** before commit, run `grep -nE '^(let|var) _?xof' test/signers/mldsa-encoding.ts test/signers/xof-adapters.ts` — must return zero hits.

- [x] **Task 3: Noble keygen fork + `ml-dsa-eth.ts` + `ml-dsa-eth.kat-internal.ts` + ESLint boundary + params-const test**
  - AC: AC-3-6 (`@delta-from-ml-dsa` module header), AC-3-7 (boundary enforcement — runtime grep per Dev Notes §"ESLint / boundary-enforcement strategy"), AC-3-8 (ML-DSA-44 params constants)
  - Files: `test/signers/ml-dsa-eth.core.ts` (new shared forked keygen; ~120 LOC), `test/signers/ml-dsa-eth.ts` (new production surface; ~40 LOC), `test/signers/ml-dsa-eth.kat-internal.ts` (new KAT surface; ~20 LOC), `test/signers/ml-dsa-eth.test.ts` (new boundary + params + interleaved tests co-location; ~40 LOC), `docs/amendments.md` (add A-003 for ESLint substitution)
  - Dependencies: Task 2 (needs `keccakXofFactory` + refactored `preparePublicKeyForDeployment` — not called from keygen itself, but shared XOF-factory types; needs `shake256XofFactory` for no reason here except type consistency)
  - Why: Keygen is the G1 deliverable. Concretely:
    1. **Fork noble's ml-dsa keygen.** The reference flow is `node_modules/@noble/post-quantum/ml-dsa.js:344-397` (the `keygen: (seed) => { ... }` function inside the `internal` object). Copy the body into `ml-dsa-eth.core.ts` and replace:
       - `const [rho, rhoPrime, K_] = seedCoder.decode(shake256(seedDst, { dkLen: seedCoder.bytesLen }));` (`:356`) → `const expansionStream = xofFactory(seedDst).xof(seedCoder.bytesLen); const [rho, rhoPrime, K_] = seedCoder.decode(expansionStream);`
       - `const xofPrime = XOF256(rhoPrime);` (`:357`) → Keccak factory driven per-`(i,j)` seed; the noble `XOF256` helper wraps shake256 internally — replicate its interface (`.get(i, j)` returns a reader) backed by `xofFactory(rhoPrime ‖ uint16_le(i) ‖ uint16_le(j))`.
       - `const xof = XOF128(rho);` (`:367`) → same, factory-backed reader over `rho ‖ uint16_le(j) ‖ uint16_le(i)` (note row/col order — Python ref `_expand_matrix_from_seed` uses `rho ‖ j ‖ i` per architecture §DD-11 §"ML-DSA-shaped seed"). Verify noble's byte order matches Python's at fork time — byte-mismatch here WILL fail AC-3-1.
       - `const tr = shake256(publicKey, { dkLen: TR_BYTES });` (`:382`) → `xofFactory(publicKey).xof(TR_BYTES)`.
       Export a single core function: `export function keygenWithXof(zeta: Uint8Array, xofFactory: XofFactory): Keypair`. Story 4 will consume the analogous `signWithXof(sk, msg, rnd, ctx, xofFactory)` from the sign fork.
    2. **Implement `ml-dsa-eth.ts`** (production). Module header starts with JSDoc containing `@delta-from-ml-dsa` section (enumerate the 5 differences listed in Dev Notes §"M-3 resolution — `@delta-from-ml-dsa`"). Body:
       ```ts
       import { keygenWithXof } from "./ml-dsa-eth.core.js";
       import { keccakXofFactory } from "./mldsa-encoding.js"; // or xof-adapters.js
       export function keygen(): Keypair {
         const zeta = new Uint8Array(32);
         crypto.getRandomValues(zeta);
         return keygenWithXof(zeta, keccakXofFactory);
       }
       ```
       (Story 4 extends this module with `signUserOp`.) **MUST NOT** import from `ml-dsa-eth.kat-internal.ts`.
    3. **Implement `ml-dsa-eth.kat-internal.ts`.** Module header starts with JSDoc containing `@delta-from-ml-dsa` + "kat-internal boundary" paragraph ("KAT-only — NEVER imported from `test/signers/index.ts` or `test/bench/**`. Boundary asserted by `test/signers/ml-dsa-eth.test.ts` via runtime grep."). Body:
       ```ts
       import { keygenWithXof } from "./ml-dsa-eth.core.js";
       import { keccakXofFactory } from "./mldsa-encoding.js";
       export function keygenInternal(zeta: Uint8Array): Keypair {
         if (zeta.length !== 32) throw new Error(`keygenInternal: zeta must be 32 bytes, got ${zeta.length}`);
         return keygenWithXof(zeta, keccakXofFactory);
       }
       ```
    4. **Write `ml-dsa-eth.test.ts`** covering:
       - **AC-3-7 boundary test** (runtime grep per Dev Notes §"ESLint / boundary-enforcement strategy"): read `test/signers/index.ts` + all files under `test/bench/` via `fs.readdirSync(..., { recursive: true })`; assert `/from\s+["'][^"']*ml-dsa-eth\.kat-internal/` matches none of them. If `test/bench/` does not exist at this story's creation, the test covers that part trivially (zero-match assertion against an empty file list).
       - **AC-3-8 params-const test**: import the `(K, L, D, GAMMA1, GAMMA2, TAU, ETA, OMEGA)` constants from `ml-dsa-eth.core.ts` (or wherever they land); assert each equals its expected literal tuple value (k=4, l=4, η=2, γ₁=2¹⁷=131072, γ₂=95232, τ=39, ω=80). Compute `BETA = TAU * ETA`; assert `BETA === 78`. Divergence from any literal fails the test.
       - **AC-3-6 @delta-from-ml-dsa assertion**: optional — grep-assert that `ml-dsa-eth.ts` + `ml-dsa-eth.kat-internal.ts` source contains the literal `@delta-from-ml-dsa` tag (read file, `.includes("@delta-from-ml-dsa")`). Cheap and catches header-comment drift.
    5. **Log A-003 amendment** in `docs/amendments.md`: "AC-3-7 ESLint substitution — runtime grep assertion in `test/signers/ml-dsa-eth.test.ts` until project-wide ESLint is adopted. Rule 2 moderate deviation: project currently has no `.eslintrc*` / `eslint.config.*`; bootstrapping ESLint for one rule exceeds Story 3's scope."

- [ ] **Task 4: G1 KAT byte-identity test**
  - AC: AC-3-1 (G1 keygen byte-identity — primary and sole)
  - Files: `test/signers/ml-dsa-eth.keygen.kat.test.ts` (new; ~25 LOC)
  - Dependencies: Tasks 1-3 (needs the forked keygen, the kat-internal surface, and the ML-DSA-ETH KAT fixtures from Story 1)
  - Why: G1 is the byte-identity gate that proves the noble-keygen fork is correct. Without this, Story 4's signer work is building on unverified ground. Concretely:
    - `import { loadKatVectors } from "../fixtures/kat/index.js";`
    - `import { keygenInternal } from "./ml-dsa-eth.kat-internal.js";`
    - `const vectors = loadKatVectors("mldsa-eth");`  ← 100 vectors per Story 1 AC-1-1
    - For each vector: `const { publicKey, secretKey } = keygenInternal(hexToBytes(v.zeta));` assert `bytesToHex(publicKey) === v.publicKey` AND `bytesToHex(secretKey) === v.secretKey`. Use `assertBytesEqual(publicKey, hexToBytes(v.publicKey), \`vec ${v.id} pk\`, "keccak-prg")` + same for sk — the `xofId` discriminant surfaces the XOF name on any divergence (AC-3-4 helper).
    - No Hardhat required — pure-JS `node:test`.
    - Cost: 100 keygen iterations is slow (noble keygen is ~150 ms each per `ml-dsa.js:388` STATS comment — DSA44 performs 24 XOF calls per keygen). Total ~15 s. Acceptable for `npm test`; not a CI bottleneck.

## Definition of Done (Gate 5 criteria — Story 3)

Beyond standard Gate 5 (format + lint + build + test + test integrity + security — `.claude/rules/code-standards.md` §2 "Verification Loop"):

1. **Frozen pre-refactor NIST fixture exists and is stable.** `test/fixtures/kat/nist-regression/vectors.json` committed BEFORE Task 2's refactor began. Exactly 100 vectors, each with `(id, pk, expectedReshapedPk)`. Re-running `npx tsx scripts/capture-nist-regression.ts` AFTER Task 2 produces a `git diff` — deliberately. The committed fixture reflects the pre-refactor baseline. [AC-3-3 half 1]
2. **Post-refactor NIST regression passes.** `npx hardhat test test/signers/mldsa-encoding.nist-regression.test.ts` — all 100 vectors byte-identical between `preparePublicKeyForDeployment(pk, shake256XofFactory, shake128XofFactory)` output and the frozen fixture's `expectedReshapedPk`. [AC-3-3 half 2]
3. **Existing NIST `MlDsaAccount` suite passes byte-for-byte.** `npx hardhat test test/accounts/mldsa.test.ts` — zero regressions (AC-D-1 blocking post-condition per architecture §"Error Handling Strategy" §"Refactor rollback").
4. **G1 KAT byte-identity passes for all ~100 vectors.** `npx hardhat test test/signers/ml-dsa-eth.keygen.kat.test.ts` — `keygenInternal(v.zeta)` produces `(publicKey, secretKey)` byte-equal to `v.publicKey` and `v.secretKey` for every vector in `loadKatVectors("mldsa-eth")`. [AC-3-1]
5. **AC-A-1 grep gate — zero module-level XOF state.** `grep -nE '^(let|var) _?xof' test/signers/mldsa-encoding.ts test/signers/xof-adapters.ts test/signers/ml-dsa-eth.ts test/signers/ml-dsa-eth.kat-internal.ts test/signers/ml-dsa-eth.core.ts` returns zero hits. Extend the grep to any sibling module introduced by this story. [AC-3-2]
6. **AC-3-7 boundary grep — kat-internal has zero importers outside KAT tests.** `grep -RnE 'from\s+["\047][^"\047]*ml-dsa-eth\.kat-internal' test/signers/index.ts test/bench/ 2>/dev/null` returns zero matches. Additionally, the runtime assertion in `test/signers/ml-dsa-eth.test.ts` passes (executes the same grep in `node:fs` and asserts zero hits). [AC-3-7]
7. **Interleaved XOF-isolation test passes.** `npx hardhat test test/signers/mldsa-encoding.xof-isolation.test.ts` — reshaping the same `pk` with SHAKE → Keccak → SHAKE interleaved in one process produces the correct golden for each variant; each assertion's `assertBytesEqual` call includes the `xofId` (`"shake256"` or `"keccak-prg"`) and would surface a `(factory=<id>)` tag on divergence. [AC-3-5 + AC-3-4]
8. **ML-DSA-44 params-const test passes.** `npx hardhat test test/signers/ml-dsa-eth.test.ts` — `(K, L, D, GAMMA1, GAMMA2, TAU, ETA, OMEGA, BETA)` literals assert `(4, 4, 13, 131072, 95232, 39, 2, 80, 78)`. [AC-3-8]
9. **`@delta-from-ml-dsa` headers present.** Both `test/signers/ml-dsa-eth.ts` and `test/signers/ml-dsa-eth.kat-internal.ts` begin with a JSDoc block containing a `@delta-from-ml-dsa` section (verified by the grep test at Task 3.4.3). Section enumerates the 5 byte-level differences listed in Dev Notes §"M-3 resolution". [AC-3-6]
10. **Amendments logged.** `docs/amendments.md` contains A-002 (two-factory refactored signature) and A-003 (AC-3-7 ESLint substitution) per `.claude/rules/code-standards.md` §4 Rule 3 and Rule 2 respectively.
11. **No new runtime dependencies.** `git diff package.json package-lock.json` — `dependencies` block unchanged.
12. **Zero assertion-free new tests.** Every new `.test.ts` file contains at least one `assert.*` call per `describe`/`it` block. Per `.claude/rules/test-integrity.md` §5 — grep audit at Gate 5.
13. **No silenced tests.** New test files contain no test-suppression annotations or helpers of any form; the entire surface exercised by Story 3 MUST run on every `npm test` invocation. Enforcement is procedural — `.claude/rules/test-integrity.md` §2 prohibits silencing without a tracking reference; VERIFY.md §4 greps for the forbidden tokens mechanically.
14. **All new tests assert on typed discriminants, not message strings.** Error assertions use `err instanceof FooError && err.code === "CODE"` pattern established by Stories 1-2. Byte assertions use `assertBytesEqual` (hex or Uint8Array), never `err.message.includes(...)`.
15. **Task-atomic commits per `.claude/rules/code-standards.md` §1.** Minimum 4 commits matching Task 1 / 2 / 3 / 4. Pre-tag `pre-mldsa-eth-3` before Task 1's first commit; post-tag `post-mldsa-eth-3` after Gate 5 passes. Rule 1 allows minor rider commits when trivial.
16. **`npm run compile` succeeds with zero warnings.** No new Solidity files in this story, but compile must stay clean.

## must_haves

truths:
  - "`preparePublicKeyForDeployment(pk, shake256XofFactory, shake128XofFactory)` post-refactor produces byte-identical output to the frozen NIST regression fixture (`test/fixtures/kat/nist-regression/vectors.json`) for all 100 `PQCsignKAT_Dilithium2.rsp` pks — AC-3-3."
  - "`keygenInternal(hexToBytes(v.zeta))` for `.rsp` vector `v` yields `{ publicKey, secretKey }` with `bytesToHex(publicKey) === v.publicKey` AND `bytesToHex(secretKey) === v.secretKey`, iterated across all ~100 vectors in `loadKatVectors('mldsa-eth')` — AC-3-1."
  - "The `XofFactory` type is `(seed: Uint8Array) => XofReader`; `preparePublicKeyForDeployment` accepts it as a REQUIRED (non-defaulted) parameter per DD-10; `XofReader.id` is the literal union `'shake128' | 'shake256' | 'keccak-prg'` (discriminant for AC-3-4)."
  - "`test/signers/ml-dsa-eth.ts` top-of-file JSDoc contains the literal string `@delta-from-ml-dsa` AND enumerates the 5 byte-level differences (XOF, fork scope, pk-transform factory, ctx, signature layout) from `test/signers/ml-dsa.ts`. Same requirement for `test/signers/ml-dsa-eth.kat-internal.ts` — AC-3-6."
  - "`grep -nE '^(let|var) _?xof' test/signers/mldsa-encoding.ts test/signers/xof-adapters.ts test/signers/ml-dsa-eth.ts test/signers/ml-dsa-eth.kat-internal.ts test/signers/ml-dsa-eth.core.ts` returns zero hits (AC-3-2 / AC-A-1 HIGH)."
  - "`grep -RnE 'from\\s+[\"\\x27][^\"\\x27]*ml-dsa-eth\\.kat-internal' test/signers/index.ts test/bench/` returns zero hits (AC-3-7 runtime boundary)."
  - "Interleaved test in `mldsa-encoding.xof-isolation.test.ts` reshapes NIST and mldsa-eth pks in interleaved SHAKE ↔ Keccak passes in one process. Per `docs/amendments.md` §A-004, the Keccak oracle is pass-to-pass self-consistency (pass 2 ≡ pass 4 across an intervening SHAKE call) rather than the `loadKatVectors('mldsa-eth')[*].reshapedPublicKey` field (Python-format, ABI-shape-different from TS output). SHAKE oracle is the NIST regression fixture's `expectedReshapedPk` for vector 0, asserted at both pass 1 and pass 3 — AC-3-5."
  - "ML-DSA-44 parameter constants in the forked keygen module assert as literals: `K === 4 && L === 4 && D === 13 && GAMMA1 === 131072 && GAMMA2 === 95232 && TAU === 39 && ETA === 2 && OMEGA === 80 && BETA === 78` (BETA = TAU * ETA derived) — AC-3-8."
  - "The single existing caller of `preparePublicKeyForDeployment` at `test/fixtures/mldsa.ts:49` is migrated to pass the two NIST XOF factories; the existing `MlDsaAccount` NIST test suite (`test/accounts/mldsa.test.ts`) passes byte-for-byte post-refactor — AC-D-1 blocking post-condition."
  - "`assertBytesEqual(actual, expected, label, xofId)` divergence message contains the substring `(factory=<xofId>)` when `xofId` is provided — AC-3-4."
  - "Production `keygen()` in `ml-dsa-eth.ts` uses `crypto.getRandomValues(new Uint8Array(32))` to source ζ and does NOT import anything from `ml-dsa-eth.kat-internal.ts`."
  - "`docs/amendments.md` contains entries A-002 (two-factory refactored signature for `preparePublicKeyForDeployment`) and A-003 (ESLint substitution — runtime grep assertion for AC-3-7)."

artifacts:
  - path: "test/signers/mldsa-encoding.ts"
    contains: ["XofReader", "XofFactory", "preparePublicKeyForDeployment", "xofFactory", "shake128", "shake256"]
  - path: "test/signers/ml-dsa-eth.ts"
    contains: ["keygen", "@delta-from-ml-dsa", "keccakXofFactory", "crypto.getRandomValues"]
  - path: "test/signers/ml-dsa-eth.kat-internal.ts"
    contains: ["keygenInternal", "@delta-from-ml-dsa", "kat-internal", "keccakXofFactory"]
  - path: "test/signers/ml-dsa-eth.core.ts"
    contains: ["keygenWithXof", "XofFactory", "K = 4", "L = 4", "TAU", "GAMMA1", "GAMMA2", "OMEGA", "ETA"]
  - path: "test/fixtures/kat/nist-regression/vectors.json"
    contains: ["expectedReshapedPk", "nist-vec-001"]
  - path: "scripts/capture-nist-regression.ts"
    contains: ["PQCsignKAT_Dilithium2.rsp", "preparePublicKeyForDeployment", "expectedReshapedPk"]
  - path: "test/signers/ml-dsa-eth.keygen.kat.test.ts"
    contains: ["keygenInternal", "loadKatVectors", "mldsa-eth", "assertBytesEqual"]
  - path: "test/signers/mldsa-encoding.nist-regression.test.ts"
    contains: ["nist-regression", "preparePublicKeyForDeployment", "shake128XofFactory", "shake256XofFactory"]
  - path: "test/signers/mldsa-encoding.xof-isolation.test.ts"
    contains: ["shake", "keccak", "interleaved", "preparePublicKeyForDeployment"]
  - path: "test/signers/ml-dsa-eth.test.ts"
    contains: ["kat-internal", "from", "131072", "95232", "@delta-from-ml-dsa"]
  - path: "test/utils/assert-bytes.ts"
    contains: ["assertBytesEqual", "factory=", "xofId"]
  - path: "docs/amendments.md"
    contains: ["A-002", "A-003"]

key_links:
  - pattern: "XofFactory"
    in: ["test/signers/mldsa-encoding.ts", "test/signers/ml-dsa-eth.core.ts", "test/signers/ml-dsa-eth.ts", "test/signers/ml-dsa-eth.kat-internal.ts"]
  - pattern: "keccakXofFactory"
    in: ["test/signers/mldsa-encoding.ts", "test/signers/ml-dsa-eth.ts", "test/signers/ml-dsa-eth.kat-internal.ts"]
  - pattern: "keygenWithXof"
    in: ["test/signers/ml-dsa-eth.core.ts", "test/signers/ml-dsa-eth.ts", "test/signers/ml-dsa-eth.kat-internal.ts"]
  - pattern: "keygenInternal"
    in: ["test/signers/ml-dsa-eth.kat-internal.ts", "test/signers/ml-dsa-eth.keygen.kat.test.ts"]
  - pattern: "@delta-from-ml-dsa"
    in: ["test/signers/ml-dsa-eth.ts", "test/signers/ml-dsa-eth.kat-internal.ts"]
  - pattern: "createKeccakPrg"
    in: ["test/signers/mldsa-encoding.ts"]
  - pattern: "loadKatVectors"
    in: ["test/signers/ml-dsa-eth.keygen.kat.test.ts", "test/signers/mldsa-encoding.xof-isolation.test.ts"]
  - pattern: "preparePublicKeyForDeployment"
    in: ["test/signers/mldsa-encoding.ts", "test/fixtures/mldsa.ts", "scripts/capture-nist-regression.ts", "test/signers/mldsa-encoding.nist-regression.test.ts", "test/signers/mldsa-encoding.xof-isolation.test.ts"]

## Detected Patterns

Codebase scan of analogous modules (consistent with Stories 1-2 tables; additions specific to Story 3's new surface):

| Pattern | Value | Sampled from | Established? |
|---------|-------|-------------|-------------|
| TypeScript module style | ESM (`.js` extension in relative imports) | `test/signers/keccak-prg.ts`, `test/signers/ml-dsa.ts`, `test/signers/mldsa-encoding.ts` | ✅ Established |
| Keygen module shape | `export function keygen(): Keypair` returning `{ publicKey, secretKey }` raw `Uint8Array`s | `test/signers/ml-dsa.ts:26`, `test/signers/falcon.ts` (via dispatcher) | ✅ Established — `ml-dsa-eth.ts` mirrors exactly |
| Per-scheme module header JSDoc | Block comment stating purpose + cross-references (FIPS section, submodule file, hash-domain notes) | `test/signers/ml-dsa.ts:1-18`, `test/signers/keccak-prg.ts:1-28`, `test/signers/mldsa-encoding.ts:152-164` | ✅ Established — extend with `@delta-from-ml-dsa` section for ETH variants |
| Error-class convention | `class FooError extends Error { readonly code: FooCode }` discriminant; tests assert on `code` not message | `test/signers/errors.ts`, `test/fixtures/kat/index.ts:49-61`, `test/signers/keccak-prg.ts:52-64` | ✅ Established (Story 3 does not introduce a new error class — keygen fails via existing noble validation) |
| noble `shake{128,256}.create()` usage | `shake128.create().update(seed)` + `.xofInto(buf)` for streaming output; `shake256(input, { dkLen })` for one-shot | `test/signers/mldsa-encoding.ts:45-53`, `:103` | ✅ Established — SHAKE adapters wrap this exact pattern |
| viem hex I/O | `hexToBytes` / `bytesToHex` at test boundaries; `0x`-lowercase idiom | `test/signers/ecdsa.ts`, `test/fixtures/mldsa.ts`, `test/fixtures/falcon.ts` | ✅ Established |
| Keccak-256 primitive | `viem.keccak256(input, "bytes")` for Uint8Array return | `test/signers/keccak-prg.ts:30`, `test/signers/userOpHash.ts:16` | ✅ Established (not directly consumed by Story 3 — consumed transitively via `createKeccakPrg`) |
| Test runner for pure-JS tiers | `node:test` + `node:assert/strict`; `describe` + `it` | `test/fixtures/kat/index.test.ts`, `test/signers/falcon-encoding.test.ts`, `test/signers/keccak-prg.test.ts` | ✅ Established |
| Hardhat integration pattern | `import hre from "hardhat"; const { viem } = await hre.network.connect();` — for EVM state tests only | `test/accounts/ecdsa.test.ts:17`, `test/bench/gas-benchmark.test.ts:337-341`, `test/signers/keccak-prg.solidity.test.ts` | ✅ Established — NOT used by Story 3 (no tests require EVM) |
| Fixture JSON layout | `test/fixtures/kat/<scheme>/vectors.json` with top-level `submoduleSha` + `vectors[]` | `test/fixtures/kat/mldsa-eth/vectors.json`, `test/fixtures/kat/keccak-prg/vectors.json` | ✅ Established — the NIST regression fixture deliberately deviates (no `submoduleSha` — it's a local pre-refactor golden, not a submodule-derived artifact) |
| Amendment-logging convention | Rule 3 amendments in `docs/amendments.md` with `## A-NNN: ...` heading, Original/Actual blocks, Evidence citations, Impact per-story | `docs/amendments.md` §A-001 | ✅ Established — Story 3 adds A-002 and A-003 matching this shape |
| `scripts/*.ts` invocation | `npx tsx scripts/<name>.ts` per Story 1 AC-1-1 convention (note `package.json` still uses `node scripts/generate-report.ts` for older scripts — `tsx` is idiomatic for new TypeScript scripts) | `scripts/generate-kat-fixtures.ts` (Story 1) | ✅ Established — `scripts/capture-nist-regression.ts` uses `tsx` |
| JSON canonicalization for fixtures | 2-space indent, `\n` line endings, lowercase hex, stable key order; see `scripts/generate-kat-fixtures.ts` | Story 1 CLI output | ✅ Established — the NIST regression capture script emits the same canonical shape |

No ⚠ Conflicting patterns detected for Story 3's surface. One **tension** flagged in Dev Notes §"XOF call-site reconciliation": architecture shows a single-factory `preparePublicKeyForDeployment` signature; correct implementation requires two factories (SHAKE-128 for ExpandA, SHAKE-256 for H-of-pk) to preserve AC-D-1 NIST byte-identity. Resolved by A-002 amendment (Task 2).

## Wave Structure

Single-wave story (Wave 3 per `docs/plan.md`). Intra-story task dependencies are strictly serial due to the refactor-rollback safety net:

```
Task 1 (capture pre-refactor NIST fixture) — MUST commit before Task 2
    │
    ▼
Task 2 (mldsa-encoding.ts XOF-factory refactor + adapters + post-refactor NIST assertion + XOF-isolation test)
    │
    ▼
Task 3 (noble keygen fork + ml-dsa-eth.ts + ml-dsa-eth.kat-internal.ts + ESLint boundary + params-const test)
    │
    ▼
Task 4 (G1 KAT byte-identity test)
```

Task 1 → Task 2 is load-bearing: the frozen fixture must exist on disk at the moment Task 2's refactor lands. If both tasks land in one PR, ensure the Task 1 commit appears BEFORE Task 2 commit in the git history (AC-3-3 sequencing). No parallel execution possible — every task's output is consumed by the next.

Task 2's internal order: (a) add types + adapters → (b) refactor function body + migrate caller → (c) write post-refactor NIST regression test → (d) write interleaved XOF-isolation test. The post-refactor test (c) MUST pass before step (d) begins — if the regression is red, Task 2 halts per the refactor-rollback protocol.

## Out of Scope

Downstream stories own these — Story 3 must not touch them:

- **`signUserOp` production sign path** — Story 4.
- **`signWithRnd` KAT-only signer** — Story 4.
- **Rejection-loop / SampleInBall / MakeHint / ExpandMask implementation** — Story 4.
- **G2 signer KAT + G3 pk-transform KAT + G4 verifier integration** — Stories 4, 5.
- **`MlDsaEthAccount.sol`** + account integration + benchmark extension + README rename attribution — Story 5.
- **A-001 rename `publicKey` → `publicKeyPointer`** — Story 5's first task.
- **Full ESLint configuration adoption** — deferred (A-003 amendment); a future infrastructure story may bootstrap ESLint and migrate AC-3-7's grep assertion to `no-restricted-imports`.
- **Extending `preparePublicKeyForDeployment` to return `Uint8Array` instead of `Hex`** — plan says `Uint8Array` but current implementation returns `Hex` and the sole caller (`test/fixtures/mldsa.ts:49`) consumes hex. Keeping `Hex` preserves AC-D-1. If the signature needs to change downstream (e.g., Story 5 prefers bytes), log a new amendment — not Story 3's scope.
- **Fixture regeneration** — Story 1's CLI territory. If `loadKatVectors("mldsa-eth")` throws `KAT_SUBMODULE_SHA_MISMATCH` mid-story, halt per AC-1-8 and escalate; do not regenerate fixtures as part of Story 3.
