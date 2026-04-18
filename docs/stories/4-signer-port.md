---
story_id: "4"
title: "Signer port + G2 KAT"
size: "L"
status: "ready-for-dev"
wave: 4
feature: mldsa-eth
created: 2026-04-18
---

# Story 4: Signer port + G2 KAT

> Ref: `docs/plan.md` §"Story 4: Signer port + G2 KAT [L]" — authoritative AC text, FR/NFR coverage, wave assignment, dependency chain (Stories 1, 2, 3).
> Ref: `docs/plan.md` §"Interface Contracts" §"`signUserOp` / `signWithRnd`" — the signatures Story 4 produces.
> Ref: `docs/architecture.md` §"Library Public API Surface" §"`test/signers/ml-dsa-eth.ts`" + §"`test/signers/ml-dsa-eth.kat-internal.ts`" — production-vs-KAT split (M-1 resolution), fork scope (keygen+sign both XOF-parameterized), module-header `@delta-from-ml-dsa` requirement (M-3).
> Ref: `docs/architecture.md` §"Design Rationale" DD-1 (XOF swap SHAKE→Keccak, LOCKED), DD-10 (parameterize-by-factory, LOCKED), DD-11 (four-implementation oracle chain — PRG delivered by Story 2).
> Ref: `docs/architecture.md` §"Data Models" §"Signature payload at Solidity boundary" — DD-8 LOCKED: `abi.encode(cTilde, z, h)` at the Solidity boundary; cTilde 32 B + z 2304 B + h 84 B = 2420 B raw concat.
> Ref: `docs/architecture.md` §"Testing Strategy" row "G2 — Signer KAT" + §"Shared helpers" (`assertBytesEqual` from Story 3 — used here for byte-identity divergence messages).
> Ref: `docs/architecture.md` §"Error Handling Strategy" §"JS signer taxonomy" — `SignerInputError` with `code: "INVALID_SECRET_KEY_LENGTH" | "INVALID_MESSAGE"` consumed by AC-4-3 / AC-4-4.
> Ref: `docs/amendments.md` §A-001 — DD-7 `reshapedPublicKey` ABI amendment: NOT directly consumed by Story 4 (sign path does not reshape pk), but relevant for Story 5 downstream.
> Ref: `docs/amendments.md` §A-002 — refactored `preparePublicKeyForDeployment` takes two factories: NOT consumed by Story 4 (sign path does not call pk-transform). Flagged for awareness only.
> Ref: `docs/amendments.md` §A-003 — AC-3-7 enforcement via runtime grep. Story 4's `signWithRnd` extends the kat-internal surface, so the Story 3 grep test MUST be extended to cover any new import paths under `ml-dsa-eth.kat-internal.ts` (see Dev Notes).
> Ref: `docs/amendments.md` §A-004 — mldsa-eth fixture `reshapedPublicKey` is Python-format: NOT consumed by Story 4 (signature byte-identity uses the `.signature` field, which IS TS-format-compatible as it's raw `cTilde‖z‖h`).
> Ref: `docs/stories/1-fixture-gen-cli.md` — upstream story; `KatVector.signature` (2420 B hex) + `KatVector.rnd` (32 B hex) fields are consumed by this story's G2 KAT; `Detected Patterns` table applies unchanged.
> Ref: `docs/stories/2-keccak-prg-port.md` — upstream story; `createKeccakPrg` + `KeccakPrg` interface are the load-bearing primitive consumed transitively via `keccakXofFactory`.
> Ref: `docs/stories/3-xof-refactor-keygen.md` — upstream story; `keygenWithXof`, `ml-dsa-eth.core.ts`, `keccakXofFactory`, `keygen()`, `keygenInternal()`, `@delta-from-ml-dsa` JSDoc convention, AC-3-7 grep boundary, `assertBytesEqual` helper are ALL produced by Story 3 and consumed by Story 4.

## User Story

As a wallet engineer, I want a JS ML-DSA-ETH signer that produces signatures byte-identical to the Python reference, so that signatures over userOps verify on-chain against the external ZKNox verifier.

## Acceptance Criteria

> All ACs copied verbatim from `docs/plan.md` §"Story 4: Signer port + G2 KAT [L]". Never paraphrase.

- **AC-4-1** (G2 KAT — FR-2/FR-8 byte-identity): Given a `.rsp` vector N's `sk`, `msg`, `rnd`, when `signWithRnd(sk, msg, rnd, ctx=0x)` is called, then output matches `sig = sm[:-mlen]` byte-for-byte across all ~100 vectors.
- **AC-4-2** (Production sign path — FR-1): Given a keypair from `keygen()` + a valid `UnsignedUserOp`, when `signUserOp(sk, userOp, entryPointAddress, chainId)` is called, then a `PackedUserOperation` with a signature of exactly 2420 bytes (32 cTilde + 2304 z + 84 h) is returned.
- **AC-4-3** (Input error — SK length): Given `signWithRnd(sk, ...)` called with `sk.length !== 2560`, then `SignerInputError` with `code: "INVALID_SECRET_KEY_LENGTH"` is thrown.
- **AC-4-4** (Input error — message type): Given `signWithRnd(sk, msg, rnd)` called with `msg` neither `Uint8Array` nor `0x`-hex, then `SignerInputError` with `code: "INVALID_MESSAGE"` is thrown.
- **AC-4-5** (Rejection loop exercised): Given the signer's ExpandMask → norm-check loop, when `signWithRnd` runs across ~100 `.rsp` vectors, then ≥1 vector observably requires more than one rejection iteration (instrumented counter > 0).
- **AC-4-6** (Hedged production path): Given `signUserOp` called twice with identical inputs, when the two signatures are compared, then they differ (probabilistic; rnd from `crypto.getRandomValues(32)`).

**FR Coverage:** FR-1 (`signUserOp`), FR-2 (signer byte-identity), FR-8 (Keccak XOF subset — signer), FR-13 (JS ETH signer surface). **NFR Coverage:** NFR-2 (direct — ~100 KAT vectors).

## Verified Interfaces

### Consumed by this story (VERIFIED against source at story-creation time)

- **`keygenWithXof(zeta, xofFactory): Keypair`** — Story 3 shared-core fork; Story 4 extends this file with a sibling `signWithXof`
  - Source: `test/signers/ml-dsa-eth.core.ts:252`
  - File hash (sha256): `3df1999c20041efcb283f94e8d6a736ec0c5cbb4c2339f17e6d3c5b06734a943`
  - Signature (verbatim): `export function keygenWithXof(zeta: Uint8Array, xofFactory: XofFactory): Keypair`
  - Shared primitives Story 4 reuses from this file: parameter constants (exported at lines 32-54: `N, Q, K, L, D, ETA, TAU, GAMMA1, GAMMA2, OMEGA, BETA, TR_BYTES`), `crystals` NTT context (line 62), `polyCoder`/`ETACoder`/`T0Coder` (lines 89-97), `secretCoder` (line 103 — decodes the 2560 B sk to `(rho, K_, tr, s1, s2, t0)`), `polyAdd`/`multiplyNTTs`/`newPoly` (lines 118-128), `rejBoundedPoly`/`rejNTTPoly`/`makeXofGet` (lines 158-215), `EXPAND_A_BLOCK = 168` / `EXPAND_S_BLOCK = 136` (lines 221-222), `Keypair` interface (line 226).
  - Migration surface for Story 4 Task 1: several of the above helpers are `const` / unexported at HEAD (e.g., `polyAdd`, `multiplyNTTs`, `rejBoundedPoly`, `rejNTTPoly`, `makeXofGet`, `secretCoder`, `EXPAND_A_BLOCK`, `EXPAND_S_BLOCK`). `signWithXof` will need them — either export them from `ml-dsa-eth.core.ts` OR keep `signWithXof` in the same file alongside `keygenWithXof`. **Recommended: keep in same file** (Dev Notes §"Core-file organisation"). File size budget still acceptable post-addition (~500 lines after ~200 LOC sign body + supporting helpers like `sampleInBall`, `expandMaskPoly`, `decompose`, `makeHint`, `bitPackZ`, `packHint`).
  - Plan match: ✓ `docs/plan.md` §"Interface Contracts" §"`keygen` / `keygenInternal`" consistent.

- **`XofFactory`, `XofReader`, `keccakXofFactory`** — Story 3 XOF adapter surface
  - Source: `test/signers/mldsa-encoding.ts:45`, `:57`, `:92`
  - File hash (sha256): `d41bfc950d85f79c11cb941954304ce4725c52c0c7e2ebb5983f77689282de2e`
  - Signatures (verbatim):
    ```ts
    export interface XofReader {
      readonly id: "shake128" | "shake256" | "keccak-prg";
      xof(length: number): Uint8Array;
    }
    export type XofFactory = (seed: Uint8Array) => XofReader;
    export const keccakXofFactory: XofFactory = (seed) => { ... };  // createKeccakPrg + flip
    ```
  - Story 4 consumes `keccakXofFactory` directly (both production `signUserOp` and KAT `signWithRnd` → shared `signWithXof` route Keccak-PRG through this single adapter). `XofFactory` / `XofReader` types flow through `signWithXof`'s signature.
  - Plan match: ✓ matches `docs/plan.md` §"Interface Contracts" §"`XofFactory` / `XofReader`".

- **`keygen(): Keypair`** — Story 3 production surface; Story 4 extends this file with `signUserOp`
  - Source: `test/signers/ml-dsa-eth.ts:61`
  - File hash (sha256): `a7bd2ca87f7e9cc0ecd58c810222970e16715726183458aa0c190a1b4d0b42b0`
  - Current exports (grep `^export`): `export function keygen(): Keypair` (line 61). Story 4 ADDS `export async function signUserOp(...)` alongside.
  - Module-header JSDoc already contains the `@delta-from-ml-dsa` block (lines 17-44) — Story 4 EXTENDS (not duplicates) items 4 (ctx handling) and 5 (signature layout) from "informational" to concrete specifications now that sign lands in this module.
  - Plan match: ✓.

- **`keygenInternal(zeta): Keypair`** — Story 3 KAT surface; Story 4 extends this file with `signWithRnd`
  - Source: `test/signers/ml-dsa-eth.kat-internal.ts:49`
  - File hash (sha256): `b0bb5cfd1cde8241bd1012eddd284b92216cf0db81aa2d57d554ea103572a215`
  - Current exports: `export function keygenInternal(zeta: Uint8Array): Keypair` (line 49). Story 4 ADDS `export function signWithRnd(...)` alongside.
  - Module-header JSDoc block (lines 14-16) already contains the KAT-boundary warning ("KAT-only — NEVER imported from `test/signers/index.ts` or `test/bench/**`"). The `@delta-from-ml-dsa` block (lines 18-32) EXTENDS (not duplicates) items 4/5.
  - Plan match: ✓.

- **`loadKatVectors(scheme: "mldsa-eth"): KatVector[]`** — Story 1 KAT loader, consumed by the G2 KAT test
  - Source: `test/fixtures/kat/index.ts:344`
  - File hash (sha256): `ca8c32db82d0d082efc53cfa92526d94f7f4d2a0e9c0d4376c7e63b4e406d4f0`
  - Signature (verbatim): `export function loadKatVectors(scheme: "mldsa-eth"): KatVector[]`
  - `KatVector` interface (from same file lines 83-101) provides — relevant fields for Story 4: `{ id, secretKey (2560 B hex), message (variable hex), rnd (32 B hex), signature (2420 B hex = cTilde‖z‖h) }`. `publicKey` is NOT needed by G2 (sign takes sk only). `reshapedPublicKey` is NOT needed by G2 (Story 5 scope).
  - Side effect: module top-level `assertSubmoduleShaMatches()` (line 391) runs at import time — G2 test gets submodule-pin validation for free.
  - Plan match: ✓.

- **`assertBytesEqual(actual, expected, label, xofId?)`** — Story 3 byte-comparison helper
  - Source: `test/utils/assert-bytes.ts:15`
  - File hash (sha256): `7bb2bc6449549cebe4b2f90988e1b07198bc32088d56ba1b41b9b408be9765ef`
  - Signature (verbatim): `export function assertBytesEqual(actual: Uint8Array, expected: Uint8Array, label: string, xofId?: string): void`
  - Story 4 uses this for per-vector G2 byte-identity assertions with `xofId = "keccak-prg"` — divergence messages include `(factory=keccak-prg)` per AC-3-4 convention.

- **`createKeccakPrg(seed?): KeccakPrg`** — Story 2 primitive, consumed transitively via `keccakXofFactory`
  - Source: `test/signers/keccak-prg.ts:92`
  - File hash (sha256): `518b57b143280a0053298a561d27eff3be0aa11a83b53b4b18dd64179b7dfa83`
  - Story 4 does NOT import this directly — only via `keccakXofFactory` per the AC-A-1 HIGH boundary (no module-level XOF instances).

- **`computeUserOpHash(userOp, entryPointAddress, chainId): Hex`** — shared ERC-4337 v0.7 hash helper
  - Source: `test/signers/userOpHash.ts:20`
  - File hash (sha256): `b1903d7438791be3ef810a37ecd336d9f9f9c1d2f2baf612b598355d36a21501`
  - Signature (verbatim): `export function computeUserOpHash(userOp: UnsignedUserOp, entryPointAddress: string, chainId: bigint): 0x${string}`
  - Consumed by `signUserOp` to build the 32-byte message passed into `signWithXof`. Identical usage to `test/signers/ml-dsa.ts:37`.

- **`UnsignedUserOp`, `PackedUserOperation`, `Keypair`** — shared signer types
  - Source: `test/signers/index.ts:16` / `:26` / `:41`
  - File hash (sha256): `5f571b4ecbe7d6a709d45df187320a5641c94aa5e2695be649170f6fc1189238`
  - Signatures (verbatim):
    ```ts
    export type Keypair = { publicKey: Uint8Array; secretKey: Uint8Array };
    export type UnsignedUserOp = { sender, nonce, initCode, callData, accountGasLimits, preVerificationGas, gasFees, paymasterAndData };
    export type PackedUserOperation = UnsignedUserOp & { signature: 0x${string} };
    ```
  - Dispatch NOTE: `Scheme` union at `:14` is `"ecdsa" | "falcon" | "mldsa"` — does NOT yet include `"mldsa-eth"`. Story 4 MUST NOT add `"mldsa-eth"` to the dispatch union (that is Story 5 scope per DD-9 / AC-5-9). Production `signUserOp` is exported from `ml-dsa-eth.ts` as a standalone symbol.

- **`test/signers/ml-dsa.ts`** — NIST ML-DSA signer reference (MUST NOT break under AC-D-1)
  - Source: `test/signers/ml-dsa.ts`
  - File hash (sha256): `cdd38b845222974a937a12e4d72ea83d5359c728df29ece4b613799a2aa500bd`
  - Current implementation wraps `ml_dsa44.keygen()` + `ml_dsa44.sign(msg, sk)` from noble (lines 27, 38). Story 4 MUST NOT modify this file or the underlying noble `ml_dsa44.sign` path — any bleed that breaks the existing NIST test suite is a Rule 3 escalation.

- **Python reference `_sign_internal`** — byte-level source of truth for AC-4-1
  - Source: `ETHDILITHIUM/pythonref/dilithium_py/dilithium/dilithium.py:267-347`
  - Signature (verbatim): `def _sign_internal(self, sk: bytes, m: bytes, rnd: bytes, external_mu: bool = False, _xof=shake256, _xof2=shake128, zk=False) -> bytes`
  - Outer wrapper `sign(sk, m, ctx=b"", deterministic=False, _xof, _xof2, zk)` at `:420-450` prepends `m_prime = bytes([0]) + bytes([len(ctx)]) + ctx + m` before `_sign_internal`. **For Story 4's `signWithRnd(sk, msg, rnd, ctx=0x)`: `m_prime = 0x00 00 || msg`** (two leading zero bytes: domain separator + ctx-len, with ctx empty).
  - Message-flow deltas the fork must preserve byte-level:
    - `mu = _h(tr + m_prime, 64, _xof=_xof)` (`:299`)
    - `rho_prime = _h(k + rnd + mu, 64, _xof=_xof)` (`:301`)
    - Rejection loop (`:305-347`): `y = _expand_mask_vector(rho_prime, kappa, _xof=_xof)` → `w = (A_hat @ y_hat).from_ntt()` → `w1 = w.high_bits(alpha)` → `c_tilde = _h(mu + w1_bytes, c_tilde_bytes=32, _xof=_xof)` → `c = sample_in_ball(c_tilde, tau=39, _xof=_xof)` → norm checks → `h = (-c_t0).make_hint(w - c_s2 + c_t0, alpha)` → `_pack_sig(c_tilde, z, h)`.
  - All `_xof` AND `_xof2` roles collapse to `keccakXofFactory` on the ETH path (DD-1 LOCKED).

- **`.rsp` KAT corpus — ETH variant**
  - Source: `ETHDILITHIUM/pythonref/assets/PQCsignKAT_Dilithium2_ETH.rsp`
  - Vector count: exactly 100 records (verified: `grep -c '^count = '`).
  - G2 consumes `KatVector.signature` which is `sm[:-mlen]` extracted by Story 1's fixture-gen — the leading 2420 bytes of the Python `sm` concatenation. Each record's `sm` layout is `signature(2420) || msg` per `PQCgenKAT_sign.c` convention.

### Produced by this story (⚠ UNVERIFIED — signatures from plan + architecture contracts)

> Marked ⚠ UNVERIFIED — source not yet implemented, using plan contract + architecture §"Library Public API Surface" + Python ref shape.

- **`signWithXof(sk, msg, rnd, ctx, xofFactory): Uint8Array`** — ⚠ UNVERIFIED (shared signer core)
  - Target location: `test/signers/ml-dsa-eth.core.ts` (sibling of `keygenWithXof`, same file per Dev Notes §"Core-file organisation").
  - Plan signature (derived from Python `_sign_internal` shape + Story 3's `keygenWithXof` single-factory precedent for the ETH path):
    ```ts
    export function signWithXof(
      sk: Uint8Array,
      msg: Uint8Array,
      rnd: Uint8Array,
      ctx: Uint8Array,
      xofFactory: XofFactory,
    ): Uint8Array;  // 2420 B — cTilde(32) ‖ z(2304) ‖ h(84)
    ```
  - Behavior:
    1. Validate `sk.length === 2560` (delegates to caller for `SignerInputError` mapping).
    2. Build `m_prime = Uint8Array([0x00, ctx.length, ...ctx, ...msg])` — matches Python `bytes([0]) + bytes([len(ctx)]) + ctx + m`. For the ETH path ctx is empty (`0x`), so `m_prime = Uint8Array([0x00, 0x00, ...msg])`.
    3. Unpack sk via `secretCoder.decode(sk)` → `(rho, K_, tr, s1, s2, t0)`.
    4. NTT-encode `s1Hat`, `s2Hat`, `t0Hat`.
    5. Rebuild `A_hat` via `makeXofGet(rho, EXPAND_A_BLOCK, xofFactory)` — same ExpandA path as keygen.
    6. Compute `mu = xofFactory(concat(tr, m_prime)).xof(64)` and `rho_prime = xofFactory(concat(K_, rnd, mu)).xof(64)`.
    7. Rejection loop (`kappa = 0`, increment by `L` each iteration): ExpandMask → `y` → `w = A_hat · y_hat (from_ntt)` → `w1 = highBits(w, alpha=2γ₂)` → `w1_bytes = bitPackW(w1, γ₂)` → `c_tilde = xofFactory(concat(mu, w1_bytes)).xof(32)` → `c = sampleInBall(c_tilde, tau=39, xofFactory)` → `c_hat = NTT.encode(c)` → compute `z = y + s1Hat·c_hat (from_ntt)`; check `‖z‖∞ ≥ γ₁ − β` → reject; compute `r0 = lowBits(w − s2Hat·c_hat, alpha)`; check `‖r0‖∞ ≥ γ₂ − β` → reject; compute `c_t0 = t0Hat·c_hat (from_ntt)`; check `‖c_t0‖∞ ≥ γ₂` → reject; compute `h = makeHint(−c_t0, w − c_s2 + c_t0, alpha)`; check `sum(h) > ω` → reject.
    8. Emit `signature = concat(c_tilde, bitPackZ(z, γ₁), packHint(h))` — 32 + 2304 + 84 = 2420 B.
  - Instrumented rejection counter (AC-4-5): optional hook — either a module-level counter (violates AC-A-1 — DO NOT DO THIS) or a closure-returning overload `signWithXofInstrumented(...): { signature: Uint8Array; iterations: number }`. Recommended: a sibling export `signWithXofInstrumented` used ONLY by the G2 KAT test (Dev Notes §"Rejection-counter instrumentation").

- **`signWithRnd(sk, msg, rnd, ctx?): Hex`** — ⚠ UNVERIFIED (KAT surface)
  - Target location: `test/signers/ml-dsa-eth.kat-internal.ts` (sibling of `keygenInternal`).
  - Plan signature:
    ```ts
    export function signWithRnd(
      sk: Uint8Array,
      msg: Uint8Array | `0x${string}`,
      rnd: Uint8Array,
      ctx?: Uint8Array,  // defaults to new Uint8Array(0) — empty bytes
    ): `0x${string}`;  // bytesToHex of the 2420 B signature
    ```
  - Input validation (AC-4-3, AC-4-4):
    - `sk.length !== 2560` → `throw new SignerInputError("INVALID_SECRET_KEY_LENGTH", ...)`.
    - `msg` neither `Uint8Array` nor `0x`-prefixed hex string → `throw new SignerInputError("INVALID_MESSAGE", ...)`. Accepted shapes: `Uint8Array` (passed through); `"0x..."` hex string (coerced via `hexToBytes`).
    - `rnd.length !== 32` → MAY throw `SignerInputError("INVALID_RND_LENGTH", ...)` — NOT required by a plan AC, but architecture §"JS signer taxonomy" allows it. Implementer discretion; document whichever choice is made.
  - Body: coerce inputs → `signWithXof(sk, msgBytes, rnd, ctx ?? new Uint8Array(0), keccakXofFactory)` → `bytesToHex(sig)`.
  - Return type: plan contract says `Uint8Array`; architecture §"Library Public API Surface" shows `Uint8Array`; for project convention consistency (Story 3 `loadKatVectors` returns hex strings at rest; viem idiom is hex), returning `Hex` is acceptable. Decision: **return `Hex`** so the G2 KAT test asserts `signWithRnd(...) === v.signature` directly. Document this as a soft deviation from the plan's `Uint8Array` return (no amendment needed — both represent the same bytes).

- **`signUserOp(sk, userOp, entryPointAddress, chainId): Promise<PackedUserOperation>`** — ⚠ UNVERIFIED (production surface)
  - Target location: `test/signers/ml-dsa-eth.ts` (sibling of `keygen`).
  - Plan signature:
    ```ts
    export async function signUserOp(
      secretKey: Uint8Array,
      userOp: UnsignedUserOp,
      entryPointAddress: string,
      chainId: bigint,
    ): Promise<PackedUserOperation>;
    ```
  - Behavior:
    1. `const userOpHash = computeUserOpHash(userOp, entryPointAddress, chainId);` — 32 B hex.
    2. `const rnd = new Uint8Array(32); globalThis.crypto.getRandomValues(rnd);` — hedged entropy (AC-4-6).
    3. `const signature = signWithXof(sk, hexToBytes(userOpHash), rnd, new Uint8Array(0), keccakXofFactory);` — ETH path ctx is empty.
    4. `return { ...userOp, signature: bytesToHex(signature) };` — matches `test/signers/ml-dsa.ts:40-43` shape.
  - The function is `async` to match `test/signers/index.ts:56`'s `signUserOp` dispatcher signature even though the body contains no `await`. Keeps future-compatibility with Story 5's dispatcher integration (`mldsa-eth` Scheme union addition).
  - **MUST NOT import from `ml-dsa-eth.kat-internal.ts`** — uses `signWithXof` directly from `ml-dsa-eth.core.ts` per the grep boundary (AC-3-7 extended).

- **`SignerInputError`** — ⚠ UNVERIFIED (new error class)
  - Target location: `test/signers/errors.ts` (extend existing file — current hash `92278a0a0ba0fd3853f68a2d6e35d9f60ae9e12b06f7fccc8830831bcbf14868`).
  - Plan signature (from architecture §"JS signer taxonomy" — Error Handling Strategy):
    ```ts
    export type SignerInputErrorCode =
      | "INVALID_SECRET_KEY_LENGTH"
      | "INVALID_MESSAGE"
      | "INVALID_PUBLIC_KEY_LENGTH";  // for future use (Story 5?)
    export class SignerInputError extends Error {
      readonly code: SignerInputErrorCode;
      constructor(code: SignerInputErrorCode, message: string) {
        super(message);
        this.code = code;
        this.name = "SignerInputError";
      }
    }
    ```
  - Established pattern: `readonly code` as `as const` discriminant. Matches `NotImplementedError` (line 10 of the same file) and `KatFixtureError` (`test/fixtures/kat/index.ts:49`) and `PrgLifecycleError` (Story 2).
  - Tests assert on `.code`, NEVER on message strings.

## Dev Notes

### Architecture context (inlined — correctness-critical)

**DD-1 LOCKED — XOF swap SHAKE → Keccak-256 at every role.** The Python reference `_sign_internal` uses `_xof=shake256` and `_xof2=shake128`; on the ETH path both collapse to `Keccak256PRNG`. Story 4's `signWithXof` takes ONE `xofFactory` argument (matching Story 3's `keygenWithXof` single-factory convention for the ETH path) and invokes it at every XOF role:

| Role (Python ref) | Seed | Output length | TS call |
|---|---|---|---|
| `_h(tr + m_prime, 64)` — mu | `tr ‖ m_prime` | 64 B | `xofFactory(concat(tr, mPrime)).xof(64)` |
| `_h(k + rnd + mu, 64)` — rho_prime | `K_ ‖ rnd ‖ mu` | 64 B | `xofFactory(concat(K_, rnd, mu)).xof(64)` |
| `_expand_mask_vector(rho_prime, kappa)` — y_i | `rho_prime ‖ uint16_le(kappa+i)` per polynomial | 640 B/poly (γ₁=2¹⁷ → 20 bits × 256 coeffs / 8) | `xofFactory(concat(rho_prime, u16le(kappa+i))).xof(640)` (one reader per coefficient polynomial) |
| `_h(mu + w1_bytes, 32)` — c_tilde | `mu ‖ w1_bytes` | 32 B (ML-DSA-44 `c_tilde_bytes` per `dilithium.py:20`) | `xofFactory(concat(mu, w1Bytes)).xof(32)` |
| `sample_in_ball(c_tilde, tau=39)` — c | `c_tilde` | streaming (variable) | `xofFactory(c_tilde)` — consume in sampleInBall |
| `_expand_matrix_from_seed(rho)` — A_hat | `rho ‖ u16_le(j,i)` per cell | 168 B/block (rejection sampling) | reuse `makeXofGet(rho, EXPAND_A_BLOCK, xofFactory)` from core |

All readers are FRESH per call-site — DD-10 LOCKED; AC-A-1 HIGH (no module-level XOF state). Grep gate at Gate 5 extends Story 3's: `grep -nE '^(let|var) _?xof' test/signers/ml-dsa-eth.core.ts test/signers/ml-dsa-eth.ts test/signers/ml-dsa-eth.kat-internal.ts` MUST return zero hits.

**DD-10 LOCKED — single-factory signature on the ETH path.** Story 4 does NOT introduce a two-factory signature for `signWithXof` — the NIST path isn't re-forked here (Story 3 amendment A-002 applies only to `preparePublicKeyForDeployment`, not the signer core). Python `_sign_internal` has two XOF arguments `_xof, _xof2` for NIST-path flexibility (SHAKE-256 for most roles; SHAKE-128 for ExpandA); on the ETH path they collapse. Single-factory is byte-correct on the ETH path AND matches Story 3's `keygenWithXof` precedent (same `ml-dsa-eth.core.ts` file, same pattern).

**Message preformatting (inlined — affects AC-4-1 byte-identity).** Python `sign(sk, m, ctx=b"")` at `dilithium.py:420-450` constructs `m_prime = bytes([0]) + bytes([len(ctx)]) + ctx + m` BEFORE calling `_sign_internal(sk, m_prime, rnd, ...)`. For the ETH path with `ctx = b""`:

```
m_prime = 0x00 00 ‖ msg  (2 bytes prefix + variable msg)
```

The ZKNox on-chain verifier at `ETHDILITHIUM/src/ZKNOX_dilithium.sol:77` performs the same prefix prepending before mu computation. This is NOT the same as noble's `ml_dsa44.sign` which is already wrapped with its own prefix handling — Story 4's `signWithXof` replicates `_sign_internal` directly and the PREFIX IS THE SIGNER'S RESPONSIBILITY (not the caller's). Both surfaces (`signWithRnd`, `signUserOp`) pass the RAW msg to `signWithXof`; the prefix is applied inside.

**DD-8 LOCKED — signature byte layout.** `c_tilde(32) ‖ bit_pack_z(z, γ₁)(2304) ‖ pack_h(h)(84) = 2420 B`. The `bit_pack_z` subroutine encodes each z-polynomial coefficient in `20 bits = bits(γ₁) + 1 = log₂(2·γ₁ − 1)` per FIPS 204; 4 polynomials × 256 coeffs × 20 bits / 8 = 2560 bytes FOR ALL z — but ML-DSA-44 has `l=4` → z has 4 polys → 4 × 576 = 2304. `pack_h` encodes the hint as `k + ω = 4 + 80 = 84` bytes: `ω` = 80 entries of coefficient indices (one per hint position), plus `k` = 4 cumulative counts at positions `[80..83]`. Returned raw (NOT abi-encoded) — abi-encoding is applied at the Solidity boundary (Story 5 scope); Story 4's `signWithRnd` returns the raw 2420 B concat as hex. AC-4-2's `PackedUserOperation.signature` field is the same raw 2420 B concat as hex (viem `bytesToHex` idiom).

**M-1 resolution — KAT helpers in a sibling module (preserved from Story 3).** Story 4 EXTENDS the kat-internal boundary:

- Production `signUserOp` lives in `ml-dsa-eth.ts` — calls `signWithXof` from `ml-dsa-eth.core.ts`.
- KAT `signWithRnd` lives in `ml-dsa-eth.kat-internal.ts` — also calls `signWithXof` from `ml-dsa-eth.core.ts`.
- Neither surface imports from the other; both share the `ml-dsa-eth.core.ts` implementation.
- Story 3's AC-3-7 grep test (`test/signers/ml-dsa-eth.test.ts`) already asserts that `test/signers/index.ts` + `test/bench/**/*.ts` contain zero matches of `/from\s+["'].*ml-dsa-eth\.kat-internal/`. **No new import paths to add to the grep pattern** — the boundary is file-scoped, not symbol-scoped. Adding `signWithRnd` to the kat-internal file does NOT expand the grep surface.

**M-3 resolution — `@delta-from-ml-dsa` JSDoc EXTENSION (AC-3-6 carryover).** Story 3 already landed the delta JSDoc in both `ml-dsa-eth.ts` and `ml-dsa-eth.kat-internal.ts`. Story 4 EXTENDS (not duplicates) the existing block — specifically items 4 (ctx handling) and 5 (signature layout) are currently marked "informational" and must be upgraded to concrete behavior descriptions now that sign lands:

- **Item 4 (ctx handling).** Promote from "ETH path uses `ctx = 0x`" to "`signWithRnd` accepts optional `ctx` with default `new Uint8Array(0)`; `signUserOp` always passes empty ctx. The signer prepends `0x00 || len(ctx) || ctx` to `msg` before mu computation, byte-matching `dilithium.py:445`."
- **Item 5 (signature layout).** Promote from "informational" to "`signWithXof` emits exactly 2420 B: 32 cTilde (Keccak-PRG over `mu ‖ w1_bytes`) + 2304 z (bit-packed 20 bits/coeff, 4 polynomials) + 84 h (k+ω=4+80; ω entries + k cumulative counts at positions [80..83]). Returned raw; abi-encoding is applied at the Solidity boundary (Story 5 scope)."

Do NOT add a second `@delta-from-ml-dsa` block; modify the existing one.

**Core-file organisation.** `ml-dsa-eth.core.ts` is currently 308 lines (keygen half). Adding `signWithXof` + supporting sub-helpers (`sampleInBall`, `expandMaskPoly`, `decompose`/`highBits`/`lowBits`, `makeHint`, `bitPackZ`, `packHint`) adds approximately ~200 additional LOC. Post-addition file size: ~500 lines. Structural check §1 (file-size >500) triggers — recommended mitigation: keep `signWithXof` in `ml-dsa-eth.core.ts` but extract the sign-specific sub-helpers (`sampleInBall` + `expandMaskPoly` + hint/packing utilities) into a sibling `test/signers/ml-dsa-eth.core-sign.ts` if the file crosses ~600 lines during implementation. Implementer discretion — the boundary is soft. Justification-over-split: keygen and sign share parameter constants, `crystals` NTT, coders, and `makeXofGet`; splitting into two files doubles the import-surface of those primitives.

**Rejection-counter instrumentation (AC-4-5).** Reject-loop instrumentation MUST NOT use module-level state (DD-10 / AC-A-1 HIGH). Two acceptable approaches:

1. **Sibling export that returns iteration count.** Add `export function signWithXofInstrumented(...): { signature: Uint8Array; iterations: number }` to `ml-dsa-eth.core.ts`. Called ONLY by the G2 KAT test. `signWithXof` becomes a thin wrapper: `signWithXof(...args) => signWithXofInstrumented(...args).signature`. Zero additional state; the counter is function-local.
2. **Counter callback.** Add an optional `onRejection?: () => void` callback parameter to `signWithXof`. G2 test passes a callback that increments a local `let counter = 0`. Awkward signature.

Recommend option 1 — cleaner signature, explicit opt-in, zero risk of accidental production use. The G2 test asserts `totalIterationsAcrossAllVectors > vectorCount` (≥1 vector needed >1 rejection — conservative; the ETH corpus empirically exhibits rejection on the majority of vectors per Python ref timing notes).

**Error taxonomy — `SignerInputError` class.** Story 4 introduces this class into the existing `test/signers/errors.ts` file (line count: 18 pre-Story-4). Matches the established pattern (`NotImplementedError` on line 10; Story 2's `PrgLifecycleError`; Story 1's `KatFixtureError`): `readonly code` discriminant, tests assert on `.code` not message strings. Codes for Story 4 scope: `"INVALID_SECRET_KEY_LENGTH"` + `"INVALID_MESSAGE"`. Future stories may add `"INVALID_PUBLIC_KEY_LENGTH"` (Story 5 if account-boundary validation lands here) and `"INVALID_RND_LENGTH"` (optional; implementer discretion per Verified Interfaces §`signWithRnd`).

**No new runtime dependencies.** `package.json` `dependencies` block stays empty. `@noble/post-quantum` and `@noble/hashes` and `viem` already present as devDependency (story 3 verified). The ML-DSA-ETH signer is built entirely from primitives already present.

**Hedged sign → `crypto.getRandomValues` for rnd (AC-4-6).** Story 3 locked the idiom: `globalThis.crypto.getRandomValues(new Uint8Array(32))` — Node v24.13.1 exposes Web Crypto API globally. `signUserOp` sources `rnd` this way; `signWithRnd` takes `rnd` as a parameter (KAT determinism).

### Behavioral requirements (inlined from plan + architecture)

- **AC-4-1 byte-identity oracle.** For each `.rsp` vector: extract `sk`, `msg`, `rnd` from `loadKatVectors("mldsa-eth")`; compute `actual = signWithRnd(hexToBytes(sk), hexToBytes(msg), hexToBytes(rnd))`; assert `actual === v.signature` byte-for-byte using `assertBytesEqual(hexToBytes(actual), hexToBytes(v.signature), \`vec ${v.id} sig\`, "keccak-prg")`. Iterate all ~100 vectors. **The `.rsp`-derived `signature` field is the 2420-byte raw concat `cTilde‖z‖h`** — see Verified Interfaces §`.rsp` KAT corpus.
- **AC-4-2 production signature length.** `signUserOp` returns `PackedUserOperation.signature: \`0x${string}\`` with `signature.length === 2 + 2420 * 2 === 4842` hex chars (leading `0x` + 4840 hex chars for 2420 bytes). Exact byte count is load-bearing — the Solidity verifier at `ETHDILITHIUM/src/ZKNOX_dilithium.sol:80` slices expecting this exact layout.
- **AC-4-3 / AC-4-4 input validation.** Assertions use `instanceof SignerInputError && err.code === "INVALID_SECRET_KEY_LENGTH"` (or `"INVALID_MESSAGE"`) pattern — NEVER `err.message.includes(...)`. See Story 1/2/3 established convention.
- **AC-4-5 rejection-counter assertion.** The G2 KAT test iterates all ~100 vectors and tracks total iterations across all. Assertion: `totalIterations > vectorCount` (strictly greater — proves at least one vector took >1 rejection iteration). Weaker form `someVectorHadIterations > 1` also acceptable. Fail the test if no rejection was ever triggered (would indicate the loop body ran only once per vector — silent correctness loss for the reject-check code paths). Python ref empirically rejects for roughly half of ML-DSA-44 signatures; expect `totalIterations / vectorCount ≈ 1.5-2.0`.
- **AC-4-6 hedged determinism check.** Test body:
    ```ts
    const sk = /* from keygen() */;
    const userOp = /* static fixture — deterministic test data */;
    const s1 = await signUserOp(sk, userOp, entryPoint, chainId);
    const s2 = await signUserOp(sk, userOp, entryPoint, chainId);
    assert.notEqual(s1.signature, s2.signature);  // probabilistic — rnd differs
    ```
    No special entropy source mocking; `globalThis.crypto.getRandomValues` is real. Failure probability is `2^-256` — astronomically low; treat as deterministic.
- **Test runner.** `node:test` + `node:assert/strict` for all Story 4 tests. None require EVM state — the G2 byte-identity test operates purely on the 2420-byte signature output. Hardhat is not required for any of Story 4's tests (Story 5 owns G4 verifier integration).
- **Hex / byte I/O.** viem `hexToBytes` / `bytesToHex` — established project convention (Stories 1/2/3 `Detected Patterns`).
- **No `!` non-null assertions in production code.** Allowed in test files only (`.claude/rules/nodejs.md`).
- **AC-D-1 byte-identity guarantee for NIST ML-DSA.** Story 4 MUST NOT modify `test/signers/ml-dsa.ts` or `test/signers/mldsa-encoding.ts`'s NIST path. If any refactor bleeds into the noble `ml_dsa44.sign` path, escalate as a Rule 3 deviation — this is NOT a Story 4 problem to solve. The existing `MlDsaAccount` NIST suite is the blocking post-condition; Story 4's own tests are additive.
- **Production `signUserOp` MUST NOT import `signWithRnd`.** Both share `signWithXof` from `ml-dsa-eth.core.ts`. The grep boundary (AC-3-7 from Story 3) already forbids `test/signers/index.ts` and `test/bench/**` from importing `ml-dsa-eth.kat-internal.ts`; Story 4 extends this discipline to the production `ml-dsa-eth.ts` module itself by convention (no grep test needed — the file's import list is trivially auditable at PR review).

### File-tree effects (expected — non-binding)

New files:
- `test/signers/ml-dsa-eth.sign.kat.test.ts` (G2 byte-identity + rejection-counter assertions; ~40 LOC)
- `test/signers/ml-dsa-eth.sign.test.ts` (input-validation + production-path + hedged test; ~60 LOC)

Modified files:
- `test/signers/ml-dsa-eth.core.ts` (ADD `signWithXof` + supporting helpers — `sampleInBall`, `expandMaskPoly`, `decompose`/`highBits`/`lowBits`, `makeHint`, `bitPackZ`, `packHint`, `signWithXofInstrumented` wrapper; ~200 LOC added; total file size ~500 lines)
- `test/signers/ml-dsa-eth.ts` (ADD `signUserOp`; EXTEND `@delta-from-ml-dsa` items 4/5 from "informational" to concrete; ~40 LOC added)
- `test/signers/ml-dsa-eth.kat-internal.ts` (ADD `signWithRnd`; EXTEND `@delta-from-ml-dsa` items 4/5; ~25 LOC added)
- `test/signers/errors.ts` (ADD `SignerInputError` class + `SignerInputErrorCode` union; ~15 LOC added)

Package files: no additions to `dependencies`; `devDependencies` unchanged.

### Library versions (verified at story creation, 2026-04-18; unchanged from Stories 1-3)

- `viem@^2.43.0`, `hardhat@3.3.0`, `typescript@^5.9.3`, Solidity `0.8.34`, Node `v24.13.1`.
- `@noble/post-quantum@^0.6.1` — forked-through at `ml-dsa-eth.core.ts`; Story 4 does NOT import noble's `ml_dsa44.sign` directly (the whole point of the fork).
- `@noble/hashes` — transitive via `@noble/post-quantum`. Story 4 does NOT import `shake*` directly; the core file already imports `splitCoder`, `vecCoder`, `genCrystals` at hashes `3df1999...`.
- No new runtime or dev dependencies introduced.

## Tasks

- [ ] **Task 1: Fork `signWithXof` into `ml-dsa-eth.core.ts` + supporting sub-helpers**
  - AC: AC-4-1 (primary — the signer fork is the byte-identity deliverable); AC-4-5 (rejection-counter instrumentation); AC-4-2 (signature-length guarantee — the 2420-byte layout comes from `_pack_sig`).
  - Files: `test/signers/ml-dsa-eth.core.ts` (extend — ADD `signWithXof`, `signWithXofInstrumented`, `sampleInBall`, `expandMaskPoly`, `decompose`/`highBits`/`lowBits`, `makeHint`, `bitPackZ`, `packHint`; ~200 LOC)
  - Dependencies: Story 3 complete (`keygenWithXof`, parameter constants, coders, `makeXofGet`, `rejNTTPoly`, `rejBoundedPoly` all at current hash `3df1999...`). No intra-Story-4 dependencies — this is the foundation for Tasks 2 + 3 + 4.
  - Why: The sign body is the G2 byte-identity deliverable. Port Python `_sign_internal` at `dilithium.py:267-347` line-for-line, replacing every `_xof(seed, outLen)` call with `xofFactory(seed).xof(outLen)` and every `_xof2(seed, outLen)` with the same (single-factory on the ETH path). Preserve the rejection-loop state machine exactly — `kappa` starts at 0 and increments by `L` per iteration; norm checks abort early on bound violations; `make_hint` is computed after all three norm checks pass. Emit `cTilde ‖ bit_pack_z(z) ‖ pack_h(h)` as a single 2420 B `Uint8Array`. Instrument rejection count via `signWithXofInstrumented` per Dev Notes §"Rejection-counter instrumentation". Verify AC-A-1 grep after landing.

- [ ] **Task 2: Add `signWithRnd` to `ml-dsa-eth.kat-internal.ts` + extend `SignerInputError`**
  - AC: AC-4-3 (SK length error), AC-4-4 (message type error); AC-4-1 prerequisite (the `signWithRnd` KAT surface is what the G2 test calls).
  - Files: `test/signers/ml-dsa-eth.kat-internal.ts` (extend — ADD `signWithRnd` + extend `@delta-from-ml-dsa` items 4/5); `test/signers/errors.ts` (extend — ADD `SignerInputError` class + `SignerInputErrorCode` union)
  - Dependencies: Task 1 (needs `signWithXof` from `ml-dsa-eth.core.ts`).
  - Why: The KAT surface is the thin, deterministic entry point the G2 test calls. Validate `sk.length === 2560` and throw `SignerInputError("INVALID_SECRET_KEY_LENGTH", ...)` on mismatch; validate `msg` is `Uint8Array` or `0x`-hex (coerce the latter via `hexToBytes`) and throw `SignerInputError("INVALID_MESSAGE", ...)` otherwise; default `ctx` to `new Uint8Array(0)`; delegate to `signWithXof(sk, msg, rnd, ctx, keccakXofFactory)`; return `bytesToHex(sig)`. Extend the `@delta-from-ml-dsa` block's items 4 + 5 per Dev Notes §"M-3 resolution — EXTENSION".

- [ ] **Task 3: Add `signUserOp` to `ml-dsa-eth.ts`**
  - AC: AC-4-2 (production signature length + `PackedUserOperation` shape), AC-4-6 (hedged path differs on repeated calls).
  - Files: `test/signers/ml-dsa-eth.ts` (extend — ADD `signUserOp` + extend `@delta-from-ml-dsa` items 4/5)
  - Dependencies: Task 1 (needs `signWithXof`). MUST NOT depend on Task 2 — production does NOT import `signWithRnd`.
  - Why: The production surface. Compute `userOpHash` via shared `computeUserOpHash`; source `rnd` via `globalThis.crypto.getRandomValues(new Uint8Array(32))`; delegate to `signWithXof(sk, hexToBytes(userOpHash), rnd, new Uint8Array(0), keccakXofFactory)`; return `{ ...userOp, signature: bytesToHex(sig) }`. Matches `test/signers/ml-dsa.ts:31-44` shape exactly. Extend the `@delta-from-ml-dsa` block's items 4 + 5 per Dev Notes §"M-3 resolution — EXTENSION".

- [ ] **Task 4: G2 KAT byte-identity + rejection-counter test**
  - AC: AC-4-1 (primary), AC-4-5 (rejection counter > 0 across ~100 vectors).
  - Files: `test/signers/ml-dsa-eth.sign.kat.test.ts` (new; ~40 LOC)
  - Dependencies: Tasks 1 + 2 (needs `signWithXofInstrumented` + `signWithRnd`).
  - Why: G2 is the byte-identity gate that proves the signer fork is correct. Concretely:
    - `import { loadKatVectors } from "../fixtures/kat/index.js";`
    - `import { signWithRnd } from "./ml-dsa-eth.kat-internal.js";`
    - `import { signWithXofInstrumented } from "./ml-dsa-eth.core.js";`
    - `import { keccakXofFactory } from "./mldsa-encoding.js";`
    - `import { assertBytesEqual } from "../utils/assert-bytes.js";`
    - Outer `describe("G2 — signer KAT byte-identity")` block iterating `loadKatVectors("mldsa-eth")` (~100 vectors).
    - For each vector: `const sig = signWithRnd(hexToBytes(v.secretKey), hexToBytes(v.message), hexToBytes(v.rnd));`. Assert: `assertBytesEqual(hexToBytes(sig), hexToBytes(v.signature), \`vec ${v.id} sig\`, "keccak-prg")`. This double-asserts `signWithRnd` output length === 2420 (from `assertBytesEqual`'s length-mismatch guard).
    - Separate `it` block for AC-4-5: iterate same vectors via `signWithXofInstrumented`, accumulate iteration counts, assert `totalIterations > vectors.length` (strictly greater — proves at least one vector >1 iteration). Preferably log the distribution (min/max/avg iterations) via `console.info` for historical record.
    - Cost: noble sign is ~200-300 ms per call × 100 vectors ≈ 25 s. Add second instrumented pass → ≈ 50 s total. Acceptable (comparable to Story 3 G1 KAT cost).
    - No Hardhat required — pure-JS `node:test`.

- [ ] **Task 5: Input-validation + production-path + hedged-sign test**
  - AC: AC-4-2 (production path returns 2420-byte signature), AC-4-3 (sk-length error), AC-4-4 (message-type error), AC-4-6 (hedged path differs).
  - Files: `test/signers/ml-dsa-eth.sign.test.ts` (new; ~60 LOC)
  - Dependencies: Tasks 2 + 3 (needs `signWithRnd` for input-validation tests; needs `keygen` + `signUserOp` for production-path + hedged tests).
  - Why: Input-validation coverage + production-path smoke + hedge assertion. Concretely:
    - `describe("signWithRnd input validation")`:
      - AC-4-3: `assert.throws(() => signWithRnd(new Uint8Array(2559), msg, rnd), (err) => err instanceof SignerInputError && err.code === "INVALID_SECRET_KEY_LENGTH")`. Also test `2561`.
      - AC-4-4: `assert.throws(() => signWithRnd(sk, 42 as any, rnd), (err) => err instanceof SignerInputError && err.code === "INVALID_MESSAGE")`. Also test `null`, `{}`, `"not-hex"`, `"0xZZ"` (invalid hex chars).
      - Positive path: `signWithRnd(sk, msg, rnd)` with valid shapes returns a string starting with `"0x"` and having exactly 4842 chars (2 + 2420*2).
      - Positive path — hex-string msg: `signWithRnd(sk, "0xdeadbeef", rnd)` and `signWithRnd(sk, hexToBytes("0xdeadbeef"), rnd)` produce IDENTICAL output (coercion equivalence).
    - `describe("signUserOp production path")`:
      - AC-4-2: given `const { secretKey } = keygen();` and a static fixture `userOp`, call `await signUserOp(secretKey, userOp, entryPoint, chainId)`; assert `result.signature.length === 4842` and `result.sender === userOp.sender` (spread preserved).
      - AC-4-6: call `signUserOp` twice with identical inputs; assert `s1.signature !== s2.signature`. Also assert both are valid 2420-byte signatures by length.
    - Static `userOp` fixture can be inlined in-file (no external dependency) — use `sender: "0x0000...0001"`, `nonce: 0n`, and zero-filled `0x...` blobs for the `bytes32` fields. Does NOT need to be a verifier-valid userOp; AC-4-2/4-6 assert on format + divergence, not on on-chain acceptance (that's Story 5's G4 gate).
    - No Hardhat required — pure-JS `node:test`.

## Definition of Done (Gate 5 criteria — Story 4)

Beyond standard Gate 5 (format + lint + build + test + test integrity + security — `.claude/rules/code-standards.md` §2 "Verification Loop"):

1. **G2 KAT byte-identity passes for all ~100 vectors.** `npx hardhat test test/signers/ml-dsa-eth.sign.kat.test.ts` — `signWithRnd(hexToBytes(v.secretKey), hexToBytes(v.message), hexToBytes(v.rnd))` produces output byte-equal to `v.signature` for every vector in `loadKatVectors("mldsa-eth")`. [AC-4-1]
2. **Rejection counter exceeds vector count.** Same test file — `totalIterationsAcrossAllVectors > vectors.length` strictly. [AC-4-5]
3. **Production path returns 2420-byte signature.** `signUserOp` result's `.signature` is a hex string of length 4842 (2 prefix + 2420 * 2). Verified in `test/signers/ml-dsa-eth.sign.test.ts`. [AC-4-2]
4. **Hedged path produces distinct signatures.** Two `signUserOp` calls with identical inputs return different signatures. [AC-4-6]
5. **Input-validation errors match architecture taxonomy.** Assertions use `err instanceof SignerInputError && err.code === "INVALID_SECRET_KEY_LENGTH"` and `"INVALID_MESSAGE"` — never message-string matching. [AC-4-3, AC-4-4]
6. **AC-A-1 grep gate — zero module-level XOF state.** `grep -nE '^(let|var) _?xof' test/signers/ml-dsa-eth.core.ts test/signers/ml-dsa-eth.ts test/signers/ml-dsa-eth.kat-internal.ts` returns zero hits (extends Story 3 Gate 5 #5).
7. **Existing NIST `MlDsaAccount` + Falcon test suites pass byte-for-byte.** `npx hardhat test` — zero regressions (AC-D-1 blocking post-condition; Story 4 MUST NOT touch `test/signers/ml-dsa.ts` or the NIST path in `mldsa-encoding.ts`).
8. **Story 3 AC-3-7 grep test still passes.** The existing `test/signers/ml-dsa-eth.test.ts` runtime-grep continues to assert zero matches against `test/signers/index.ts` + `test/bench/**/*.ts`. Adding `signWithRnd` to kat-internal does NOT expand the grep surface (file-scoped boundary).
9. **`@delta-from-ml-dsa` headers EXTENDED (not duplicated).** Both `test/signers/ml-dsa-eth.ts` and `test/signers/ml-dsa-eth.kat-internal.ts` contain exactly ONE `@delta-from-ml-dsa` JSDoc block; items 4 (ctx) + 5 (signature layout) upgraded from "informational" to concrete behavior. Grep check: `grep -c "@delta-from-ml-dsa" test/signers/ml-dsa-eth.ts test/signers/ml-dsa-eth.kat-internal.ts` returns `1` for each file.
10. **Production `ml-dsa-eth.ts` does NOT import from kat-internal.** `grep -nE "from\\s+[\"'][^\"']*ml-dsa-eth\\.kat-internal" test/signers/ml-dsa-eth.ts` returns zero matches. Soft-enforced (no automated grep test for this specific check — PR-review discipline).
11. **No new runtime dependencies.** `git diff package.json package-lock.json` — `dependencies` block unchanged.
12. **Zero assertion-free new tests.** Every new `.test.ts` file contains at least one `assert.*` call per `describe`/`it` block. Per `.claude/rules/test-integrity.md` §5 — grep audit at Gate 5.
13. **No silenced tests.** New test files contain no test-suppression annotations of any form. `.claude/rules/test-integrity.md` §2 prohibits silencing without a tracking reference; VERIFY.md §4 greps for forbidden tokens.
14. **All new error assertions use typed discriminants.** `err instanceof SignerInputError && err.code === "..."` pattern, never `err.message.includes(...)`.
15. **Task-atomic commits per `.claude/rules/code-standards.md` §1.** Minimum 5 commits matching Tasks 1/2/3/4/5. Pre-tag `pre-mldsa-eth-4` before Task 1's first commit; post-tag `post-mldsa-eth-4` after Gate 5 passes. Rule 1 allows minor rider commits when trivial.
16. **`npm run compile` succeeds with zero warnings.** No new Solidity files in this story, but compile must stay clean.
17. **File-size budget respected.** `test/signers/ml-dsa-eth.core.ts` stays under ~600 lines post-addition — if approaching that threshold during Task 1, extract sign-specific sub-helpers into `test/signers/ml-dsa-eth.core-sign.ts` per Dev Notes §"Core-file organisation".

## must_haves

truths:
  - "`signWithRnd(hexToBytes(v.secretKey), hexToBytes(v.message), hexToBytes(v.rnd))` produces hex output byte-identical to `v.signature` for every vector in `loadKatVectors('mldsa-eth')` (~100 vectors; 2420 B = 32 cTilde + 2304 z + 84 h per vector) — AC-4-1."
  - "`signWithRnd` internally prefixes `msg` with `0x00 || 0x00` (domain byte + ctx-length byte for empty ctx) to match Python `dilithium.py:445` `m_prime = bytes([0]) + bytes([len(ctx)]) + ctx + m` before calling the shared `signWithXof` — byte-identity load-bearing for AC-4-1."
  - "`signWithXofInstrumented(sk, msg, rnd, ctx, keccakXofFactory)` returns `{ signature, iterations }`; summed across all `loadKatVectors('mldsa-eth')` calls, `totalIterations > vectors.length` (strictly greater — ≥1 vector required a rejection retry) — AC-4-5."
  - "`signUserOp(sk, userOp, entryPointAddress, chainId)` returns a `PackedUserOperation` whose `.signature: \`0x${string}\`` has length exactly 4842 characters (2 prefix + 2420 bytes × 2 hex chars); the byte layout is `cTilde(32) || bit_pack_z(z, γ₁=131072)(2304) || pack_h(h, k=4, ω=80)(84)` — AC-4-2."
  - "Two back-to-back `signUserOp(sk, userOp, entryPointAddress, chainId)` calls with IDENTICAL inputs produce DIFFERENT `.signature` values with probability 1 − 2^-256 (treated as deterministic inequality in the AC-4-6 test) — AC-4-6."
  - "`signWithRnd(sk, msg, rnd)` called with `sk.length !== 2560` throws `SignerInputError` whose `.code === 'INVALID_SECRET_KEY_LENGTH'` (assert with `err instanceof SignerInputError && err.code === 'INVALID_SECRET_KEY_LENGTH'`, NEVER message-string matching) — AC-4-3."
  - "`signWithRnd(sk, msg, rnd)` called with `msg` that is neither `Uint8Array` nor a `0x`-prefixed hex string throws `SignerInputError` whose `.code === 'INVALID_MESSAGE'` — AC-4-4."
  - "`signWithRnd(sk, '0x' + bytesToHex-of-msg, rnd)` and `signWithRnd(sk, msg-as-Uint8Array, rnd)` produce IDENTICAL output (coercion equivalence check is part of the input-validation test suite)."
  - "Production `signUserOp` sources `rnd` via `globalThis.crypto.getRandomValues(new Uint8Array(32))` and passes `ctx = new Uint8Array(0)` (empty bytes) to `signWithXof` — AC-4-6 load-bearing + ETH-path ctx convention per `dilithium.py:420-450`."
  - "Production `test/signers/ml-dsa-eth.ts` does NOT import from `test/signers/ml-dsa-eth.kat-internal.ts`; `signUserOp` uses `signWithXof` directly from `ml-dsa-eth.core.ts`. Both production and KAT surfaces share the `signWithXof` core."
  - "`grep -nE '^(let|var) _?xof' test/signers/ml-dsa-eth.core.ts test/signers/ml-dsa-eth.ts test/signers/ml-dsa-eth.kat-internal.ts` returns zero hits post-Story-4 (AC-A-1 HIGH grep gate extends Story 3's #5)."
  - "`test/signers/errors.ts` exports `class SignerInputError extends Error` with `readonly code: 'INVALID_SECRET_KEY_LENGTH' | 'INVALID_MESSAGE' | 'INVALID_PUBLIC_KEY_LENGTH'` — the three codes from architecture §'Error Handling Strategy' §'JS signer taxonomy'. Tests assert on `.code` via discriminant, matching established `NotImplementedError` / `KatFixtureError` / `PrgLifecycleError` pattern."
  - "Both `test/signers/ml-dsa-eth.ts` and `test/signers/ml-dsa-eth.kat-internal.ts` contain EXACTLY ONE `@delta-from-ml-dsa` JSDoc block each; Story 4 EXTENDS items 4 (ctx handling) and 5 (signature layout) from Story 3's 'informational' status to concrete behavior descriptions — AC-3-6 carryover."
  - "Story 3's runtime-grep boundary test (`test/signers/ml-dsa-eth.test.ts` per `docs/amendments.md` §A-003) continues to pass post-Story-4 — adding `signWithRnd` to `ml-dsa-eth.kat-internal.ts` does NOT introduce any import of that file from `test/signers/index.ts` or `test/bench/**/*.ts`."
  - "Existing NIST `MlDsaAccount` + Falcon test suites pass byte-for-byte post-Story-4 — `npx hardhat test` (all tiers) shows zero regressions (AC-D-1 blocking post-condition; Story 4 does NOT modify `test/signers/ml-dsa.ts` or the NIST path in `mldsa-encoding.ts`)."

artifacts:
  - path: "test/signers/ml-dsa-eth.core.ts"
    contains: ["signWithXof", "signWithXofInstrumented", "sampleInBall", "keygenWithXof", "TAU", "GAMMA1", "GAMMA2", "OMEGA", "BETA", "makeHint", "bitPackZ", "packHint"]
  - path: "test/signers/ml-dsa-eth.ts"
    contains: ["keygen", "signUserOp", "@delta-from-ml-dsa", "keccakXofFactory", "crypto.getRandomValues", "computeUserOpHash", "signWithXof"]
  - path: "test/signers/ml-dsa-eth.kat-internal.ts"
    contains: ["keygenInternal", "signWithRnd", "@delta-from-ml-dsa", "kat-internal", "keccakXofFactory", "SignerInputError", "INVALID_SECRET_KEY_LENGTH", "INVALID_MESSAGE"]
  - path: "test/signers/errors.ts"
    contains: ["SignerInputError", "SignerInputErrorCode", "INVALID_SECRET_KEY_LENGTH", "INVALID_MESSAGE", "readonly code"]
  - path: "test/signers/ml-dsa-eth.sign.kat.test.ts"
    contains: ["signWithRnd", "signWithXofInstrumented", "loadKatVectors", "mldsa-eth", "assertBytesEqual", "keccak-prg", "totalIterations"]
  - path: "test/signers/ml-dsa-eth.sign.test.ts"
    contains: ["signUserOp", "signWithRnd", "SignerInputError", "INVALID_SECRET_KEY_LENGTH", "INVALID_MESSAGE", "4842", "keygen"]

key_links:
  - pattern: "signWithXof"
    in: ["test/signers/ml-dsa-eth.core.ts", "test/signers/ml-dsa-eth.ts", "test/signers/ml-dsa-eth.kat-internal.ts"]
  - pattern: "signWithXofInstrumented"
    in: ["test/signers/ml-dsa-eth.core.ts", "test/signers/ml-dsa-eth.sign.kat.test.ts"]
  - pattern: "signWithRnd"
    in: ["test/signers/ml-dsa-eth.kat-internal.ts", "test/signers/ml-dsa-eth.sign.kat.test.ts", "test/signers/ml-dsa-eth.sign.test.ts"]
  - pattern: "signUserOp"
    in: ["test/signers/ml-dsa-eth.ts", "test/signers/ml-dsa-eth.sign.test.ts"]
  - pattern: "SignerInputError"
    in: ["test/signers/errors.ts", "test/signers/ml-dsa-eth.kat-internal.ts", "test/signers/ml-dsa-eth.sign.test.ts"]
  - pattern: "INVALID_SECRET_KEY_LENGTH"
    in: ["test/signers/errors.ts", "test/signers/ml-dsa-eth.kat-internal.ts", "test/signers/ml-dsa-eth.sign.test.ts"]
  - pattern: "INVALID_MESSAGE"
    in: ["test/signers/errors.ts", "test/signers/ml-dsa-eth.kat-internal.ts", "test/signers/ml-dsa-eth.sign.test.ts"]
  - pattern: "keccakXofFactory"
    in: ["test/signers/ml-dsa-eth.ts", "test/signers/ml-dsa-eth.kat-internal.ts"]
  - pattern: "@delta-from-ml-dsa"
    in: ["test/signers/ml-dsa-eth.ts", "test/signers/ml-dsa-eth.kat-internal.ts"]
  - pattern: "loadKatVectors"
    in: ["test/signers/ml-dsa-eth.sign.kat.test.ts"]
  - pattern: "computeUserOpHash"
    in: ["test/signers/ml-dsa-eth.ts"]
  - pattern: "crypto.getRandomValues"
    in: ["test/signers/ml-dsa-eth.ts"]

## Detected Patterns

Codebase scan of analogous modules (consistent with Stories 1-3 tables; Story 4 introduces no new pattern kinds — all additions follow established conventions from Story 3).

| Pattern | Value | Sampled from | Established? |
|---------|-------|-------------|-------------|
| TypeScript module style | ESM (`.js` extension in relative imports) | `test/signers/ml-dsa-eth.core.ts`, `test/signers/ml-dsa-eth.ts`, `test/signers/ml-dsa.ts` | ✅ Established |
| Signer module shape | `export async function signUserOp(secretKey, userOp, entryPointAddress, chainId): Promise<PackedUserOperation>` with `computeUserOpHash` + `bytesToHex(signature)` | `test/signers/ml-dsa.ts:31-44`, `test/signers/ecdsa.ts`, `test/signers/falcon.ts` | ✅ Established — `ml-dsa-eth.ts#signUserOp` mirrors `ml-dsa.ts:31` shape exactly |
| Fork-core + production/KAT split | Production `ml-dsa-eth.ts` + KAT `ml-dsa-eth.kat-internal.ts` both import from shared `ml-dsa-eth.core.ts`; neither surface imports the other | `test/signers/ml-dsa-eth.ts:47` + `test/signers/ml-dsa-eth.kat-internal.ts:35` (Story 3) | ✅ Established — Story 4 extends the same pattern for sign |
| Module-header `@delta-from-ml-dsa` | JSDoc block enumerating byte-level differences from `test/signers/ml-dsa.ts`; items 1-5 covering XOF, fork scope, pk-transform, ctx, signature | `test/signers/ml-dsa-eth.ts:17-44`, `test/signers/ml-dsa-eth.kat-internal.ts:18-32` (Story 3) | ✅ Established — Story 4 EXTENDS items 4 + 5 in-place, not duplicated |
| Error-class discriminant | `class FooError extends Error { readonly code: FooCode }`; tests assert on `.code` not `.message` | `test/signers/errors.ts:10` (`NotImplementedError`), `test/fixtures/kat/index.ts:49` (`KatFixtureError`), Story 2 `PrgLifecycleError` | ✅ Established — `SignerInputError` mirrors exactly |
| Hex I/O at test/module boundaries | viem `hexToBytes` / `bytesToHex` with `0x`-prefixed lowercase strings | `test/signers/ml-dsa.ts:21`, `test/signers/userOpHash.ts:16`, `test/signers/mldsa-encoding.ts:3` | ✅ Established |
| Kat-internal grep boundary | runtime grep in `test/signers/ml-dsa-eth.test.ts` against `test/signers/index.ts` + `test/bench/**/*.ts`; per `docs/amendments.md` §A-003 | `docs/stories/3-xof-refactor-keygen.md` Task 3, step 4; existing test file | ✅ Established — Story 4 does NOT change the grep pattern (boundary is file-scoped, symbol-agnostic) |
| Hedged randomness idiom | `globalThis.crypto.getRandomValues(new Uint8Array(32))` in `ml-dsa-eth.ts#keygen` | `test/signers/ml-dsa-eth.ts:63` | ✅ Established (Story 3 locked the idiom) — `signUserOp` reuses |
| XOF-factory discipline | `xofFactory(seed).xof(outLen)` — no module-level readers; `XofReader.id` discriminant surfaces in error messages via `assertBytesEqual`'s `xofId` tag | `test/signers/mldsa-encoding.ts:45-101`, `test/signers/ml-dsa-eth.core.ts:205-215` (`makeXofGet`), `test/utils/assert-bytes.ts:15-44` | ✅ Established — `signWithXof` applies the same discipline |
| KAT test shape | `import { loadKatVectors } from "../fixtures/kat/index.js"` → iterate vectors with `describe`/`it` → `assertBytesEqual(actual, expected, label, xofId)` per vector | `test/signers/ml-dsa-eth.keygen.kat.test.ts` (Story 3) | ✅ Established — Story 4 G2 test mirrors the shape |
| Test runner for pure-JS tiers | `node:test` + `node:assert/strict`; `describe` + `it` | `test/fixtures/kat/index.test.ts`, `test/signers/keccak-prg.test.ts`, Story 3's keygen KAT test | ✅ Established — Story 4 tests use the same runner |
| Deterministic-alphabet discriminant | `xofId = "keccak-prg"` used at `assertBytesEqual` call-sites for ETH-path byte-identity tests (vs `"shake128"` / `"shake256"` on NIST-path tests) | Story 3 `ml-dsa-eth.keygen.kat.test.ts`, `mldsa-encoding.xof-isolation.test.ts` | ✅ Established — Story 4 G2 test uses `"keccak-prg"` |

No ⚠ Conflicting patterns detected for Story 4's surface. All new code follows the patterns that Stories 1-3 established.

## Wave Structure

Single-wave story (Wave 4 per `docs/plan.md`). Intra-story task dependencies form a shallow DAG with Task 1 as the foundational dependency for Tasks 2 + 3 + 4 + 5; Tasks 2 + 3 are independent of each other; Tasks 4 + 5 depend on downstream tasks.

```
Task 1 (signWithXof + supporting helpers in ml-dsa-eth.core.ts)
    │
    ├─► Task 2 (signWithRnd + SignerInputError)
    │       │
    │       └────────► Task 4 (G2 KAT byte-identity + rejection-counter test)
    │
    └─► Task 3 (signUserOp)
            │
            └──► Task 5 (input-validation + production + hedged-sign test)
                 (also depends on Task 2 for signWithRnd in the validation tests)
```

Tasks 2 and 3 are independent of each other — both depend only on Task 1's `signWithXof`. They can be implemented in parallel (or in either order) once Task 1 lands. Tasks 4 and 5 depend on Tasks 2 + 3 for the test surface.

Commit ordering: Task 1 → Task 2 → Task 3 → Task 4 → Task 5 produces the cleanest commit series; Task 1 → Task 3 → Task 2 → Task 5 → Task 4 is equally valid. Each task is a separate atomic commit per `.claude/rules/code-standards.md` §1.

## Out of Scope

Downstream stories own these — Story 4 must NOT touch them:

- **G3 pk-transform KAT** — Story 5 (consumes `preparePublicKeyForDeployment` with `keccakXofFactory` twice per `docs/amendments.md` §A-002).
- **G4 verifier integration** — Story 5 (`MlDsaEthAccount.sol` + on-chain `validateUserOp` path + ZKNox submodule deployment).
- **`MlDsaEthAccount.sol`** — Story 5.
- **Benchmark extension to 4 schemes** — Story 5.
- **`docs/gas-report.md` rename / regeneration** — Story 5.
- **README attribution** — Story 5.
- **A-001 rename `publicKey` → `publicKeyPointer`** — Story 5's first task (`MlDsaAccount.sol` + `FalconAccount.sol` + their tests).
- **A-004 fixture-format reconciliation** — Story 5 (`reshapedPublicKey` Python-format vs TS-format divergence).
- **Adding `"mldsa-eth"` to the `Scheme` union at `test/signers/index.ts:14`** — Story 5 (DD-9 dispatcher extension + AC-5-9 `SCHEMES.length` derivation).
- **Moving `signWithXof`'s rejection-counter surface into production** — `signWithXofInstrumented` is KAT-test-only; production `signUserOp` must NEVER consume it. Future benchmark story (separate from Story 5) could instrument the production path if needed; out of scope for Story 4.
- **Modifying `test/signers/ml-dsa.ts` or the NIST path in `test/signers/mldsa-encoding.ts`** — AC-D-1 blocking post-condition; any bleed into these files is a Rule 3 escalation, not Story 4 scope.
- **Bootstrapping ESLint** — still deferred per Story 3's A-003 amendment. The runtime-grep in `test/signers/ml-dsa-eth.test.ts` remains the AC-3-7 enforcement mechanism through Story 4. Future infrastructure story may migrate to ESLint `no-restricted-imports`.
- **Fixture regeneration** — Story 1's CLI territory. If `loadKatVectors("mldsa-eth")` throws `KAT_SUBMODULE_SHA_MISMATCH` mid-story, halt per AC-1-8 and escalate; do not regenerate fixtures as part of Story 4.
