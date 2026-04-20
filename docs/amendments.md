# Amendments

Architecture corrections discovered during implementation. Each amendment is a binding override of the frozen architecture document — the story-creator-agent and implementers MUST treat amended values as authoritative over the original architecture.md / stories/*.md text.

---

## A-002: PRE_G4_DRBG_PROBE byte-equality target — ETHFALCON `sm` layout is not NIST `sig || msg`

- **Story:** 1-1 (`falcon-eth-fixtures`)
- **Task:** T0 (PRE_G4_DRBG_PROBE)
- **Date:** 2026-04-19
- **Classification:** Rule 3 (Significant — interface/contract correction). The probe's byte-equality predicate was stated against an `sm[:-mlen]` slice that is NOT a clean signature under ETHFALCON's `.rsp` format. Left unamended, the probe would compute the wrong comparison and either (a) always fail on a real `.rsp` or (b) if coerced into reporting success, would leave the A-005 audit invariant unchecked.
- **Affects:** `docs/stories/1-1.md` §"Acceptance Criteria" AC-3 line 33; §"Architecture Guardrails" §"A-005 lesson — PRE_G4_DRBG_PROBE" line 65-69; §"must_haves.truths[4]" line 341. All reference `sm[:-mlen]`.

### Original (docs/stories/1-1.md:33)

> **AC-3:** Given PRE_G4_DRBG_PROBE is run on vec 0 from `.rsp`, When Python ref signs `(sk, msg)` with the same AES256_CTR_DRBG-derived entropy order as the captured signature, Then the re-computed signature byte-equals `sm[:-mlen]` from the `.rsp`; probe failure HALTS the fixture-gen pipeline.

### Actual (verified against pinned submodule `03ed0d60c67087527de7c4a3c1c469b89611bd68`)

> **AC-3 (amended):** Given PRE_G4_DRBG_PROBE is run on vec 0 from `.rsp`, When Python ref performs the exact `test_KAT_ETH` flow — `AES256_CTR_DRBG(seed)` → `inner_seed = drbg.random_bytes(48)` → `SHAKE.new(inner_seed).flip()` → `ntru_gen(…)` → `SecretKey` → `sk.sign(msg, randombytes=drbg.random_bytes, xof=KeccakPRNG)`, Then:
>   1. The recovered `PublicKey.pk` coefficient array equals `PublicKey.from_bytes(expected_pk).pk` (proves keygen-DRBG determinism);
>   2. The Python-sig `salt = sig[1:41]` equals `sm[2:42]` from the `.rsp` (proves the post-keygen `random_bytes` call consumed by salt generation is state-consistent);
>   3. The Python-sig `enc_s = sig[41:]` byte-equals `esig[1:1+len(enc_s)]` where `esig = sm[42+mlen : 42+mlen+sig_len]` and `sig_len = (sm[0]<<8) | sm[1]` (proves Gaussian-sample DRBG advancement is reproducible).
> Probe failure HALTS the fixture-gen pipeline with a structured error naming `docs/amendments.md` and the observed-vs-expected prefixes.

### Evidence

1. **ETHFALCON `.rsp` layout** — `ETHFALCON/pythonref/scripts/generate_kat_rsp.py:229-238`:
   ```python
   # Build Solidity-compatible format:
   # slen(2) + salt(40) + message(mlen) + solidity_header(1=0x29) + compressed_sig
   slen_bytes = slen.to_bytes(2, 'big')
   solidity_header = bytes([0x29])
   sm = slen_bytes + salt + msg + solidity_header + compressed_sig
   ```

2. **ETHFALCON reference test** — `ETHFALCON/pythonref/test_falcon_KAT.py:93-107` (authoritative comparison pattern):
   ```python
   sig_len = (expected_sm[0] << 8) | expected_sm[1]
   nonce = expected_sm[2:42]
   message = expected_sm[42:42 + mlen]
   esig = expected_sm[42 + mlen:42 + mlen + sig_len]
   esig_body = esig[1:]
   # Parse Python sig
   py_header = sig[0:1]
   py_salt = sig[1:41]
   py_enc_s = sig[41:]
   # Compare
   self.assertEqual(py_salt, nonce)
   self.assertEqual(py_header, esig[0:1])
   self.assertEqual(esig_body, py_enc_s[:len(esig_body)])
   ```

3. **Vec 0 smlen math** (from `.rsp`): `smlen = 691, mlen = 33`. Under the NIST `sig || msg` layout, `sm[:-mlen] = sm[:658]` would be `slen(2) + salt(40) + msg(33) + esig_partial(583)` — NOT a clean sig. Under the ETHFALCON layout, a clean sig is reconstructed as `salt(40) + header(1) + enc_s(variable)` via the two-window slice above.

### Impact

- **Story 1-1 Task T0:** Probe implementation compares `(recoveredPk.pk, py_salt, py_enc_s[:len(esig_body)])` against `(expectedPk.pk, nonce, esig_body)` rather than a naive `sig == sm[:-mlen]` slice. The A-005 audit invariant (DRBG state advancement reproducibility) is preserved — in fact strengthened, because three independent byte-equality assertions (keygen NTRU gen, salt derivation, Gaussian body) fail-fast rather than a single composite signature slice.
- **Story 1-1 Task T1:** Bulk `.rsp` transcription writes `signature` as the Python-recovered `sig` bytes (= `header(1)+salt(40)+enc_s`) prefix-packed to 1064 B per schema. `salt` embedded at offset `1..41` inside the 1064-byte signature (NOT `0..40`). The schema in Architecture Guardrails §"Fixture schema — falcon-eth vectors.json" line 111 claims "Salt is embedded at offset 0..40 inside the 1064-byte signature" — this will also need verification in T1 (tracked as a potential follow-up amendment; not in T0 scope).
- **Story 1-1 must_haves[4] line 341:** Amended in spirit — the probe HALT condition remains unchanged (any of the three byte-equality checks failing triggers HALT); the specific slice `sm[:-mlen]` is replaced by the three-window comparison above.
- **Downstream stories (1-2, 2-1, 2-3, 2-4):** Unaffected. They consume `test/fixtures/kat/falcon-eth/vectors.json`, which stores the post-T1 signature bytes; they do not re-derive against `sm[:-mlen]`.

### Rationale

`docs/stories/1-1.md` §"Architecture Guardrails" §"A-005 lesson" (line 67) drafted the probe predicate by analogy with the mldsa-eth `.rsp`, which DOES pack `sm = sig || msg` (NIST-standard layout). ETHFALCON's `.rsp` is produced by a custom generator (`generate_kat_rsp.py`) that emits a Solidity-oriented layout (`slen || salt || msg || header || esig`) for direct on-chain consumption. The story author's investigation did not sample the `.rsp` layout directly — it relied on the NIST convention as a placeholder. The main-agent pre-investigation caught this via the `test_KAT_ETH` reference test (lines 109-149), which is the authoritative byte-equality harness upstream.

### Resolution

Probe implemented in `scripts/generate-kat-fixtures.ts` (function `preG4DrbgProbe`) uses the three-window comparison documented in "Actual" above. The reference test path `ETHFALCON/pythonref/test_falcon_KAT.py::TestFalconKAT::test_KAT_ETH` is a real-path counterpart (per `.claude/rules/retrospect/universal.md` §"[2026-04-18] Override-based tests need a real-path counterpart") — our CLI-side probe is the happy-path exercise of the same invariants.

Story AC-3, A-005 lesson, and must_haves[4] language referencing `sm[:-mlen]` is **superseded** by this amendment for all downstream implementation, verification, and acceptance-gate purposes.

---

## A-003: AC-7 rename-file count — `KatVector` touches 2 files, not 8 (substring vs whole-word grep)

- **Story:** 1-1 (`falcon-eth-fixtures`)
- **Task:** T3 (pure rename `KatVector` → `MlDsaEthKatVector`)
- **Date:** 2026-04-19
- **Classification:** Rule 3 (Significant — AC contract correction). The literal "≥7 files" threshold in AC-7 and the "8 known sites" claim in must_haves[7] + must_haves[13] cannot be met without introducing gratuitous type annotations in files that currently rely on TypeScript inference — which would itself violate DD-26's "zero new symbols, zero feature-adding edits" clause.
- **Affects:** `docs/stories/1-1.md` §AC-7 (line 37); §"Verified Interfaces" §"Inbound rename dependency" (lines 256-265 — the 8-file "Known consumers" list); §must_haves truths[7] (line 344, "8 known sites"); §must_haves truths[13] (line 350, "T3 touches exactly the 8 known rename-impacted files").

### Original (`docs/stories/1-1.md:37`)

> **AC-7 (Commit discipline, DD-26):** Given Task 3 (pure rename) is committed before Task 4 (loader feature), When `git log` is inspected, Then the rename commit touches **≥7 files** with no behavior change; the subsequent Task 4 commit adds the multi-submodule probe + discriminated overload without any rename-only edits.

### Actual (verified at T3-start via `git grep -wn 'KatVector\|KatVectorsFile' HEAD`)

At the pre-T3 HEAD (commit `b3958c2`, T2-complete), only **2 files** contain `KatVector` or `KatVectorsFile` as whole-word identifiers:

- `test/fixtures/kat/index.ts` — 5 hits (interface decls, field type, return type, assertion).
- `scripts/generate-kat-fixtures.ts` — 6 hits (imports, param type, const type, comment, local var type).

The 6 test files originally listed in `docs/stories/1-1.md:257-264` (`index.test.ts`, `mldsa-eth.test.ts`, `mldsa-encoding.xof-isolation.test.ts`, `ml-dsa-eth.keygen.kat.test.ts`, `ml-dsa-eth.sign.kat.test.ts`, `mldsa-encoding.pk-transform.kat.test.ts`) consume `loadKatVectors(...)` return values via **TypeScript inference** only — they never annotate the returned array with `KatVector[]`. The story-creator's grep was a substring match (`KatVector` matches the substring inside `loadKatVectors`), which miscounted these 6 files as containing the type identifier.

### Evidence

```
$ git grep -wn 'KatVector\|KatVectorsFile' b3958c2 -- 'scripts/' 'test/' 'contracts/'
b3958c2:scripts/generate-kat-fixtures.ts:98:  KatVector,
b3958c2:scripts/generate-kat-fixtures.ts:99:  KatVectorsFile,
b3958c2:scripts/generate-kat-fixtures.ts:2281:function serializeKatFixture(f: KatVectorsFile): string {
b3958c2:scripts/generate-kat-fixtures.ts:2573:  // ... DD-7 KatVector[].
b3958c2:scripts/generate-kat-fixtures.ts:2574:  const katVectors: KatVector[] = rspRecords.map((r) => {
b3958c2:scripts/generate-kat-fixtures.ts:2595:  const katFixture: KatVectorsFile = {
b3958c2:test/fixtures/kat/index.ts:83:export interface KatVector {
b3958c2:test/fixtures/kat/index.ts:112:export interface KatVectorsFile {
b3958c2:test/fixtures/kat/index.ts:123:  vectors: KatVector[];
b3958c2:test/fixtures/kat/index.ts:344:export function loadKatVectors(scheme: "mldsa-eth"): KatVector[] {
b3958c2:test/fixtures/kat/index.ts:383:  return vectors as KatVector[];
```

Only 2 files named. Forcing the count to ≥7 would require adding `const vectors: KatVector[] = loadKatVectors("mldsa-eth")` annotations to the 6 consumer test files — **feature-adding code that violates DD-26's pure-rename mandate**. The correct reading of DD-26 is "rename every current occurrence of the identifier, isolated from feature work" — which T3 does.

### Amended

> **AC-7 (Commit discipline, DD-26):** Given Task 3 (pure rename) is committed before Task 4 (loader feature), When `git log` is inspected, Then the rename commit touches **only files that currently contain the whole-word identifier `KatVector` or `KatVectorsFile`** (at T3-start: 2 files — `scripts/generate-kat-fixtures.ts` and `test/fixtures/kat/index.ts`). The commit adds **no new symbols, no aliased re-export, no behavior change**; every remaining occurrence of the legacy identifier across `scripts/`, `test/`, `contracts/` is zero after the commit (`git grep -w 'KatVector\|KatVectorsFile'` → no hits). The subsequent Task 4 commit adds the multi-submodule probe + discriminated overload without any rename-only edits.

### Impact

- **Story 1-1 T3:** Commit touches 2 files (not ≥7). Bisect-surgical property holds: T3 is identifier-only, T4 is additive. DD-26's essential invariant (rename commit separable from feature commit) is preserved.
- **must_haves truths[7] "8 known sites":** re-read as "all current whole-word occurrences of the legacy identifier in `scripts/` and `test/`" (currently 2 files, 11 hits total). The post-T3 grep-zero assertion is unchanged.
- **must_haves truths[13] "T3 touches exactly the 8 known rename-impacted files":** re-read as "T3 touches exactly the files currently containing the whole-word legacy identifier (2 files at T3-start); T4 touches `test/fixtures/kat/index.ts` additively (new exports appended) plus `test/fixtures/kat/index.test.ts` (new tests) + `test/fixtures/kat/mldsa-eth/vectors.json` (backfill) + `scripts/generate-kat-fixtures.ts` (emit `submoduleSource`). The disjoint-diff intent holds: T4 adds new exports below the renamed interface block; T3's edits are identifier-only."

### Rationale

Story-creator used substring-match grep (`git grep -n KatVector`) rather than whole-word grep (`git grep -wn 'KatVector\|KatVectorsFile'`). The substring match hits `loadKatVectors` (5 of the 6 test files use this function), inflating the per-file count from 2 → 8 and producing the erroneous AC-7 threshold. This is an audit-trail correction, not a scope change. The `> Ref:` in `.claude/rules/retrospect/universal.md` §"[2026-04-18] Amendment doc sweep" applies — this amendment commit also updates AC-7 + must_haves[7] + must_haves[13] + the "Known consumers" list in the same commit.

### Resolution

T3 commit (`refactor(kat): T3 rename KatVector → MlDsaEthKatVector`) touches 2 files. AC-7, must_haves[7], must_haves[13], and the "Inbound rename dependency" file enumeration in `docs/stories/1-1.md` are **superseded** by this amendment for Gate 5 verification purposes.

---

## A-004: ETHFALCON's PRG class is `KeccakPRNG()` (0-arg) — the plan/architecture/research wording `Keccak256PRNG(a, b)` is the ETHDILITHIUM wrapper's name mis-attributed to the ETHFALCON upstream

- **Story:** 1-2 (`keccak-prg-verification`)
- **Task:** T1 (G1 vector capture from ETHFALCON's Python wrapper)
- **Date:** 2026-04-19
- **Classification:** Rule 3 (Significant — AC contract language correction; same classification as A-002/A-003). The AC-1 text, DD-13 rationale row, and plan/architecture running prose all claim that ETHFALCON's wrapper class is `Keccak256PRNG(a, b)`. The actual upstream class is `KeccakPRNG()` with a 0-arg constructor (verified at `ETHFALCON/pythonref/keccak_prng.py:13-29`). `Keccak256PRNG(a=None, b=None)` is the ETHDILITHIUM wrapper's name (verified at `ETHDILITHIUM/pythonref/dilithium_py/keccak_prng/keccak_prng_wrapper.py:21-23`). The two names have been inverted in the plan/architecture docs. Story 1-1's CLI already imports the correct ETHFALCON class (`from keccak_prng import KeccakPRNG` at `scripts/generate-kat-fixtures.ts:867`), so no runtime byte is wrong — but the docs prescribe a non-existent class name that would confuse any future implementer who reads plan/architecture before source.
- **Affects:**
  - `docs/plan.md:20, 59, 65, 69` — Story 1-2 row + T1 task def + AC-1 running prose
  - `docs/architecture.md:29, 195, 228, 535` — Component Decomposition row "Keccak-CTR-PRNG primitive"; §"Testing Strategy" G1 row; §"Story sequencing" Story 2 row; §"Design Rationale" DD-13 row
  - `docs/stories/1-2.md:25, 31, 42` — User Story verbatim from plan, AC-1 verbatim from plan, DD-13 LOCKED quote (all copied verbatim and thus inherit the misnomer)
  - Additional known loci outside this commit's modification scope (flagged for a future Rule-1 follow-up amendment): `docs/research.md:28, 75, 104, 159, 170`; `docs/spec.md:109, 165, 174, 242, 372`; `docs/sprint-status.yaml:17`. These are research/spec-phase artifacts whose plan-of-record authority is superseded by this amendment for implementation purposes — implementers MUST read A-004 as the authoritative source of truth regardless of which doc they encountered first.

### Original (docs/plan.md:65, 69)

> 1. **T1 — Capture G1 vectors** from ETHFALCON's `Keccak256PRNG` Python wrapper.
> - **AC-1:** Given a fresh `KeccakPrg` seeded with G1 vector inputs, When scripted `inject`/`flip`/`extract` is applied per vector, Then output byte-equals ETHFALCON's Python `Keccak256PRNG(a, b)` output for the same seed + call sequence; divergence prints first-differing byte ±8 B context plus `(factory=keccak-prg)` discriminant.

### Actual (verified against pinned submodule `03ed0d60c67087527de7c4a3c1c469b89611bd68`)

ETHFALCON's PRG class is `KeccakPRNG` with a zero-arg constructor:

```python
# ETHFALCON/pythonref/keccak_prng.py:13-29 (authoritative upstream source)
class KeccakPRNG:
    def __init__(self):
        """ Initialize a Keccak PRNG context. """
        self.buffer = bytearray(MAX_BUFFER_SIZE)
        self.state = bytearray(KECCAK_OUTPUT)
        self.buffer_len = 0
        self.counter = 0
        self.finalized = False
        self.out_buffer = bytearray(KECCAK_OUTPUT)
        self.out_buffer_pos = 0
        self.out_buffer_len = 0

    @classmethod
    def new(self):
        return self()
```

ETHDILITHIUM's copy of the same file is `Keccak256PRNG(a=None, b=None)` — note the renamed class AND the 2-arg constructor (added explicitly to "match the shake wrapper implementation of this project"):

```python
# ETHDILITHIUM/pythonref/dilithium_py/keccak_prng/keccak_prng_wrapper.py:21-23
class Keccak256PRNG:
    # I put a and b so that it matches the shake wrapper implementation of this project...
    def __init__(self, a=None, b=None):
        ...
```

### Evidence

1. **ETHFALCON class name + arity** — `ETHFALCON/pythonref/keccak_prng.py:13-14`: `class KeccakPRNG:` then `def __init__(self):`. Zero non-self arguments.

2. **ETHDILITHIUM class name + arity** — `ETHDILITHIUM/pythonref/dilithium_py/keccak_prng/keccak_prng_wrapper.py:21-23`: `class Keccak256PRNG:` then `def __init__(self, a=None, b=None):`. Two optional kwargs.

3. **ETHDILITHIUM file header confirms upstream origin** — `keccak_prng_wrapper.py:4-6`:
   ```python
   # This file is copied from ETHFALCON
   # It should be done in another repository.
   ```
   So ETHFALCON IS the upstream origin; ETHDILITHIUM is the fork. The plan's mis-attribution likely arose because the research-phase probe (`docs/research.md:170`) accidentally assigned the ETHDILITHIUM wrapper name to ETHFALCON and vice versa. Every downstream doc (plan, architecture, spec, DD-13 rationale) inherited the inversion.

4. **Story 1-1's CLI already uses the correct ETHFALCON class name** — `scripts/generate-kat-fixtures.ts:867`: `from keccak_prng import KeccakPRNG`. Story 1-1 implementers caught the misnomer during fixture-gen but never amended the plan/architecture wording back.

5. **Story 1-2 author caught the delta during story creation** — `docs/stories/1-2.md:462` §Risks/Gotchas #1 explicitly calls out the inversion and recommends this exact amendment. This amendment closes that recommendation.

### Amended (docs/plan.md:65, 69 — in spirit; verbatim text preserved with callout)

The verbatim plan text is preserved (plan artifacts are frozen per DD-26 commit-discipline, not rewritten). Each affected line receives a callout pointing at A-004:

> 1. **T1 — Capture G1 vectors** from ETHFALCON's `Keccak256PRNG` Python wrapper. [**See `docs/amendments.md` A-004** — the actual ETHFALCON class is `KeccakPRNG()` (0-arg); `Keccak256PRNG(a, b)` is the ETHDILITHIUM wrapper.]
> - **AC-1 (amended by A-004):** Given a fresh `KeccakPrg` seeded with G1 vector inputs, When scripted `inject`/`flip`/`extract` is applied per vector, Then output byte-equals ETHFALCON's Python `KeccakPRNG()` output for the same seed + call sequence; divergence prints first-differing byte ±8 B context plus `(factory=keccak-prg)` discriminant. The plan's verbatim wording "`Keccak256PRNG(a, b)`" refers to the ETHDILITHIUM wrapper name and is superseded by this amendment for all Gate-5 verification purposes.

Story 1-2's AC-1 quotes plan verbatim — that line is preserved with an A-004 callout note immediately below, per `.claude/rules/retrospect/universal.md` §"[2026-04-18] Amendment doc sweep — don't leak the old shape".

### Impact

- **Story 1-2 T1:** Python subprocess uses `from keccak_prng import KeccakPRNG` + `prng = KeccakPRNG()` (no args). Correct by construction — amendment is docs-only, no code delta.
- **Story 1-2 T2:** The test-file top-of-file JSDoc and describe-block title refer to `KeccakPRNG` (not `Keccak256PRNG`). The AC-2 DD-13 reminder string also uses the corrected class name.
- **must_haves coverage:** no must_haves are reworded. Each must_have already references the correct class name (`"from keccak_prng import KeccakPRNG"` explicitly, `KeccakPRNG` in `scripts/generate-kat-fixtures.ts` artifact `contains` list).
- **Downstream stories (2-1, 2-3):** unaffected by this amendment — they consume the G1-verified `keccakXofFactory` symbol, not the Python class name. But future story authors reading plan/architecture will now see the corrected class name alongside the original.

### Rationale

The research-phase probe inverted the two class names. Every document that quoted the research probe (spec.md C-10 and A-2, architecture.md DD-13 and §Testing Strategy, plan.md Story 1-2 row) inherited the inversion. Story 1-1's CLI was drafted against live source and got the import right; Story 1-2's story-creator caught the delta at §Risks/Gotchas #1 but flagged it as a proposed amendment rather than pre-amending. T1 opens this amendment now so that all future implementers reading plan/architecture/stories get the corrected class name in-line without needing to cross-reference the source tree.

Universal rule `.claude/rules/retrospect/universal.md` §"[2026-04-18] Amendment doc sweep — don't leak the old shape" mandates the same-commit doc sweep across `{scripts,src,test,contracts,docs/stories}`. `git grep -n 'Keccak256PRNG' docs/` post-commit returns only hits that (a) correctly attribute the name to ETHDILITHIUM, (b) are amendment-callout explanatory text, or (c) are archived mldsa-eth-era docs (`docs/.archive-mldsa-eth/**`) which correctly reference the ETHDILITHIUM wrapper and are out of falcon-eth scope. Research-phase and spec-phase mis-attributions at `docs/research.md` and `docs/spec.md` remain as-is in this commit (outside the T1 modification scope declared in Story 1-2) and are flagged above as Rule-1 follow-ups — a future amendment may sweep those; meanwhile A-004 is authoritative per its "Affected" enumeration.

### Resolution

The T1 commit (`feat(fixture-gen): T1 G1 Keccak-PRG vector capture + A-004 class-name amendment`) lands:
- (a) `scripts/generate-kat-fixtures.ts` — new `writeFalconPrgFixture()` using the correct `KeccakPRNG()` class via `python3 -c` subprocess.
- (b) `test/fixtures/kat/falcon-eth/prg-vectors.json` — new G1 fixture output.
- (c) `docs/amendments.md` — this A-004 entry.
- (d) `docs/plan.md`, `docs/architecture.md`, `docs/stories/1-2.md` — per-line A-004 callout annotations on every `Keccak256PRNG(a, b)` (or `Keccak256PRNG(a,b)` or bare `Keccak256PRNG`) reference that attributes the name to ETHFALCON.

The plan/architecture text is **superseded** by this amendment for all Gate-5 verification, code-review, and downstream-story-creation purposes. The authoritative ETHFALCON class name is `KeccakPRNG`; the authoritative constructor arity is zero non-self arguments.

---

## A-005: Noble wraps Falcon keygen byte-identically; `@noble/ciphers#rngAesCtrDrbg256` replays the .rsp DRBG at test time — Story 2-1 resizes L→S (no fixture schema changes, no new crypto code)

- **Stories:** 2-1 (`core-and-keygen-port`) — lands the doc sweep + keygen wrapper (no fixture or Python-recorder changes). 2-3 (`signer port + G4`) — forward-bound (consumes the same `drbgSeed` field already in the fixture; derives signing randomness TS-side via `rngAesCtrDrbg256`).
- **Task:** Story 2-1 T1 lands the full amendment + doc sweep + story rewrite. Story 2-1 T2 adds the two wrapper files. Story 2-1 T3 adds the G3 KAT test (derives `innerSeed` via `rngAesCtrDrbg256` at test time).
- **Date:** 2026-04-20 (originally landed with fixture schema extension; revised same day to use `rngAesCtrDrbg256` after noble-ciphers audit).
- **Classification:** Rule 3 (Significant — interface correction + forward contract). Two intertwined issues resolved together:
  1. **Scope over-estimate (size):** Story 2-1 story-creator-agent drafted a ~500-LOC NTRU source-transplant from `@noble/post-quantum/src/falcon.ts` + XOF-factory abstraction + `falcon-eth.core.ts` module split. Empirical byte-identity shows noble's `falcon512.keygen(inner_seed)` is already bit-identical to `ETHFALCON.ntru_gen + encoders`. Port is unnecessary.
  2. **DRBG trust anchor placement:** Both Story 2-1's original draft AND Story 2-3's plan.md text imply writing a new AES-256-CTR-DRBG implementation in TypeScript. That's the ~80-LOC new-crypto-code concern. **`@noble/ciphers/aes.js` ships `rngAesCtrDrbg256` as a first-class public export** — byte-identical to ETHFALCON's Python `AES256_CTR_DRBG` (verified empirically; see Evidence §5). Neither fixture-gen recording nor TS-side hand-port is required: TS tests call `rngAesCtrDrbg256(hexToBytes(v.drbgSeed))` directly and derive both `inner_seed` (for keygen) and the 88 B signer randomness (for the signer) from the existing `drbgSeed` fixture field. The architecture.md:33+90 "DRBG runs at fixture-gen" framing is still correct for keygen/sign OUTPUT capture (those run in Python for `publicKey`/`secretKey`/`signature` fields), but the DRBG state itself is reproducible on either side — we pick the simpler one (TS at test time) to avoid new fixture fields.
- **Affects:**
  - `docs/architecture.md:33` (fixture-gen description) — inline A-005 callout (Python-side DRBG is load-bearing for capture of keygen+sign OUTPUT fields; TS replays DRBG at test time via `rngAesCtrDrbg256` for INPUT derivation)
  - `docs/architecture.md:90` (`drbgDerivation` in data model) — inline A-005 callout (`drbgSeed` field alone is sufficient; no fixture schema additions)
  - `docs/architecture.md:197+198` (G3 + G4 row surfaces) — inline A-005 callouts (KAT surfaces take derived `innerSeed` / `BytesReader` inputs; sourcing documented inline)
  - `docs/plan.md` §"Story 2-1: `core + keygen port` [L]" (size + task decomposition) — inline A-005 callout; superseded by this amendment's "Impact on Story 2-1" block
  - `docs/plan.md` §"Story 2-3: `signer port + G4`" lines 139/144/148/150 (`signWithDrbgRnd` + `drbgSeed` + `INVALID_DRBG_SEED_LENGTH`) — inline A-005 callouts; surface shape superseded by this amendment's "Forward contract for Story 2-3" block
  - `docs/stories/2-1.md` — rewritten to the S-sized shape landed in this commit chain (T1 = doc sweep only; T2 = wrappers; T3 = KAT test with TS-side DRBG derivation)
  - **Nothing under `scripts/`, `test/fixtures/kat/`, or `test/signers/`** is affected by T1 — no fixture changes, no Python-recorder changes. Story 2-1 T2 + T3 add new files under `test/signers/`.

### Evidence (unchanged — two independent proof paths)

1. **ETHFALCON reference tests are byte-identical for keygen:** `ETHFALCON/pythonref/test_falcon_KAT.py` defines `test_sign_KAT` (NIST-XOF signing) and `test_KAT_ETH` (Keccak-XOF signing). Lines 80-89 (NIST) and 122-131 (ETH) are byte-for-byte identical keygen code:
   ```python
   drbg = AES256_CTR_DRBG(seed)
   inner_seed = drbg.random_bytes(48)
   prng = SHAKE.new(inner_seed)          # ← SHAKE for keygen, not KeccakPRNG
   prng.flip()
   n = 512
   f, g, F, G = ntru_gen(n, randombytes=prng.read, logn=9)
   sk = SecretKey(n, [f, g, F, G])
   pk = PublicKey(n, sk.h)
   ```
   `expected_pk` (line 74 vs 117) and `expected_sk` (line 75 vs 118) are identical hex strings — ETHFALCON's KAT proves keygen outputs match NIST under the shared `seed`. Only `sig = sk.sign(msg, xof=SHAKE)` at line 92 vs `sig = sk.sign(msg, xof=KeccakPRNG)` at line 134 diverges. **The ETH-specific variation is the signing XOF only.**

2. **Empirical TS byte-identity (2026-04-20):** Against the vector-0 seed `061550…1FFA1` from `test_falcon_KAT.py:71`, Python's `AES256_CTR_DRBG(seed).random_bytes(48)` yields `inner_seed = 7c9935…5e47`. Passing that `inner_seed` directly to `noble.falcon512.keygen(inner_seed)` produces:
   - `publicKey` (897 B, header `0x09`) — byte-match `expected_pk` ✓
   - `secretKey` (1281 B, header `0x59`) — byte-match `expected_sk` ✓
   Command: `node --input-type=module -e "import { falcon512 } from '@noble/post-quantum/falcon.js'; …"` — pk/sk hex match verified.

3. **Noble's NTRU implements the right algorithm.** `node_modules/@noble/post-quantum/src/falcon.ts:13` imports `shake256 from '@noble/hashes/sha3.js'`; line 1244 in `NTRU.constructor` captures `this.shake = shake256.create().update(seed)`; line 2320 in `keygen()` calls `new NTRU(logn, seed).generate()` which consumes the SHAKE256 reader exactly as ETHFALCON's `ntru_gen(n, randombytes=prng.read, logn=9)` does. Encoders `secretKeyCoder.encode([f, g, F])` + `publicKeyCoder.encode(pub)` produce Round-3 canonical format (897/1281 bytes, headers `0x09`/`0x59`). No encoder / sampler / XOF divergence.

4. **Architecture's Python-side DRBG framing is valid for OUTPUT capture; INPUT derivation can be TS-side.** `docs/architecture.md:33+90` describe where the DRBG lives at fixture-gen time: Python's `AES256_CTR_DRBG(seed).random_bytes(N)` drives the keygen+sign subprocess that produces the output fields (`publicKey`, `secretKey`, `signature`, `reshapedPublicKey`) we already store. That framing is unchanged — those fields still come from Python. What the architecture did NOT prescribe (because `N` was "TBD") is a parallel TS-side DRBG to derive INPUTS (the 48 B `inner_seed` for keygen, the 88 B sig randomness for signing). Both options satisfy the architecture: (a) extend fixture with precomputed `innerSeed`/`signingDrbg` and a Python recorder; (b) derive TS-side via `rngAesCtrDrbg256` at test time. This amendment chooses (b) because the TS library IS bit-identical (Evidence §5) and avoids fixture-schema and Python-recorder complexity.

5. **`@noble/ciphers#rngAesCtrDrbg256` is byte-identical to ETHFALCON's `AES256_CTR_DRBG` (2026-04-20 empirical).** For vec-0's `drbgSeed = 0x061550…1FFA1`:
   ```ts
   import { rngAesCtrDrbg256 } from '@noble/ciphers/aes.js';
   const drbg = rngAesCtrDrbg256(hexToBytes(vec0.drbgSeed));
   drbg.randomBytes(48);  // → 0x7c9935a0b07694aa…5e47 (= Python inner_seed, ✓)
   drbg.randomBytes(40);  // → 0x33b3c07507e42017… (= first 40 B of Python signingDrbg, ✓)
   drbg.randomBytes(48);  // → … (= next 48 B of Python signingDrbg, ✓)
   ```
   All three draws byte-match Python's reference output. The DRBG state evolves identically across libraries (same NIST SP 800-90A algorithm, same AES-256-ECB primitive underneath). Ships as a FIRST-CLASS public export (not an `__tests` escape hatch) so API-stability risk is standard noble-ecosystem-level. See imports table in "Noble alignment discovery" for Rule-3 pin guidance.

### DRBG derivation contract (TS-side, binding)

**Story 2-1 + 2-3 derive DRBG outputs TS-side at test time.** No fixture schema changes. Fixture retains existing 7 fields (`id`, `drbgSeed`, `publicKey`, `secretKey`, `reshapedPublicKey`, `message`, `signature`).

**Derivation pattern (identical shape in 2-1 and 2-3):**

```ts
import { rngAesCtrDrbg256 } from "@noble/ciphers/aes.js";
import { hexToBytes } from "viem";

// Per-vector at test time:
const drbg = rngAesCtrDrbg256(hexToBytes(v.drbgSeed));   // 48 B seed from .rsp

// Story 2-1 (keygen G3):
const innerSeed = drbg.randomBytes(48);                  // first draw — SHAKE256 seed for noble.falcon512.keygen
const { publicKey, secretKey } = keygenInternal(innerSeed);
assertBytesEqual(publicKey, hexToBytes(v.publicKey));
assertBytesEqual(secretKey, hexToBytes(v.secretKey));

// Story 2-3 (signer G4 — forward-bound here):
drbg.randomBytes(48);                                     // advance past keygen's inner_seed draw
const reader: BytesReader = { read: (n) => drbg.randomBytes(n) };
const sig = signWithKatBytes(sk, msg, reader);           // consumes 40 (salt) + 48 (seed) = 88 B from reader
assertBytesEqual(sig, hexToBytes(v.signature));
```

**Why this is correct:** the DRBG is a deterministic state machine. Seeding with identical 48 B and making identical `randomBytes(n)` calls in the same order produces byte-identical output in Python and in TS (empirical proof §5). `drbgSeed` is sufficient; `innerSeed` + `signingDrbg` are redundant precomputations.

**Why not extend the fixture anyway:** storing 88+48 = 136 extra bytes per vector × 100 vectors × 2 (hex encoding) = ~27 KB of fixture bloat with zero information gain. The TS derivation is ~3 lines per test file; the Python recorder would be ~30 lines of fragile instrumentation. Simpler code + smaller fixture wins.

### Forward contract for Story 2-3 (binding, pre-lands surface shape + fork inventory)

The plan.md §"Story 2-3" text (lines 139/144/148/150) names a KAT surface `signWithDrbgRnd(sk, msg, drbgSeed)` + error code `INVALID_DRBG_SEED_LENGTH`. **This surface shape is superseded by A-005.** The signer-fork inventory below is also locked here (result of deep noble-source audit at amendment-drafting time — avoids another scope-drift at 2-3 creation).

#### signingDrbg byte decomposition (verified against `ETHFALCON/pythonref/falcon.py:442-467`)

Signing consumes the DRBG **exactly twice**, in this order:
```python
salt = randombytes(SALT_LEN)       # line 451 — SALT_LEN = 40 (falcon.py:45)
hashed = self.hash_to_point(self.n, message, salt, xof=xof)   # line 452 (HashToPoint — uses KeccakPRNG, NOT DRBG)
if randombytes != urandom:
    seed = randombytes(SEED_LEN)   # line 455 — SEED_LEN = 48 (falcon.py:46)
    shake_prng = SHAKE.new(seed); shake_prng.flip()
# --- DRBG IS DONE. All further randomness comes from shake_prng (→ ChaCha20-per-iteration). ---
```
Total DRBG consumption per vector: **40 + 48 = 88 bytes** (regardless of rejection-loop iteration count — the rejection entropy comes from `shake_prng.read(56)` → `ChaCha20(chacha_seed).randombytes(...)`, not from the DRBG). Fixed per vector; not variable. Verified empirically in Python + cross-validated against `rngAesCtrDrbg256` TS-side.

**Structure of the 88 B (consumed in order by noble's `signRaw` at `falcon.ts:2187` + `:2192`, matching ETHFALCON Python lines 451 + 455):**
- **bytes [0..40):** `salt` — feeds HashToPoint at Python line 452 (and is also the first 40 bytes of the output signature per `return header + salt + enc_s` at line 477).
- **bytes [40..88):** `seed` — feeds `SHAKE.new(seed).flip()` at Python line 456-457. The resulting SHAKE256 state drives ChaCha20 seeding **inside** the rejection loop (`chacha_seed = shake_prng.read(56); chacha = ChaCha20(chacha_seed)` at lines 465-466).

**Source for Story 2-3's KAT tests:** derived TS-side from the existing `v.drbgSeed` fixture field via `rngAesCtrDrbg256` (see "DRBG derivation contract" above). No fixture field added; no 88 B blob stored.

#### Noble alignment discovery (falcon.ts source audit, 2026-04-20)

**Noble already implements ETHFALCON's full sampler pipeline verbatim, except for HashToPoint XOF.** Key evidence from `node_modules/@noble/post-quantum/src/falcon.ts`:

1. **`signRaw` at lines 2159-2250** takes `rnd: FalconRandom` (signature `(len: number) => Uint8Array`) and consumes it EXACTLY as ETHFALCON:
   - `const nonce = rnd(40);` (line 2187) ≡ ETHFALCON `salt = randombytes(SALT_LEN)`
   - `const hm = HashToPoint(nonce, msg);` (line 2191) — **the one divergence; noble hardcodes SHAKE256 at line 1767**
   - `const seed = rnd(48);` (line 2192) ≡ ETHFALCON `seed = randombytes(SEED_LEN)`
   - `const sampler = new FFSampler(logn, seed, b00, b01, b10, b11);` (line 2203) ≡ ETHFALCON `shake_prng = SHAKE.new(seed); shake_prng.flip()`
2. **`FFSampler` class at lines 1781-1850** is the exact SHAKE256→ChaCha20 cascade ETHFALCON uses:
   - Line 1807: `this.shake = shake256.create().update(seed)` (SHAKE256 state from 48 B seed)
   - Lines 1808-1811: reads 56 B from SHAKE256 per refill, splits into 32 B chacha key + 16 B nonce + 8 B counter
   - Line 1842: `chacha20(this.key, u8(n.subarray(1)), EMPTY_CHACHA20_BLOCK, this.curBlock, n[0])` from `@noble/ciphers/chacha.js` — this IS ETHFALCON's `ChaCha20(chacha_seed).randombytes(...)`
3. **Noble explicitly comments this flow** at lines 104-108: `"1. aes-drbg generates seed · 2. The seed passes CSPRNG into sign, which uses shake256 to produce another seed and nonce · 3. Then a separate rejection sampling chacha20 CSPRNG is created, based on that seed."` — this IS the ETHFALCON flow, NIST-KAT-compatible by construction.
4. **Noble exposes `rngAesCtrDrbg256`** from `@noble/ciphers/aes.js` (first-class public export, not via `__tests`). `@noble/post-quantum/falcon.js:7` imports it; `@noble/post-quantum` uses it internally at `falcon.ts:2296` for `opts.extraEntropy`. **Byte-identical to ETHFALCON's Python `AES256_CTR_DRBG`** (vec-0 test 2026-04-20, see Evidence §5). Story 2-1 + 2-3 import it directly and derive DRBG outputs TS-side at test time.
5. **`@noble/ciphers/chacha.js` is already installed** as a transitive dep (`node_modules/@noble/ciphers/chacha.js` present; `@noble/post-quantum/falcon.ts:8` imports from it). Story 2-3 may import `chacha20` directly if needed, but in practice the FFSampler copy-port encapsulates this.

#### Story 2-3 fork inventory (locked)

The only algorithmic divergence between noble and ETHFALCON signing is **HashToPoint's XOF** (SHAKE256 vs KeccakPRNG). Story 2-3 MUST fork noble's closure-scoped internals into `test/signers/falcon-eth.core.ts` with that single change. Noble's `signRaw`, `FFSampler`, `HashToPoint`, and `completePrivate` are NOT exported — only via a `// NOTE: for tests only, don't use` escape hatch `__tests` at `falcon.ts:2490-2503`. Fork is unavoidable.

**Copy targets (with @delta-from-falcon headers per story convention):**

| Component | Source | LOC est. | Changes in fork |
|---|---|---|---|
| `HashToPoint` | `falcon.ts:1752-1777` | ~25 | **Swap `shake256.create().update(nonce).update(msg)` → Story 2-2's `hashToPointEVM(nonce, msg)` (KeccakPRNG-based).** Match the `Uint16Array(N)` return shape verbatim. |
| `FFSampler` class (full: ctor + refill + gaussian0 + sampleNext + sample) | `falcon.ts:1781-~1940` (end marker TBD by story-creator reading) | ~150 | Verbatim copy. No algorithmic change — the SHAKE256→ChaCha20 cascade IS the Falcon reference. |
| `signRaw` | `falcon.ts:2159-2250` | ~90 | Verbatim copy with ONE change at line 2191: `HashToPoint(nonce, msg)` → the fork's `HashToPoint` (which now calls `hashToPointEVM`). Nonce + seed injection via `rnd` callback is unchanged. |
| `completePrivate` helper | `falcon.ts` (lookup during 2-3 T1) | ~20 | Verbatim copy. |
| **Total fork size** | | **~285 LOC** | Source-transplant. Substantially smaller than plan.md's original "hybrid-fork" framing. |

**Reusable imports from noble (no copy needed):**

| Symbol | Source | Purpose |
|---|---|---|
| `rngAesCtrDrbg256` | `@noble/ciphers/aes.js` | **KAT DRBG replay** — Stories 2-1 + 2-3 consume to derive `innerSeed` / signer `BytesReader` from the fixture's `drbgSeed` field. First-class public export. |
| `chacha20` | `@noble/ciphers/chacha.js` | For FFSampler fork's copy of line 1842. First-class export. |
| `shake256` | `@noble/hashes/sha3.js` | For FFSampler fork's copy of line 1807. First-class export. |
| `Float`, `SIGMA_MIN`, `INV_SIGMA`, `COMPLEX_ROOTS`, `BNORM_MAX` | `@noble/post-quantum/falcon.js` `__tests` export (line 2490) | Sampler math constants. **Test-only export — Rule-3 API-stability risk (see mitigation below).** |
| `getFloatPoly` (factory) | `@noble/post-quantum/falcon.js` `__tests` | Float polynomial arithmetic. Test-only. |
| `cleanCPoly` | `@noble/post-quantum/falcon.js` `__tests` | Memory hygiene. Test-only. |
| `falcon512.__test.privateKeyCoder` | `@noble/post-quantum/falcon.js` `__tests` | For `secretKeyCoder.decode(sk)` in forked `signRaw`. Test-only. |
| `falcon512.__test.maxS2Len` | `@noble/post-quantum/falcon.js` `__tests` | For signature-length bound in forked `signRaw`. Test-only. |

**⚠ Rule-3 API-stability dependency:** `__tests` is annotated `// NOTE: for tests only, don't use`. Any noble version bump that removes or restructures `__tests` breaks the fork. **Mitigation:** pin `@noble/post-quantum` to a narrow version range (e.g., `~0.6.x` instead of `^0.6.x`) so minor-bumps require a conscious amendment. Fallback plan: if `__tests` goes away, fork the math helpers too (+~500 LOC — still cheaper than hand-implementing Falcon float/int arithmetic). Treat noble bumps during Stories 2-3 + 2-4 as Rule-3 events.

#### Surface shape

- **KAT surface (binding):** `signWithKatBytes(sk: Uint8Array, msg: Uint8Array, reader: BytesReader): Uint8Array` returning 1064 B `header(1) ‖ salt(40) ‖ s2_compact(1023)`. Reader is sourced TS-side: `const drbg = rngAesCtrDrbg256(hexToBytes(v.drbgSeed)); drbg.randomBytes(48); const reader = { read: (n) => drbg.randomBytes(n) };` — advances the DRBG past keygen's inner_seed draw, then yields the 88 B (40 + 48) signer randomness through sequential `read(40)` + `read(48)` calls driven by noble's forked `signRaw`. **Reader MUST enforce: on `read(n)` beyond the expected 88 B total, throw `SIGNING_BYTES_EXHAUSTED` — indicates TS signer divergence from the canonical flow.**
- **Production surface:** `signUserOp(...)` wraps `globalThis.crypto.getRandomValues` into a `BytesReader`. Reader allocates 88 B upfront, fills via CSPRNG, yields on sequential reads. Same forked signer path.
- **`BytesReader` interface** (declared in 2-3's core module):
  ```ts
  export interface BytesReader {
    /** Returns exactly `n` bytes. Throws SIGNING_BYTES_EXHAUSTED if fewer remain (KAT) or if the underlying source fails (production). */
    read(n: number): Uint8Array;
  }
  ```
  One shared interface between KAT + production avoids two divergent signer code paths. Story 2-3 picks the final type name (may prefer `SigningRandomness` or similar over generic `BytesReader` if clearer).
- **Error codes:** `INVALID_DRBG_SEED_LENGTH` (from plan) is DROPPED — no drbgSeed in the signer's surface. Introduce (names approximate — 2-3's story-creator finalizes):
  - `SIGNING_BYTES_EXHAUSTED` — KAT reader ran past 88 B (port bug: TS signer drew more DRBG randomness than Python).
  - `SIGNING_BYTES_SHORT` — reader returned fewer than `n` bytes on `read(n)` (production CSPRNG wrapper bug).
  - Retained: `INVALID_SECRET_KEY_LENGTH` (same shape as plan), `INVALID_MESSAGE` (same shape).
- **AC-1 (G4 KAT) reinterpreted:** Given vec N's `(sk, msg, drbgSeed)` from fixture, When `signWithKatBytes(sk, msg, drbgReader(v.drbgSeed))` runs (where `drbgReader` is `const d = rngAesCtrDrbg256(hexToBytes(seed)); d.randomBytes(48); return { read: (n) => d.randomBytes(n) }`), Then output 1064 B byte-equals `vector.signature` for that vector — over 100 vectors. The 1064 B layout itself is unchanged from the plan.
- **AC-6 (PRE_G4_DRBG_PROBE composition) retained** — the probe lives at fixture-gen (Python-side) and validated for vec 0 at Story 1-1 T0. If probe passed, 100 vectors' `publicKey`/`secretKey`/`signature` outputs were Python-reproducible under the shared `drbgSeed`. If >1 G4 KAT vector fails in 2-3, it's a TS signer port bug (likely a FFSampler copy error or an off-by-one in HashToPoint `hashToPointEVM`), not a fixture-gen bug. The DRBG-state-reproducibility aspect of the probe is ALSO validated TS-side (see Evidence §5 — `rngAesCtrDrbg256` byte-match vs Python reference).

#### 2-3 story-creator mandate

When the story-creator for 2-3 runs (wave 4, after 2-1 closes), it MUST:
1. Read this A-005 section in full (including "DRBG derivation contract" + "Noble alignment discovery" + "Story 2-3 fork inventory" + "Surface shape").
2. Read the `FalconKatVector` interface in `test/fixtures/kat/index.ts` — note it has ONLY 7 fields; `drbgSeed` is the sole DRBG input.
3. Read `docs/stories/2-1.md` §"Tasks → T3" to see the `rngAesCtrDrbg256` derivation pattern used at test time; Story 2-3's T1 mirrors it (advance past 48 B, then read 88 B).
4. Read `node_modules/@noble/post-quantum/src/falcon.ts` lines 1752-1850 (FFSampler + HashToPoint) and 2159-2250 (signRaw) to confirm the fork inventory is accurate at the time of 2-3 creation (noble version may have bumped — if line numbers shift, the `__tests` export at line 2490-2503 is the anchor). If `__tests` is gone or the math helpers no longer export, this is a Rule-3 amendment trigger — HALT and raise with user before continuing 2-3.
5. Do NOT re-introduce `signWithDrbgRnd(drbgSeed)` from plan.md — that surface is superseded.
6. Do NOT re-port `AES-256-CTR-DRBG` (use `@noble/ciphers#rngAesCtrDrbg256`), `ChaCha20` (use `@noble/ciphers#chacha20`), or `SHAKE256` (use `@noble/hashes#shake256`) — all are first-class imports.
7. Do NOT re-port `NTRU-gen`, `ffSampling`, `splitFFT`, or `mergeFFT` — signer doesn't need NTRU-gen (that's keygen's domain, done in noble's `falcon512.keygen`), and `ffSampling` is inside `FFSampler.sample()` which we copy verbatim.
8. Do NOT propose fixture schema extensions for `innerSeed` or `signingDrbg` — they are derivable TS-side from the existing `drbgSeed`. A fixture extension was considered and rejected (see "DRBG derivation contract" for rationale).
9. The `BytesReader`-over-`rngAesCtrDrbg256`-DRBG pattern + fork-with-HashToPoint-swap is the binding contract.

### Impact on Story 2-1

- **Size:** L → S (3 tasks, ~100 LOC total target).
- **Tasks (new):**
  - **T1 — Amendment + doc sweep + story rewrite** (docs-only; no code or fixture changes):
    1. Write this A-005 amendment in `docs/amendments.md`.
    2. Sweep `docs/plan.md` Story 2-1 + Story 2-3 headers with inline A-005 callouts (match A-004 callout style).
    3. Sweep `docs/architecture.md:33`, `:90`, `:197`, `:198` with inline A-005 callouts.
    4. Rewrite `docs/stories/2-1.md` to the S-sized task decomposition defined here (T1 = this doc sweep; T2 = wrappers; T3 = KAT test with TS-side DRBG derivation).
    5. Update `docs/sprint-status.yaml` (size L→S already done pre-commit).
    6. Update `docs/state.json` (metrics).
    7. Commit message: `feat(falcon-eth): T1 A-005 amendment + doc sweep — Story 2-1 Task 1/3 · forward-binds Story 2-3 to rngAesCtrDrbg256 pattern`.
    8. **No `scripts/`, `test/fixtures/`, or `test/signers/` files touched in T1.** Fixture retains its existing 7 fields. Python subprocess unchanged.
  - **T2 — `keygenInternal(innerSeed)` + production `keygen()`:**
    - `test/signers/falcon-eth.kat-internal.ts` (NEW, ~15 LOC): `keygenInternal(innerSeed: Uint8Array): Keypair` — guards `innerSeed instanceof Uint8Array && innerSeed.length === 48` with `SignerInputError { code: "INVALID_INNER_SEED_LENGTH" }`, then `return falcon512.keygen(innerSeed)`. No DRBG import — the DRBG derivation happens in T3's test code, not inside `keygenInternal` itself.
    - `test/signers/falcon-eth.ts` (NEW, ~15 LOC): `keygen(): Keypair` — sources `seed = globalThis.crypto.getRandomValues(new Uint8Array(48))`, calls `falcon512.keygen(seed)`, returns. Does NOT import from `falcon-eth.kat-internal.ts`.
    - `test/signers/falcon-eth.test.ts` (NEW, small): AC-2 + AC-3 + AC-5 + AC-6 unit tests.
    - Commit: `feat(falcon-eth): T2 keygenInternal + production keygen — Story 2-1 Task 2/3 · AC-2/AC-3/AC-5/AC-6`.
  - **T3 — G3 KAT byte-identity test with TS-side DRBG derivation:**
    - `test/signers/falcon-eth.keygen.kat.test.ts` (NEW, ~55 LOC): iterate `loadKatVectors("falcon-eth")`; for each `v`:
      ```ts
      import { rngAesCtrDrbg256 } from "@noble/ciphers/aes.js";
      const drbg = rngAesCtrDrbg256(hexToBytes(v.drbgSeed));
      const innerSeed = drbg.randomBytes(48);
      const { publicKey, secretKey } = keygenInternal(innerSeed);
      // assert byte-identity vs hexToBytes(v.publicKey) and hexToBytes(v.secretKey)
      ```
      Module-scope divergence-message helper per `.claude/rules/retrospect/typescript.md` §"[2026-04-20] Duplicated failure-message templates".
    - Commit: `test(falcon-eth): T3 G3 KAT byte-identity via rngAesCtrDrbg256 — Story 2-1 Task 3/3 · AC-1`.

- **Tasks (dropped from original story-creator draft):**
  - ❌ "NTRU fork + `keygenWithXof` in core" — noble is verbatim-correct.
  - ❌ `falcon-eth.core.ts` shared-core module — no shared helpers needed for keygen.
  - ❌ `XofFactory` parameterization — keygen hardcodes SHAKE256 via noble; nothing to inject.
  - ❌ `@delta-from-falcon` JSDoc + `FALCON_DELTA_HEADINGS` grep gate — no delta to document.
  - ❌ `(let|var) _?xof` grep gate — keygen has no xof variable; trivially satisfied.
  - ❌ **AES-256-CTR-DRBG port to TypeScript** — `rngAesCtrDrbg256` from `@noble/ciphers/aes.js` imported directly.
  - ❌ **Fixture schema extension (`innerSeed`, `signingDrbg` fields) + Python recorder** — rejected per "DRBG derivation contract" section; TS-side derivation is simpler and redundancy-free.

- **ACs retained from plan (reinterpreted):**
  - **AC-1 (G3 KAT):** byte-identity over ≥100 vectors — unchanged. Input to `keygenInternal` is the 48 B `innerSeed` DERIVED at test time via `rngAesCtrDrbg256(hexToBytes(v.drbgSeed)).randomBytes(48)`. Output comparison unchanged.
  - **AC-2 (Production surface hedging):** unchanged — `keygen()` entropy-sourced, two calls produce different keys.
  - **AC-3 (Input validation):** reinterpreted — `keygenInternal` throws `SignerInputError { code: "INVALID_INNER_SEED_LENGTH" }` on non-48-byte input. The error code name changes (`INVALID_DRBG_SEED_LENGTH` → `INVALID_INNER_SEED_LENGTH`) to reflect what the parameter actually is.
  - **AC-4 (Module-header structural check):** dropped — no delta-from header required.
  - **AC-5 (Grep gates):** reduced — only the `KAT_INTERNAL_MODULES` import check (`test/signers/index.ts` + `test/bench/**/*.ts` must not import `falcon-eth.kat-internal`). `(let|var) _?xof` dropped.
  - **AC-6 (Interface):** reduced — `falcon-eth.ts` exports `keygen()`; `falcon-eth.kat-internal.ts` exports `keygenInternal(innerSeed)`. Neither imports the other. No `core` module.
  - **AC-7 (Fixture schema extension):** DROPPED — rejected in favor of TS-side derivation via `rngAesCtrDrbg256`. Fixture retains existing 7 fields.

### Retrospect candidate (to be proposed at Gate 5 if findings-deferred captures knowledge gap)

The class-of-bug surfaced here is worth a retrospect rule (target: `.claude/rules/retrospect/universal.md`):

> **[TBD date] Story-creator must check existing dependencies before proposing new runtime crypto.** When plan.md says "implement foo that does X (cryptographic primitive)", story-creator must: (a) grep `node_modules/` for existing library exports that implement X (e.g., `node_modules/@noble/{hashes,ciphers,curves,post-quantum}/*.ts` for hash/cipher/signature primitives); (b) check architecture.md for whether X's computation happens at fixture-gen time (Python) vs runtime (TS) vs both; (c) check the data-model section for whether X's output is stored as a fixture field rather than a derived value. Plan text is often ambiguous ("implement foo that replays Y" can mean port-to-TS, import-from-library, derive-from-fixture-field, or fixture-gen-recording — four distinct designs); architecture + existing library/fixture inventory are the ground truth.
>
> **Why:** This rule was derived from Story 2-1's journey through three designs in 4 hours:
> 1. **L-sized "NTRU fork + XOF-factory + falcon-eth.core.ts"** (original story-creator draft) — missed that noble.falcon512.keygen is byte-identical to ETHFALCON's ntru_gen.
> 2. **S-sized "port AES-CTR-DRBG to TS + fixture schema extension + Python recorder"** (amendment v1) — missed that `@noble/ciphers/aes.js` ships `rngAesCtrDrbg256` as a first-class export, byte-identical to ETHFALCON's Python DRBG. Also added 2 unnecessary fixture fields.
> 3. **S-sized "import rngAesCtrDrbg256 + wrap falcon512.keygen"** (amendment v2, final) — the library-first approach. ~50 LOC total. No fixture changes. No Python changes. No new crypto code.
>
> Each design iteration shrank scope by 2-5x once the correct library/primitive was discovered. The iteration cost was real (re-reading architecture, reverting committed fixture changes), and each pivot would have been avoidable with an upfront "grep node_modules" pass.
>
> **How to apply:** At story creation time, for every task that proposes "X cryptographic primitive", do an **explicit library survey** of `node_modules/@noble/*` (and any other trusted crypto libs in the project) BEFORE writing the task spec. If a byte-identical library function exists, the task is "import + wrap," not "port." If the fixture already has the inputs needed to derive X, NO fixture schema change is needed. Treat "port to TS" as the LAST resort; library-first, fixture-first, port-only-if-neither.

Proposal lands at Gate 5 of Story 2-1 via `[L] Apply fixes + learn` (or equivalent) if the code-review surfaces the knowledge gap.

### Downstream implications

- **Story 2-3 (signer):** scope LIKELY SHRINKS L → M. Noble source audit (2026-04-20, documented in "Noble alignment discovery" above) shows noble's `signRaw` + `FFSampler` + `HashToPoint` implement the ETHFALCON flow **verbatim except for HashToPoint's XOF**. Story 2-3 is therefore a ~285-LOC source-transplant fork with a single algorithmic change (HashToPoint call-site → `hashToPointEVM`), not a ground-up Gaussian sampler port. The rejection-sampling ChaCha20 pipeline is already in noble. Noble's `__tests` escape hatch exposes all required math helpers; Story 2-3 imports them rather than re-implementing. Net: 2-3 story-creator should size at M. The "L" in plan.md reflects the original "hybrid-fork from scratch" framing which is superseded by this amendment.
- **Story 2-4 (integration + benchmark):** unaffected.
- **Stories 1-2 (Keccak-PRG) and 2-2 (HashToPoint):** unaffected. Both remain load-bearing for the signer path.

### Resolution

- This A-005 amendment landed in `docs/amendments.md` in Story 2-1's first T1 commit (e4b2a5a, 2026-04-20). That commit included a fixture schema extension + Python recorder changes; those were REVERTED in the corrective follow-up commit upon discovery of `@noble/ciphers#rngAesCtrDrbg256` (Evidence §5). A-005 now reflects the final "library-first" design: no fixture changes, no Python changes, no new crypto code.
- `docs/architecture.md:33`, `:90`, `:197`, `:198` + `docs/plan.md` Story 2-1 + Story 2-3 headers carry inline A-005 callouts (matching A-004 callout style).
- `docs/stories/2-1.md` rewrote to the S-sized shape. T1 = doc sweep only (no code); T2 = wrappers; T3 = KAT test with TS-side `rngAesCtrDrbg256` derivation.
- Upstream retrospect rule **carried from** `.claude/rules/retrospect/universal.md` §"[2026-04-18] Amendment doc sweep — don't leak the old shape": this amendment's doc sweep is exactly that rule's prescribed action. The architecture/plan/story texts that implied TS-side DRBG re-port are stale and are corrected here.
- **NEW retrospect candidate** documented above ("library-first vs port-first"): proposed at Gate 5 via `[L] Apply fixes + learn` if code-review surfaces the knowledge gap. Story 2-1's three-design journey (L NTRU fork → S fixture-recorder → S library-wrapper) is strong evidence for the rule.
- Plan/architecture phrasing is **superseded** by this amendment for all Gate-5 verification, code-review, and downstream-story-creation purposes (Stories 2-1 T2/T3, 2-3, 2-4).
