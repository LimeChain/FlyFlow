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

## A-005: Fixture-side Python AES-CTR-DRBG IS the architecture decision — Story 2-1 resizes L→S (noble wrapper) and forward-binds Story 2-3 to consume precomputed signingDrbg

- **Stories:** 2-1 (`core-and-keygen-port`) — lands the fixture schema extension + keygen wrapper. 2-3 (`signer port + G4`) — forward-bound (consumes the new fixture field; no TS-side DRBG).
- **Task:** Story 2-1 T1 lands the full amendment + doc sweep + fixture extension. Story 2-1 T2/T3 consume `innerSeed`. Story 2-3 will consume `signingDrbg`.
- **Date:** 2026-04-20
- **Classification:** Rule 3 (Significant — interface correction + forward contract). Two intertwined issues resolved together:
  1. **Scope over-estimate (size):** Story 2-1 story-creator-agent drafted a ~500-LOC NTRU source-transplant from `@noble/post-quantum/src/falcon.ts` + XOF-factory abstraction + `falcon-eth.core.ts` module split. Empirical byte-identity shows noble's `falcon512.keygen(inner_seed)` is already bit-identical to `ETHFALCON.ntru_gen + encoders`. Port is unnecessary.
  2. **Drift from architecture (DRBG placement):** Both Story 2-1's original draft AND Story 2-3's plan.md text imply AES-256-CTR-DRBG gets ported to TypeScript (to "replay" the .rsp drbgSeed at runtime). This contradicts `docs/architecture.md:33` and `docs/architecture.md:90`, which explicitly place DRBG derivation at the Python fixture-gen layer (`scripts/generate-kat-fixtures.ts` — already runs `AES256_CTR_DRBG(seed)` via `python3 -c` subprocess for falcon-eth's existing fields). The established pattern (carried from mldsa-eth per `docs/research.md:109`) is: Python computes, TS consumes. Both stories' drift came from anchoring on plan.md phrasing without cross-checking architecture + existing fixture-gen code.
- **Affects:**
  - `docs/architecture.md:33` (fixture-gen description) — inline A-005 callout
  - `docs/architecture.md:90` (`drbgDerivation` in data model) — inline A-005 callout (N is now known, captured per-vector via recorder; no longer "TBD by Python-ref audit")
  - `docs/architecture.md:197` (G3 row — "Uses G1-verified XOF") — inline A-005 callout (G3 uses SHAKE256, not Keccak-PRG; G1 is load-bearing for 2-3 signing, not 2-1 keygen)
  - `docs/plan.md` §"Story 2-1: `core + keygen port` [L]" (size + task decomposition) — inline A-005 callout; superseded by this amendment's "Impact on Story 2-1" block
  - `docs/plan.md` §"Story 2-3: `signer port + G4`" lines 139/144/148/150 (`signWithDrbgRnd` + `drbgSeed` + `INVALID_DRBG_SEED_LENGTH`) — inline A-005 callouts; surface shape superseded by this amendment's "Forward contract for Story 2-3" block
  - `scripts/generate-kat-fixtures.ts` — Story 2-1 T1 extends Python recorder + TS schema to emit `innerSeed` + `signingDrbg` per vector
  - `test/fixtures/kat/index.ts` — Story 2-1 T1 extends `FalconKatVector` interface with `innerSeed` + `signingDrbg`
  - `test/fixtures/kat/falcon-eth/vectors.json` — Story 2-1 T1 regenerates with 100 vectors × new fields
  - `docs/stories/2-1.md` — rewritten to the S-sized shape landed in this commit chain

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

4. **Architecture already placed DRBG in Python (not TS).** `docs/architecture.md:33` ("Fixture-gen CLI extension... spawns one `python3 -c ...`") and `docs/architecture.md:90` (`drbgDerivation: AES256_CTR_DRBG(drbgSeed).random_bytes(N)` — a data-model field description for the fixture's `source` block, not a TS-side runtime contract). `scripts/generate-kat-fixtures.ts:870-902` already invokes Python with `AES256_CTR_DRBG(seed)` for falcon-eth's existing fixture fields. **The Python-side DRBG is shipped infrastructure, not new work.** The new work is extending the Python recorder to ALSO capture `inner_seed` (the keygen draw) and `signingDrbg` (all post-keygen draws during `sk.sign`).

### Fixture schema extension (Story 2-1 T1 contract)

`test/fixtures/kat/index.ts` `FalconKatVector` gains two fields; `test/fixtures/kat/falcon-eth/vectors.json` regenerates with them populated for all 100 vectors:

```jsonc
// FalconKatVector (extended)
{
  "id":                "vec-000",
  "drbgSeed":          "0x…(48B)",            // existing — .rsp seed, audit trail
  "publicKey":         "0x…(897B)",           // existing — G3 expected
  "secretKey":         "0x…(1281B)",          // existing — G3 expected
  "reshapedPublicKey": "0x…",                 // existing — G5 expected
  "message":           "0x…",                 // existing — G4 input
  "signature":         "0x…(1064B)",          // existing — G4 expected

  // NEW fields (A-005):
  "innerSeed":         "0x…(48B)",            // = drbg.random_bytes(48) post-seed; keygen XOF seed.          Consumed by Story 2-1 `keygenInternal(innerSeed)`.
  "signingDrbg":       "0x…(variable B)"      // = concat of all drbg.random_bytes(N) calls during sk.sign(). Consumed by Story 2-3 via a `BytesReader`.
}
```

**Capture mechanism (Python, in `scripts/generate-kat-fixtures.ts` inline Python):** wrap `AES256_CTR_DRBG` with a `RecordingDRBG` that passively appends every `random_bytes(n)` return-value to an internal buffer. After keygen, capture `innerSeed = drbg.random_bytes(48)` directly. Reset the recorder. Run `sk.sign(msg, randombytes=rec.random_bytes, xof=KeccakPRNG)` — the recorder naturally captures exactly the bytes the signer consumed (rejection-loop-aware; no guessing). Dump `rec.drawn.hex()` as `signingDrbg`. Deterministic per vector (same `drbgSeed` + `msg` + `sk` → same byte count + bytes). See `docs/stories/2-1.md` §"Tasks → T1" for the concrete Python sketch.

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
Total DRBG consumption: **40 + 48 = 88 bytes per vector** (regardless of rejection-loop iteration count — the rejection entropy comes from `shake_prng.read(56)` → `ChaCha20(chacha_seed).randombytes(...)`, not from the DRBG). Empirically confirmed across all 100 vectors by Story 2-1 T1's `RecordingDRBG` diagnostic: `min=max=mean=88 B`. The 88 B is stable; the fixture field `signingDrbg` is ALWAYS exactly 88 hex bytes (176 hex chars, excluding the `0x` prefix — the loader test at `test/fixtures/kat/index.test.ts` validates the 0x-prefix + even-length shape, but Story 2-3 can additionally assert `signingDrbg.length === 178` in its KAT loader).

**Structure of the 88 B:**
- **bytes [0..40):** `salt` — feeds HashToPoint at Python line 452 (and is also the first 40 bytes of the output signature per `return header + salt + enc_s` at line 477).
- **bytes [40..88):** `seed` — feeds `SHAKE.new(seed).flip()` at Python line 456-457. The resulting SHAKE256 state drives ChaCha20 seeding **inside** the rejection loop (`chacha_seed = shake_prng.read(56); chacha = ChaCha20(chacha_seed)` at lines 465-466).

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
4. **Noble ships its own `rngAesCtrDrbg256`** (used at `falcon.ts:2296` for `opts.extraEntropy`) — confirms noble is Falcon-NIST-KAT-compatible end-to-end. Story 2-3 does NOT consume this (fixture precomputes DRBG output), but its existence validates our structural decisions.
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
| `chacha20` | `@noble/ciphers/chacha.js` | For FFSampler fork's copy of line 1842 |
| `shake256` | `@noble/hashes/sha3.js` | For FFSampler fork's copy of line 1807 |
| `Float`, `SIGMA_MIN`, `INV_SIGMA`, `COMPLEX_ROOTS`, `BNORM_MAX` | `@noble/post-quantum/falcon.js` `__tests` export (line 2490) | Sampler math constants |
| `getFloatPoly` (factory) | `@noble/post-quantum/falcon.js` `__tests` | Float polynomial arithmetic |
| `cleanCPoly` | `@noble/post-quantum/falcon.js` `__tests` | Memory hygiene |
| `falcon512.__test.privateKeyCoder` | `@noble/post-quantum/falcon.js` `__tests` | For `secretKeyCoder.decode(sk)` in forked `signRaw` |
| `falcon512.__test.maxS2Len` | `@noble/post-quantum/falcon.js` `__tests` | For signature-length bound in forked `signRaw` |

**⚠ Rule-3 API-stability dependency:** `__tests` is annotated `// NOTE: for tests only, don't use`. Any noble version bump that removes or restructures `__tests` breaks the fork. **Mitigation:** pin `@noble/post-quantum` to a narrow version range (e.g., `~0.6.x` instead of `^0.6.x`) so minor-bumps require a conscious amendment. Fallback plan: if `__tests` goes away, fork the math helpers too (+~500 LOC — still cheaper than hand-implementing Falcon float/int arithmetic). Treat noble bumps during Stories 2-3 + 2-4 as Rule-3 events.

#### Surface shape

- **KAT surface (binding):** `signWithKatBytes(sk: Uint8Array, msg: Uint8Array, reader: BytesReader): Uint8Array` returning 1064 B `header(1) ‖ salt(40) ‖ s2_compact(1023)`. Reader wraps `vector.signingDrbg` via `bytesReaderFromHex(hex)`; reader.read(40) returns salt, reader.read(48) returns seed. **Reader MUST enforce: exactly 88 B available, reader.read beyond 88 B is a port bug (throw).**
- **Production surface:** `signUserOp(...)` wraps `globalThis.crypto.getRandomValues` into a `BytesReader` that returns 88 B of CSPRNG-drawn randomness on first (and only) read. Same forked signer path.
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
- **AC-1 (G4 KAT) reinterpreted:** Given vec N's `(sk, msg, signingDrbg)` from fixture, When `signWithKatBytes(sk, msg, bytesReaderFromHex(signingDrbg))` runs, Then output 1064 B byte-equals `vector.signature` for that vector — over 100 vectors. The 1064 B layout itself is unchanged from the plan.
- **AC-6 (PRE_G4_DRBG_PROBE composition) retained** — the probe lives at fixture-gen (Python-side), so: if probe passed for vec 0, and T1's `signingDrbg` capture is deterministic (verified via RecordingDRBG passive wrap), then 100 vectors' `signingDrbg` reflects the byte-exact Python flow. If >1 G4 KAT vector fails in 2-3, it's a TS signer port bug (likely a FFSampler copy error or an off-by-one in HashToPoint `hashToPointEVM`), not a fixture-gen bug.

#### 2-3 story-creator mandate

When the story-creator for 2-3 runs (wave 4, after 2-1 closes), it MUST:
1. Read this A-005 section in full (including "Noble alignment discovery" + "Story 2-3 fork inventory" + "Surface shape").
2. Read the updated `FalconKatVector` interface in `test/fixtures/kat/index.ts` (landed by Story 2-1 T1).
3. Read `docs/stories/2-1.md` §"Out of Scope" which references `signingDrbg` as a forward crumb.
4. Read `node_modules/@noble/post-quantum/src/falcon.ts` lines 1752-1850 (FFSampler + HashToPoint) and 2159-2250 (signRaw) to confirm the fork inventory is accurate at the time of 2-3 creation (noble version may have bumped — if the line numbers are off, the `__tests` export at line 2490-2503 is the anchor). If `__tests` is gone or the math helpers no longer export, this is a Rule-3 amendment trigger — HALT and raise with user before continuing 2-3.
5. Do NOT re-introduce `signWithDrbgRnd(drbgSeed)` from plan.md — that surface is superseded.
6. Do NOT re-port `AES-256-CTR-DRBG` or `ChaCha20` or `SHAKE256` — all are imported from noble's ecosystem.
7. Do NOT re-port `NTRU-gen`, `ffSampling`, `splitFFT`, or `mergeFFT` — signer doesn't need NTRU-gen (that's keygen's domain, done in noble's `falcon512.keygen`), and `ffSampling` is inside `FFSampler.sample()` which we copy verbatim.
8. The `BytesReader` pattern + fork-with-HashToPoint-swap is the binding contract.

### Impact on Story 2-1

- **Size:** L → S (3 tasks).
- **Tasks (new):**
  - **T1 — Fixture schema extension + Python recorder + regen + doc sweep + story rewrite** (landed together; all drift guards live in one atomic commit):
    1. Extend inline Python in `scripts/generate-kat-fixtures.ts` (the falcon-eth batch Python source string, currently at lines ~870-902) with a `RecordingDRBG` wrapper. Emit `innerSeed` (48 B) + `signingDrbg` (variable-length) per record.
    2. Extend `FalconKatVector` interface in `test/fixtures/kat/index.ts` with `innerSeed: \`0x${string}\`` + `signingDrbg: \`0x${string}\``. Update `FalconKatVectorsFile` schema Source block to reflect that `signingDrbg` is captured per-vector (not a static N).
    3. Regenerate `test/fixtures/kat/falcon-eth/vectors.json` via `npm run kat:regen -- --scheme falcon-eth` (or equivalent CLI path; check existing `package.json` scripts).
    4. Add loader unit tests (in `test/fixtures/kat/index.test.ts`) confirming new fields present + length invariants: `innerSeed` = 48 B (98 hex chars including `0x`), `signingDrbg.length > 2` (at least 1 B of signing randomness) and even hex length.
    5. Sweep `docs/plan.md` lines 139/144/148/150 + line 229 area with inline A-005 callouts (pattern: `<!-- A-005: see docs/amendments.md -->` or equivalent — match A-004 callout style).
    6. Sweep `docs/architecture.md:33`, `:90`, `:197` with inline A-005 callouts.
    7. Rewrite `docs/stories/2-1.md` to the S-sized task decomposition defined here.
    8. Commit message: `feat(fixture-gen): T1 innerSeed + signingDrbg fixture fields + A-005 doc sweep — Story 2-1 Task 1/3 · enables AC-1 + forward-binds Story 2-3`.
  - **T2 — `keygenInternal(innerSeed)` + production `keygen()`:**
    - `test/signers/falcon-eth.kat-internal.ts` (NEW, ~15 LOC): `keygenInternal(innerSeed: Uint8Array): Keypair` — guards `innerSeed instanceof Uint8Array && innerSeed.length === 48` with `SignerInputError { code: "INVALID_INNER_SEED_LENGTH" }`, then `return falcon512.keygen(innerSeed)`. No DRBG import, no AES primitive, no crypto code at all.
    - `test/signers/falcon-eth.ts` (NEW, ~15 LOC): `keygen(): Keypair` — sources `seed = globalThis.crypto.getRandomValues(new Uint8Array(48))`, calls `falcon512.keygen(seed)`, returns. Does NOT import from `falcon-eth.kat-internal.ts`.
    - `test/signers/falcon-eth.test.ts` (NEW, small): AC-2 + AC-3 + AC-5 + AC-6 unit tests.
    - Commit: `feat(falcon-eth): T2 keygenInternal + production keygen — Story 2-1 Task 2/3 · AC-2/AC-3/AC-5/AC-6`.
  - **T3 — G3 KAT byte-identity test:**
    - `test/signers/falcon-eth.keygen.kat.test.ts` (NEW, ~50 LOC): iterate `loadKatVectors("falcon-eth")`; for each `v`, call `keygenInternal(hexToBytes(v.innerSeed))` and assert `publicKey === hexToBytes(v.publicKey)` + `secretKey === hexToBytes(v.secretKey)` byte-identical. Module-scope divergence-message helper per `.claude/rules/retrospect/typescript.md` §"[2026-04-20] Duplicated failure-message templates".
    - Commit: `test(falcon-eth): T3 G3 KAT byte-identity — Story 2-1 Task 3/3 · AC-1`.

- **Tasks (dropped from original story-creator draft):**
  - ❌ "NTRU fork + `keygenWithXof` in core" — noble is verbatim-correct.
  - ❌ `falcon-eth.core.ts` shared-core module — no shared helpers needed for keygen.
  - ❌ `XofFactory` parameterization — keygen hardcodes SHAKE256 via noble; nothing to inject.
  - ❌ `@delta-from-falcon` JSDoc + `FALCON_DELTA_HEADINGS` grep gate — no delta to document.
  - ❌ `(let|var) _?xof` grep gate — keygen has no xof variable; trivially satisfied.
  - ❌ **AES-256-CTR-DRBG port to TypeScript** — deviates from architecture lines 33+90; DRBG lives in Python at fixture-gen.

- **ACs retained from plan (reinterpreted):**
  - **AC-1 (G3 KAT):** byte-identity over ≥100 vectors — unchanged. Input changes from `drbgSeed` (48 B) to `innerSeed` (48 B precomputed); output comparison unchanged.
  - **AC-2 (Production surface hedging):** unchanged — `keygen()` entropy-sourced, two calls produce different keys.
  - **AC-3 (Input validation):** reinterpreted — `keygenInternal` throws `SignerInputError { code: "INVALID_INNER_SEED_LENGTH" }` on non-48-byte input. The error code name changes (`INVALID_DRBG_SEED_LENGTH` → `INVALID_INNER_SEED_LENGTH`) to reflect what the parameter actually is.
  - **AC-4 (Module-header structural check):** dropped — no delta-from header required.
  - **AC-5 (Grep gates):** reduced — only the `KAT_INTERNAL_MODULES` import check (`test/signers/index.ts` + `test/bench/**/*.ts` must not import `falcon-eth.kat-internal`). `(let|var) _?xof` dropped.
  - **AC-6 (Interface):** reduced — `falcon-eth.ts` exports `keygen()`; `falcon-eth.kat-internal.ts` exports `keygenInternal(innerSeed)`. Neither imports the other. No `core` module.

### Retrospect candidate (to be proposed at Gate 5 if findings-deferred captures knowledge gap)

The class-of-bug surfaced here is worth a retrospect rule (target: `.claude/rules/retrospect/universal.md`):

> **[TBD date] Story-creator must cross-check architecture + existing code before proposing new runtime crypto.** When plan.md says "implement foo that replays/derives X", story-creator must (a) check architecture for whether foo's derivation lives elsewhere (e.g., fixture-gen, prior infrastructure), (b) grep the codebase for existing X-derivation code, (c) check the data-model section for whether X is a consumed fixture field rather than a runtime-derived value. Plan text can be ambiguous ("keygenInternal(drbgSeed) that replays AES256_CTR_DRBG" can mean either "replays in TS" or "consumes Python-derived replay output"); architecture + existing code are the ground truth.
>
> **Why:** This rule was derived from Story 2-1's initial L-sized draft (which re-ported AES-CTR-DRBG to TS contrary to architecture lines 33+90) and Story 2-3's plan-level `signWithDrbgRnd(drbgSeed)` surface (which would have propagated the same drift). Caught at implementation time only because the user Socratically pushed back on the T1 proposal; story-creator had anchored on plan.md phrasing without checking architecture + existing fixture-gen code.
>
> **How to apply:** At story creation time, for every task that proposes "X cryptographic primitive", (a) read the data-model fixture schema in architecture.md to see if X is stored as a fixture field; (b) grep `scripts/generate-kat-fixtures.ts` (or equivalent fixture-gen script) for X-related invocations; (c) read architecture.md's "boundaries" and "fixture-gen" rows before deciding X lives in TS.

Proposal lands at Gate 5 of Story 2-1 via `[L] Apply fixes + learn` (or equivalent) if the code-review surfaces the knowledge gap.

### Downstream implications

- **Story 2-3 (signer):** scope LIKELY SHRINKS L → M. Noble source audit (2026-04-20, documented in "Noble alignment discovery" above) shows noble's `signRaw` + `FFSampler` + `HashToPoint` implement the ETHFALCON flow **verbatim except for HashToPoint's XOF**. Story 2-3 is therefore a ~285-LOC source-transplant fork with a single algorithmic change (HashToPoint call-site → `hashToPointEVM`), not a ground-up Gaussian sampler port. The rejection-sampling ChaCha20 pipeline is already in noble. Noble's `__tests` escape hatch exposes all required math helpers; Story 2-3 imports them rather than re-implementing. Net: 2-3 story-creator should size at M. The "L" in plan.md reflects the original "hybrid-fork from scratch" framing which is superseded by this amendment.
- **Story 2-4 (integration + benchmark):** unaffected.
- **Stories 1-2 (Keccak-PRG) and 2-2 (HashToPoint):** unaffected. Both remain load-bearing for the signer path.

### Resolution

- This A-005 amendment lands in `docs/amendments.md` as part of Story 2-1 T1 commit.
- `docs/architecture.md:33`, `:90`, `:197` + `docs/plan.md` lines 139/144/148/150 + line ~229 get inline A-005 callouts (matching A-004 callout style) in the SAME T1 commit.
- `docs/stories/2-1.md` gets rewritten to the S-sized shape in the SAME T1 commit.
- `scripts/generate-kat-fixtures.ts` + `test/fixtures/kat/index.ts` + `test/fixtures/kat/falcon-eth/vectors.json` + `test/fixtures/kat/index.test.ts` get the fixture schema extension + regen + tests in the SAME T1 commit.
- Upstream retrospect rule **carried from** `.claude/rules/retrospect/universal.md` §"[2026-04-18] Amendment doc sweep — don't leak the old shape": this amendment's doc sweep is exactly that rule's prescribed action. The architecture/plan/story texts that implied TS-side DRBG are stale and are corrected here.
- Plan/architecture phrasing is **superseded** by this amendment for all Gate-5 verification, code-review, and downstream-story-creation purposes (Stories 2-1 T2/T3, 2-3, 2-4).
