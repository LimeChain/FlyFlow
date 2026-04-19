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
