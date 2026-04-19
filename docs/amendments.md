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
