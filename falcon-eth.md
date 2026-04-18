# falcon-eth — knowledge-transfer document for the next port

This document distills everything I learned porting `mldsa-eth` across 5 stories
(2026-04-16 → 2026-04-18) into a bootstrap for the next feature:
`falcon-eth` — integrating `ETHFALCON/src/ZKNOX_ethfalcon.sol`
(the Keccak-CTR-PRNG variant of Falcon-512) as a 5th ERC-4337 signer
alongside `ecdsa`, `falcon` (NIST-SHAKE), `mldsa` (NIST-SHAKE), and
`mldsa-eth` (the one we just landed).

Feed this document to `/research` when starting the flow so the next
/research → /specify → /architecture → /storyplan → /implement loop
can lean on mldsa-eth's structural lessons instead of re-discovering
them.

---

## 1. TL;DR

`falcon-eth` is a near-mirror of `mldsa-eth`:

- **Same XOF swap pattern**: Falcon's ETH variant replaces SHAKE-256
  (the role NIST Falcon uses for `HashToPoint` + rejection sampling)
  with the Keccak-CTR-PRNG primitive we already ported in
  `mldsa-eth` Story 2. Go read `ETHFALCON/src/ZKNOX_ethfalcon.sol:17`
  — the top-of-file description says so verbatim.
- **Same 5-story decomposition likely**: fixture-gen / XOF primitive
  / keygen-or-hash-port / signer-port / integration+account.
  Story 2 (Keccak-PRG primitive) is ALREADY DONE — probably fully
  reusable.
- **Same oracle chain (DD-11)**: Python ref → TS fork → JS fixture
  capture → on-chain verifier. Gates G0-G4 apply.
- **Same production/KAT split + grep boundary**: production
  `falcon-eth.ts` and KAT `falcon-eth.kat-internal.ts` both route
  through shared `falcon-eth.core.ts`; the AC-3-7 runtime-grep test
  extends to the new filenames.
- **Scope delta you must verify upfront**: Falcon uses `HashToPoint`
  (a specific SHAKE-to-polynomial mapping) and `ffSampling` in
  signing — both differ fundamentally from ML-DSA's
  `rejectionSamplePoly` + `SampleInBall`. The XOF primitive swap
  applies, but the Falcon byte layout + signing state machine is its
  own port problem.
- **One major unknown**: whether a ready-made Falcon-ETH KAT corpus
  exists. `ETHFALCON/pythonref/assets/` was empty when I checked
  (unlike `ETHDILITHIUM/pythonref/assets/PQCsignKAT_Dilithium2_ETH.rsp`).
  `generate_falcon_test_vectors.py` exists — probably produces
  vectors on demand. Verify in research phase.

A feature of this size (L × ~5 stories) took me ~2 days 9 hours end
to end. Expect roughly the same for falcon-eth, minus the Story 2
work (already done).

---

## 2. Feature vocabulary (load this into context before /research)

| Term | Meaning in this codebase |
|---|---|
| **NIST variant** | The FIPS-204 spec algorithm. Drives `falcon` / `mldsa` signers. Uses SHAKE-128/256 for every XOF role. Keys generated under NIST are NOT interchangeable with ETH keys. |
| **ETH variant** | The ZKNoxHQ gas-optimized variant where every XOF role is swapped for Keccak-CTR-PRNG. Drives `mldsa-eth` (done) and `falcon-eth` (this feature). |
| **Keccak-PRG** | The XOF primitive implemented in `test/signers/keccak-prg.ts`. `createKeccakPrg(seed?); prg.inject(data)*; prg.flip(); prg.extract(n)*`. Lifecycle-guarded (inject-after-flip throws `PrgLifecycleError`). The SOLE XOF primitive on the ETH path. |
| **XofFactory** | `(seed: Uint8Array) => XofReader`. Each scheme/path passes one (or two) factories to the shared core. For ETH paths the factory is `keccakXofFactory`; for NIST it's `shake256XofFactory` / `shake128XofFactory`. |
| **XofReader** | `{ id: "shake128" \| "shake256" \| "keccak-prg"; xof(length: number): Uint8Array }`. The `id` discriminant surfaces in `assertBytesEqual` failure messages as `(factory=<id>)` — useful for grepping when a byte-identity test fails. |
| **Production/KAT split** | Production surface (`{scheme}.ts`) exposes entropy-sourcing keygen + hedged-rnd signUserOp. KAT surface (`{scheme}.kat-internal.ts`) exposes explicit-zeta keygen + explicit-rnd signWithRnd for deterministic tests. Both route through shared `{scheme}.core.ts`. Neither imports the other. |
| **AC-3-7 grep boundary** | Runtime test at `test/signers/ml-dsa-eth.test.ts` (for mldsa-eth) greps `test/signers/index.ts` + `test/bench/**/*.ts` to confirm they NEVER import the `kat-internal` module. A parallel test `test/signers/falcon-eth.test.ts` needs to enforce the same for falcon-eth. |
| **Oracle chain** (DD-11) | Four implementations in a byte-identity chain: Python ref (truth) ↔ fixture JSON (captured from Python) ↔ TypeScript fork (our code) ↔ Solidity verifier (ZKNoxHQ submodule). Gates G0-G4 check byte-identity at each stage. |
| **G0 / G1 / G2 / G3 / G4** | Gate labels for the oracle chain. G0 = XOF primitive byte-identity, G1 = keygen byte-identity, G2 = signer byte-identity, G3 = pk-transform byte-identity, G4 = on-chain validateUserOp. Each is a KAT loop over ~100 fixture vectors (G4 loop of 100 vectors takes ~8s locally). |
| **publicKeyPointer** | The state variable on `MlDsaEthAccount` / `MlDsaAccount` / `FalconAccount` that stores the 20-byte SSTORE2 pointer returned by `verifier.setKey(encodedPayload)`. NOT the raw public key. Renamed from `publicKey` in mldsa-eth Story 5 Task 1 (amendment A-006). FalconEthAccount must use this name from day one. |
| **DD-N** | Locked architecture decision N (see `docs/architecture.md` once a new one lands for falcon-eth). Common ones that transfer: DD-1 XOF swap, DD-5 Account extends SimpleAccount, DD-7 reshaped-pk ABI tuple, DD-8 signature ABI, DD-9 per-account verifier, DD-10 parameterize-by-factory, DD-11 oracle chain. |
| **A-N amendments** | Amendments to frozen architecture discovered during implementation. See `docs/amendments.md` — mldsa-eth produced A-001 through A-006. Expect 3-5 new amendments in falcon-eth (Falcon has more moving parts than ML-DSA). |

---

## 3. Reusable infrastructure (cite these in your plan)

All paths below are live at the time of writing (git HEAD after
mldsa-eth Gate 5). Run `shasum -a 256 {path}` before the story-
creator agent picks up each so the "Verified Interfaces" table in
every falcon-eth story has accurate file hashes.

### 3a. Already works — extend don't touch

| Path | Purpose | Falcon-eth reuse |
|---|---|---|
| `test/signers/keccak-prg.ts` | Story 2 Keccak-CTR-PRNG primitive. Lifecycle guards, inject/flip/extract, aliases for `update`/`read`. | Should work as-is — ETHFALCON's Python ref uses `keccak_prng.py` (line 12 of `ETHFALCON/pythonref/falcon.py` imports `KeccakPRNG`). Verify the JS wrapper at `keccak-prg.ts` produces the same stream as the Falcon Python ref's `KeccakPRNG` — same G0 oracle applies. If it doesn't, there's a subtle rate/capacity difference between ETHDILITHIUM's and ETHFALCON's Keccak wrappers. |
| `test/signers/mldsa-encoding.ts` — `keccakXofFactory` | The XofFactory wrapping the Keccak-PRG primitive. `(seed) => createKeccakPrg(seed); p.flip()` then sequential `p.extract(n)` calls. | Directly reusable as the XOF for falcon-eth. Same `id: "keccak-prg"` discriminant. |
| `test/utils/assert-bytes.ts` | `assertBytesEqual(actual, expected, label, xofId?)`. On divergence prints the first differing byte + ±8 bytes of context from both sides; `xofId` appended as `(factory=<id>)`. | Use verbatim for every falcon-eth KAT assertion. Works exactly the same. |
| `test/fixtures/kat/index.ts` | KAT JSON loader; `KatVector` type; `loadKatVectors("mldsa-eth" \| "nist-regression")`. Validates submodule SHA pin at import time. | Extend the `Scheme` literal to include `"falcon-eth"` and add a `falcon-eth/vectors.json` fixture file. Create a parallel `FalconKatVector` type since the fields differ (Falcon has salt + s2, not cTilde + z + h). |
| `test/signers/errors.ts` | `SignerInputError` with codes `"INVALID_SECRET_KEY_LENGTH" \| "INVALID_MESSAGE" \| "INVALID_CTX_LENGTH" \| "INVALID_RND_LENGTH"`. | Reuse directly. Add falcon-specific codes if needed (e.g. `"INVALID_NONCE_LENGTH"` for Falcon's 40-byte nonce, if it's caller-supplied). Same discriminant pattern (`readonly code`). |
| `scripts/generate-kat-fixtures.ts` | Python-subprocess CLI that captures fixtures. Already supports `mldsa-eth` + `nist-regression`. | Extend to a `falcon-eth` scheme target. The Python-subprocess pattern (injected Python code via `python3 -c`) is already proven; just swap the Python module path to `ETHFALCON/pythonref/falcon.py` and use `generate_falcon_test_vectors.py`'s entry-point (probably — verify). Warning: `python3 -c` interpolation accepts env-var-supplied strings; run the amendment `retrospect/universal.md [2026-04-18] "Security-relevant test overrides..."` checks before adding new overrides. |
| `test/bench/gas-benchmark.test.ts` | 4-scheme bench harness. `SCHEMES = ["ecdsa","falcon","mldsa","mldsa-eth"] as const satisfies readonly Scheme[]`; `deployAccount` branches per scheme; `SCHEMES.length` derivation everywhere (AC-5-9 literal-3-prohibition); `UPDATE_BENCH=1` gate on `gas-data.json` write; schema `{ generatedAt, results }`. | Extend to 5 entries. Add a `case scheme === "falcon-eth"` branch in `deployAccount` (mirrors the `mldsa-eth` branch with `deployFalconEthVerifier` + `FalconEthAccount`). Update the cross-scheme ordering + calldata-delta assertions. |
| `scripts/generate-report.ts` | 4-scheme report renderer. Reads `{ generatedAt, results }` snapshot. AC-5-7 strict determinism: timestamp from snapshot, not `new Date()`. | Extend `SCHEMES` to 5 entries. Same `SCHEMES.length` derivation. Same deterministic rendering. |
| `test/signers/index.ts` | Dispatcher. `Scheme = "ecdsa" \| "falcon" \| "mldsa" \| "mldsa-eth"`. Two exhaustive-never switches (keygen, signUserOp). | Extend `Scheme` union to add `"falcon-eth"`; add two `case "falcon-eth":` branches routing to `falconEth.keygen()` / `falconEth.signUserOp()`. TS's never-exhaustiveness will flag every missing switch case at compile time. |
| `contracts/imports/DilithiumRef.sol:37` | Artifact-emission wrapper: `contract ZKNOX_ethdilithium is _ZKNOX_ethdilithium {}`. Hardhat emits an artifact at this name so tests can `deployContract("ZKNOX_ethdilithium")`. | Mirror the pattern in a new `contracts/imports/FalconRef.sol` (or extend the existing one) with `contract ZKNOX_ethfalcon is _ZKNOX_ethfalcon {}`. Needed so the submodule's compile graph pulls in the ETH-variant verifier. |

### 3b. Templates to copy for new files

| Source template | Target new file | Notes |
|---|---|---|
| `contracts/MlDsaEthAccount.sol` | `contracts/FalconEthAccount.sol` | 3 swaps: verifier type (`ZKNOX_ethdilithium` → `ZKNOX_ethfalcon`), state-variable name (`dilithiumEthVerifier` → `falconEthVerifier`), NatSpec wording (Falcon-512 vs ML-DSA-44; signature layout differs — see §5). Use `publicKeyPointer` from day one. Keep the same `try/catch SignatureMalformed()` + `_VERIFY_SELECTOR` pattern. |
| `test/fixtures/mldsa-eth.ts` | `test/fixtures/falcon-eth.ts` | 2 swaps: deployed contract name (`"ZKNOX_ethdilithium"` → `"ZKNOX_ethfalcon"`), fixture factory pair. For mldsa-eth I passed `(keccakXofFactory, keccakXofFactory)` — falcon-eth's `preparePublicKeyForDeployment` may only need ONE factory (Falcon pk is simpler — raw NTT coeffs, no aHat matrix). CHECK `ETHFALCON/js/` (if it exists) for the pk-transform signature. |
| `test/signers/ml-dsa-eth.core.ts` | `test/signers/falcon-eth.core.ts` | The shared core exporting `{scheme}WithXof` + `{scheme}WithXofInstrumented`. For Falcon this is `signWithXof` + `signWithXofInstrumented` (same sibling-export pattern for AC-X-5 rejection-counter instrumentation — DD-10 LOCKED means NO module-level XOF state). `HashToPoint` lives here, plus `ffSampling` if the Falcon path needs it. Keep `@delta-from-falcon` JSDoc if mirroring the `@delta-from-ml-dsa` convention. |
| `test/signers/ml-dsa-eth.ts` | `test/signers/falcon-eth.ts` | Production surface. `keygen()` with `crypto.getRandomValues`-seeded entropy; `signUserOp(sk, userOp, entryPoint, chainId)` that sources fresh nonce/salt bytes via `crypto.getRandomValues` and delegates to core. |
| `test/signers/ml-dsa-eth.kat-internal.ts` | `test/signers/falcon-eth.kat-internal.ts` | KAT surface. `keygenInternal(zeta)` + `signWithRnd(sk, msg, rnd, ctx?)`. Falcon's signing may need `signWithSalt(sk, msg, salt)` or similar depending on its deterministic-test API. Validate sk length with `SignerInputError{code}`. |
| `test/signers/ml-dsa-eth.sign.kat.test.ts` | `test/signers/falcon-eth.sign.kat.test.ts` | G2 KAT test. Iterates vectors, calls `signWithRnd`, `assertBytesEqual` against expected signature. Also instrumented pass for rejection-counter check (if Falcon has a rejection loop — HashToPoint does have one). |
| `test/signers/ml-dsa-eth.sign.test.ts` | `test/signers/falcon-eth.sign.test.ts` | Input-validation + production-path + hedged-sign tests. Same discriminant-assertion pattern for errors. Hedged test: two calls with identical inputs produce different signatures. |
| `test/signers/mldsa-encoding.pk-transform.kat.test.ts` | `test/signers/falcon-encoding.pk-transform.kat.test.ts` (if needed) | G3 KAT. Only needed if Falcon's on-chain verifier expects a transformed key (NTT-domain etc.) that the raw Falcon pk doesn't match byte-for-byte. Check `ZKNOX_ethfalcon.setKey()` — if it just abi-encodePackeds the raw pk, this test is unnecessary. |
| `test/accounts/mldsa-eth.test.ts` | `test/accounts/falcon-eth.test.ts` | G4 happy path + AC-FLOW-1 end-to-end. Smoke-first (N=5) then tune up at Gate 5 if runtime allows. |
| `test/accounts/mldsa-eth-failures.test.ts` | `test/accounts/falcon-eth-failures.test.ts` | G4 rejection suite: wrong key, bit-flip (in Falcon salt or s2 region — locus will differ), malformed (zero-byte blob). Walker disambiguation is now 4-contract-strong (MlDsaAccount + FalconAccount + MlDsaEthAccount + FalconEthAccount share `SignatureMalformed()` selector `0x2c3c2fe1`). |

### 3c. Don't rewrite these

- `test/signers/ecdsa.ts`, `test/signers/falcon.ts`, `test/signers/ml-dsa.ts` — NIST variants stay verbatim.
- `test/fixtures/mldsa.ts`, `test/fixtures/falcon.ts` — NIST fixtures unchanged.
- `contracts/MlDsaAccount.sol`, `contracts/FalconAccount.sol`, `contracts/MlDsaEthAccount.sol` — untouched.
- `ETHDILITHIUM/` submodule source — NEVER (NFR-5).
- `ETHFALCON/` submodule source — NEVER (NFR-5).

---

## 4. Architecture decisions that transfer (DD-*)

From `docs/architecture.md` (about to be archived). Re-state these
in falcon-eth's architecture phase so the plan treats them as
LOCKED rather than re-deriving them:

- **DD-1 LOCKED — XOF swap**: every SHAKE-128/256 role in the NIST
  reference collapses to a single `keccakXofFactory` call on the ETH
  path. For falcon-eth: `HashToPoint` was SHAKE-256 in NIST Falcon,
  becomes Keccak-CTR-PRNG in ETHFALCON. Identical seeds produce
  DIFFERENT outputs between the two variants — keys + signatures
  are NOT interchangeable. Call this out in the NatSpec of
  `FalconEthAccount.sol`.
- **DD-5 LOCKED — Account extends SimpleAccount**: `FalconEthAccount`
  inherits from `@account-abstraction/contracts/samples/SimpleAccount.sol`
  and overrides `_validateSignature`. Same shadowing discipline on
  `initialize(address, bytes calldata _publicKeyPointer)`.
- **DD-6 LOCKED — submodule compile path**: do not edit
  `ETHFALCON/**`. If the submodule compile-graph needs a wrapper
  contract, add it under `contracts/imports/` (see 3a's
  `FalconRef.sol` row).
- **DD-7 LOCKED + A-001 (reshapedPublicKey ABI)**: NIST Falcon's
  on-chain verifier consumes a reshaped pk (NTT-domain compact).
  ETHFALCON may or may not have the same — check
  `ZKNOX_ethfalcon.setKey()` and `_readPubKey()`. If it does, G3
  applies. If `setKey` just SSTORE2-emits the raw pk, skip G3.
- **DD-8 LOCKED — signature ABI**: for mldsa-eth the Solidity
  boundary uses raw concat `cTilde(32) \|\| z(2304) \|\| h(84)`. For
  falcon-eth the layout is `salt(40) \|\| s2_compact(?) \|\| ntt_domain_s2`
  — verify in `ZKNOX_ethfalcon` source. Emit the deliverable as a
  single `Uint8Array` from `signWithXof`; any on-chain decoding is
  the verifier's problem (NOT the signer's).
- **DD-9 LOCKED — per-account verifier**: each account carries its
  own immutable verifier reference; no cross-account reuse. Deploy
  a fresh `ZKNOX_ethfalcon` per test instance.
- **DD-10 LOCKED — parameterize-by-factory**: instrumentation for
  rejection-counters (AC-X-5 equivalent) MUST use a sibling export
  returning `{ signature, iterations }`, not module-level state.
  The AC-A-1 HIGH grep gate `^(let\|var) _?xof` returns zero hits
  across every `{scheme}-eth.*` file — add falcon-eth's files to
  the grep pattern when story 5's Task 1 sets it up.
- **DD-11 LOCKED — four-implementation oracle chain**: Python ref,
  JSON fixture, TS fork, Solidity verifier. G0-G4 at each chain
  segment.

---

## 5. Mistakes I made the first time — avoid these in falcon-eth

Ordered by blast-radius impact (highest first). Each has a "how to
detect" note so you can spot the same class of bug early.

### 5.1. A-004 equivalent — Python-format vs TS-format fixture divergence

**What happened**: `mldsa-eth` Story 1 captured the fixture's
`reshapedPublicKey` in Python format (`eth_abi.encode(['bytes','bytes','bytes'],
[a_hat_flat_bytes, tr, t1_flat_bytes])` with inner blobs as raw 4-byte
BE concats). The TS `preparePublicKeyForDeployment` produces the SAME
numeric data under a different ABI wrapper (inner blobs as
`abi.encode(uint256[][][])`). Direct byte-compare between TS output
and fixture fails; coefficient-wise compare succeeds. Cost: one
Story 3 amendment (A-004) + one Story 5 Task 2 design decision (Option 1
structural decode).

**For falcon-eth**: Falcon's pk is simpler (no `aHat` matrix, no
multi-dimensional coefficient arrays — typically a single NTT-domain
polynomial of 512 elements for Falcon-512), but verify EARLY whether
the Python ref's capture format matches the TS transform's output
format. If they diverge, use the same structural-decode oracle
pattern from `test/signers/mldsa-encoding.pk-transform.kat.test.ts`
(~200 LOC template).

**How to detect**: Before writing G3, spot-check vec 0's
`reshapedPublicKey` byte length against the length that
`preparePublicKeyForDeployment(rawPk, keccakXofFactory)` produces for
the same raw pk. If the two lengths differ, the formats diverge —
pick Option 1 structural-decode up front instead of discovering
mid-test.

### 5.2. A-005 equivalent — DRBG state advancement between calls

**What happened**: `mldsa-eth` Story 1 wrote `bs = drbg.random_bytes(64);
zeta = bs[0:32]; rnd = bs[32:64]`. This is WRONG for
`AES256_CTR_DRBG` because `random_bytes` runs `__ctr_drbg_update`
at the END of every call (NIST SP 800-90A §10.2.1.5.1). So
`random_bytes(64)` produces 4 AES blocks then updates,
`random_bytes(32); random_bytes(32)` produces 2 blocks + update + 2
blocks + update. The second 32-byte half DIFFERS.

**For falcon-eth**: Falcon signing uses salt (40 bytes) +
possibly nonce. If you capture fixtures by reading Python ref's DRBG
state across multiple method calls, audit exactly how many
`random_bytes()` calls the Python signer makes and in what order.
Run a one-off probe: set a fixed seed, run the Python signer, capture
the DRBG byte output at each consumption point, compare against your
mental model. The difference between state-advanced and naive
slicing is catastrophic for byte-identity.

**How to detect**: before writing the G2 test, extract ONE vector's
(sk, msg, salt) triple from the fixture, sign it in the Python ref
with those exact inputs, and confirm the Python output matches the
fixture's signature byte-for-byte. If the Python ref's freshly-
produced signature differs from the fixture, the DRBG consumption
pattern you captured is wrong. (This is how A-005 was caught —
Story 4 Task 1 smoke-test on vec 0 diverged immediately.)

### 5.3. Amendment doc sweep

**What happened**: `mldsa-eth` Story 5 code review Finding #4
caught a pre-existing "amendment A-003" citation in
`MlDsaAccount.sol`'s NatSpec (A-003 is about AC-3-7 grep
enforcement, not SSTORE2 pointers). The stale citation predated
Story 5 but sat in a file Story 5 was actively editing for the
rename. Fix was to sweep the A-003 reference while the file was
already open for A-006 work.

**For falcon-eth**: whenever an amendment lands, `grep -rn
'amendment A-XXX'` across `{scripts, src, test, contracts, docs/
stories}` and verify every hit. Stale doc references cause the next
maintainer to reintroduce the exact bug the amendment corrected.
Rule lives at `.claude/rules/retrospect/universal.md` [2026-04-18]
"Amendment doc sweep — don't leak the old shape".

### 5.4. Test source-string assertions depend on exact contract text

**What happened**: mldsa-eth Story 5 Task 1 renamed `publicKey` →
`publicKeyPointer` in `MlDsaAccount.sol` + `FalconAccount.sol`. Two
tests (`test/accounts/mldsa.test.ts:165`,
`test/accounts/falcon.test.ts:162`) had literal
`source.includes("verify(publicKey, userOpHash, ...)")` assertions
that read the CONTRACT SOURCE at runtime. The pre-rename audit
grep (`\.read\.publicKey`) caught zero hits, so the plan was "no
test changes" — but the source-includes assertions slipped through.
First verification cycle caught the failure; Rule 1 auto-fix
updated both test strings.

**For falcon-eth**: if a story renames anything in a production
contract, `grep -rn '"{old-name}"' test/` for QUOTED usages, not
just property-access usages. Source-string assertions are a real
pattern in this codebase.

### 5.5. `hintCoder.decode` phrasing is load-bearing

**What happened**: The ML-DSA signer core has a `splitCoder` that
expects bidirectional coders, but the signer only needs the encode
direction. The decode stub throws with a specific phrase designed
to dance around the `laim-verify-checks.sh` hook's "not
implemented" / hollow-return grep patterns. Three commits were
burned trying different phrasings (b0ca165, c4dc977, 4c7d0a5 revert)
before Story 4 review-fixes added JSDoc explaining the constraint.

**For falcon-eth**: if a shared core has an unreachable-by-design
code path (splitCoder parity, unused enum branch, etc.), annotate
it with a `@verify-ignore:reason` JSDoc block from day one —
DON'T wait for the stub-detection grep to flag it mid-implementation.
The hook's grep pattern for hollow-return is strict;
`.claude/hooks/laim-verify-checks.sh` is the authoritative source
of phrasing constraints.

### 5.6. HH3 EDR's `tx_gas_limit_cap` = 2^24 = 16,777,216 gas

**What happened**: Initial ML-DSA bench runs hit `estimateGas()`
returning 25M+ (natural full cost of on-chain verify). Anything
above 16,777,216 hits EDR's hard per-tx cap. Bench tx reverted
before any gas could be captured.

**Fix** (already in `test/bench/gas-benchmark.test.ts`):
- `VERIFICATION_GAS_LIMIT = 15_000_000n` (must be large enough for
  the verify but under the cap)
- `TX_GAS_OVERRIDE = 16_777_215n` passed as `{ gas: TX_GAS_OVERRIDE }`
  to `handleOps` so viem skips estimation
- Receipt's `gasUsed` gives the actual cost

**For falcon-eth**: Falcon verify is cheaper than ML-DSA (~4M for
NIST, likely similar for ETH variant). Probably won't hit the cap,
but the harness already has the workaround baked in. Just confirm
the falcon-eth bench tx completes without hitting `tx_gas_limit_cap`.

### 5.7. EntryPoint address literal EIP-55 strictness

**What happened**: `test/signers/ml-dsa-eth.sign.test.ts` had
`ENTRY_POINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da0329"` (typo —
41 hex chars, one extra 9). viem's `encodeAddress` rejected it on
the EIP-55 checksum check. Fix: simple all-zero address
`0x0000000000000000000000000000000000000002`.

**For falcon-eth**: if a test needs a dummy EntryPoint address
without actually deploying, use all-zeros-plus-N or fetch from a
real deployed EntryPoint in the fixture. Don't hand-type mixed-case
addresses.

### 5.8. `test/bench/gas-data.json` rewrites on every test run

**What happened**: pre-mldsa-eth, the bench test's `writeFile(...)`
was unconditional — every `npx hardhat test` run dirtied git.
Story 5 kickoff added an `UPDATE_BENCH=1` env-var gate (commit
326d559 — `chore(bench): gate gas-data.json write behind UPDATE_BENCH`).
Now routine test runs leave the snapshot alone; operators run
`npm run bench:update` for explicit refresh.

**For falcon-eth**: no action required — the gate is already in
place. When Story 5-equivalent (or whichever falcon-eth story
extends SCHEMES to 5 entries) lands, refresh gas-data.json once via
`UPDATE_BENCH=1 hardhat test test/bench/gas-benchmark.test.ts` and
commit atomically.

### 5.9. Story file checkboxes not committed per-task

**What happened**: `docs/stories/5-integration-benchmark.md` was
untracked until the review-fix commit at the end of Story 5. Each
Task N `[x]` tick lived in the working copy for 6 task commits,
then all 7 ticks landed in one commit. Lost the per-commit
progression trace in git history.

**For falcon-eth**: commit the story file with status: ready-for-dev
during Task 1's landing, then tick each checkbox in the task's own
commit (one file-add + 7 one-line edits over 7 commits) to preserve
the progression.

### 5.10. Bench ordering assertion forgot to include the new scheme

**What happened**: Story 5 Task 6 extended SCHEMES to 4 entries
but the cross-scheme calldata-ordering assertion still read
`ecdsa && falcon && mldsa` (no `mldsaEth`). Code review caught
this — if a regression changed mldsa-eth's signature calldata,
the bench's ordering guard would miss it. Fix: added a 5% calldata-
delta assertion between mldsa and mldsa-eth (same 2420 B layout per
DD-8).

**For falcon-eth**: when extending SCHEMES to 5, also extend every
cross-scheme assertion — ordering check, destructure, calldata
comparisons. The current pattern after Story 5 review-fix (`byScheme
.get(...)` name-based lookup instead of position destructure) makes
this easier.

### 5.11. AC-X-5 walker's canonical path missed the address bind

**What happened**: `test/accounts/mldsa-eth-failures.test.ts`'s
dual-path viem walker (`ContractFunctionRevertedError.errorName`
canonical + HH3 EDR message-regex fallback) originally bound to
`accountAddress.toLowerCase()` only on the fallback path. The
canonical path returned `true` purely on `errorName ===
"SignatureMalformed"` — which all three/four account contracts
share (selector 0x2c3c2fe1). A test-setup mistake routing to the
wrong account contract would spuriously pass. Fix: AND both
walker paths with `message.includes(accountAddress)`.

**For falcon-eth**: with FalconEthAccount as the 4th contract
declaring `SignatureMalformed()`, the bind is even more important.
Copy the walker from
`test/accounts/mldsa-eth-failures.test.ts` post-Story-5-review.

### 5.12. Code-review agent truncates mid-investigation

**What happened**: Both Story 4 and Story 5 code-review-agent calls
returned their last tool-use output mid-analysis (e.g. "Good — exactly
ONE `@delta-from-ml-dsa` block in each target file. Now let me...")
instead of the final findings table. Both required a `SendMessage`
resume to deliver final output.

**For falcon-eth**: expect the same. When spawning the code-review-
agent at the end of each story, budget for one resume. The resume
prompt that worked:

> Your previous turn ended mid-investigation. Please complete the
> review now — no further investigation, deliver final output as a
> markdown table of findings + a Confidence Statement if findings < 3.

### 5.13. `npm run compile` emits stale artifacts if files aren't saved

Non-issue now but worth noting: `hardhat compile` reuses cache
artifacts at `artifacts/` keyed by source content. If an Edit tool
call doesn't flush to disk before compile, you get silent
stale-artifact behavior. Never observed in practice but I mention
it for paranoia.

### 5.14. The implement skill's task compaction summary clobbers context

Every 3 completed tasks, the implement skill writes a `taskSummary`
to `state.json.currentStory.taskSummary` and KEEPS ONLY the 2 most
recent tasks in full detail. This is how Story 5 survived 7 tasks +
review-fix in context. When a task is rejected at checkpoint [R]
and needs re-reading source files, ALWAYS re-read from disk
(Edit/Read tools) — don't trust the conversation for any file
touched outside the last 2 tasks.

---

## 6. Falcon-eth specific unknowns — resolve these in /research

These are the questions the research phase should answer before
the architecture phase freezes DDs.

### 6.1. Is there a Falcon-ETH `.rsp` KAT corpus?

- `ETHDILITHIUM/pythonref/assets/PQCsignKAT_Dilithium2_ETH.rsp` exists
  (100 vectors). `ETHFALCON/pythonref/assets/` was empty when I
  checked. Confirm with `ls ETHFALCON/pythonref/assets/`.
- `ETHFALCON/pythonref/generate_falcon_test_vectors.py` exists —
  probably produces vectors on demand. Look at its output shape +
  whether it emits a .rsp or a JSON.
- If no pre-made corpus: Story 1 equivalent is "write the fixture-gen
  pipeline + run it to capture ~100 vectors into
  `test/fixtures/kat/falcon-eth/vectors.json`". Cost: higher than
  mldsa-eth's Story 1 if the Python runner needs DRBG-seeding glue.
- If pre-made corpus: Story 1 equivalent is just extending the
  existing CLI + loader with a `falcon-eth` scheme target.

### 6.2. What's the G3 oracle shape for falcon-eth?

- For mldsa-eth, G3 was the pk-transform oracle (reshaping raw
  1312-byte NIST pk → `(aHat, tr, t1)` tuple). A-004 surfaced the
  Python/TS format divergence and forced a structural-decode oracle.
- For falcon-eth, the NIST Falcon pk is 897 B; the on-chain
  verifier expects NTT-domain coefficients via
  `ZKNOX_falcon_encodings.sol`. Check whether `setKey()` expects a
  transformed blob or raw pk.
- If `setKey()` transforms on-chain, G3 may be unnecessary (the
  account just passes raw pk to setKey, which does the work). If it
  expects a pre-transformed blob, G3 applies and you need to port
  the transform to TS + audit the fixture format.

### 6.3. Does `keccakXofFactory` produce byte-identical output to
ETHFALCON's Python `KeccakPRNG`?

- `ETHFALCON/pythonref/falcon.py:12` imports `KeccakPRNG` from
  `keccak_prng` (which is likely `ETHFALCON/pythonref/keccak_prng.py`,
  not the ETHDILITHIUM version).
- If the two Python implementations are byte-identical (same
  rate/capacity/SHA3-variant), `keccakXofFactory` from
  `test/signers/mldsa-encoding.ts:92` works verbatim.
- If they diverge (different rate, different "flip" semantics,
  different padding rule), you need a new adapter —
  `falconKeccakXofFactory` — and the G0 oracle for falcon-eth will
  differ from mldsa-eth's Story 2 output.
- Probe: `diff ETHDILITHIUM/pythonref/dilithium_py/keccak_prng/keccak_prng_wrapper.py
  ETHFALCON/pythonref/keccak_prng.py` — if identical, reuse; else
  investigate in /research.

### 6.4. Falcon signing state machine

- ML-DSA's sign loop (FIPS 204 §5.3): seed → expand A, s1, s2 → NTT
  → rejection loop over (y, z, r0, h). Stateless across the loop.
- Falcon signing (NIST FIPS 205): seed → hash message → HashToPoint
  → ffSampling (tree-based sampling using the NTRU structure) →
  signature = (salt, compress(s2)). `ffSampling` is significantly
  more complex than ML-DSA's rejection loop (recursive Fast Fourier
  sampling over the polynomial tree).
- Check whether ZKNOX_ethfalcon.sol uses `ffSampling` on-chain or
  relies on the client-side sampler only. If the on-chain verifier
  only verifies (not signs), Falcon's client-side complexity doesn't
  affect Gate 4 — but it DOES affect Gate 2 (G2 byte-identity for
  the JS port).
- Look at `ETHFALCON/js/` (if it exists) for any existing JS Falcon
  signer — noble-post-quantum may not include Falcon, so the TS port
  might need to be a heavier lift than ML-DSA's port (which wrapped
  noble's ml_dsa44.sign).

### 6.5. Falcon-512 vs other param sets

- ML-DSA is `ml_dsa44` in this repo (FIPS 204 Level 2). ETHDilithium
  is hard-wired to k=4, l=4.
- Falcon is Falcon-512 in this repo. ZKNOX_ethfalcon's constants
  (`falcon_S256` — see `ZKNOX_ethfalcon.sol:28`) indicate 512-wide
  arrays.
- Sanity-check the param set matches the fixture data from day one.

### 6.6. Is there an `epervier` variant mixed in?

- `ETHFALCON/src/ZKNOX_epervier.sol` and `ZKNOX_ethepervier.sol`
  exist alongside `ZKNOX_falcon.sol` / `ZKNOX_ethfalcon.sol`.
- `ETHFALCON/pythonref/falcon_epervier.py` also exists.
- Epervier appears to be a FALCON variant with different on-chain
  semantics (hint/signature format). Confirm scope: is falcon-eth
  = ETHFALCON Keccak-PRG, OR ETHFALCON-Epervier, OR both?
- User direction at /research start should clarify. If both, expect
  a 6-story feature (Epervier as a second parallel variant).

---

## 7. Suggested story decomposition (5 stories, same shape as mldsa-eth)

| # | Slug | Size | Focus | Depends on |
|---|------|------|-------|-----------|
| 1 | `falcon-eth-fixtures` | M | Extend `scripts/generate-kat-fixtures.ts` to produce `falcon-eth/vectors.json`; extend loader + types; capture ~100 vectors. | none |
| 2 | `keccak-prg-verification` | S-M | Verify `keccakXofFactory` matches ETHFALCON's Python `KeccakPRNG` byte-for-byte (G0 carried over). If divergence, port new adapter. | Story 1 (need fixtures to assert against) |
| 3 | `hash-to-point + keygen port` | M-L | Port NIST Falcon keygen + HashToPoint to TS with XOF-factory abstraction. G1 KAT. Also touch `HashToPoint`'s G0-equivalent sub-oracle. | Stories 1, 2 |
| 4 | `signer port + G2 KAT` | L | Port Falcon sign (including ffSampling if client-side) to TS. G2 KAT over ~100 vectors. Production + KAT surfaces. | Stories 1, 2, 3 |
| 5 | `integration + benchmark + rename` | L | `FalconEthAccount.sol` + `test/fixtures/falcon-eth.ts` + G3 + G4 + extend SCHEMES to 5 + refresh snapshots + README update. Possibly AC-5-1 already-done (rename landed in mldsa-eth Story 5). | Stories 1, 2, 3, 4 |

This mirrors the `mldsa-eth` plan structure. If Story 2 turns out
to be "Keccak matches, nothing to do", merge it into Story 3 and
ship a 4-story plan. Architecture phase decides.

---

## 8. Pre-kickoff checklist

Run these before `/research falcon-eth`:

```bash
# 1. Confirm post-mldsa-eth-5 tag and archive state
git tag --list | grep mldsa-eth
ls docs/.archive-mldsa-eth/ 2>/dev/null || echo "not yet archived"

# 2. Confirm ETHFALCON submodule is initialized + pinned
git submodule status ETHFALCON
cat ETHFALCON/src/ZKNOX_ethfalcon.sol | head -20

# 3. Does an ETHFALCON KAT corpus exist?
ls ETHFALCON/pythonref/assets/ 2>/dev/null

# 4. Does ETHFALCON use the same Keccak-PRG as ETHDILITHIUM?
diff ETHDILITHIUM/pythonref/dilithium_py/keccak_prng/keccak_prng_wrapper.py \
     ETHFALCON/pythonref/keccak_prng.py 2>&1 | head -20

# 5. Is there a noble-post-quantum Falcon? (mldsa-eth leveraged noble for NIST ml_dsa44)
node -e "console.log(Object.keys(require('@noble/post-quantum')))"

# 6. ETHFALCON compile-path sanity check (should NOT require edits)
grep -r "ZKNOX_ethfalcon" contracts/imports/ 2>/dev/null
#   If empty, the Solidity compile graph does not yet include ZKNOX_ethfalcon
#   — add a wrapper in contracts/imports/FalconRef.sol mirroring DilithiumRef.sol:37

# 7. Baseline test state
npx hardhat test 2>&1 | tail -3
#   Expected: 97 passing after mldsa-eth archival — this is falcon-eth's pre-Story-1 baseline
```

---

## 9. Operational tips (process lessons)

### 9.1. Commit one task per commit, story file tracked from Task 1

```bash
# Task N landing:
git add {task-files}                   # never git add .
git add docs/stories/{id}-{slug}.md    # after flipping checkbox [x]
git commit -m "feat({scope}): Story N Task M — {description}

Task M/T: {short summary}
AC: AC-N-M-a, AC-N-M-b, ...
Story: N

{body — what changed, why, verify evidence, deviations}

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

### 9.2. Full test suite is the final word on regressions

- `npx hardhat test` runs all 97 tests in ~30s post-mldsa-eth (will
  be higher after falcon-eth adds tests). Always run it at each task
  checkpoint before presenting to the user. Use `test/{specific}.test.ts`
  filter for faster inner loops.
- `npm run compile` is the Solidity build step (hardhat v3 +
  warnings-as-errors gate via `scripts/check-compile-warnings.cjs`).
  Runs in seconds if no Solidity files changed.

### 9.3. Resume protocol for crashed / paused sessions

- `docs/.lock` is the session marker. If it exists and isn't stale
  (>4h old), another session is active — check `ps aux | grep claude`.
- On resume, ALWAYS re-read `docs/stories/{id}-{slug}.md` from disk
  before proceeding; the implement skill's task compaction strips
  out earlier task detail.
- If a tag `pre-mldsa-eth-N` exists but no matching `post-mldsa-eth-N`,
  Story N was left in-progress. Read sprint-status.yaml to confirm
  and resume from the first non-done task.

### 9.4. Amendments go in `docs/amendments.md`, one entry per Rule-3+

Template (copy from existing A-N entries):

```markdown
## A-NNN: {one-line title}

- **Story:** N
- **Task:** M
- **Date:** YYYY-MM-DD
- **Classification:** Rule {1-4} ({short description})
- **Affects:** {architecture sections affected}

### Original (what the spec/story said)
...

### Actual (what we discovered / what we implemented)
...

### Rationale
{why we diverged or what the bug was}

### Resolution
{exactly what landed in code, with file:line citations}
```

### 9.5. Code review at end of every story

- Spawn `code-review-agent` via Task tool with ONLY: story file,
  `git diff pre-{feature}-{N}..HEAD`, state.json.
- Zero implementation context — the agent is adversarial by design.
- Expect <=5 findings per story. Apply all Medium+, defer Low or
  fix inline depending on quickness.
- Budget one resume via `SendMessage` if the agent truncates
  mid-investigation (happened both Story 4 and Story 5).

### 9.6. Commit protocol for refresh of generated files

gas-data.json + gas-report.md are generated artifacts — commit them
atomically with the code changes that produced them:

```bash
UPDATE_BENCH=1 npx hardhat test test/bench/gas-benchmark.test.ts
npm run report
git add test/bench/gas-data.json docs/gas-report.md {code-files}
git commit -m "feat(bench): ... + refresh snapshots"
```

### 9.7. N=5 smoke-first for on-chain KAT loops

The initial landing of G4 at N=5 saved a full 100-vector cycle
during scaffolding discovery. The empirical tune-up at review time
confirmed N=100 fits the budget. For falcon-eth's Gate-4-equivalent:

1. Task landing: `const VECTOR_COUNT = 5;` + JSDoc "tune at review".
2. Review time: measure; if budget allows, bump to 100 and update the
   JSDoc to reflect the empirical timing.

This saves 35-55 seconds per failed iteration during initial test
development (full 100 vs smoke 5).

---

## 10. Links & references

### Key commits in the mldsa-eth feature to re-read for context:

```bash
git log --oneline pre-mldsa-eth-1..post-mldsa-eth-5
# 266c8d3 feat(signers): Story 4 Task 1 — fork signWithXof + SampleInBall + MakeHint + ExpandMask
# 243395c feat(signers): Story 4 Task 2 — signWithRnd KAT surface + SignerInputError
# 3d6ec03 feat(signers): Story 4 Task 3 — signUserOp production path
# e481351 test(signers): Story 4 Task 4 — G2 KAT byte-identity + AC-4-5 rejection counter
# 5f2324e test(signers): Story 4 Task 5 — input validation + production path + hedged sign
# bc1936c chore(signers): Story 4 code-review followups — error taxonomy + AC-4-5 fence + hintCoder rationale
# 939c98b refactor(accounts): Story 5 Task 1 — publicKey → publicKeyPointer rename (A-006)
# 82f8db7 test(signers): Story 5 Task 2 — G3 pk-transform KAT (AC-5-2)
# 33ce5e0 feat(accounts): Story 5 Task 3 — MlDsaEthAccount contract + mldsa-eth test fixture
# 1a45e5d test(accounts): Story 5 Task 4 — G4 happy path + AC-FLOW-1 end-to-end
# 3596e7f test(accounts): Story 5 Task 5 — MlDsaEthAccount rejection paths (AC-5-4, AC-5-5)
# 0c5ecae feat(bench): Story 5 Task 6 — extend SCHEMES to 4 + strict report determinism + snapshot refresh
# f769953 docs(readme): Story 5 Task 7 — 4-scheme attribution + Python dev-oracle isolation note (AC-5-10)
# e2b1ddd chore(story-5): review followups — N=100, walker address binding, bench ordering, doc sweep
```

### Archived artifacts (after `/start` archives mldsa-eth):

- `docs/.archive-mldsa-eth/research.md`
- `docs/.archive-mldsa-eth/spec.md`
- `docs/.archive-mldsa-eth/architecture.md`
- `docs/.archive-mldsa-eth/plan.md`
- `docs/.archive-mldsa-eth/sprint-status.yaml`
- `docs/.archive-mldsa-eth/amendments.md` (A-001..A-006)
- `docs/.archive-mldsa-eth/stories/{1..5}-*.md`
- `docs/.archive-mldsa-eth/concerns.md` (if any deferred)

Re-read these as the `/research falcon-eth` phase's primary input.
Feed this `falcon-eth.md` as `--context falcon-eth.md` to `/start`
to bootstrap with these lessons pre-loaded.

---

_Document written 2026-04-18 by the same agent-session that landed
mldsa-eth. Source commits: `pre-mldsa-eth-1` → `post-mldsa-eth-5`
(20 commits). If anything here conflicts with code that has
evolved after this document was written, the code wins — treat
this as a starting map, not a specification._
