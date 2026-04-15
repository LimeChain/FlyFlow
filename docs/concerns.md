# Concerns Log

Known issues, deferred fixes, and upstream defects accepted as tolerated
deviations. Each entry documents why the project chooses to live with the
issue instead of fixing it immediately.

---

## C-001 — Unused local variable in ETHFALCON submodule

**Source:** `ETHFALCON/src/ZKNOX_falcon_encodings.sol:102`
**First observed:** Story 1-1 / Task 3 (2026-04-14)
**Compiler:** `solc 0.8.25`
**Severity:** Informational (compiler warning, not an error)

### Warning text

```
Warning: Unused local variable.
   --> ETHFALCON/src/ZKNOX_falcon_encodings.sol:102:5:
    |
102 |     uint256 slen = (uint256(uint8(sm[0])) << 8) + uint256(uint8(sm[1]));
    |     ^^^^^^^^^^^^
```

### Analysis

- The variable `slen` is computed but never read within `falcon_compact`.
- It appears to be a leftover from a sanity check that was moved elsewhere.
- No functional impact: the computation has no side effects, and the
  surrounding logic does not depend on its value.
- Deemed **benign** — at worst wastes a couple of stack slots at compile
  time; the optimizer elides the dead computation.

### Why we do not fix

DD-3 (LOCKED) forbids modifications to submodule sources. The ZKNoxHQ
ETHFALCON repository is consumed as a read-only git submodule pinned to a
specific commit SHA. Patching the upstream would break our security
guarantee that the submodule content matches what was audited upstream.

### Mitigation

The `npm run compile` script's warnings-as-errors gate scopes its
pattern match to the project's own `contracts/` sources. Warnings
originating from paths prefixed with `ETHFALCON/` or `ETHDILITHIUM/`
pass through informationally. See `package.json` `compile` script and
`hardhat.config.ts` for the exact regex.

### Re-evaluation triggers

- When the ETHFALCON submodule is bumped to a new commit, re-run the
  verification loop; if the warning disappears upstream, this entry can
  be deleted.
- If upstream adds more warnings, re-evaluate whether the narrow
  submodule-scoped exception is still appropriate or whether individual
  entries per warning are warranted.

---

## C-002 — HH3 strict npm-import parsing forces `remappings.txt`

**Source:** Hardhat 3.3.0 import resolver (`parseNpmDirectImport`)
**First observed:** Story 1-1 / Task 3 (2026-04-14)
**Severity:** Informational (workaround in place; build is green)

### Context

ETHFALCON submodule sources contain bare imports that reference two
Foundry-style libraries vendored in `ETHFALCON/lib/`:

```solidity
import "sstore2/contracts/SSTORE2.sol";
import "InterfaceVerifier/src/IVerifier.sol";
```

Under Hardhat 2.x, `scripts/link-submodule-libs.ts` resolved these by
symlinking `node_modules/sstore2` and `node_modules/InterfaceVerifier`
into `ETHFALCON/lib/`. Hardhat 3.3.0 tightened its npm import parser —
`parseNpmDirectImport` now rejects package names that do not match a
strict lowercase/kebab regex, so `InterfaceVerifier/…` fails with
`HHE902: IMPORT_WITH_INVALID_NPM_SYNTAX` before the symlink can be
consulted.

### Resolution

A project-root `remappings.txt` rewrites the two prefixes to the in-tree
submodule paths:

```
InterfaceVerifier/=ETHFALCON/lib/InterfaceVerifier/
sstore2/=ETHFALCON/lib/sstore2/
```

This is HH3's documented user-remapping mechanism. NFR-5 is preserved:
`git diff` inside either submodule is empty.

The HH2-era `scripts/link-submodule-libs.ts` (which staged symlink stubs
in `node_modules/`) was removed — empirically verified redundant once
`remappings.txt` is in place.

### Re-evaluation triggers

- When the ETHFALCON submodule is bumped, confirm the remapping still
  covers all bare imports in the new tree. If upstream drops the
  `InterfaceVerifier/` or `sstore2/` prefixes, the remapping can be
  removed.
- When Hardhat is bumped, confirm the `remappings.txt` format is still
  honored (HH3's resolver is the source of truth; breaking changes
  should surface as `HHE9xx` codes during compile).

---

## C-003 — AC-4 source grep uses CWD-relative path

**Source:** `test/accounts/ecdsa.test.ts` (AC-4 assertion)
**First observed:** Story 2-1 code review (2026-04-14)
**Severity:** Low (test-infra hardening)

`readFile("contracts/EcdsaAccount.sol", ...)` resolves against
`process.cwd()`. Works today because `npm test` runs from project root.
Future runners/debuggers that set CWD elsewhere would cause ENOENT.
Fix-when-touched: replace with
`new URL("../../contracts/EcdsaAccount.sol", import.meta.url)`. Not
blocking — any CWD-shift produces an ENOENT that surfaces as a test
failure (not a silent DD-10 bypass).

## C-004 — AC-4 grep narrower than DD-10 intent

**Source:** `test/accounts/ecdsa.test.ts` (AC-4) vs `docs/architecture.md` DD-10
**First observed:** Story 2-1 code review (2026-04-14)
**Severity:** Low (literal-compliance gap)

AC-4 greps only for `_validateSignature` absence. DD-10 actually forbids
any override of SimpleAccount validation-path methods (`_validateNonce`,
`_payPrefund`, `validateUserOp`, `execute`, etc.). Story 2-1's literal
AC is SATISFIED. Consider widening the guard in Story 5-1 prep since
the gas baseline depends on byte-for-byte bytecode equality with
SimpleAccount. Practical hardening: assert `EcdsaAccount.sol` file size
below ~700 bytes, OR extend grep to the full override surface.

## C-005 — `publicKey` field type differs across schemes

**Source:** `test/signers/ecdsa.ts:32` vs future `test/signers/falcon.ts`, `ml-dsa.ts`
**First observed:** Story 2-1 code review (2026-04-14)
**Severity:** Low (surfaces in Stories 3-1 / 4-1)

ECDSA's signer stores the 20-byte Ethereum address in `Keypair.publicKey`
(matching SimpleAccount's owner model). Falcon and ML-DSA's raw public
keys are hundreds of bytes — not addresses. Tests cannot use
`bytesToHex(alice.publicKey)` as an `initialize(ownerAddress)` input in
3-1/4-1 because those accounts will verify against a public-key hash or
the raw key itself, not a recovered-address model. Resolution belongs
to Story 3-1's / 4-1's signer module design (how do they expose "the
thing the account compares against"?). Flagged for story-creator-agent
when drafting 3-1.

**Resolved 2026-04-15** by amendment **A-003** — all PQC accounts store
the 20-byte SSTORE2 pointer returned by `ISigVerifier.setKey(rawKey)`;
the signer module's `Keypair.publicKey` continues to hold the raw
NIST-encoded key. See `docs/amendments.md#A-003`.

## C-006 — Flaky AC-1 in `ecdsa.test.ts` (intermittent ECDSAInvalidSignature revert)

**Source:** `test/accounts/ecdsa.test.ts` AC-1 (`valid owner signature returns SIG_VALIDATION_SUCCESS`)
**First observed:** Story 3-1 baseline snapshot (2026-04-15)
**Severity:** Low (intermittent; may escalate to Medium under Story 5-1's loop pressure)

Baseline run for Story 3-1 hit a single `ECDSAInvalidSignature()` revert
inside `EcdsaAccount._validateSignature → ECDSA.recover`. Same git SHA,
same input shape, **second run passed 9/9 cleanly**. No code changed
between runs.

Likely cause: viem's `signMessage` or hardhat-EDR's signing path
occasionally produces a signature OZ's `ECDSA.tryRecover` rejects on the
high-S malleability check (EIP-2 / SignatureS guard at
`@openzeppelin/contracts/utils/cryptography/ECDSA.sol`'s
`InvalidSignatureS` short-circuit, which `tryRecover` collapses to
`InvalidSignature`). Probability appears low (~1 in N runs) but
deterministic in distribution.

**Why it matters for Story 5-1:** the gas benchmark loops many UserOps
per run. If the failure rate is ~1/N, the benchmark will hit it within
a handful of iterations. Variance numbers will be polluted unless the
signer is hardened to enforce low-S before returning.

**Fix-when-touched (Story 5-1 prep):** After `viem.signMessage`, if the
signature's `s` byte (offset 32..63 of the 65-byte sig) is in the upper
half of the curve order, flip `s` to `n - s` and toggle the recovery byte
(`v` at offset 64) between 27/28. This is the canonical EIP-2 low-S
normalization. Encapsulate inside `test/signers/ecdsa.ts` so all
consumers (3-1's userOpHash extraction in Task 3, 5-1's benchmark loop)
inherit it. Not blocking Story 3-1 — Story 3-1 doesn't re-sign with
ECDSA in its happy path.

## C-007 — Story 3-1 paused on Falcon JS encoding bridge

**Source:** Story 3-1 / Task 4 (encoding bridge)
**First observed:** Story 3-1 implementation (2026-04-15)
**Severity:** Medium (blocks Stories 3-2 and 5-1 until resumed)

### Context

Story 3-1's Task 4 requires bridging two Falcon-512 encodings: noble's
NIST-format outputs (897-byte public key, ~666-byte Golomb-Rice-compressed
signature) and ZKNOX/ETHFALCON's on-chain dialect (NTT-domain compacted
public key as `uint256[32]`, fixed-size 1064-byte signature `salt(40) ||
s2_compact(1024)`). Tasks 1 and 3 are committed (FalconAccount.sol at
6cdfc22; userOpHash helper extracted at 43b331b). Tasks 2, 4, 5, 6, 7
remain.

Unlike ETHDILITHIUM, the ETHFALCON repository ships **no JavaScript
reference implementation** — only Solidity verifier + Python signer
(`ETHFALCON/python-ref/`). Writing the bridge from scratch requires
porting NTT (Z_q[x]/(x^512+1) with q=12289) and Golomb-Rice signature
compression to TypeScript.

### User decision (2026-04-15)

Pause Story 3-1, complete Story 4-1 (ML-DSA) first, then return to 3-1.
Rationale:

- **JS-only constraint preserved.** No Python fallback, no shell-out,
  no separate runtime. The full toolchain stays Node + viem + Hardhat.
- **ETHDILITHIUM ships `ETHDILITHIUM/js/`** — a complete JS reference
  for the analogous ML-DSA bridge problem (`utils_mldsa.js`,
  `pkDeploy.js`, `execute.js`). Building Story 4-1 first establishes
  the bridge pattern (noble → on-chain encoding → ABI-encoded SSTORE2
  payload → account deployment) end-to-end in JS.
- **Story 3-1 then becomes a port problem, not a discovery problem.**
  Returning to Falcon with the ML-DSA bridge as a working template
  reduces the open question to "translate ETHFALCON's Python signer to
  TS" — a mechanical transcription where the surrounding scaffolding
  is already proven.

### What is committed under Story 3-1

- `contracts/FalconAccount.sol` (Task 1, commit 6cdfc22) — full
  implementation, NatSpec, two-deviation handling (selector ambiguity,
  view-mutability warning) documented in commit message.
- `test/signers/userOpHash.ts` (Task 3, commit 43b331b) — shared helper
  used by ECDSA today and consumed by ML-DSA in Story 4-1.

### Resume condition

Story 4-1 reaches Gate 5 PASS. At that point, Story 3-1 resumes at
Task 2 (Falcon signer JS module) with the ML-DSA implementation as the
template — same flow: decode NIST key with noble, transform to on-chain
encoding, ABI-encode for `setKey()`, deploy, sign, verify on-chain.

### Why we do not fix now

Pushing through Task 4 in Story 3-1 today would either (a) introduce a
Python dependency the project explicitly rejects, or (b) commit days to
porting NTT + Golomb-Rice with no reference JS for sanity-checking
intermediate values. Doing ML-DSA first amortizes the bridge-design
work across both schemes and yields a working JS reference before the
Falcon port begins.

### Re-evaluation triggers

- Story 4-1 Gate 5 PASS → unpause 3-1; revisit Task 2/4 design with
  ML-DSA bridge as reference.
- If Story 4-1 itself reveals the JS bridge approach is unsuitable
  (e.g., noble internals don't expose the right primitives for either
  scheme), escalate to architecture amendment before resuming 3-1.

## C-008 — Story 4-1 code review deferrals (LOW severity)

**Source:** code-review-agent on commits `b3954e3` + `d2a093e` (Story 4-1 close)
**First observed:** 2026-04-15
**Severity:** Low (none block Gate 5)

Four LOW-severity findings deferred for a future quality-cycle pass.
Finding 2 (AC-4 substring matching) was fixed inline in the next commit;
the four below remain.

### C-008.1 — `deployDilithiumVerifier` return shape footgun (multi-connection)

`test/fixtures/mldsa.ts:35-43` returns `{ dilithiumVerifier, publicClient,
walletClients }`. When a caller passes its own `viem` (the documented use
case for cross-fixture sharing), the returned `publicClient` and
`walletClients` are still derived from the fixture's `v` reference — which
is fine when the caller passed `v`, but a future caller mixing fixture
clients with a different connection would re-introduce the exact
cross-network bug the single-connection refactor exists to prevent.

**Fix-when-touched:** when `viem` is provided, return only
`{ dilithiumVerifier }`. Force the caller to re-use their own connection's
clients.

### C-008.2 — Dead `walletClients` wire + unreachable length check

`test/fixtures/mldsa.ts:39, 62-66`. `walletClients` is fetched and returned
but never read by the only caller. `hexToBytes(pointerHex).length !== 20`
is essentially unreachable given `ZKNOX_dilithium.setKey`'s
`abi.encodePacked(address)` (always 20 bytes). Defensive but redundant.

**Fix-when-touched:** drop `walletClients`; either drop the length check or
cache `hexToBytes(pointerHex).length` in a local.

### C-008.3 — `F_INV = 8347681` magic constant lacks FIPS 204 citation

`test/signers/mldsa-encoding.ts:22`. Comment says "256^-1 mod q" but every
other constant in the file cites a FIPS 204 section. This one breaks the
pattern and forces a reader to rederive.

**Fix-when-touched:** add `// FIPS 204 §7.5 — F in Algorithm 41 (NTT⁻¹
normalization)`. Pure documentation.

### C-008.4 — Reliance on noble's `_crystals` private-ish entrypoint

`test/signers/mldsa-encoding.ts:2` imports `genCrystals` from
`@noble/post-quantum/_crystals.js`. The leading underscore is noble's
convention for "internal — may change without semver bump." `package.json`
exports it (so the import resolves), but a noble minor-version bump could
silently change `genCrystals`'s signature and the t1 storage form.

**Why not fix now:** lockfile-pinned noble version (`0.6.1`) is stable.
Reimplementing `transformT1Poly` against the raw FIPS 204 zeta table
+ Cooley-Tukey butterflies (~50 LOC) eliminates the dependency but adds
maintenance surface that has to track noble's bug fixes.

**Re-evaluation triggers:** noble-post-quantum 1.0 release, OR the import
breaks on a routine `npm update`. Until then, lockfile is the safety net.

### Resolution path

All four are eligible for a single follow-up commit during a future
quality-cycle pass (e.g. between Story 4-2 and Story 5-1). None block
Story 4-1 Gate 5 or Story 3-1 resumption.
