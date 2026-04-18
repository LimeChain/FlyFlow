---
story_id: "1"
title: "Fixture-gen CLI + submodule compile path + KAT loader"
size: "M"
status: "ready-for-dev"
wave: 1
created: 2026-04-17
feature: mldsa-eth
---

# Story 1: Fixture-gen CLI + submodule compile path + KAT loader

> Ref: `docs/plan.md` §"Story 1: Fixture-gen CLI + submodule compile path + KAT loader [M]" — authoritative AC text and wave assignment.
> Ref: `docs/architecture.md` §"Component Decomposition" rows "Fixture-gen CLI" and "KAT loader" — component responsibilities.
> Ref: `docs/architecture.md` §"Error Handling Strategy" §"Fixture-gen CLI diagnostics (AC-U-2)" — the four onboarding failure modes.

## User Story

As a test author, I want a fixture-gen CLI that produces byte-accurate KAT fixtures from the pinned ZKNox reference implementations, so that all downstream KAT tests have authoritative vectors to assert against and can be regenerated deterministically when the submodule bumps.

## Acceptance Criteria

> All ACs copied verbatim from `docs/plan.md` §"Story 1". Never paraphrase.

- **AC-1-1** (CLI regeneration — FR-7): Given the ETHDILITHIUM submodule at its pinned commit, when `npx tsx scripts/generate-kat-fixtures.ts` runs, then `test/fixtures/kat/mldsa-eth/vectors.json` contains ≥100 vectors with fields `(id, drbgSeed, zeta, rnd, publicKey, secretKey, reshapedPublicKey, message, signature)` + embedded `submoduleSha` matching HEAD, and `test/fixtures/kat/keccak-prg/vectors.json` contains 4 `source: "zhenfei-canonical"` vectors (hex literals from `ETHDILITHIUM/test/keccak_prng.t.sol`) + ≥3 `source: "python-ref-extended"` boundary vectors.
- **AC-1-2** (Determinism): Given identical submodule state, when the CLI runs twice, then `git diff test/fixtures/kat/` produces zero output.
- **AC-1-3** (pk_for_eth invocation): Given each `.rsp` vector's raw pk, when `Dilithium2.pk_for_eth(pk, _xof=Keccak256PRNG, _xof2=Keccak256PRNG)` is invoked from the submodule's Python module, then the resulting `abi.encode(aHatEncoded, tr, t1Encoded)` bytes land in the `reshapedPublicKey` field.
- **AC-1-4** (Submodule pin mismatch — AC-NFR-4): Given `.gitmodules` records the pinned ETHDILITHIUM SHA, when the CLI is invoked with submodule HEAD at a different SHA, then the CLI refuses to run and prints both expected + actual SHAs plus the reset-to-pin command.
- **AC-1-5** (AC-U-2 diagnostic — uninit'd submodule): Given ETHDILITHIUM submodule is uninitialized, when CLI is invoked, then it exits with `code "SUBMODULE_UNINIT"` and message containing `git submodule update --init --recursive`.
- **AC-1-6** (AC-U-2 diagnostic — Python version): Given detected `python3 --version` does not satisfy the required version, when CLI is invoked, then it exits with error naming required + detected versions.
- **AC-1-7** (AC-U-2 diagnostic — pip deps): Given pip dependencies in the submodule's `requirements.txt` are missing, when CLI is invoked, then it exits with the pinned requirements path + exact `pip install -r ...` command.
- **AC-1-8** (Loader SHA check at import): Given a committed `vectors.json.submoduleSha` differs from current submodule HEAD, when any KAT test file imports via `loadPrgVectors()` or `loadKatVectors("mldsa-eth")`, then a `KatFixtureError` with `code: "KAT_SUBMODULE_SHA_MISMATCH"` is thrown at import time with the regeneration command.
- **AC-1-9** (Submodule compile path): Given the Hardhat compile graph covers `ETHDILITHIUM/src/` contracts (via the pre-existing `contracts/imports/DilithiumRef.sol` Ref-wrapper pattern — see `hardhat.config.ts` block comment for the forge-std-pollution rationale that rules out direct `paths.sources.solidity` extension), when `npx hardhat compile` runs, then `ZKNOX_ethdilithium.sol` and its transitively-imported dependencies (`ZKNOX_SampleInBall.sol`, `ZKNOX_NTT_dilithium.sol`, `ZKNOX_dilithium_core.sol`, `ZKNOX_dilithium_utils.sol`, `ZKNOX_hint.sol`, `ZKNOX_keccak_prng.sol`) compile without warnings using the existing Solidity 0.8.34. Note: `ZKNOX_keccak_prng.sol` declares only free functions + a struct (no contract/interface/library), so solc correctly emits no standalone artifact for it — its compiled source is present in `artifacts/build-info/*.output.json` and grep-verifiable there.
- **AC-1-10** (No new runtime deps): Given `package.json` + `package-lock.json`, when Story 1 commit diff is inspected, then no new runtime dependencies are introduced.

**FR Coverage:** FR-7. **NFR Coverage:** NFR-3 (cross-cutting), NFR-4 (AC-1-9+1-10), NFR-5 (AC-1-4+1-8).

## Verified Interfaces

Status: **UNVERIFIED** — Story 1 is the first in the feature. Interfaces this story PRODUCES do not yet exist; interfaces this story CONSUMES (external Python + submodule Solidity) are verified against the pinned submodule source at creation time.

### Produced by this story (placeholders from plan contracts)

- **`scripts/generate-kat-fixtures.ts`** — CLI entry-point. [UNVERIFIED — will exist after this story]
  - Plan contract: no exported symbols; invoked via `npx tsx scripts/generate-kat-fixtures.ts`. Exit 0 on success; non-zero with diagnostic on failure.
- **`test/fixtures/kat/index.ts`** — typed loaders. [UNVERIFIED — will exist after this story]
  - Plan contract (from `docs/plan.md` §"Interface Contracts" → "KAT loaders"):
    ```ts
    function loadPrgVectors(): PrgVector[];
    function loadKatVectors(scheme: "mldsa-eth"): KatVector[];
    // Both run assertSubmoduleShaMatches() at import time,
    // throwing KatFixtureError with code: "KAT_SUBMODULE_SHA_MISMATCH" on drift.
    ```
  - Also exports the error class `KatFixtureError extends Error` with `readonly code: "KAT_SUBMODULE_SHA_MISMATCH" | "KAT_SCHEMA_MISMATCH"` (per architecture §"Error Handling Strategy" §"JS signer taxonomy").

### Consumed by this story (VERIFIED against pinned submodule source)

- **`Dilithium2.pk_for_eth(pk, _xof=Keccak256PRNG, _xof2=Keccak256PRNG, zk=False)`**
  - Source: `ETHDILITHIUM/pythonref/dilithium_py/dilithium/dilithium.py:568`
  - File hash (sha256): `9249013644a34b3ad5060b08570e300b7bd723cc5e75b443123130cb9dff84e7`
  - Signature (verbatim): `def pk_for_eth(self, pk, _xof=Keccak256PRNG, _xof2=Keccak256PRNG, zk=False)` — returns `(A_hat, tr, t1_new)` (a 3-tuple; CLI must ABI-encode into `reshapedPublicKey`).
  - Plan match: ✓ matches `docs/plan.md` §"Story 1" AC-1-3 and architecture §"Fixture-gen CLI".

- **`Dilithium2.random_bytes` — backed by `AES256_CTR_DRBG(seed).random_bytes(n)`**
  - DRBG source: `ETHDILITHIUM/pythonref/dilithium_py/drbg/aes256_ctr_drbg.py:7` (`class AES256_CTR_DRBG`)
  - DRBG file hash (sha256): `a6a58752b46684109e346ac7043ccca181915f2471b0ed6b04441c6815683147`
  - DRBG constraint: constructor requires exactly 48-byte seed (`self.seed_length = 48`); the `.rsp` `seed` field is 48 bytes hex → 96 hex chars. ✓ Confirmed (header row 1 of `PQCsignKAT_Dilithium2_ETH.rsp` shows `seed = 0615... (96 hex chars)`).
  - Consumption order (load-bearing for AC-1-3):
    - `dilithium.py:399` (keygen): `zeta = self.random_bytes(32)` — consumes DRBG bytes `[0:32]`.
    - `dilithium.py:442` (sign, non-deterministic branch): `rnd = self.random_bytes(32)` — consumes DRBG bytes `[32:64]` if DRBG is driven by the same seeded instance across keygen→sign.
    - Replay rule: `(ζ, rnd) = AES256_CTR_DRBG(drbgSeed).random_bytes(64)[0:32], [32:64]`. ✓ Matches architecture §"Data Models" §"KAT fixture JSON (DD-7 LOCKED)".
  - Plan match: ✓ matches AC-1-1 field list and architecture §UC-2 "replay `AES256_CTR_DRBG(drbgSeed).random_bytes(64)`".

- **`Keccak256PRNG(a=None, b=None)`** (XOF passed to `pk_for_eth`)
  - Source: `ETHDILITHIUM/pythonref/dilithium_py/keccak_prng/keccak_prng_wrapper.py:21`
  - File hash (sha256): `090abd67de8e120e5c44e927293244b54c7919e3c2e6dcf4cbe5be18dff4097f`
  - Notes: `__call__(input_bytes)` signature lets the class be passed as `_xof=Keccak256PRNG` — Python `pk_for_eth` calls `_xof()` internally to construct an instance. The Layer-1 canonical PRG vectors (4) are copied verbatim from `ETHDILITHIUM/test/keccak_prng.t.sol:12-27` (file sha256: `085ede486f2be7148e8e558d426fd0a123839ddbf723b7471b168e17eba361d8`).

### External `.rsp` corpus

- **`ETHDILITHIUM/pythonref/assets/PQCsignKAT_Dilithium2_ETH.rsp`** — file sha256: `f8e8166ae44d8fe1d5c21fc49abf1b8833b0dc516f8fd261db3155e56e6c6f85`
- Contains exactly **100** vectors (verified: `grep -c '^count = '` = 100). Each record: `count`, `seed` (48 B hex = 96 chars), `mlen`, `msg`, `pk`, `sk`, `smlen`, `sm`. `sig = sm[:-mlen]` (strip appended message).

## Dev Notes

### Architecture context (inlined — correctness-critical)

> **Amendment A-001 applies:** DD-7's `reshapedPublicKey` ABI tuple is `abi.encode(bytes aHatEncoded, bytes tr, bytes t1Encoded)` — `tr` is variable-length `bytes` (64 B via Keccak-PRG stream, not native 32 B `bytes32`). Original architecture text said `bytes32 tr = Keccak256(ρ ∥ t1)` — corrected in `docs/amendments.md` §A-001 after verification against Python ref (`dilithium.py:573` — `tr = self._h(pk, 64, _xof=_xof)`) and Solidity `_readPubKey` (`ZKNOX_ethdilithium.sol:183-184` — decodes as `(bytes, bytes, bytes)`). Fixture-gen CLI follows the amended contract.

**DD-7 LOCKED — ML-DSA KAT fixture schema.** File at `test/fixtures/kat/mldsa-eth/vectors.json`:

```jsonc
{
  "scheme": "mldsa-eth",
  "params": "dilithium2-keccak",
  "submoduleSha": "<40-hex>",
  "generatedAt": "<ISO 8601>",
  "source": {
    "rspFile": "ETHDILITHIUM/pythonref/assets/PQCsignKAT_Dilithium2_ETH.rsp",
    "drbgDerivation": "AES256_CTR_DRBG(drbgSeed).random_bytes(64) → ζ=[0:32], rnd=[32:64]",
    "ctx": "0x"
  },
  "vectors": [
    {
      "id": "vec-001",
      "drbgSeed":          "0x…(48B — audit trail; JS never consumes)",
      "zeta":              "0x…(32B — G1 input; CTR-DRBG bytes 0..32)",
      "rnd":               "0x…(32B — G2 input; CTR-DRBG bytes 32..64)",
      "publicKey":         "0x…(1312B — raw Dilithium2 pk)",
      "secretKey":         "0x…(2560B — raw Dilithium2 sk)",
      "reshapedPublicKey": "0x…(SSTORE2 payload = abi.encode(aHatEncoded,tr,t1Encoded))",
      "message":           "0x…",
      "signature":         "0x…(raw cTilde‖z‖h concatenation; 32+2304+84=2420B)"
    }
  ]
}
```

Hex-encoded with `0x` prefix (viem idiom). `signature` is raw concatenation — ABI-encoding is applied at contract-call time, not in the fixture. `drbgSeed` is retained for independent audit; it is not consumed by any downstream JS test. `ctx` is empty (`b""`) — matches `generate_KAT_example.py` and the `.rsp` source convention.

**DD-11 LOCKED — PRG KAT fixture schema.** File at `test/fixtures/kat/keccak-prg/vectors.json`. Per-vector schema:

```jsonc
{
  "id": "prg-vec-001",
  "source": "zhenfei-canonical" | "python-ref-extended",
  "description": "<short, human-readable>",
  "injects":  ["0x..."],          // bytes absorbed in order before flip
  "extracts": [N1, N2, ...],      // byte-counts per extract call after flip
  "expected": ["0x..."],          // expected outputs, aligned to extracts[]
  "expected_slice":  { "from": N, "to": N } | undefined,  // optional slice within the last extract
  "expected_slices": [{ ... }]    | undefined             // optional multi-slice form
}
```

Top-level file carries `submoduleSha` (AC-1-8 enforced) and `generatedAt`. Two layers:

- **Layer 1 (4 vectors, `source: "zhenfei-canonical"`)** — copied as hex literals from `ETHDILITHIUM/test/keccak_prng.t.sol:12-27`:
  - v1: `inject("test input"); flip(); extract(32)` → `0x5b9e99370fa4b753ac6bf0d246b3cec353c84a67839f5632cb2679b4ae565601`
  - v2: `inject("test input"); flip(); extract(64)` — **last 32 bytes** equal `0x569857b781dd8b81dd9cb45d06999916742043ff52f1cf165e161bcc9938b705`
  - v3: `inject("testinput"); flip(); extract(32)` → `0x120f76b5b7198706bc294a942f8d17467aadb2bb1fa2cc1fecadbaba93c0dd74`
  - v4: `inject("test sequence"); flip()`; three successive `extract(32)` — **high-16 bytes** of each: `0x9e96b1e50719da6f0ea5b664ac8bbac5`, `0x1be071eca45961aca979e88e3784a751`, `0x5f19135442b6b848b2f51f7cb58bc583`
  - Encode v2 as a single `extract(64)` with `expected_slice: {from: 32, to: 64}`. Encode v4 as three `extract(32)`s, each paired with `expected_slice: {from: 0, to: 16}` (high 16 B of each block).

- **Layer 2 (≥3 vectors, `source: "python-ref-extended"`)** — generated at fixture-gen time by invoking the submodule's `Keccak256PRNG` class directly. Boundary cases the canonical set doesn't reach (per architecture §DD-11 §"Layer 2"):
  - **cross-extract** — `inject(seed); flip(); extract(5); extract(27)` equals `inject(seed); flip(); extract(32)` on a fresh instance. Fixture records both concatenation and the 32-B expected stream.
  - **multi-inject absorb concatenation** — `inject(a); inject(b); flip(); extract(64)` equals `inject(concat(a,b)); flip(); extract(64)`.
  - **empty-seed** — no `inject` before `flip` (equivalently `inject(b""); flip()`); `extract(32)` records the empty-buffer Keccak state.
  - **ML-DSA-shaped seed (ExpandA shape)** — `inject(rho ‖ j_uint16_le ‖ i_uint16_le); flip(); extract(~408)` — the byte count used by `rejection_sample_ntt_poly`. Optional if ≥3 boundary vectors already present; include to strengthen Story 3 G1 root-cause localization.

**AC-U-2 diagnostic taxonomy — four onboarding failure modes** (from architecture §"Error Handling Strategy" §"Fixture-gen CLI diagnostics"):

| # | Detection | Exit code | Exact next-command message |
|---|-----------|-----------|----------------------------|
| 1 | `ETHDILITHIUM/` exists but is empty OR `git submodule status` returns entry starting with `-` | `code "SUBMODULE_UNINIT"` | must contain `git submodule update --init --recursive` |
| 2 | Current submodule HEAD SHA differs from pinned SHA | `code "SUBMODULE_PIN_MISMATCH"` | must print both `expected=<40hex>` and `actual=<40hex>` SHAs plus the reset-to-pin command (e.g., `git -C ETHDILITHIUM checkout <pinned-sha>`) |
| 3 | `python3 --version` fails OR detected version does not satisfy required range | `code "PYTHON_VERSION_MISMATCH"` | must print both required range and detected version |
| 4 | A `python3 -c "import dilithium_py.dilithium, dilithium_py.keccak_prng, dilithium_py.drbg"` probe raises `ImportError` | `code "PYTHON_DEPS_MISSING"` | must print `ETHDILITHIUM/pythonref/requirements.txt` path + `pip install -r ETHDILITHIUM/pythonref/requirements.txt` |

Implementer-visible: the exact `code` strings are the contract. Message text is flexible as long as the exact next-command substring is present (AC-1-5/6/7 assert on `code` + substring match). `KatFixtureError.code = "KAT_SUBMODULE_SHA_MISMATCH"` (loader, AC-1-8) is architecture-defined per §"JS signer taxonomy"; do not repurpose that code for CLI-side checks.

**Pinned submodule SHA (authoritative at story-creation time).**

- ETHDILITHIUM pinned HEAD: `b9ca7f72526ecc696230d3c774a6e2c12c9b37c2` (from `git submodule status` at creation). `.gitmodules` currently records only the URL; Task 1 must confirm or add a pin record. If `.gitmodules` does not encode the SHA (Git convention stores the pin in the parent-tree gitlink, not `.gitmodules`), the CLI reads the pin from `git ls-tree HEAD ETHDILITHIUM` (or equivalent) and the story's plain-English AC-1-4 wording of "`.gitmodules` records the pinned ETHDILITHIUM SHA" is satisfied by *any* repo-tracked pin source the CLI reads deterministically. Document the chosen source in `scripts/generate-kat-fixtures.ts` top-of-file JSDoc.

**Python version detection (AC-1-6).** Local dev shows `Python 3.9.6`; the `dilithium_py` package uses `from typing import Optional`, f-strings, type hints — compatible with 3.8+. Choose a required range ≥3.8 (reasonable floor for `pycryptodome==3.23.0`). Implementer may tighten based on submodule `pyproject.toml` inspection. The version check is a soft guard — if it passes but imports fail, fall through to failure mode #4.

**Four-implementation oracle chain (DD-11 background).** The PRG has C ref (`ETHDILITHIUM/c-ref/keccak_prng.c`), Python ref (consumed here), Solidity (`ZKNOX_keccak_prng.sol`, Layer-1 canonical vectors asserted by ZKNox's own Forge test `ETHDILITHIUM/test/keccak_prng.t.sol`), and the forthcoming JS port (Story 2). Story 1 establishes the fixture substrate; Story 2 consumes it for G0/G0-prime.

### Behavioral requirements (inlined from plan + architecture)

- **Python is invoked once at fixture-gen time only — never at `npm test`.** CLI spawns `python3 -c "..."` (or `python3 scripts/<helper>.py`) into the submodule's `dilithium_py` package. Architecture §"Component Decomposition" row "Fixture-gen CLI" is explicit: "Python invoked once at fixture-gen time only — never at `npm test`."
- **Zero Python files in shipped tree (NFR-3).** All Python execution consumes code already resident under `ETHDILITHIUM/pythonref/` (submodule — `.gitignore`-able per architecture §"Boundaries"). The CLI itself is TypeScript. No Python files are added under `scripts/` or `test/`. Passing Python as a multi-line string to `python3 -c "..."` is architecture-compliant; writing a separate `.py` file to `scripts/` is not.
- **Determinism (AC-1-2).** Stable vector ordering (follow `count` from the `.rsp` file, `id = "vec-001"` through `vec-100`). Canonical JSON serialization: fixed key order per schema above, `\n`-only line endings, 2-space indent, lowercase hex, no trailing whitespace. `generatedAt` is the single exception — must be derived from a source that is stable across runs when inputs are unchanged (e.g., the submodule commit's author date via `git -C ETHDILITHIUM log -1 --format=%cI HEAD`, not `new Date()`).
- **Loader runs SHA guard at import time (AC-1-8).** `assertSubmoduleShaMatches()` reads `vectors.json.submoduleSha` and compares to current submodule HEAD (per architecture §"KAT loader" row: `git submodule status ETHDILITHIUM | cut -c2-41` with fallback to reading `.git/modules/ETHDILITHIUM/HEAD`). Throw `KatFixtureError` with `code: "KAT_SUBMODULE_SHA_MISMATCH"`, message naming both SHAs and the regeneration command (`npx tsx scripts/generate-kat-fixtures.ts`). Must execute at module top-level, not inside `loadKatVectors`/`loadPrgVectors` function bodies — import-time is the AC.
- **No runtime deps added (AC-1-10).** `package.json` `dependencies` block stays empty (it currently has none — only `devDependencies`). `tsx` is already reachable via `npx tsx` through transitive hardhat tooling (confirmed: `node_modules/tsx/` exists via `package-lock.json`). If any story-specific CLI dep is required, add to `devDependencies` only and justify.

### Testing standards (story-specific — this story adds no unit tests)

- No G0–G4 gate runs here. Gate 5 for Story 1 is **operational**: run the CLI end-to-end, inspect the two emitted JSON files, assert schema + vector counts, then corrupt the committed SHA and verify the loader throws.
- No `node:test` / `hardhat test` file is introduced by this story (downstream gates in Stories 2–5 consume the fixtures). If the implementer adds a thin sanity test for the loader's SHA-guard path, keep it ≤20 LOC and colocate as `test/fixtures/kat/index.test.ts`.
- `@noble/post-quantum` is not touched here. It is imported but unused for ML-DSA-ETH (Story 3 introduces the Keccak-adapter). No deps change.

### Library versions (verified at story creation, 2026-04-17)

- `hardhat@3.3.0` (from installed `node_modules/hardhat/package.json`). Hardhat 3 `paths.sources` is a single string; external sources are handled via `npmFilesToBuild` (for npm deps) OR `paths.sources` override OR a conditional multi-config approach. The specific mechanism is **implementation discretion** — the constraint is AC-1-9 (`ZKNOX_keccak_prng.sol` + `ZKNOX_ethdilithium.sol` + dependencies compile without warnings under Solidity 0.8.34).
  - Note: `ETHDILITHIUM/src/ZKNOX_ethdilithium.sol` uses `pragma solidity ^0.8.25;` and imports `sstore2/SSTORE2.sol` + `InterfaceVerifier/IVerifier.sol`. Both remappings exist in `remappings.txt` (they resolve through `ETHFALCON/lib/`). No new remappings should be needed.
- `@noble/post-quantum@^0.6.1`, `viem@^2.43.0`, `typescript@^5.9.3`, `@nomicfoundation/hardhat-toolbox-viem@^5.0.3` — unchanged.
- `tsx` is present transitively; no explicit add required. If the implementer adds it explicitly to `devDependencies` for discoverability, that is acceptable under AC-1-10 (runtime deps are what AC-1-10 guards).
- Node local: `v24.13.1`. Python local: `3.9.6`.

### File-tree effects (expected — non-binding)

New files:
- `scripts/generate-kat-fixtures.ts` (CLI; TypeScript)
- `test/fixtures/kat/index.ts` (loader + error class + types)
- `test/fixtures/kat/mldsa-eth/vectors.json` (generated artifact, checked in)
- `test/fixtures/kat/keccak-prg/vectors.json` (generated artifact, checked in)

Modified files:
- `hardhat.config.ts` (extend to compile `ETHDILITHIUM/src/*.sol`)
- `package.json` (add `kat:regen` script; optional `devDependencies.tsx`)
- `.gitmodules` (if pin-SHA recording convention requires — see Task 1 note)

`package-lock.json` changes only if `tsx` is explicitly added to `devDependencies`; otherwise untouched.

## Tasks

- [x] **Task 1: Submodule pin wiring + Hardhat compile path + compile verification**
  - AC: AC-1-4 (partial — pin-read plumbing), AC-1-9, AC-1-10
  - Files: `hardhat.config.ts`, `.gitmodules` (if pin-SHA recording changes), `remappings.txt` (only if ETHDILITHIUM imports require additional remapping — current `remappings.txt` already covers `sstore2/` and `InterfaceVerifier/`)
  - Dependencies: none (first task)
  - Why: Every subsequent task needs a deterministic read of the pinned SHA and a working Solidity compile path. Implement the minimal Hardhat 3 change (see Dev Notes §"Library versions" — implementer discretion on mechanism) such that `npx hardhat compile` succeeds zero-warning and all `ETHDILITHIUM/src/ZKNOX_*.sol` artifacts are generated. Verify by running `npm run compile` (which already pipes into `check-compile-warnings.cjs`) and visually confirming `artifacts/` contains `ETHDILITHIUM/src/ZKNOX_keccak_prng.sol/...` + `ZKNOX_ethdilithium.sol/...`.

- [x] **Task 2: KAT loader module + error class + SHA guard + types**
  - AC: AC-1-8 (primary); supports AC-1-1 (schema type definitions)
  - Files: `test/fixtures/kat/index.ts` (new; ~80 LOC target)
  - Dependencies: Task 1 (needs the pinned-SHA read logic to factor into a shared helper)
  - Why: Downstream stories (2–5) import this loader; it must exist before their KAT tests can be written. Module-top-level `assertSubmoduleShaMatches()` call is the AC-1-8 enforcement point. Export: `KatFixtureError` (extending `Error` with `readonly code` discriminant per architecture §"JS signer taxonomy"), `KatVector` and `PrgVector` TS types matching the DD-7 / DD-11 schemas inlined above, `loadKatVectors(scheme: "mldsa-eth"): KatVector[]`, `loadPrgVectors(): PrgVector[]`. Both loaders re-invoke the SHA guard defensively (cheap) and validate schema shape on parse — on missing top-level keys throw `KatFixtureError` with `code: "KAT_SCHEMA_MISMATCH"`.

- [x] **Task 3: Fixture-gen CLI — core generation path**
  - AC: AC-1-1, AC-1-2, AC-1-3 (primary)
  - Files: `scripts/generate-kat-fixtures.ts` (new; ~120 LOC target)
  - Dependencies: Task 1 (needs pinned-SHA read), Task 2 (imports types — the CLI produces JSON matching `KatVector[]` / `PrgVector[]`)
  - Why: Core deliverable. Flow:
    1. Read pinned ETHDILITHIUM SHA (source determined in Task 1); compare to current HEAD; emit diagnostic + exit on mismatch (AC-1-4 path feeds this but the CLI plumbing lives here).
    2. Parse `ETHDILITHIUM/pythonref/assets/PQCsignKAT_Dilithium2_ETH.rsp` into the 100 records (fields: `count`, `seed`, `mlen`, `msg`, `pk`, `sk`, `sm` — extract `sig = sm[:-mlen]`).
    3. Spawn ONE `python3 -c "..."` invocation (batch, not per-vector — architecture §UC-2 "spawns a single `python3 -c`"). Python snippet imports `AES256_CTR_DRBG`, `Dilithium2`, `Keccak256PRNG` from `dilithium_py`, iterates records, replays DRBG to derive `(zeta, rnd)`, calls `Dilithium2.pk_for_eth(pk, _xof=Keccak256PRNG, _xof2=Keccak256PRNG)` to get `(A_hat, tr, t1_new)`, ABI-encodes into `reshapedPublicKey` via `eth_abi.encode(['bytes','bytes32','bytes'], [...])`, emits JSON-lines or single JSON blob on stdout.
    4. Merge Python output with `.rsp`-derived fields (drbgSeed, publicKey, secretKey, message, signature) into the 8-field per-vector schema.
    5. Generate PRG Layer 2 (boundary vectors) via the same Python batch — call `Keccak256PRNG` directly for each scripted `inject`/`flip`/`extract` sequence.
    6. Embed Layer 1 (4 Zhenfei-canonical PRG vectors) from hex literals in the CLI source (verbatim from `ETHDILITHIUM/test/keccak_prng.t.sol:12-27` — see Dev Notes §"DD-11 LOCKED").
    7. Canonicalize + write both JSON files deterministically (stable key order, stable `generatedAt` source per Dev Notes, 2-space indent, `\n` line endings).

- [x] **Task 4: AC-U-2 onboarding diagnostics (4 failure modes)**
  - AC: AC-1-4 (pin mismatch — finalize from Task 3's plumbing), AC-1-5, AC-1-6, AC-1-7
  - Files: `scripts/generate-kat-fixtures.ts` (extend Task 3's CLI with pre-flight checks)
  - Dependencies: Task 3 (CLI skeleton exists)
  - Why: Each of the four failure modes must run as a pre-flight check BEFORE any work is done (empty submodule → emit SUBMODULE_UNINIT and exit; pin mismatch → SUBMODULE_PIN_MISMATCH; python check → PYTHON_VERSION_MISMATCH; dep probe → PYTHON_DEPS_MISSING). Table in Dev Notes §"AC-U-2 diagnostic taxonomy" enumerates exact `code` values and required-substring message content. Each exits non-zero with a stderr diagnostic; pass through the error `code` in a structured way (e.g., log `{"code":"SUBMODULE_UNINIT","message":"..."}` as a single JSON line to stderr) so tests can grep deterministically.

- [x] **Task 5: Wire `npm run` script + end-to-end Gate 5 verification**
  - AC: AC-1-1 (end-to-end), AC-1-2 (determinism), AC-1-10 (no new runtime deps)
  - Files: `package.json` (add script; optional `devDependencies.tsx` entry), `README.md` (optional one-liner under a "Fixtures" heading pointing at the regen command)
  - Dependencies: Tasks 1–4 complete
  - Why: Add `"kat:regen": "tsx scripts/generate-kat-fixtures.ts"` (or equivalent). Gate 5 for Story 1 is operational:
    1. `rm -f test/fixtures/kat/mldsa-eth/vectors.json test/fixtures/kat/keccak-prg/vectors.json`; run `npm run kat:regen`; assert both files produced with correct schema + vector counts (100 ML-DSA, 4 Layer-1 PRG + ≥3 Layer-2 PRG).
    2. Run `npm run kat:regen` a second time with no other changes; `git diff test/fixtures/kat/` must be empty (AC-1-2).
    3. Manually corrupt the committed `submoduleSha` in one of the vectors.json files; run a one-off `node -e "require('./test/fixtures/kat/index.ts')"` (via tsx) and assert it throws `KatFixtureError` with `code: "KAT_SUBMODULE_SHA_MISMATCH"` (AC-1-8); restore.
    4. Run `npm run compile` and assert zero warnings + artifact presence for `ZKNOX_keccak_prng.sol` and `ZKNOX_ethdilithium.sol` (AC-1-9).
    5. `git diff package.json package-lock.json` — confirm no additions to `dependencies` (AC-1-10; `devDependencies.tsx` is acceptable).

## Definition of Done (Gate 5 criteria — Story 1)

1. `npm run kat:regen` exits 0 and emits both JSON fixture files with correct schema (DD-7 eight-field per-vector + DD-11 two-layer) and the expected vector counts (exactly 100 ML-DSA, exactly 4 Layer-1 PRG, ≥3 Layer-2 PRG). [AC-1-1]
2. Second immediate run of `npm run kat:regen` produces zero `git diff` under `test/fixtures/kat/`. [AC-1-2]
3. For ≥3 sampled `.rsp` vectors, manual spot-check: `reshapedPublicKey` is a well-formed ABI-encoded `(bytes, bytes, bytes)` triple (per **A-001** amendment: `tr` is variable-length 64 B via Keccak-PRG stream, not `bytes32`; matches Solidity `_readPubKey` at `ZKNOX_ethdilithium.sol:183`). Expected lengths: `aHatEncoded` = 16384 B (4×4×256 coefficients × 4 B BE-packed), `tr` = 64 B, `t1Encoded` = 4096 B (4×256 × 4 B). Full byte-identity vs the `.rsp` is downstream (Story 5 G3) — at this gate, confirm encoding shape. [AC-1-3]
4. Simulated pin drift (e.g., `git -C ETHDILITHIUM checkout HEAD~1` temporarily) causes the CLI to exit non-zero with `code "SUBMODULE_PIN_MISMATCH"` and both SHAs named in stderr; restored after verification. [AC-1-4]
5. Simulated submodule-uninit (`mv ETHDILITHIUM /tmp/x`) causes exit with `code "SUBMODULE_UNINIT"` and the `git submodule update --init --recursive` substring in stderr; restored. [AC-1-5]
6. Simulated Python version mismatch (e.g., spoof via `PATH` or equivalent) exits with `code "PYTHON_VERSION_MISMATCH"` naming required + detected. [AC-1-6]
7. Simulated missing pip deps (remove one pycryptodome import via `pip uninstall` OR mock via env — implementer discretion, keep non-destructive) exits with `code "PYTHON_DEPS_MISSING"` and the `pip install -r ETHDILITHIUM/pythonref/requirements.txt` substring. [AC-1-7]
8. With fixtures present and committed SHA matching HEAD, `await import('./test/fixtures/kat/index.ts')` (via tsx) succeeds. With the committed SHA manually corrupted, the same import throws `KatFixtureError` with `code: "KAT_SUBMODULE_SHA_MISMATCH"` naming both SHAs and the regen command. [AC-1-8]
9. `npm run compile` succeeds with zero warnings; `artifacts/contracts/imports/DilithiumRef.sol/ZKNOX_ethdilithium.json` exists (Ref-wrapper emits the concrete artifact); `ZKNOX_keccak_prng.sol` is verified as compiled via `grep -l ZKNOX_keccak_prng artifacts/build-info/*.output.json` returning a match (solc emits no standalone artifact for the free-functions-only file by design). [AC-1-9]
10. `git diff package.json package-lock.json` shows no additions to `dependencies`. [AC-1-10]
11. Commit tagged `pre-mldsa-eth-1` before first commit and `post-mldsa-eth-1` after Gate 5 passes (per `.claude/rules/code-standards.md` §"Tagging Protocol").

## Out of Scope

Explicitly NOT part of Story 1 (downstream stories own these):
- **JS Keccak-PRG port** (`test/signers/keccak-prg.ts`) — Story 2.
- **G0 / G0-prime KAT test files** (`test/signers/keccak-prg.kat.test.ts`, `keccak-prg.solidity.test.ts`) — Story 2.
- **`test/signers/ml-dsa-eth.ts` + `ml-dsa-eth.kat-internal.ts`** — Story 3 (keygen) and Story 4 (signer).
- **`XofFactory` / `XofReader` refactor of `mldsa-encoding.ts`** — Story 3.
- **`MlDsaEthAccount.sol`** + G4 integration — Story 5.
- **Benchmark-harness 4-scheme extension + `SCHEMES` const extraction** — Story 5.
- **`@delta-from-ml-dsa` module-header JSDoc** — Story 3 (lands with `ml-dsa-eth.ts`).
- **A-001 rename `publicKey` → `publicKeyPointer`** — Story 5's first task (not blocked by Story 1).
- **README "Supported schemes" section + ZKNox attribution** — Story 5 (AC-U-5/AC-5-10).
- **Any `.rsp`-vector-vs-JS byte-identity assertion** — these are G1/G2/G3 gates owned by Stories 3, 4, 5. Story 1 produces the substrate; it does not run comparisons against any JS implementation (no JS implementation exists yet).

## must_haves

truths:
  - "Running `npx tsx scripts/generate-kat-fixtures.ts` with pinned submodule HEAD produces `test/fixtures/kat/mldsa-eth/vectors.json` with exactly 100 vectors and `test/fixtures/kat/keccak-prg/vectors.json` with 4 zhenfei-canonical + ≥3 python-ref-extended vectors, both with top-level `submoduleSha` matching current HEAD."
  - "Running the CLI twice on unchanged submodule state produces byte-identical files — `git diff test/fixtures/kat/` is empty."
  - "CLI exits non-zero with structured error code `SUBMODULE_PIN_MISMATCH` (stderr contains both expected and actual 40-hex SHAs) when submodule HEAD != pinned SHA."
  - "CLI exits non-zero with code `SUBMODULE_UNINIT` and stderr containing `git submodule update --init --recursive` when ETHDILITHIUM is uninitialized."
  - "CLI exits non-zero with code `PYTHON_VERSION_MISMATCH` naming required + detected versions when `python3 --version` fails the required range check."
  - "CLI exits non-zero with code `PYTHON_DEPS_MISSING` and stderr containing `pip install -r ETHDILITHIUM/pythonref/requirements.txt` when `python3 -c 'import dilithium_py.*'` raises ImportError."
  - "Importing `test/fixtures/kat/index.ts` (via tsx) when committed `submoduleSha` differs from current submodule HEAD throws `KatFixtureError` with `code === 'KAT_SUBMODULE_SHA_MISMATCH'` at import time (not lazily inside loader calls), and the error message names both SHAs plus the regen command."
  - "`npx hardhat compile` completes with zero warnings under Solidity 0.8.34. `ZKNOX_ethdilithium` is emitted as an artifact under `artifacts/contracts/imports/DilithiumRef.sol/` (via the Ref-wrapper pattern). `ZKNOX_keccak_prng.sol` is compiled transitively through the verifier's import chain (present in `artifacts/build-info/*.output.json`); solc emits no standalone artifact because the file declares only free functions and a struct (no contract/interface/library) by design."
  - "`package.json` diff for Story 1 shows no additions to the `dependencies` block; `devDependencies` may optionally gain `tsx`."
  - "`reshapedPublicKey` for each ML-DSA vector is produced by invoking `Dilithium2.pk_for_eth(pk, _xof=Keccak256PRNG, _xof2=Keccak256PRNG)` from the submodule's Python module and ABI-encoding the resulting `(A_hat, tr, t1)` into `bytes` per DD-7."

artifacts:
  - path: "scripts/generate-kat-fixtures.ts"
    contains: ["Keccak256PRNG", "pk_for_eth", "AES256_CTR_DRBG", "SUBMODULE_PIN_MISMATCH", "SUBMODULE_UNINIT", "PYTHON_VERSION_MISMATCH", "PYTHON_DEPS_MISSING"]
  - path: "test/fixtures/kat/index.ts"
    contains: ["KatFixtureError", "KAT_SUBMODULE_SHA_MISMATCH", "loadKatVectors", "loadPrgVectors", "assertSubmoduleShaMatches"]
  - path: "test/fixtures/kat/mldsa-eth/vectors.json"
  - path: "test/fixtures/kat/keccak-prg/vectors.json"
  - path: "hardhat.config.ts"
    contains: ["ETHDILITHIUM"]
  - path: "package.json"
    contains: ["kat:regen"]

key_links:
  - pattern: "import .* from \"../fixtures/kat\""
    in: ["test/fixtures/kat/index.ts"]
  - pattern: "KAT_SUBMODULE_SHA_MISMATCH"
    in: ["test/fixtures/kat/index.ts", "scripts/generate-kat-fixtures.ts"]
  - pattern: "pk_for_eth"
    in: ["scripts/generate-kat-fixtures.ts"]
  - pattern: "Keccak256PRNG"
    in: ["scripts/generate-kat-fixtures.ts"]
  - pattern: "AES256_CTR_DRBG"
    in: ["scripts/generate-kat-fixtures.ts"]
  - pattern: "ETHDILITHIUM/src"
    in: ["hardhat.config.ts"]

## Detected Patterns

Codebase scan of analogous modules (to keep Story 1 consistent with established conventions):

| Pattern | Value | Sampled from | Established? |
|---------|-------|-------------|-------------|
| TypeScript module style | ESM (`.js` extension in relative imports, `import ... from "./foo.js"`) | `test/signers/index.ts`, `test/signers/userOpHash.ts`, `test/signers/ecdsa.ts` | ✅ Established (tsconfig `module: NodeNext`; `package.json` `"type": "module"`) |
| Error-class convention | Class extending `Error` with `readonly code = "CODE" as const` discriminant; exported from module; tests assert on `code` not message | `test/signers/errors.ts` (`NotImplementedError`) | ✅ Established (matches architecture §"JS signer taxonomy" §"Error classes") |
| Top-of-file JSDoc | Block comment describing purpose + cross-references; no `@author` header | `test/signers/userOpHash.ts`, `test/signers/index.ts` | ✅ Established |
| Hex encoding at fixture boundary | viem `bytesToHex` / `hexToBytes` with `0x`-prefixed lowercase hex | `test/signers/ecdsa.ts` (uses viem's `Hex` type) | ✅ Established |
| `scripts/*.ts` invocation | Top-level async IIFE OR `if (import.meta.main)` guard; `node scripts/foo.ts` (not `ts-node`); package.json has `"report": "node scripts/generate-report.ts"` — but Story 1 AC explicitly says `npx tsx scripts/generate-kat-fixtures.ts`. ⚠ Mild inconsistency: existing `generate-report.ts` is invoked via plain `node` while this story uses `tsx`. Defer to AC wording — AC-1-1 literally names `npx tsx`. | `scripts/generate-report.ts`, `scripts/check-compile-warnings.cjs` | ⚠ Conflicting (node vs tsx) — story binds to tsx per AC-1-1 |
| Per-scheme test fixture layout | `test/fixtures/<scheme>.ts` as TypeScript module, not JSON | `test/fixtures/entryPoint.ts`, `test/fixtures/falcon.ts`, `test/fixtures/mldsa.ts` | ⚠ Partial conflict — Story 1 introduces JSON fixtures under a new `test/fixtures/kat/` subtree per DD-7 LOCKED. The TS `.ts` pattern remains the convention for hand-authored fixtures; JSON is justified for KAT corpora (DD-7 — machine-generated, diffable, SHA-embedded). Both conventions coexist. |
| Solidity account contract shape | `contract XxxAccount is SimpleAccount { error SignatureMalformed(); ... }` with NatSpec per-function | `contracts/MlDsaAccount.sol`, `contracts/FalconAccount.sol` | ✅ Established (not consumed by Story 1 — listed for downstream reference) |

Resolution of ⚠ conflicts: AC-1-1 binding text is the contract — use `npx tsx` for CLI invocation. JSON vs TS fixture: use JSON per DD-7 LOCKED.

## Wave Structure

Single-wave story (Wave 1 per `docs/plan.md`). Intra-story task dependencies are strictly serial: Task 1 → Task 2 → Task 3 → Task 4 → Task 5. No parallel sub-waves. Rationale: Task 2 consumes Task 1's pin-read helper; Task 3 consumes Task 2's types; Task 4 extends Task 3's CLI; Task 5 verifies the whole. No task pair operates on disjoint files without a dependency, so serial execution is correct.
