---
story_id: "2"
title: "Keccak-PRG port + G0 KAT + G0-prime"
size: "M"
status: "ready-for-dev"
wave: 2
feature: mldsa-eth
created: 2026-04-18
---

# Story 2: Keccak-PRG port + G0 KAT + G0-prime

> Ref: `docs/plan.md` §"Story 2: Keccak-PRG port + G0 KAT + G0-prime [M]" — authoritative AC text, interface contracts, wave assignment.
> Ref: `docs/architecture.md` §"Component Decomposition" row "Keccak-256 PRG", §"Library Public API Surface" §"`test/signers/keccak-prg.ts`", §"Testing Strategy" rows "PRG unit" + "G0 — Keccak-PRG KAT" + "G0-prime — Solidity PRG cross-check", §"Design Rationale" DD-11, §"Error Handling Strategy" §"JS signer taxonomy" (PRG_* codes).
> Ref: `docs/stories/1-fixture-gen-cli.md` — upstream story that produced the KAT loader + fixtures; its `Detected Patterns` table and `Dev Notes` apply here unchanged.

## User Story

As a signer engineer, I want a byte-compatible JS port of ZKNox's Keccak-PRG primitive validated against both the canonical C/Solidity vectors and the Python reference, so that downstream crypto ports have a byte-identity-verified primitive to build on.

## Acceptance Criteria

> All ACs copied verbatim from `docs/plan.md` §"Story 2". Never paraphrase.

- **AC-2-1** (G0 Layer 1 canonical — NFR-9): Given a `createKeccakPrg()` instance and the 4 Zhenfei-canonical PRG fixtures, when each fixture's scripted `inject`/`flip`/`extract` sequence runs, then every output matches the committed hex-literal expected bytes byte-for-byte.
- **AC-2-2** (G0 Layer 2 cross-extract): Given `inject(seed); flip()` on one instance, when `extract(5)` then `extract(27)` is called, then the concatenated output equals `extract(32)` from a fresh identically-seeded instance.
- **AC-2-3** (G0 Layer 2 absorb concatenation): Given `inject(a); inject(b); flip(); extract(64)` vs `inject(concat(a,b)); flip(); extract(64)`, then outputs are byte-identical.
- **AC-2-4** (Lifecycle — inject after flip): Given a `KeccakPrg` with `flip()` called, when `inject(data)` is called, then `PrgLifecycleError` with `code: "PRG_INJECT_AFTER_FLIP"` is thrown.
- **AC-2-5** (Lifecycle — extract before flip): Given a `KeccakPrg` with no prior `flip()`, when `extract(32)` is called, then `PrgLifecycleError` with `code: "PRG_EXTRACT_BEFORE_FLIP"` is thrown.
- **AC-2-6** (G0-prime Solidity cross-check — required): Given `ZKNOX_keccak_prng.sol` deployed on Hardhat, when each Layer-2 fixture's scripted operations are driven through the Solidity API (`initPrng` + `refill` + `prng.pool`), then Solidity outputs match JS `extract()` outputs byte-for-byte.

**FR Coverage:** FR-8 (PRG subset). **NFR Coverage:** NFR-9 (direct).

## Verified Interfaces

### Consumed by this story (VERIFIED against source at story-creation time)

- **`loadPrgVectors(): PrgVector[]`** — loader for PRG KAT fixtures
  - Source: `test/fixtures/kat/index.ts:300`
  - File hash (sha256): `ca8c32db82d0d082efc53cfa92526d94f7f4d2a0e9c0d4376c7e63b4e406d4f0`
  - Signature (verbatim): `export function loadPrgVectors(): PrgVector[]`
  - Import shape: `import { loadPrgVectors } from "../fixtures/kat/index.js";`
  - Side effect: the module's top-level `assertSubmoduleShaMatches()` call (line 391) runs at import time — any Story 2 test that imports this module eagerly validates submodule pin. No further action required from this story.
  - Plan match: ✓ matches `docs/plan.md` §"Interface Contracts" §"KAT loaders".

- **`PrgVector`** — per-vector fixture type
  - Source: `test/fixtures/kat/index.ts:68-80`
  - File hash (sha256): `ca8c32db82d0d082efc53cfa92526d94f7f4d2a0e9c0d4376c7e63b4e406d4f0`
  - Signature (verbatim):
    ```ts
    export interface PrgVector {
      id: string;
      source: "zhenfei-canonical" | "python-ref-extended";
      injects: string[];                           // "0x..." hex
      extracts: number[];                          // bytes-per-extract call
      expected: string[];                          // aligned to extracts[]
      expected_slices?: Array<{ from: number; to: number; value: string }>;
      description?: string;
    }
    ```
  - Plan match: ✓ consistent with `docs/plan.md` §"Interface Contracts" and architecture §DD-11.
  - Fixture content verified: `test/fixtures/kat/keccak-prg/vectors.json` contains 8 vectors at HEAD — 4 `zhenfei-canonical-*` (01, 02, 03, 04-stream) + 4 `python-ref-extended` (`prg-cross-extract`, `prg-multi-inject`, `prg-empty-seed`, `prg-ml-dsa-shaped-seed`). Vector `zhenfei-canonical-01` has `injects: ["0x7465737420696e707574"]` (ASCII `"test input"` = 10 B), `extracts: [32]`, `expected[0] = 0x5b9e99370fa4b753ac6bf0d246b3cec353c84a67839f5632cb2679b4ae565601` — this is the grep-verified probe used in `must_haves.truths` below.

- **`KatFixtureError`** — structured error class, same module
  - Source: `test/fixtures/kat/index.ts:49-61`
  - Signature (verbatim): `export class KatFixtureError extends Error { readonly code: KatFixtureErrorCode; ... }`
  - Story 2 does not throw this; reference only — the `readonly code` pattern is the established project convention that `PrgLifecycleError` must follow (confirmed against `test/signers/errors.ts:10` where `NotImplementedError` uses `readonly code = "NOT_IMPLEMENTED" as const`).

### Produced by this story (NOT YET IMPLEMENTED — signatures from plan contracts + architecture §"Library Public API Surface")

> Marked ⚠ UNVERIFIED — source not yet implemented, using plan contract + architecture §"`test/signers/keccak-prg.ts`".

- **`createKeccakPrg(seed?: Uint8Array): KeccakPrg`** — ⚠ UNVERIFIED
  - Target location: `test/signers/keccak-prg.ts`
  - Plan signature: `function createKeccakPrg(seed?: Uint8Array): KeccakPrg`
  - Architecture note (`docs/architecture.md` §"`test/signers/keccak-prg.ts`"): "Optional ctor seed is equivalent to `prg.inject(seed)`. Not auto-flipped — caller calls `flip()` after any additional `inject()`, mirroring Python." Matches Python ref `Keccak256PRNG.__init__(a=None, b=None)` at `keccak_prng_wrapper.py:23` (sha256 `090abd67de8e120e5c44e927293244b54c7919e3c2e6dcf4cbe5be18dff4097f`) which injects `a` if provided.

- **`KeccakPrg`** — ⚠ UNVERIFIED (interface to be exported)
  - Target location: `test/signers/keccak-prg.ts`
  - Plan signature:
    ```ts
    export interface KeccakPrg {
      inject(data: Uint8Array): void;      // absorb; throws if called after flip
      flip(): void;                         // finalize; throws if called twice
      extract(length: number): Uint8Array;  // stream; throws if called before flip
      update(data: Uint8Array): void;       // alias for inject (noble SHAKE parity)
      read(length: number): Uint8Array;     // alias for extract  (noble SHAKE parity)
    }
    ```
  - The `update` / `read` aliases mirror Python ref `keccak_prng_wrapper.py:124-130` (`update` → `inject`; `read` → `extract`) — they exist so Story 3's XOF-factory adapter can present a SHAKE-like surface without branching per-XOF at call-sites.

- **`PrgLifecycleError`** — ⚠ UNVERIFIED (error class to be exported)
  - Target location: `test/signers/keccak-prg.ts`
  - Plan signature (from architecture §"Error Handling Strategy"):
    ```ts
    export type PrgLifecycleCode =
      | "PRG_INJECT_AFTER_FLIP"
      | "PRG_EXTRACT_BEFORE_FLIP"
      | "PRG_DOUBLE_FLIP"
      | "PRG_BUFFER_OVERFLOW";
    export class PrgLifecycleError extends Error {
      readonly code: PrgLifecycleCode;
      // constructor follows established pattern in test/signers/errors.ts
    }
    ```
  - Pattern source: `test/signers/errors.ts:9-18` (`NotImplementedError extends Error` with `readonly code = "..." as const`). `PrgLifecycleError` follows the same shape but with a `PrgLifecycleCode` union discriminant (runtime-assignable in the constructor, not a literal `as const`), mirroring `KatFixtureError` (`test/signers/index.ts:49-61`).

### External — Solidity API consumed by G0-prime (VERIFIED against submodule HEAD)

- **`ZKNOX_keccak_prng.sol`** — counter-based Solidity PRNG (used only by `keccak-prg.solidity.test.ts`)
  - Source: `ETHDILITHIUM/src/ZKNOX_keccak_prng.sol`
  - File hash (sha256): `992bc13327b896eed264ece19483a16dcd7b47192fcac4abdb12dc9587f9a2c3`
  - Declares only free functions + one struct (no contract/interface/library). Relevant symbols:
    - `struct KeccakPrng { bytes32 state; uint64 counter; bytes32 pool; uint8 remaining; }` (line 9)
    - `function initPrng(bytes memory input) pure returns (KeccakPrng memory prng)` (line 16) — computes `state = keccak256(input)`, then produces the first 32 B block `keccak256(state ‖ counter_be_u64=0)` into `pool`, sets `remaining = 32`, `counter = 1`.
    - `function refill(KeccakPrng memory prng) pure` (line 33) — produces next block `keccak256(state ‖ counter_be_u64)` into `pool`; increments `counter`; resets `remaining = 32`.
    - `function nextByte(KeccakPrng memory prng) pure returns (uint8 b)` (line 54) — pops one byte from `pool` (big-endian MSB-first), auto-refills when `remaining == 0`.
  - Compile note: declares no contract — solc emits no standalone artifact. AC-1-9 (Story 1) confirms the file is compiled transitively via `contracts/imports/DilithiumRef.sol`'s Ref-wrapper; symbols are importable in a Solidity test harness via a thin `contracts/test-harness/KeccakPrngHarness.sol` (TBD in Task 3) that calls the free functions and exposes the struct fields for viem read-back.
  - Plan match: ✓ matches AC-2-6 wording (`initPrng` + `refill` + `prng.pool`).

- **ZKNox's own Forge test (Layer 1 canonical witness — not consumed at runtime)**
  - Source: `ETHDILITHIUM/test/keccak_prng.t.sol:12-27`
  - File hash (sha256): `085ede486f2be7148e8e558d426fd0a123839ddbf723b7471b168e17eba361d8`
  - The 4 Zhenfei-canonical hex literals embedded in our `vectors.json` are copied verbatim from this file (per Story 1 Dev Notes §"DD-11 LOCKED"). Story 2 relies on Story 1's `zhenfei-canonical-*` fixtures as the G0 Layer-1 witness; no direct Forge interaction needed.

## Dev Notes

### Architecture context (inlined — correctness-critical)

**DD-11 LOCKED — Four-implementation oracle chain** (from `docs/architecture.md` §"Design Rationale"). The PRG has four on-disk implementations and Story 2 closes the chain:

| # | Implementation | Role in this story |
|---|----------------|--------------------|
| a | `ETHDILITHIUM/c-ref/keccak_prng.c` (Zhenfei Falcon-Go defining source) | Informational — not consumed |
| b | `ETHDILITHIUM/pythonref/dilithium_py/keccak_prng/keccak_prng_wrapper.py:21` (`Keccak256PRNG`) | Behavioral reference for JS port semantics; Layer-2 fixtures were generated by running this class against scripted sequences at Story-1 fixture-gen time |
| c | `ETHDILITHIUM/src/ZKNOX_keccak_prng.sol` | On-chain Solidity — G0-prime cross-check target |
| d | `ETHDILITHIUM/test/keccak_prng.t.sol` (ZKNox Forge test) | Layer-1 canonical vectors (already witnessed C ≡ Solidity upstream) — embedded as hex literals in Story 1's `vectors.json` |

G0 = JS vs (b, d) via fixtures. G0-prime = JS vs (c) directly on Hardhat. Layer-1 is already cross-verified via ZKNox's own Forge test; G0-prime runs Layer-2 scripts only (per plan §"Story 2 deliverables" and architecture §"Testing Strategy" §"G0-prime" row).

**PRG construction semantics** (ported from `keccak_prng_wrapper.py:21-139` — this is the behavioral contract the JS port must satisfy, enumerated here because the Python ref is not in the shipped tree and the JS implementer cannot assume import-time access):

Three phases, one-way state machine:

1. **Inject phase** (`buffer: bytearray(MAX_BUFFER_SIZE=4096)`, `buffer_len: 0`):
   - `inject(data)` appends `data` to `buffer[buffer_len:buffer_len+len(data)]`; advances `buffer_len`.
   - Throws if `finalized` → `PRG_INJECT_AFTER_FLIP`.
   - Throws if `buffer_len + len(data) > MAX_BUFFER_SIZE=4096` → `PRG_BUFFER_OVERFLOW`.
   - `update(data)` is an alias; it `inject`s — identical lifecycle semantics.

2. **Flip phase** (one-shot; `finalized: bool`):
   - `flip()` computes `state = keccak256(buffer[:buffer_len])` (32 B). Sets `finalized = true`. Resets `out_buffer_pos = 0`, `out_buffer_len = 0`.
   - Throws if already `finalized` → `PRG_DOUBLE_FLIP`.
   - Empty-seed path is valid: `inject` never called → `buffer_len = 0` → `state = keccak256(b"")` = `0xc5d2460186f7233c927e7db2dccc703c0e500b653ca82273b7bfad8045d85a470...` (matches `prg-empty-seed` fixture expected).

3. **Extract phase** (streaming; `counter: u64 = 0`, `out_buffer: bytearray(32)`, `out_buffer_pos: int`, `out_buffer_len: int`):
   - `extract(n)` returns `n` bytes. Throws if not `finalized` → `PRG_EXTRACT_BEFORE_FLIP`.
   - Algorithm (verbatim from Python `extract`):
     1. Drain `out_buffer[out_buffer_pos : out_buffer_len]` first (up to `n` bytes). Advance `out_buffer_pos`. If `n` satisfied, return.
     2. Otherwise loop: build `block = state ‖ struct.pack(">Q", counter)` (40 B: 32 B state + 8 B **big-endian** u64 counter). `out_buffer = keccak256(block)` (32 B). Copy up to `min(remaining_n, 32)` bytes into output. Set `out_buffer_pos = to_copy`, `out_buffer_len = 32`. Increment `counter += 1`. Repeat until `n` satisfied.
   - **Out-buffer-pos persistence is load-bearing:** `extract(5)` followed by `extract(27)` on the same instance reads the first 5 B of block 0, then 27 B from `out_buffer[5:32]` (no new Keccak call, `counter` stays at 1), matching `extract(32)` on a fresh instance (AC-2-2). Implementations that re-hash on each call will fail this.
   - **Big-endian u64 counter is load-bearing:** any little-endian or differently-sized counter produces a different stream. The Python `struct.pack(">Q", counter)` emits 8 B in network byte order. `ZKNOX_keccak_prng.sol:24` confirms the same: `mstore(add(ptr, 32), shl(192, counter))` shifts the `uint64` into the top 8 bytes (MSB first) of a 32 B slot, then `keccak256(ptr, 40)` hashes only those 40 bytes — semantically equivalent to `state ‖ u64_be`.
   - **Counter start = 0** (Python `self.counter = 0` at init, used as-is in the first `extract` call's first Keccak invocation, then incremented). Note the Solidity `initPrng` **pre-computes** block 0 during init (`counter=0` inside `initPrng`, then sets `prng.counter = 1` for the next call) — same net state; the difference is stylistic, not semantic.

**`ctor seed` shorthand.** `createKeccakPrg(seed)` with `seed` defined ≡ `const prg = createKeccakPrg(); prg.inject(seed);`. Caller still must call `flip()` before extract. `createKeccakPrg()` (no arg) ≡ `createKeccakPrg(new Uint8Array(0))` ≡ empty-inject path. Source of truth: Python `__init__` at lines 36-39 (injects `a` if `b is None and a is not None`).

**`PrgLifecycleError` code taxonomy** (from `docs/architecture.md` §"Error Handling Strategy" §"JS signer taxonomy" rows 6-9):

| `code` | Trigger |
|--------|---------|
| `PRG_INJECT_AFTER_FLIP` | `inject` or `update` called after `flip()` returned successfully |
| `PRG_EXTRACT_BEFORE_FLIP` | `extract` or `read` called without a prior successful `flip()` |
| `PRG_DOUBLE_FLIP` | `flip()` called when `finalized === true` |
| `PRG_BUFFER_OVERFLOW` | cumulative inject size would exceed `MAX_BUFFER_SIZE = 4096` |

These codes are the contract — tests assert on `err.code === "PRG_INJECT_AFTER_FLIP"` (not message text). `PrgLifecycleError extends Error` with `readonly code: PrgLifecycleCode` discriminant, matching the `KatFixtureError` shape at `test/fixtures/kat/index.ts:49-61`.

### Amendment A-001 relevance

A-001 (`docs/amendments.md`) amends DD-7's `tr` type in the ML-DSA reshaped public key (bytes32 → variable-length `bytes`). **Not relevant to Story 2.** The PRG primitive does not touch `tr`, `pk_for_eth`, or any ML-DSA-level encoding. `tr` is computed inside `mldsa-encoding.ts` in a future story (Story 5) using the PRG as its XOF.

### Behavioral requirements (inlined from plan + architecture)

- **Keccak-256 primitive via viem.** Use `viem`'s `keccak256` (established project convention — `test/signers/userOpHash.ts:16` and `test/signers/mldsa-encoding.ts:3` both use `import { keccak256 } from "viem"`). No new hash library. `keccak256` accepts `Uint8Array` or `0x`-hex; return type is `0x${string}` in hex mode or `Uint8Array` via the `"bytes"` overload. Project-established usage pattern: call the `"bytes"` overload (`keccak256(input, "bytes")`) to get a `Uint8Array` directly — avoids an extra hex round-trip.
- **Stateful per-instance design (DD-10 + DD-11).** `createKeccakPrg()` returns a fresh stateful object each call. No module-level state (AC-A-1 from spec — grep for `let _prg` / `var _prg` at module scope must return zero hits). Every caller constructs their own instance.
- **No `!` non-null assertions in production.** Ecosystem rule per `.claude/rules/nodejs.md`. Story 2's source counts as production. Test files may use `!`.
- **Test runner + framework.** `node:test` + `node:assert/strict` for unit + KAT tiers (non-Hardhat). Hardhat-in-node:test wrapper (`import hre from "hardhat"`) for G0-prime. Established by `test/accounts/ecdsa.test.ts:13-17` and `test/fixtures/kat/index.test.ts:17-23`; follow that pattern.
- **Solidity test harness for G0-prime.** `ZKNOX_keccak_prng.sol` declares only free functions — viem cannot call free functions directly, so `keccak-prg.solidity.test.ts` must deploy a thin wrapper contract under `contracts/test-harness/KeccakPrngHarness.sol` (TBD — Task 3) that (a) exposes `initPrng(bytes) → returns (bytes32 state, uint64 counter, bytes32 pool, uint8 remaining)`, (b) exposes `refill(KeccakPrng memory) → returns (KeccakPrng memory)`, (c) exposes a convenience `extract(bytes input, uint256 length) → bytes` that loops `nextByte` or composes `initPrng` + N×`refill` reading full `pool` bytes. Option (c) yields a single on-chain call per fixture; it is the recommended shape for AC-2-6. Harness deployment via `viem.deployContract("KeccakPrngHarness")` per the established `test/accounts/ecdsa.test.ts:17` + `test/bench/gas-benchmark.test.ts:337-341` pattern.

### File-tree effects (expected — non-binding)

New files:
- `test/signers/keccak-prg.ts` (primitive; ~80 LOC)
- `test/signers/keccak-prg.test.ts` (PRG unit; ~20 LOC)
- `test/signers/keccak-prg.kat.test.ts` (G0; ~30 LOC)
- `test/signers/keccak-prg.solidity.test.ts` (G0-prime; ~30 LOC)
- `contracts/test-harness/KeccakPrngHarness.sol` (G0-prime thin wrapper; ~20 LOC)

Modified files: none expected. `hardhat.config.ts` already compiles `ETHDILITHIUM/src/ZKNOX_keccak_prng.sol` transitively via the Ref-wrapper (Story 1 AC-1-9). The new harness under `contracts/test-harness/` falls under `paths.sources.solidity` (default `./contracts`) → solc will emit its artifact automatically; no config change needed.

### Library versions (verified at story creation, 2026-04-17; unchanged from Story 1)

- `viem@^2.43.0`, `hardhat@3.3.0`, `typescript@^5.9.3`, Solidity `0.8.34`, Node `v24.13.1`.
- No new runtime or dev dependencies introduced by Story 2 (mirrors Story 1's AC-1-10 discipline, though Story 2 has no formal equivalent AC — operational Gate 5 item).

## Tasks

- [x] **Task 1: Port `keccak-prg.ts` + `PrgLifecycleError` + PRG unit tests**
  - AC: AC-2-4 (primary), AC-2-5 (primary); foundational for AC-2-1/2/3/6 (they all construct instances via `createKeccakPrg`)
  - Files: `test/signers/keccak-prg.ts` (new; ~80 LOC), `test/signers/keccak-prg.test.ts` (new; ~20 LOC)
  - Dependencies: none (first task — consumes only Story 1's already-landed code + viem `keccak256`)
  - Why: Every downstream AC in this story, and every story in the feature (Story 3 XOF-factory adapter, Story 4 signer, Story 5 pk-transform), needs this primitive byte-correct. Task 1 lands the module + exercises the lifecycle guard surface exhaustively in a cheap non-fixture tier. Concretely:
    - `keccak-prg.ts` exports: `createKeccakPrg(seed?: Uint8Array): KeccakPrg`; `interface KeccakPrg { inject; flip; extract; update; read }`; `class PrgLifecycleError extends Error { readonly code: PrgLifecycleCode }`; `type PrgLifecycleCode` union (4 codes above). Implementation is a closure-over-state factory (not a class) matching how the noble-style SHAKE interface is usually surfaced — but a class-based implementation is also acceptable as long as the public surface matches the interface. Internal state: `buffer: Uint8Array(4096)`, `bufferLen: number`, `state: Uint8Array(32)`, `counter: bigint` (JS u64), `outBuffer: Uint8Array(32)`, `outBufferPos: number`, `outBufferLen: number`, `finalized: boolean`. Extract loop builds `block[0..32] = state; block[32..40] = u64_be(counter)` (write 8 B with `DataView.setBigUint64(0, counter, false)`) then `outBuffer = keccak256(block, "bytes")`. Counter is `bigint` to stay well clear of JS Number safe-int limits (though the PRG's practical stream length puts Number at no risk for ML-DSA use; `bigint` keeps the implementation honest and mirrors Python's arbitrary-precision int).
    - `keccak-prg.test.ts` contains lifecycle-guard unit tests (AC-2-4, AC-2-5, plus double-flip for `PRG_DOUBLE_FLIP` and buffer-overflow for `PRG_BUFFER_OVERFLOW` — the taxonomy table above enumerates all four codes; assert all four trigger with the right `code`). Also assert empty-seed path works: `createKeccakPrg(); flip(); extract(32)` returns a `Uint8Array` of length 32 without throwing. Tests assert on `err.code` (discriminant), NOT message strings. Use `node:assert/strict`'s `assert.throws(fn, err => err instanceof PrgLifecycleError && err.code === "PRG_INJECT_AFTER_FLIP")` pattern or equivalent.

- [x] **Task 2: G0 KAT tier — `keccak-prg.kat.test.ts`**
  - AC: AC-2-1 (primary), AC-2-2 (primary), AC-2-3 (primary)
  - Files: `test/signers/keccak-prg.kat.test.ts` (new; ~30 LOC)
  - Dependencies: Task 1 (needs `createKeccakPrg`)
  - Why: G0 is the byte-identity anchor for every downstream crypto port. The test loads `loadPrgVectors()` (8 vectors in the current fixture), iterates each, constructs a fresh `createKeccakPrg()`, replays the scripted operations, and asserts `extract` output against `expected[i]` (or against `expected_slices` where present — vector `zhenfei-canonical-02` uses high-32-B slice, `zhenfei-canonical-04-stream` uses high-16-B slices). Concretely:
    - For each vector: loop `for (const hex of vector.injects) prg.inject(hexToBytes(hex));` → `prg.flip();` → for each `n` in `vector.extracts` call `prg.extract(n)` and accumulate the outputs.
    - Assertion: if `vector.expected_slices` is present, compare the per-slice substrings; else compare `bytesToHex(extract_output_i)` vs `vector.expected[i]` directly (both are lowercase hex with `0x` prefix — viem `bytesToHex` default).
    - AC-2-2 (cross-extract) is verified by the `prg-cross-extract` fixture directly — no additional in-test logic needed.
    - AC-2-3 (absorb concatenation) is verified by the `prg-multi-inject` fixture directly — Python-ref already hashed the concat-then-single-inject case; if the fixture's `expected[0]` matches JS output for the multi-inject path, the byte-identity invariant holds transitively.
    - Note: the absorb-concatenation invariant is also worth a JS-internal self-consistency check (do both paths in one `it()` block: two multi-inject instances, one via `inject(a); inject(b)` and one via `inject(concat(a,b))`, flip both, extract 64 B from each, assert equal). That is zero-cost and catches implementation bugs the fixture alone would miss if both paths shared a bug. Recommended but not AC-mandated.
    - Use `assertBytesEqual` helper if it exists at test-runtime (Story 1 didn't introduce it; likely Story 3 does per architecture §"Shared helpers"). If absent, use `assert.equal(bytesToHex(actual), expected)` with `hex` or `Uint8Array` comparison — the test is temporary-acceptable without the helper.

- [ ] **Task 3: G0-prime Solidity cross-check — `keccak-prg.solidity.test.ts` + `KeccakPrngHarness.sol`**
  - AC: AC-2-6 (primary)
  - Files: `test/signers/keccak-prg.solidity.test.ts` (new; ~30 LOC), `contracts/test-harness/KeccakPrngHarness.sol` (new; ~20 LOC)
  - Dependencies: Task 1 (needs JS `createKeccakPrg` for the equivalence assertion)
  - Why: Closes the JS ≡ Solidity loop directly for the 4 Layer-2 fixtures. Layer-1 is already witnessed by ZKNox's own Forge test (`ETHDILITHIUM/test/keccak_prng.t.sol`) — re-running Layer-1 here adds only redundant coverage. Concretely:
    - `KeccakPrngHarness.sol` wraps the free functions from `ETHDILITHIUM/src/ZKNOX_keccak_prng.sol`. Import: `import {KeccakPrng, initPrng, refill} from "../../ETHDILITHIUM/src/ZKNOX_keccak_prng.sol";`. Expose one entry point sufficient for the assertion surface — simplest is `function extract(bytes calldata input, uint256 outLen) external pure returns (bytes memory)` that calls `initPrng(input)`, then loops `(outLen + 31) / 32` iterations: write `pool` into output, call `refill(prng)`. Caveat: `initPrng` already pre-computes block 0 (`counter=0`) into `pool` and advances `counter` to 1, so iteration 0 consumes `pool` without calling `refill` first; iterations 1..N call `refill` before consuming. For the final partial block, slice down to `outLen % 32` bytes if non-zero.
    - Test flow: `deployContract("KeccakPrngHarness")`; for each `loadPrgVectors()` vector with `source === "python-ref-extended"` (the 4 Layer-2 vectors), concat all `injects[]` into one `bytes` input, compute `totalOutLen = sum(extracts[])`, call `harness.read.extract([input, totalOutLen])` (viem public-client-read path — the function is `external pure`, callable via `read`), compare the Solidity bytes against JS `createKeccakPrg` driving the same `injects[] / flip / extracts[]` sequence and concatenating the extract outputs.
    - Note the **semantic equivalence for absorb concatenation**: Python Layer-2 fixture `prg-multi-inject` performs `inject(a); inject(b); flip()`. Since `flip` hashes the concatenated buffer, `keccak256(a‖b) === keccak256(concat_buffer)`; the Solidity harness with `input = a ‖ b` produces the same `state`. This is the Story's AC-2-3 invariant re-verified at the Solidity boundary.
    - Use `hre.network.connect()` per `test/accounts/ecdsa.test.ts` pattern. This test runs under `hardhat test`, not `node --test`, because it requires EVM state.

## Definition of Done (Gate 5 criteria — Story 2)

Beyond standard Gate 5 (format + lint + build + test + test integrity + security — `.claude/rules/code-standards.md` §2 "Verification Loop"):

1. `npx hardhat test test/signers/keccak-prg.test.ts` — all 5 lifecycle-guard assertions pass (`PRG_INJECT_AFTER_FLIP`, `PRG_EXTRACT_BEFORE_FLIP`, `PRG_DOUBLE_FLIP`, `PRG_BUFFER_OVERFLOW` all throw with correct `code`; empty-seed path returns 32 B without throwing). [AC-2-4, AC-2-5]
2. `npx hardhat test test/signers/keccak-prg.kat.test.ts` — all 8 fixtures from `loadPrgVectors()` pass byte-identity assertion (4 `zhenfei-canonical-*` + 4 `python-ref-extended`). [AC-2-1, AC-2-2, AC-2-3]
3. `npx hardhat test test/signers/keccak-prg.solidity.test.ts` — all 4 Layer-2 fixtures drive through the `KeccakPrngHarness`'s `extract(bytes, uint256)` and match JS `extract()` output byte-for-byte. [AC-2-6]
4. `loadPrgVectors()` runs without throwing — fixture-embedded `submoduleSha` still matches current submodule HEAD at the time of Story 2 Gate 5 (i.e., no submodule bump happened mid-story). If mismatch appears, halt per AC-1-8; do not regenerate fixtures as part of Story 2 (that is Story 1's CLI territory).
5. No changes to `test/fixtures/kat/**/*.json` — Story 1 owns those artifacts; Story 2 only reads. `git diff test/fixtures/kat/` must be empty.
6. No changes to `scripts/generate-kat-fixtures.ts` — Story 1 owns the CLI; Story 2 only consumes fixtures.
7. `npm run compile` succeeds with zero warnings — the new `contracts/test-harness/KeccakPrngHarness.sol` compiles clean under Solidity 0.8.34, and `KeccakPrngHarness.json` artifact is present under `artifacts/contracts/test-harness/KeccakPrngHarness.sol/`.
8. Source grep confirms no module-level PRG state in `test/signers/keccak-prg.ts`: `grep -nE '^(let|var) _?prg' test/signers/keccak-prg.ts` returns zero hits. Every `createKeccakPrg()` call constructs fresh state.
9. Commits tagged: `pre-mldsa-eth-2` before the first commit of this story; `post-mldsa-eth-2` after all ACs verified (per `.claude/rules/code-standards.md` §"Tagging Protocol"). Task-atomic commits per the same rule (one commit per task unless the diff is trivial and clearly a rider).
10. All new `.ts` files pass `eslint` (strict preset established in project) and `prettier`; all new `.sol` files conform to the project's existing NatSpec convention (`.claude/rules/solidity.md`): harness contract has `@title` + `@notice`; `extract` has `@notice` + `@param input` + `@param outLen` + `@return`.

## Out of Scope

Downstream stories own these — Story 2 must not touch them:

- **XOF-factory refactor of `mldsa-encoding.ts`** + `XofFactory` / `XofReader` types — Story 3.
- **Keccak XOF adapter** (the `(seed) => { const p = createKeccakPrg(seed); p.flip(); return { id: "keccak-prg", xof: (n) => p.extract(n) }; }` wrapper) — Story 3.
- **`@noble/post-quantum` fork for keygen** — Story 3.
- **`test/signers/ml-dsa-eth.ts`** + **`test/signers/ml-dsa-eth.kat-internal.ts`** — Stories 3 (keygen) and 4 (signer).
- **G1 / G2 / G3 / G4 KAT tests** — Stories 3 / 4 / 5.
- **`MlDsaEthAccount.sol`** + pk-transform + verifier integration + benchmark extension + rename (A-001) — Story 5.
- **`@delta-from-ml-dsa` module-header JSDoc** — Story 3 (lands with `ml-dsa-eth.ts`).
- **Fixture regeneration** — Story 1's CLI territory. If PRG fixtures need a bump during Story 2 (they should not — the submodule has not moved), escalate to user per `.claude/rules/code-standards.md` §4 Rule 3 amendment process.

## must_haves

truths:
  - "Importing `test/signers/keccak-prg.ts` exports a named function `createKeccakPrg` whose return value has methods `inject`, `flip`, `extract`, `update`, `read` — callable in that order without throwing (empty-seed path) and returning a `Uint8Array` of length 32 from `extract(32)` post-flip."
  - "Given `const prg = createKeccakPrg(); prg.inject(new Uint8Array([0x74,0x65,0x73,0x74,0x20,0x69,0x6e,0x70,0x75,0x74])); prg.flip();` (ASCII 'test input', 10 B), then `bytesToHex(prg.extract(32)) === '0x5b9e99370fa4b753ac6bf0d246b3cec353c84a67839f5632cb2679b4ae565601'` — matches zhenfei-canonical-01 fixture at `test/fixtures/kat/keccak-prg/vectors.json`."
  - "Cross-extract invariant: for a 32-byte seed `s`, `extract(5)` followed by `extract(27)` on a single instance (seeded+flipped) yields the same 32 bytes as a single `extract(32)` on a fresh identically-seeded+flipped instance — AC-2-2."
  - "Absorb-concatenation invariant: `createKeccakPrg(); inject(a); inject(b); flip(); extract(64)` yields the same 64 bytes as `createKeccakPrg(); inject(concat(a,b)); flip(); extract(64)` — AC-2-3."
  - "Calling `inject(data)` on an instance whose `flip()` has returned throws an error `e` where `e instanceof PrgLifecycleError && e.code === 'PRG_INJECT_AFTER_FLIP'` — AC-2-4."
  - "Calling `extract(32)` on an instance whose `flip()` has NOT been called throws an error `e` where `e instanceof PrgLifecycleError && e.code === 'PRG_EXTRACT_BEFORE_FLIP'` — AC-2-5."
  - "Calling `flip()` twice on the same instance throws an error `e` where `e instanceof PrgLifecycleError && e.code === 'PRG_DOUBLE_FLIP'`."
  - "Calling `inject` with data whose cumulative length (since construction) would exceed 4096 bytes throws an error `e` where `e instanceof PrgLifecycleError && e.code === 'PRG_BUFFER_OVERFLOW'`."
  - "For each of the 4 `source: 'python-ref-extended'` PRG fixtures (`prg-cross-extract`, `prg-multi-inject`, `prg-empty-seed`, `prg-ml-dsa-shaped-seed`), driving the scripted `injects[] / flip / extracts[]` sequence through the `KeccakPrngHarness` Solidity contract (deployed via Hardhat) produces bytes byte-identical to JS `createKeccakPrg` driving the same sequence — AC-2-6."
  - "For each of the 4 `source: 'zhenfei-canonical'` PRG fixtures, JS `createKeccakPrg` driving the scripted sequence matches `vector.expected[i]` (or its `expected_slices[*].value` when present) byte-for-byte — AC-2-1."

artifacts:
  - path: "test/signers/keccak-prg.ts"
    contains: ["createKeccakPrg", "KeccakPrg", "PrgLifecycleError", "PrgLifecycleCode", "PRG_INJECT_AFTER_FLIP", "PRG_EXTRACT_BEFORE_FLIP", "PRG_DOUBLE_FLIP", "PRG_BUFFER_OVERFLOW", "keccak256"]
  - path: "test/signers/keccak-prg.test.ts"
    contains: ["PrgLifecycleError", "PRG_INJECT_AFTER_FLIP", "PRG_EXTRACT_BEFORE_FLIP", "PRG_DOUBLE_FLIP", "PRG_BUFFER_OVERFLOW", "createKeccakPrg"]
  - path: "test/signers/keccak-prg.kat.test.ts"
    contains: ["loadPrgVectors", "createKeccakPrg", "zhenfei-canonical", "python-ref-extended"]
  - path: "test/signers/keccak-prg.solidity.test.ts"
    contains: ["KeccakPrngHarness", "createKeccakPrg", "hre.network.connect", "python-ref-extended", "deployContract"]
  - path: "contracts/test-harness/KeccakPrngHarness.sol"
    contains: ["ZKNOX_keccak_prng", "initPrng", "refill", "KeccakPrng"]

key_links:
  - pattern: "createKeccakPrg"
    in: ["test/signers/keccak-prg.ts", "test/signers/keccak-prg.test.ts", "test/signers/keccak-prg.kat.test.ts", "test/signers/keccak-prg.solidity.test.ts"]
  - pattern: "PrgLifecycleError"
    in: ["test/signers/keccak-prg.ts", "test/signers/keccak-prg.test.ts"]
  - pattern: "loadPrgVectors"
    in: ["test/signers/keccak-prg.kat.test.ts", "test/signers/keccak-prg.solidity.test.ts"]
  - pattern: "import .* from \"./keccak-prg.js\""
    in: ["test/signers/keccak-prg.test.ts", "test/signers/keccak-prg.kat.test.ts", "test/signers/keccak-prg.solidity.test.ts"]
  - pattern: "keccak256"
    in: ["test/signers/keccak-prg.ts"]

## Detected Patterns

Codebase scan of analogous modules (consistent with Story 1's table; additions specific to Story 2's new surface):

| Pattern | Value | Sampled from | Established? |
|---------|-------|-------------|-------------|
| TypeScript module style | ESM (`.js` extension in relative imports, `import ... from "./foo.js"`) | `test/signers/index.ts`, `test/signers/userOpHash.ts`, `test/signers/mldsa-encoding.ts` | ✅ Established |
| Error-class convention | `class FooError extends Error { readonly code: FooCode; ... }` with `readonly code` discriminant; tests assert on `code` | `test/signers/errors.ts:9` (`NotImplementedError`), `test/fixtures/kat/index.ts:49-61` (`KatFixtureError`) | ✅ Established — `PrgLifecycleError` follows this exactly |
| Keccak-256 usage | viem `keccak256` (two overloads: default returns `0x` hex; `keccak256(bytes, "bytes")` returns `Uint8Array`) | `test/signers/userOpHash.ts:16`, `test/signers/mldsa-encoding.ts:3` | ✅ Established — use the `"bytes"` overload inside the extract loop to avoid hex round-trip |
| Hex I/O at test boundary | viem `hexToBytes` / `bytesToHex` with `0x`-lowercase | `test/signers/falcon-encoding.test.ts:16`, `test/accounts/ecdsa.test.ts:21-24` | ✅ Established |
| Test runner for pure-JS tiers | `node:test` + `node:assert/strict`; `describe` + `it` | `test/fixtures/kat/index.test.ts:17-23`, `test/signers/falcon-encoding.test.ts:12-13` | ✅ Established |
| Hardhat integration-test import | `import hre from "hardhat"; const { viem } = await hre.network.connect();` + `viem.deployContract("Name", [args])` | `test/accounts/ecdsa.test.ts:17`, `test/bench/gas-benchmark.test.ts:337-341` | ✅ Established |
| Top-of-file JSDoc | Block comment describing purpose + AC cross-references; no `@author` | `test/signers/userOpHash.ts`, `test/fixtures/kat/index.ts:1-31`, `test/accounts/ecdsa.test.ts:1-11` | ✅ Established — Story 2 `.ts` files should include a leading JSDoc naming the AC they cover |
| Solidity NatSpec on test harness | `@notice` on every external function; `@param` for each argument; `@return` when returning | `contracts/MlDsaAccount.sol`, `contracts/FalconAccount.sol` + `.claude/rules/solidity.md` | ✅ Established — apply to `KeccakPrngHarness.sol` despite being test-only |
| Solidity import from ETHDILITHIUM submodule | Relative path `"../../ETHDILITHIUM/src/ZKNOX_*.sol"` — no remapping needed for this file since it has no third-party imports | `contracts/imports/DilithiumRef.sol` (Ref-wrapper pattern from Story 1) | ✅ Established |

No ⚠ Conflicting patterns detected for Story 2's surface. All conventions align with Story 1's table and the established project codebase.

## Wave Structure

Single-wave story (Wave 2 per `docs/plan.md`). Intra-story task dependencies:

- **Wave 2a (task parallelization window, optional):** Task 1 — no deps beyond Story 1's landed code.
- **Wave 2b:** Task 2 and Task 3 — both depend on Task 1's `keccak-prg.ts`, independent of each other (different test files, different target surfaces — KAT fixtures vs Solidity harness). Can run in parallel if Agent Teams is enabled and user opts in.

No shared files between Task 2 and Task 3 outputs. No shared runtime state — Task 3 deploys a Solidity contract into a fresh Hardhat EDR; Task 2 is pure-JS. Wave independence verified per `.claude/agents/story-creator-agent.md` Rule 7.
