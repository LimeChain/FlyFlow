---
status: current
scope: whole-project
lastUpdated: 2026-04-22
supersedes:
  - docs/.archive-pqc-4337-20260416-115932/architecture.md
  - docs/.archive-mldsa-eth/architecture.md
  - docs/.archive-falcon-eth/architecture.md
---

# Architecture: pqc-4337-laim

Five ERC-4337 account types share a single EntryPoint, a single JS/TS signer dispatcher, and a single 5-scheme gas benchmark. Each account delegates `_validateSignature` to a different on-chain verifier. The Keccak-based "ETH" variants (ML-DSA-ETH, Falcon-ETH) are optimised for on-chain gas and derive from the same ZKNoxHQ research line; the NIST variants (`falcon`, `mldsa`) are baselines.

This document is a current-state description. Historical decision rationale lives in `docs/.archive-*/architecture.md` and `docs/.archive-*/amendments.md`.

## Goals & Constraints

**Research goal.** Compare the on-chain cost of ECDSA (baseline), NIST Falcon-512, NIST ML-DSA-44, ML-DSA-ETH (Keccak-PRG variant), and Falcon-ETH (Keccak-HashToPoint variant) inside a real ERC-4337 v0.7 `validateUserOp` call path.

**Non-negotiable boundaries.**

- Local Hardhat 3 + EDR only — no testnet or mainnet deployment.
- All PQC accounts inherit eth-infinitism `SimpleAccount` unchanged.
- ZKNoxHQ verifier contracts consumed as read-only git submodules pinned to specific SHAs; zero in-tree modifications (NFR-5).
- Off-chain signing in TypeScript via `@noble/post-quantum` (live fork — owns the full Falcon-ETH crypto surface: Keccak-based HashToPoint primitive + ZKNox wire-format encoders under a `utils-eth` subpath. See §Dependencies).
- On-chain verification via ZKNoxHQ Solidity verifiers — `ZKNOX_falcon`, `ZKNOX_ethfalcon`, `ZKNOX_dilithium`, `ZKNOX_ethdilithium`.
- Python reference lives exclusively inside `ETHDILITHIUM/pythonref/` and `ETHFALCON/pythonref/`, invoked only by the fixture regeneration CLI — never by `npm test`.
- Archived docs under `docs/.archive-*` are frozen audit artefacts; current state lives only in this file + `docs/gas-report.md` + `docs/stories/*` (when a feature is in-flight).

**Terminology.** "Falcon" refers to the Round-3 submission that both `@noble/post-quantum` and ZKNoxHQ implement; NIST FN-DSA (FIPS 206) is not yet final. "ML-DSA-44" is FIPS 204 Level 2 (`k=4, l=4`) — the only parameter set the ETHDILITHIUM verifier supports.

## Component Decomposition

### Smart Contracts (`contracts/`)

| Contract                      | File                                  | Responsibility                                                                                  | Verifier dependency                |
| ----------------------------- | ------------------------------------- | ----------------------------------------------------------------------------------------------- | ---------------------------------- |
| `EcdsaAccount`                | `contracts/EcdsaAccount.sol`          | Baseline — inherits `SimpleAccount` with **no override**; uses `ecrecover` via the parent path. | None (EVM native)                  |
| `FalconAccount`               | `contracts/FalconAccount.sol`         | NIST Falcon-512 account.                                                                        | `ZKNOX_falcon`                     |
| `MlDsaAccount`                | `contracts/MlDsaAccount.sol`          | NIST ML-DSA-44 account.                                                                         | `ZKNOX_dilithium`                  |
| `MlDsaEthAccount`             | `contracts/MlDsaEthAccount.sol`       | Keccak-PRG ML-DSA-44 account (`@custom:experimental`).                                          | `ZKNOX_ethdilithium`               |
| `FalconEthAccount`            | `contracts/FalconEthAccount.sol`      | Keccak-HashToPoint Falcon-512 account (`@custom:experimental`).                                 | `ZKNOX_ethfalcon`                  |
| `FalconRef` (wrappers)        | `contracts/imports/FalconRef.sol`     | Compile-graph shim — forces HH3 to emit artifacts for `ZKNOX_falcon` + `ZKNOX_ethfalcon` + `ZKNOX_HashToPointExposed` (the G2 fixture-gen helper). | ETHFALCON submodule                |
| `DilithiumRef` (wrappers)     | `contracts/imports/DilithiumRef.sol`  | Same pattern for `ZKNOX_dilithium` + `ZKNOX_ethdilithium`.                                      | ETHDILITHIUM submodule             |
| `KeccakPrngHarness` (test)    | `contracts/test-harness/KeccakPrngHarness.sol` | Deployed in tests only — drives `ZKNOX_keccak_prng` through scripted inject/flip/extract sequences for the JS↔Solidity cross-check. | ETHDILITHIUM submodule |

All four PQC accounts expose the same shape: immutable verifier reference, `bytes public publicKeyPointer` (20-byte SSTORE2 pointer, not the raw key), and a `_validateSignature` override that try-catches the verifier and returns either `SIG_VALIDATION_SUCCESS`, `SIG_VALIDATION_FAILED`, or reverts `SignatureMalformed()`. The selector is computed via `bytes4(keccak256("verify(bytes,bytes32,bytes)"))` because every verifier exposes multiple `verify` overloads and `ZKNOX_*.verify.selector` is ambiguous under argument-dependent lookup.

### TypeScript signer layer (`test/signers/`)

**Dispatcher** — `test/signers/index.ts`: `Scheme = "ecdsa" | "falcon" | "mldsa" | "mldsa-eth" | "falcon-eth"` union with exhaustive-never `keygen` / `signUserOp` switches.

**Per-scheme modules** (production surface, `keygen()` + `signUserOp()`):

| Scheme       | Production file                   | KAT-only sibling (explicit seeds)                  | Underlying library                                                    |
| ------------ | --------------------------------- | -------------------------------------------------- | --------------------------------------------------------------------- |
| `ecdsa`      | `test/signers/ecdsa.ts`           | —                                                  | viem                                                                  |
| `falcon`     | `test/signers/falcon.ts`          | —                                                  | `@noble/post-quantum/falcon.js` (upstream shape via fork — see below) |
| `mldsa`      | `test/signers/ml-dsa.ts`          | —                                                  | `@noble/post-quantum/ml-dsa.js#ml_dsa44`                              |
| `mldsa-eth`  | `test/signers/ml-dsa-eth.ts`      | `test/signers/ml-dsa-eth.kat-internal.ts`          | `ml-dsa-eth.core.ts` + `mldsa-encoding.ts` + `keccak-prg.ts`          |
| `falcon-eth` | `test/signers/falcon-eth.ts`      | — (KAT tests call noble primitives directly post-fork-extraction) | Fork-owned: `@noble/post-quantum/falcon.js#falcon512paddedEth` + `@noble/post-quantum/utils-eth.js` (hashToPointEVM, encodeFalconPublicKey, encodeFalconSignature) |

**`*.kat-internal.ts` boundary (ML-DSA-ETH only).** The ML-DSA-ETH KAT helpers (`test/signers/ml-dsa-eth.kat-internal.ts`) accept explicit seeds/readers so fixture tests can replay exact byte sequences; `test/signers/index.ts` and `test/bench/**/*.ts` MUST NOT import them — enforced by a runtime grep test in `ml-dsa-eth.test.ts`. Falcon-ETH's previous `kat-internal` module (`keygenInternal`, `signWithKatBytes`, `BytesReader`) was removed during the fork extraction; its KAT tests now call noble primitives directly, so no boundary enforcement is needed on the Falcon-ETH side.

**Shared primitives.**

- `test/signers/keccak-prg.ts` — stateful Keccak-256 PRG (`inject` → `flip` → `extract`). Byte-compatible with ETHDILITHIUM's `Keccak256PRNG(a=None, b=None)` wrapper. Lifecycle guards throw `PrgLifecycleError` on inject-after-flip, extract-before-flip, double-flip, or buffer-overflow.
- `test/signers/mldsa-encoding.ts` — ML-DSA-44 pk reshape (`preparePublicKeyForDeployment(rawPk, xofForTr, xofForExpandA)`) + `XofReader` / `XofFactory` interface + NIST adapters (`shake256XofFactory`, `shake128XofFactory`) + ETH adapter (`keccakXofFactory`).
- **Falcon-ETH crypto surface — fork-owned.** Consumed from `@noble/post-quantum/falcon.js` (`falcon512paddedEth` — the Keccak-HashToPoint Falcon-512 instance) and `@noble/post-quantum/utils-eth.js` (public: `hashToPointEVM`, `encodeFalconPublicKey`, `encodeFalconSignature`). Private fork internals (Falcon-512 14-bit pk decode, Algorithm-18 Golomb-Rice signature decompress, `compactPoly256`, `packBigEndianWords`, ABI envelope builder) stay non-exported. Repo retains only the thin wrapper `test/signers/falcon-eth.ts` (production `keygen` + `signUserOp` + NFR-11 `preparePublicKeyForDeployment` shape shim).
- `test/signers/userOpHash.ts` — ERC-4337 v0.7 `PackedUserOperation` hash helper; shared across all PQC schemes.
- `test/signers/errors.ts` — `SignerError` base + `SignerInputError` (ML-DSA codes only, post-Falcon-ETH extraction), `PrgLifecycleError`, `SignerInternalError`. Stable `readonly code` discriminants; tests assert on `.code`, never on message strings.

**Deployer registry.** `test/signers/deployers.ts` exports `SCHEME_DEPLOYERS: Record<Scheme, Deployer>`. Each deployer deploys an `ERC1967Proxy` over the scheme's implementation, wires its verifier (where applicable), and registers the public key via the corresponding `test/fixtures/*.ts` module. TypeScript's `Record<Scheme, Deployer>` enforces compile-time exhaustiveness; the bench harness adds `Object.keys(SCHEME_DEPLOYERS).length === SCHEMES.length` as a defense-in-depth runtime guard.

### Test infrastructure (`test/`)

| Directory                    | Contents                                                                                              |
| ---------------------------- | ----------------------------------------------------------------------------------------------------- |
| `test/accounts/*.test.ts`    | One happy-path + one failures file per scheme. Covers `validateUserOp` against EntryPoint, wrong-key + bit-flip + malformed rejection classes, `SignatureMalformed` dual-path walker. |
| `test/bench/gas-benchmark.test.ts` | 5-scheme gas measurement through a real EntryPoint impersonation path; per-scheme try/catch isolation; writes `test/bench/gas-data.json` only when `UPDATE_BENCH=1`. |
| `test/fixtures/*.ts`         | Per-scheme deployment helpers (verifier deploy, key registration via `setKey`). Shared EntryPoint fixture in `entryPoint.ts`. |
| `test/fixtures/kat/`         | JSON KAT vectors for 5 gate suites — see §KAT loader.                                                  |
| `test/signers/*.test.ts` + `*.kat.test.ts` | Signer-level unit tests, KAT byte-identity gates, XOF-isolation tests, naming grep, delta-header structural checks. |
| `test/scripts/`              | Tests for `scripts/generate-kat-fixtures.ts` + `scripts/generate-report.ts`.                           |
| `test/utils/`                | `assertBytesEqual` (divergence context reporter), `fs-walk.ts` (`listTsFiles`), `signature-malformed-walker.ts` (EDR-resistant revert matcher). |

### KAT fixture loader (`test/fixtures/kat/index.ts`)

Single loader module with a multi-submodule SHA-drift guard:

- Fixtures embed a `submoduleSource: "ethdilithium" | "ethfalcon"` discriminator + `submoduleSha` (40-hex).
- At import time + per-call, the loader runs `git submodule status <SUBMODULE>` and `git -C <SUBMODULE> rev-parse HEAD` via `execFileSync` (argv form — no shell) and throws `KAT_SUBMODULE_SHA_MISMATCH` if the fixture's SHA doesn't match the parent-tree gitlink.
- Unknown `submoduleSource` raises `KAT_UNKNOWN_SUBMODULE_SOURCE`; missing required fields raise `KAT_SCHEMA_MISMATCH`.
- `loadKatVectors(scheme)` is a discriminated overload returning per-scheme typed arrays (`MlDsaEthKatVector[]` vs `FalconKatVector[]`) — cross-scheme field access fails at `tsc --noEmit`.
- `loadPrgVectors()` / `loadFalconPrgVectors()` / `loadHashToPointVectors()` are separate loaders, each carrying its own SHA-drift guard.

### Fixture generation (`scripts/generate-kat-fixtures.ts`)

One CLI, five target fixtures. Invoked via `npm run kat:regen`. Spawns a single `python3 -c "..."` subprocess per target to run the pinned submodules' Python references, never runs during `npm test`. Test-override env vars are regex-validated and gated behind an `ALLOW_TEST_OVERRIDES=1` sentinel (see §Security).

| Target                  | Fixture path                                            | Source + method                                                                                             |
| ----------------------- | ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `nist-regression`       | `test/fixtures/kat/nist-regression/vectors.json`        | Pre-refactor capture of NIST ML-DSA-44 `preparePublicKeyForDeployment` outputs over the `.rsp` corpus (AC-D-2 blocking regression). |
| `mldsa-eth`             | `test/fixtures/kat/mldsa-eth/vectors.json`              | ~100 vectors parsed from `ETHDILITHIUM/pythonref/assets/PQCsignKAT_Dilithium2_ETH.rsp`; ζ + rnd derived by TWO separate `random_bytes(32)` calls on `AES256_CTR_DRBG(drbgSeed)` (A-005). |
| `keccak-prg` (mldsa-eth) | `test/fixtures/kat/keccak-prg/vectors.json`             | Layer 1 = 4 canonical vectors from `ETHDILITHIUM/test/keccak_prng.t.sol` (embedded hex); Layer 2 = Python-generated boundary cases.   |
| `falcon-eth`            | `test/fixtures/kat/falcon-eth/vectors.json`             | ~100 vectors transcribed from `ETHFALCON/test/ethfalcon512-KAT.rsp`; 88 B signing randomness derived TS-side via `@noble/ciphers/aes.js#rngAesCtrDrbg256` at test time.                  |
| `falcon-eth` (PRG)      | `test/fixtures/kat/falcon-eth/prg-vectors.json`         | G1 vectors captured from ETHFALCON's `KeccakPRNG()` Python class (0-arg — distinct from the ETHDILITHIUM `Keccak256PRNG(a, b)` wrapper). |
| `falcon-eth` (HashToPoint) | `test/fixtures/kat/falcon-eth/hashtopoint-vectors.json` | G2 vectors captured by deploying `ZKNOX_HashToPointExposed` in Hardhat and calling `.compute(salt, msg)`. Trust anchor = the pinned Solidity source itself; regeneration is forced on any ETHFALCON SHA bump. |

### Report generation (`scripts/generate-report.ts`)

Reads `test/bench/gas-data.json`, computes `overhead = (scheme.totalGas − ecdsa.totalGas) / ecdsa.totalGas`, splits each row into calldata vs execution gas (EIP-2028: 16 gas/non-zero, 4 gas/zero over `userOp.signature` bytes only), and emits `docs/gas-report.md`. Timestamp comes from the snapshot, not `new Date()` — deterministic re-runs produce byte-identical output.

## Smart-Contract Interfaces

### ERC-4337 integration

All accounts deploy behind `ERC1967Proxy` (OpenZeppelin) — direct-instance initialization fails on OZ v5 because `SimpleAccount`'s constructor calls `_disableInitializers()`. The benchmark therefore measures the real production path: DELEGATECALL + SLOAD proxy overhead per call. Canonical deployer shape:

```ts
const impl  = await viem.deployContract("FalconEthAccount", [entryPoint, verifier]);
const data  = encodeFunctionData({ abi, functionName: "initialize", args: [ZERO_ADDRESS, pointerHex] });
const proxy = await viem.deployContract("ERC1967Proxy", [impl.address, data]);
const acct  = await viem.getContractAt("FalconEthAccount", proxy.address);
```

### ZKNoxHQ verifier interface

All four ZKNox verifiers expose the same `ISigVerifier` pair (declared in `ETHFALCON/lib/InterfaceVerifier/src/IVerifier.sol`):

```solidity
function setKey(bytes calldata encodedPk) external returns (bytes memory); // returns abi.encodePacked(address) — 20-byte SSTORE2 pointer
function verify(bytes calldata pk, bytes32 m, bytes calldata signature) external view returns (bytes4);
```

`pk` is always the 20-byte SSTORE2-pointer bytes (not the raw key). `setKey` SSTORE2-writes the full reshaped key and returns the pointer; the account stores the pointer blob verbatim. The verifier extracts the pointer address with `shr(96, calldataload(pk.offset))` and follows it to read the reshaped key.

**Success contract (3-arg overload):** verifiers return their own selector on success. Account compares against `bytes4(keccak256("verify(bytes,bytes32,bytes)"))` (NOT `ZKNOX_*.verify.selector` — ambiguous under ADL since each verifier also exposes a 4-arg `verify(bytes,bytes,...)` overload).

## Data Models

### Public-key storage rule

All PQC accounts store `bytes public publicKeyPointer` — the 20-byte SSTORE2 pointer. The raw NIST-encoded key lives inside the SSTORE2 payload. Consumers pass the pointer bytes back to `verify(pk, ...)` unchanged. `EcdsaAccount` inherits `owner` from SimpleAccount (20-byte address); no pointer.

### Per-scheme payload sizes

| Scheme       | Parameters                    | Raw public key (off-chain) | Reshaped on-chain payload                                   | Signature at verifier boundary                        |
| ------------ | ----------------------------- | -------------------------: | ------------------------------------------------------------ | ------------------------------------------------------ |
| `ecdsa`      | secp256k1                     | 20 B (address)             | —                                                            | 65 B (`r‖s‖v`, EIP-2 low-S enforced)                   |
| `falcon`     | Falcon-512                    | 897 B (header + 896 B `h`) | `abi.encode(uint256[32])`, NTT-compact                       | 1064 B raw concat `salt(40) ‖ s2_compact(1024)`        |
| `falcon-eth` | Falcon-512 (Keccak-HashToPoint) | 897 B                    | `abi.encode(uint256[])`, NTT-compact — on-chain `abi.decode(..., (uint256[]))` | 1064 B raw concat `salt(40) ‖ s2_compact(1024)`   |
| `mldsa`      | ML-DSA-44 (NIST FIPS 204 Level 2) | 1 312 B                | `abi.encode(bytes aHatEncoded, bytes tr, bytes t1Encoded)` — `tr` is 64 B | 2 420 B raw concat `cTilde(32) ‖ z(2304) ‖ h(84)` |
| `mldsa-eth`  | ML-DSA-44 (Keccak-PRG)        | 1 312 B                    | Same `(bytes, bytes, bytes)` tuple; `tr = Keccak-PRG(pk, 64)` rather than `SHAKE-256(pk, 64)` | 2 420 B same layout |

Secret-key sizes (off-chain only): Falcon-512 = 1 281 B; ML-DSA-44 = 2 560 B.

**Falcon-ETH pk-transform note.** The ZKNoxHQ verifier's on-chain `abi.decode(SSTORE2.read(pointer), (uint256[]))` expects a DYNAMIC `uint256[]` ABI layout (1 088 B). The `.rsp`-sourced fixture `reshapedPublicKey` field is a FIXED `uint256[32]` ABI layout (1 024 B) because that is what `ETHFALCON/pythonref/sig_sol.py` emits. The two wrappers hold the same 32 `uint256` coefficients and differ only by the 64-byte dynamic-array `[offset][length]` prefix. The G5 KAT test therefore asserts structural coefficient-equality (decode both sides, compare the `bigint[]`s element-wise), not raw byte-equality.

### `mldsa-eth` DRBG seed consumption

Fixture-gen Python replays `AES256_CTR_DRBG(drbgSeed)` per vector. Consumption order MUST be two SEPARATE `random_bytes(32)` calls, not a slice of `random_bytes(64)` — the DRBG runs `__ctr_drbg_update` at the end of every call (NIST SP 800-90A § 10.2.1.5.1), so slicing a 64-byte draw produces a different second half than two 32-byte draws. `ζ` (keygen) is the first draw; `rnd` (sign) is the second.

### `falcon-eth` DRBG seed consumption

Fixture retains only the 48 B `drbgSeed` NIST field. At test time, TS code reconstructs all downstream randomness:

```ts
const drbg = rngAesCtrDrbg256(hexToBytes(v.drbgSeed));  // @noble/ciphers/aes.js
// Keygen:
const innerSeed = drbg.randomBytes(48);                  // byte-identical to Python inner_seed
// Signer (advance past keygen draw, then yield 88 B total directly into noble):
drbg.randomBytes(48);
const nobleSig = falcon512paddedEth.sign(msg, sk, {
  random: (n) => drbg.randomBytes(n ?? 0),               // 40 B salt, then 48 B FFSampler seed
});
const rawSig = encodeFalconSignature(nobleSig);          // 666 B → 1064 B salt‖s2_compact
```

No fixture schema additions needed — noble's `rngAesCtrDrbg256` is byte-identical to ETHFALCON's Python `AES256_CTR_DRBG` (empirically verified; same NIST SP 800-90A algorithm).

### `Scheme` union + `SCHEMES` const

```ts
export type Scheme = "ecdsa" | "falcon" | "mldsa" | "mldsa-eth" | "falcon-eth";
export const SCHEMES = ["ecdsa", "falcon", "mldsa", "mldsa-eth", "falcon-eth"] as const satisfies readonly Scheme[];
```

Dispatcher switches are exhaustive-never; `SCHEME_DEPLOYERS: Record<Scheme, Deployer>` is exhaustive at compile time. Any 6th scheme is a one-entry edit in three places (`Scheme` union, `SCHEMES` array, `SCHEME_DEPLOYERS` registry) plus one new signer module.

## Key Workflows

### WF-1 — Sign & verify user-op (happy path, all 5 schemes)

1. `keygen(scheme)` returns `{ publicKey, secretKey }`.
2. Test fixture calls the scheme's `registerPublicKey` helper, which runs the reshape (NTT-compact for Falcon schemes; `preparePublicKeyForDeployment` for ML-DSA schemes) and calls `verifier.setKey(encoded)`, returning the 20-byte pointer bytes.
3. Account is deployed via `ERC1967Proxy` with `initialize(ZERO_ADDRESS, pointerBytes)` — for ECDSA the arg is the owner address and there's no verifier.
4. `signUserOp(scheme, sk, userOp, entryPoint, chainId)` computes `userOpHash` (shared helper), sources fresh entropy from `globalThis.crypto.getRandomValues`, signs via the scheme's production path, returns a `PackedUserOperation`.
5. Test drives the user-op through EntryPoint impersonation (`testClient.impersonateAccount(entryPoint)`) → `account.validateUserOp(op, hash, prefund)` → `_validateSignature` → verifier call → `SIG_VALIDATION_SUCCESS` (0).

### WF-2 — Reject invalid signature (3 failure classes per PQC account)

- **Cryptographic reject** (wrong key, bit-flip over valid-length blob): verifier returns `0xFFFFFFFF` → account returns `SIG_VALIDATION_FAILED` (uint256 1). EntryPoint does not execute; no revert.
- **Malformed** (truncated, over-length, unparseable): verifier reverts internally → account `catch`es → `revert SignatureMalformed()`.
- **Wrong-key** (valid sig under a different key): cryptographic reject path.

The dual-path walker in `test/utils/signature-malformed-walker.ts` binds to `accountAddress.toLowerCase()` on BOTH the canonical `ContractFunctionRevertedError.errorName === "SignatureMalformed"` path AND the HH3 EDR message-regex fallback path. Without the address bind, a test-setup routing bug pointed at a different contract would spuriously pass.

### WF-3 — 5-scheme gas benchmark (`test/bench/gas-benchmark.test.ts`)

Iterates `SCHEMES` (guarded against drift via `SCHEMES.length === Object.keys(SCHEME_DEPLOYERS).length`). For each scheme:
1. `SCHEME_DEPLOYERS[scheme](ctx)` deploys verifier + account proxy, registers the key.
2. 2 warm-up user-ops at nonces 0, 1 (stabilises EIP-3529 refund-cap interactions).
3. 3 measured user-ops; per-run gas captured via EntryPoint impersonation.
4. Result recorded as `{ scheme, status, runs[], mean, variance, totalGas, calldataGas, executionGas }` — **each scheme wrapped in try/catch**, so a single scheme failure does not abort the bench (AC-A-3 isolation).
5. Snapshot written to `test/bench/gas-data.json` only if `UPDATE_BENCH=1` is set.
6. Calldata-vs-execution split asserted per scheme; inter-scheme ordering asserted as `ecdsa < falcon-eth < falcon == (same 1064 B layout)` and `mldsa-eth < mldsa == (same 2420 B layout)`; within-pair gas bound is 5% for the ML-DSA pair, 25% for the Falcon pair (NTT-compact vs Algorithm-17-compress byte-distribution differences).
7. Variance tolerance: ECDSA `< 0.01`, PQC schemes `< 0.10` (EIP-3529 refund-cap timing; cross-scheme ranking + calldata/execution split are unaffected by ±5 % noise).

### WF-4 — KAT regeneration (dev-only)

```bash
npm run kat:regen
```

Validates test-override env vars (regex + `ALLOW_TEST_OVERRIDES=1` sentinel), probes both submodule SHAs against `.gitmodules` pins, spawns one `python3 -c "..."` per target (ML-DSA KAT, Falcon KAT, Keccak-PRG Layer 2, Falcon PRG vectors), deploys `ZKNOX_HashToPointExposed` in Hardhat to capture G2 HashToPoint vectors, writes the five fixture files with embedded `submoduleSha` + `submoduleSource`. Deterministic (byte-identical output across runs on the same submodule SHAs).

## Oracle Chain (KAT Verification Gates)

Each ETH variant is covered by an ordered byte-identity chain. A red gate localises the bug to one ported component rather than bisecting the full signer state machine.

**ML-DSA-ETH (5 gates, run by `test/signers/ml-dsa-eth.*.kat.test.ts`):**

1. **G0 — Keccak-PRG byte-identity.** Layer 1 canonical + Layer 2 boundary vectors.
2. **G0′ — Solidity cross-check.** `KeccakPrngHarness` deployed in Hardhat; JS ≡ Solidity on Layer 2.
3. **G1 — Keygen.** `keygenInternal(zeta)` over ~100 `.rsp` vectors, byte-identical pk + sk.
4. **G2 — Signer.** `signWithRnd(sk, msg, rnd)` over ~100 vectors, byte-identical 2420 B signature.
5. **G3 — pk-transform.** `preparePublicKeyForDeployment(pk, keccakXofFactory, keccakXofFactory)` byte-identical to fixture `reshapedPublicKey`.
6. **G4 — Verifier integration.** Deploy `ZKNOX_ethdilithium` + `MlDsaEthAccount`; submit `(pointer, msg, sig)` via `validateUserOp`; assert success + rejection classes.

**Falcon-ETH (6 gates):**

1. **G1 — Keccak-PRG vs ETHFALCON.** `KeccakPRNG()` (0-arg) byte-identity; upstream of the signer path. (ETHFALCON upstream; the ETHDILITHIUM wrapper — `Keccak256PRNG(a=None, b=None)` — is a downstream fork.)
2. **G2 — HashToPoint.** `hashToPointEVM(salt, msg)` over ≥6 vectors captured from `ZKNOX_HashToPointExposed` (trust anchor = pinned Solidity).
3. **G3 — Keygen.** noble's `falcon512.keygen(innerSeed)` is byte-identical to ETHFALCON's `ntru_gen + encoders` (empirically verified); no TS-side keygen port needed. Innersseed derived from `rngAesCtrDrbg256(drbgSeed).randomBytes(48)`.
4. **G4 — Signer.** `encodeFalconSignature(falcon512paddedEth.sign(msg, sk, { random }))` over ~100 `.rsp` vectors. `random` is driven by `rngAesCtrDrbg256` advanced past the 48 B keygen draw — noble consumes 40 B for the salt + 48 B for the FFSampler seed (88 B total).
5. **G5 — pk-transform.** Structural coefficient-equality (decode both sides, compare `bigint[]`s element-wise). Primary oracle for the `uint256[]` vs `uint256[32]` wrapper divergence.
6. **G6 — Verifier integration.** Deploy `ZKNOX_ethfalcon` + `FalconEthAccount`; identical flow to G4 for ML-DSA-ETH. Gas-cap assertion `verifyGas < 16_777_216` per vector.

## Signer Fork Strategy

### ML-DSA-ETH — `XofFactory` parameterization

`ml-dsa-eth.core.ts` forks noble's `_keygen_internal` / `_sign_internal` to take two `XofFactory` parameters (`_xof`, `_xof2`). NIST callers pass `(shake256XofFactory, shake128XofFactory)`; ETH callers pass `(keccakXofFactory, keccakXofFactory)` — the DD-1 collapse of SHAKE-256/128 onto the single Keccak-PRG primitive. Every call-site constructs a fresh `XofReader` via `xofFactory(seed)`; no module-level mutable state (enforced by an `^(let|var) _?xof` grep in `test/signers/naming.test.ts`).

`preparePublicKeyForDeployment(rawPk, xofTr, xofExpandA)` inside `mldsa-encoding.ts` uses its two factories for `tr = _xof(pk, 64)` and `A_hat = ExpandA(rho, _xof2)` respectively. `tr` is 64 B `bytes` (NOT `bytes32`) — the ZKNox Solidity struct is `PubKey { uint256[][][] aHat; bytes tr; uint256[][] t1; }`.

### Falcon-ETH — fork-owned instance + encoders

The fork at `github.com/LimeChain/noble-post-quantum-eth` (branch `falcon-eth-complete`) OWNS the full Falcon-ETH crypto surface. Previously the fork carried only a minimal HashToPoint-injection seam with the encoders living in this repo; the falcon-eth extraction moved the ETH-specific primitives and wire-format encoders into the fork's `src/utils-eth.ts` under a public `./utils-eth` subpath. The extraction leaves upstream noble's API additively extended — `falcon512paddedEth` appears alongside `falcon512` / `falcon512padded` with the same `Falcon` contract; `genFalcon` and `falcon512paddedOpts` remain fork-internal.

Fork src layout (strict DAG: `utils-eth.ts` is leaf, `falcon.ts` imports from it):

- `src/utils-eth.ts` — public exports: `hashToPointEVM(salt, msg) → Uint16Array`, `encodeFalconPublicKey(rawPk) → Uint8Array` (1088 B ABI-encoded `uint256[]`), `encodeFalconSignature(nobleSig) → Uint8Array` (1064 B raw `salt‖s2_compact`). Private internals: `decodePublicKey14Bit`, `decompressSignature`, `compactPoly256`, `packBigEndianWords`, `encodeUint256ArrayAbi`. Imports only from `@noble/{hashes,curves}` + `./_crystals.ts` — no viem dependency in the fork.
- `src/falcon.ts` — patched to import `hashToPointEVM` from `./utils-eth.ts` and export `falcon512paddedEth = genFalcon({ ...falcon512paddedOpts, hashToPoint: hashToPointEVM })`. Net delta vs upstream is ~25 LOC (the internal `opts.hashToPoint?` seam + the new export with its JSDoc).

Repo-side consumption:

```ts
// test/signers/falcon-eth.ts — thin ERC-4337 glue only
import { falcon512, falcon512paddedEth } from "@noble/post-quantum/falcon.js";
import {
  encodeFalconPublicKey,
  encodeFalconSignature,
} from "@noble/post-quantum/utils-eth.js";
```

`signUserOp` (production) wraps `falcon512paddedEth.sign(msg, sk, { random })` — randomness fetched on-demand via `globalThis.crypto.getRandomValues` — and re-encodes noble's 666 B detached signature (`header(1) ‖ salt(40) ‖ enc_s(625)`) via `encodeFalconSignature` into the 1064 B ZKNox layout. `preparePublicKeyForDeployment(rawPk, _xofFactory)` is an NFR-11 cross-scheme shape shim over `encodeFalconPublicKey` — the second parameter is unused (Falcon-ETH's pk-transform is deterministic over raw bytes) and exists only to keep the 5-scheme grep uniform with `mldsa-encoding.ts`.

KAT tests call noble primitives directly:

- G3 keygen — `falcon512.keygen(innerSeed)` (noble's `abytes` validates seed length; no repo-side wrapper needed).
- G4 signer — inline `encodeFalconSignature(falcon512paddedEth.sign(msg, sk, { random }))` with the DRBG driving `random`.
- G5 pk-transform — `preparePublicKeyForDeployment(rawPk, keccakXofFactory)` (thin repo shim) for the `uint256[]` ABI payload; `decodeAbiParameters(encodeFalconPublicKey(rawPk))` directly for structural-sub-check decode.

**Dependency pin (`package.json`):** during iteration, `"@noble/post-quantum": "file:../noble-post-quantum-eth"` — local symlink to the fork checkout. Edits to `src/*.ts` in the fork require `npm run build` in the fork (or `tsc --watch` in a dedicated terminal) to regenerate the dist the consumer imports. npm does NOT hoist a `file:` pin's transitive deps, so the three fork runtime deps (`@noble/{ciphers,curves,hashes}@~2.2.0`) are also listed explicitly in this repo's `devDependencies` so test files can import them directly. Post-stabilization, the pin will flip back to `git+ssh://…#<sha>` (SHA, not branch) — a future hardening step once the fork goes read-only.

**ml-dsa-eth migration to the fork's `utils-eth.ts` is tracked separately** — the falcon-eth extraction was the test run for Layout B. During the transition `compactPoly256` is duplicated (fork + `test/signers/mldsa-encoding.ts`); the duplication gets consolidated when ml-dsa-eth extracts.

## Error Handling

### JS signer error taxonomy

`test/signers/errors.ts` declares a `SignerError` base with a `readonly code` discriminant and three subclasses:

| Class                | Example codes                                                                                                     |
| -------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `SignerInputError`   | `INVALID_SECRET_KEY_LENGTH`, `INVALID_PUBLIC_KEY_LENGTH`, `INVALID_MESSAGE`, `INVALID_CTX_LENGTH`, `INVALID_RND_LENGTH` (ML-DSA paths only; Falcon-ETH-specific `INVALID_INNER_SEED_LENGTH` + `SIGNING_BYTES_EXHAUSTED` were dropped when the Falcon-ETH surface moved to the fork — noble's `abytes` handles seed validation; Falcon's randomness request size is fixed by construction so no budget guard is needed) |
| `KatFixtureError`    | `KAT_SCHEMA_MISMATCH`, `KAT_SUBMODULE_SHA_MISMATCH`, `KAT_UNKNOWN_SUBMODULE_SOURCE`, `KAT_FIXTURE_MISSING`, `KAT_GIT_PROBE_FAILED` |
| `PrgLifecycleError`  | `PRG_INJECT_AFTER_FLIP`, `PRG_EXTRACT_BEFORE_FLIP`, `PRG_DOUBLE_FLIP`, `PRG_BUFFER_OVERFLOW`                       |
| `FixtureGenError`    | `TEST_OVERRIDE_INVALID_FORMAT`, `TEST_OVERRIDE_SENTINEL_MISSING`                                                  |
| `SignerInternalError`| `INTERNAL_SIGNER_ERROR` — escape hatch for unexpected XOF / NTT / encoding failures                               |

Tests always assert on `.code`, never on message strings. The `code` contract is what downstream stories depend on; message text is free to change.

### Contract-level reverts

- `SignatureMalformed()` — shared custom error across `FalconAccount`, `FalconEthAccount`, `MlDsaAccount`, `MlDsaEthAccount`; selector `0x2c3c2fe1`. Reserved for verifier-internal revert (decode/format failure); cryptographic rejection uses the ERC-4337 `SIG_VALIDATION_FAILED` return, not a revert.
- **Gas-cap-breach UX (Falcon-ETH NFR-5 reminder).** The README contains a runbook entry mapping "OOG during `validateUserOp`" → "check tx_gas_limit_cap = 2^24 = 16 777 216". No structured contract-level error is introduced — production-adjacent operators read the runbook. `test/docs/readme-runbook.test.ts` grep-asserts the entry exists.

### Flaky baseline entries

- Historical C-006 (ECDSA `ECDSAInvalidSignature` under HH3 EDR plaintext-revert handling) was resolved by extending `test/accounts/ecdsa.test.ts` AC-3 to accept the substring match in `err.shortMessage` / `err.details` / `err.message` when `ContractFunctionRevertedError.data.errorName` is `undefined`. Low-S normalization in `test/signers/ecdsa.ts` remains defensively correct but empirically a no-op against current viem (`@noble/curves` enforces `lowS: true` by default).
- Historical C-012 (PQC bench variance exceeding the original `<0.01` target) is accepted — PQC tolerance relaxed to `<0.10` inside the bench harness.

## Security

**Tier: low.** Research tool, local Hardhat only; no PII, no finance, no deployment. All ETH-variant verifiers carry `@custom:experimental` — the Keccak-based schemes are NOT yet audited.

- **Submodule pinning.** `.gitmodules` records URLs; the parent-tree gitlink records SHAs. KAT fixtures embed `submoduleSource` + `submoduleSha`; loader fails loudly on drift. Current pins: `ETHFALCON @ 03ed0d60c67087527de7c4a3c1c469b89611bd68`, `ETHDILITHIUM @ b9ca7f72526ecc696230d3c774a6e2c12c9b37c2`.
- **Hardhat 3 `remappings.txt`** rewrites ETHFALCON's bare imports (`sstore2/`, `InterfaceVerifier/`) to the in-tree submodule paths. HH3's `parseNpmDirectImport` tightened regex rejects the camel-case `InterfaceVerifier/…` — remapping is the documented HH3 escape hatch; NFR-5 (zero submodule modifications) preserved.
- **Fork dependency posture.** During iteration, `@noble/post-quantum` pinned to `file:../noble-post-quantum-eth` (local symlink) on the fork's `falcon-eth-complete` branch. `package-lock.json` records no resolved SHA for a `file:` pin — the trust anchor during iteration is the local checkout itself. Future hardening = flip pin to `git+ssh://…#<sha>` (SHA-pinned, not branch-ref) once the fork goes read-only; that unlocks `package-lock.json` recording the resolved SHA as a drift guard.
- **Dev-oracle isolation (NFR-3).** `npm test` never spawns a Python interpreter. Only `scripts/generate-kat-fixtures.ts` does, and it's gated behind `npm run kat:regen`.
- **Test-override safety (NFR-9).** Every env var that alters fixture-gen behaviour (path redirection, Python version/deps probe, submodule-pin bypass) is (a) regex-validated at ingest, (b) gated behind `ALLOW_TEST_OVERRIDES=1` sentinel. Sentinel is set only by the test harness. Operationalises the universal rule "security-relevant test overrides need runtime gates, not just docs." Python subprocesses use `execFileSync` argv form with regex-validated embedded values — no shell expansion.
- **No secrets in fixtures.** KAT vectors include test secret keys by design; README attribution states this posture.
- **Solc warnings-as-errors gate.** `scripts/check-compile-warnings.cjs` fails the compile on any warning originating from `contracts/`; warnings from submodule paths pass through (historical C-001: `ETHFALCON/src/ZKNOX_falcon_encodings.sol:102` has an unused local `slen` — benign, upstream-sourced, preserved per NFR-5).

## Testing Strategy

**Framework.** Hardhat 3 + `@nomicfoundation/hardhat-toolbox-viem` + `node:test` + `node:assert/strict`. No Chai, no Mocha BDD.

**Tiered structure.**

- **Unit** — `test/signers/*.test.ts` (signer internals, error-class discriminants, XOF isolation grep, `FALCON_DELTA_HEADINGS` / `@delta-from-ml-dsa` structural header checks, `KAT_INTERNAL_MODULES` boundary grep, snake-case `falcon_eth` naming grep).
- **KAT byte-identity** — `*.kat.test.ts` files, one per gate (G0/G0′/G1/G2/G3/G4 for ML-DSA-ETH; G1/G2/G3/G4/G5 for Falcon-ETH; G6 is the verifier-integration gate handled in `test/accounts/`).
- **Account-level** — `test/accounts/<scheme>.test.ts` (happy path, valid + invalid signatures, AC-3 rejection classes) + `test/accounts/<scheme>-failures.test.ts` (malformed + wrong-key + bit-flip paths).
- **Bench + report** — `test/bench/gas-benchmark.test.ts` + `test/scripts/generate-report.test.ts`.

**Shared helpers.**

- `test/utils/assert-bytes.ts` — `assertBytesEqual(actual, expected, label, xofId?)` prints the first-divergent byte with ±8 B context plus the XOF `id` discriminant (if supplied). Used across every KAT file.
- `test/utils/fs-walk.ts` — `listTsFiles(dir)` walks `test/bench/` for grep-gate tests (ensures no bench file imports a `*.kat-internal` surface).
- `test/utils/signature-malformed-walker.ts` — dual-path `SignatureMalformed` error matcher resilient to HH3 EDR plaintext reverts.

**Baselines.** Current full suite size is maintained as `baselineTests.passingTests` in `docs/state.json` during in-flight features. Between features, baselines are reset at Gate 5 closure. Historical flaky-test baselines (C-006 for ECDSA, C-012 for PQC variance) are documented above and guarded by the test predicates themselves, not via skip annotations — `.claude/rules/test-integrity.md` forbids `@Disabled` / `t.Skip` without a tracking reference.

## Dependencies

### npm (`package.json` devDependencies)

| Package                                         | Version pin                                                              | Purpose                                                                    |
| ----------------------------------------------- | ------------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| `@account-abstraction/contracts`                | `^0.7.0`                                                                 | `SimpleAccount`, `IEntryPoint`, `PackedUserOperation`, `Helpers.sol` sentinels |
| `@noble/post-quantum`                           | `file:../noble-post-quantum-eth` (local symlink during iteration; SHA-pinned post-stabilization) | Fork — owns the full Falcon-ETH crypto surface via `./utils-eth` subpath + `falcon512paddedEth` instance; consumed by all PQC signers |
| `@noble/ciphers`                                | `~2.2.0`                                                                 | `rngAesCtrDrbg256`, `chacha20`. Explicit devDep because npm does not hoist transitive deps from `file:` pins |
| `@noble/curves`                                 | `~2.2.0`                                                                 | secp256k1 for ECDSA + `abstract/modular.js#invert` for Falcon NTT bootstrap. Explicit devDep (same reason) |
| `@noble/hashes`                                 | `~2.2.0`                                                                 | SHAKE-256/128, Keccak-256. Explicit devDep (same reason) |
| `@nomicfoundation/hardhat-toolbox-viem`         | `^5.0.3`                                                                 | Viem-native HH3 test matchers + deploy helpers                             |
| `hardhat`                                       | `^3.3.0`                                                                 | HH3 (ESM-only; config is async)                                            |
| `typescript`                                    | `^5.9.3`                                                                 | `tsc --noEmit` for type gates (exhaustive union, Record exhaustiveness)    |
| `viem`                                          | `^2.43.0`                                                                | Primary on-chain client                                                    |

Transitive: OpenZeppelin (`ERC1967Proxy`). (The `@noble/{hashes,ciphers,curves}` packages are now explicit devDeps above — see the `file:` pin note on `@noble/post-quantum`.)

### Git submodules

- **ETHFALCON** — `https://github.com/ZKNoxHQ/ETHFALCON.git`, pinned at SHA `03ed0d60…`. Provides `ZKNOX_falcon`, `ZKNOX_ethfalcon`, `ZKNOX_HashToPoint.sol`, the `.rsp` KAT corpus, and the Python reference (`KeccakPRNG`, `AES256_CTR_DRBG`, `falcon.py`).
- **ETHDILITHIUM** — `https://github.com/ZKNoxHQ/ETHDILITHIUM.git`, pinned at SHA `b9ca7f72…`. Provides `ZKNOX_dilithium`, `ZKNOX_ethdilithium`, `ZKNOX_keccak_prng.sol`, and the Python reference (`dilithium_py`, `Keccak256PRNG(a, b)` wrapper). Keccak-PRG source-of-truth is ETHFALCON; ETHDILITHIUM ships a copy with a renamed 2-arg constructor.

## Design Rationale (current-state summary)

Only decisions that are still binding in the current codebase are listed; history of alternatives lives in the archived architecture docs.

| ID      | Decision                                                                                                                    | Rationale                                                                                                  |
| ------- | --------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| DD-1    | Hardhat 3.x + TypeScript + viem; no TypeChain (viem codegen); no `hardhat-gas-reporter` (HH3-native gas capture).           | HH2-era toolchain migrated in amendment A-001 of the pqc-4337 feature.                                     |
| DD-2    | Inherit eth-infinitism `SimpleAccount`; deploy via `ERC1967Proxy`; `_disableInitializers()` in the impl constructor.        | Matches production 4337 shape; gas benchmark includes real DELEGATECALL + SLOAD overhead.                  |
| DD-3    | ZKNox verifiers as read-only git submodules pinned to SHAs; bare imports resolved via `remappings.txt`.                     | NFR-5 zero-modification rule; upstream audits preserved.                                                   |
| DD-4    | Parameter sets: Falcon-512, ML-DSA-44 (FIPS 204 Level 2, `k=4, l=4`).                                                       | ETHDILITHIUM hard-codes `k=4, l=4`; Falcon-512 is the only variant both ZKNox and noble implement.         |
| DD-5    | All PQC accounts store `bytes public publicKeyPointer` (20-byte SSTORE2 pointer), never the raw key.                        | `verify`'s `_pubkey` parameter is interpreted as a pointer in all four ZKNox verifiers.                    |
| DD-6    | `EcdsaAccount` carries no `_validateSignature` override — pure `SimpleAccount` subclass.                                    | Baseline measures the exact eth-infinitism bytecode path.                                                  |
| DD-7    | Per-account verifier instance (immutable reference in constructor); never shared across accounts.                           | Simplest model; gas benchmark incorporates a fresh deploy per scheme.                                      |
| DD-8    | Custom error `SignatureMalformed()` for verifier-internal reverts; cryptographic failure uses `SIG_VALIDATION_FAILED`.      | ERC-4337 `validationData` low-20-byte authorizer field cannot encode a third class without breaking spec.  |
| DD-9    | `SCHEMES` const + `Scheme` union + `Record<Scheme, Deployer>` registry for the bench harness.                               | TS exhaustiveness checks + runtime length-match guard catch scheme-drift at compile AND run time.          |
| DD-10   | XOF injection for ML-DSA-ETH via `XofFactory` parameter at every call-site; no module-level mutable state.                  | Interleaved SHAKE / Keccak in the same process must not cross-contaminate. Enforced by `^(let\|var) _?xof` grep. |
| DD-11   | Fixture `reshapedPublicKey` sourced from Python ref; TS emits a structurally-equivalent but ABI-different wrapper for Falcon-ETH. | Fixture format matches Python's on-chain call shape (`uint256[32]`); TS emits the dynamic form the Solidity reader expects (`uint256[]`). G5 oracle uses structural coefficient-equality. |
| DD-12   | Falcon-ETH crypto surface lives in the fork's `utils-eth.ts` (Layout B — fork-owned HashToPoint + encoders + finished `falcon512paddedEth` instance). Repo retains only ERC-4337 glue + an NFR-11 `preparePublicKeyForDeployment` shape shim. | Supersedes the earlier Strategy-E injection-seam design — the fork is now a first-class Falcon-ETH provider, not a pure upstream mirror. See §"Falcon-ETH — fork-owned instance + encoders" for rationale. |
| DD-13   | Keccak-PRG promoted to first-class ported component with dedicated G0 KAT + G0′ Solidity cross-check.                       | A primitive-level bug at G0 would surface as a non-localised failure across G1–G4 otherwise.               |
| DD-14   | Fixture-gen CLI spawns Python via `execFileSync` argv form; overrides regex-validated + `ALLOW_TEST_OVERRIDES=1`-sentinel-gated. | Operationalises the "test-overrides need runtime gates" universal rule; no shell expansion.            |
| DD-15   | Multi-submodule SHA-drift loader (`submoduleSource` discriminator on every fixture).                                        | Single-submodule loader would silently tautology-match once Falcon fixtures landed.                        |
| DD-16   | Calldata-asymmetry gas bounds: `mldsa-pair` at 5%, `falcon-pair` at 25% (equal length).                                     | NTT-compact vs Algorithm-17-compress byte distributions differ even at equal signature length.             |
| DD-17   | Discriminated `loadKatVectors` overload; `KatVector` renamed to `MlDsaEthKatVector` (no aliased re-export).                 | Union-extend would allow silent `undefined` on cross-scheme field access at runtime.                       |
| DD-18   | Pure-rename refactors touching >3 files land as their own commit BEFORE any feature-adding commit that depends on the rename. | Bisect-surgical — downstream regression points at exactly one commit.                                     |
