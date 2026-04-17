---
id: "4-1"
slug: mldsa-account
title: "ML-DSA signer + MlDsaAccount + happy-path acceptance"
size: M
wave: 2
status: complete
dependencies: ["1-1"]
unblocks: ["3-1"]
created: 2026-04-15
completed: 2026-04-15
gate5: pass
---

# Story: ML-DSA signer + MlDsaAccount + happy-path acceptance

## User Story
As an engineer, I want an ML-DSA-signing smart account that validates a correctly-signed UserOp on-chain, so that ML-DSA is integrated end-to-end.

## Acceptance Criteria

- AC-1: Given `SigningUtils.keygen('mldsa')`, When called, Then returns Alice's ML-DSA-65 keypair via `@noble/post-quantum/ml-dsa` with a 1,952-byte public key.
- AC-2: Given Alice's ML-DSA keypair, When calling `signUserOp('mldsa', aliceSecretKey, userOp)`, Then returns a `PackedUserOperation` whose `signature` field is a 3,309-byte ML-DSA-65 blob.
- AC-3: Given a deployed `MlDsaAccount` initialized with Alice's 1,952-byte public key and a `ZKNOX_dilithium` verifier reference, When Alice's ML-DSA-signed UserOp is submitted to `validateUserOp`, Then it returns `SIG_VALIDATION_SUCCESS`.
- AC-4: Given `MlDsaAccount._validateSignature`, When inspected, Then it calls `dilithiumVerifier.verify(publicKey, userOpHash, userOp.signature)` wrapped in try/catch.

## Architecture Guardrails

**Amendments are binding — A-001, A-002, A-003 all apply.** HH3 + viem + `node:test`/`node:assert/strict` toolchain (A-001). Account-under-test deployed via `ERC1967Proxy`, never directly (A-002). `bytes public publicKey` stores the **SSTORE2 pointer returned by `dilithiumVerifier.setKey(abiEncodedKey)`, NOT the raw NIST key** (A-003).

### MlDsaAccount shape (LOCKED, mirrors FalconAccount.sol byte-for-byte modulo types)

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.34;

import {SimpleAccount} from "@account-abstraction/contracts/samples/SimpleAccount.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "@account-abstraction/contracts/core/Helpers.sol";
import {ZKNOX_dilithium} from "../ETHDILITHIUM/src/ZKNOX_dilithium.sol";

contract MlDsaAccount is SimpleAccount {
    error SignatureMalformed();

    // Selector workaround: ZKNOX_dilithium exposes TWO verify overloads —
    // `verify(bytes,bytes32,bytes)` (ISigVerifier, returns bytes4) and
    // `verify(bytes,bytes,bytes,bytes)` (with ctx, returns bool). Solidity's
    // `ZKNOX_dilithium.verify.selector` is ambiguous under overload lookup.
    // Hash the explicit signature instead — this mirrors FalconAccount.sol's
    // _VERIFY_SELECTOR pattern (contracts/FalconAccount.sol:30-31).
    bytes4 private constant _VERIFY_SELECTOR =
        bytes4(keccak256("verify(bytes,bytes32,bytes)"));

    ZKNOX_dilithium public immutable dilithiumVerifier;
    bytes public publicKey;

    constructor(IEntryPoint anEntryPoint, ZKNOX_dilithium _verifier)
        SimpleAccount(anEntryPoint)
    {
        dilithiumVerifier = _verifier;
    }

    function initialize(address, bytes calldata _publicKey) public initializer {
        publicKey = _publicKey;
    }

    /// @inheritdoc SimpleAccount
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 validationData) {
        try dilithiumVerifier.verify(publicKey, userOpHash, userOp.signature) returns (bytes4 result) {
            return result == _VERIFY_SELECTOR
                ? SIG_VALIDATION_SUCCESS
                : SIG_VALIDATION_FAILED;
        } catch {
            revert SignatureMalformed();
        }
    }
}
```

**Why `view` mutability on the override:** the inherited `SimpleAccount._validateSignature` is non-view, but `ZKNOX_dilithium.verify(bytes,bytes32,bytes)` is `view`. Solidity allows an override to tighten (non-view → view). FalconAccount.sol:76 does the same; the Story 1-1 compile-warnings-as-errors gate (`scripts/check-compile-warnings.cjs`) did NOT flag it there and will not flag it here.

**Initializer shadowing (identical to FalconAccount):** `SimpleAccount.initialize(address)` has a different selector than our `initialize(address, bytes)` — no override clash. The `address` first arg is intentionally unused (the ML-DSA path identifies the signer via `publicKey`, not SimpleAccount's `owner`). Do NOT forward to `super.initialize(...)`; that creates a misleading dual-identity model.

**`SignatureMalformed` custom error:** standards-compliant way to surface "format/decode failure" without colliding with `validationData`'s aggregator-address interpretation (architecture §Error Handling Strategy). Declared on the contract; Story 4-2 asserts on it.

### Parameter-set deviation — DD-7 [DISCRETION] realization: ML-DSA-44, not ML-DSA-65

**The plan and architecture specify ML-DSA-65 (pk=1952 bytes, sig=3309 bytes). The actual ETHDILITHIUM submodule is hard-wired to ML-DSA-44 parameters (pk=1312, sig=2420).**

Evidence (from source):

- `ETHDILITHIUM/src/ZKNOX_dilithium_utils.sol:44-45` declares `uint256 constant k = 4;` and `uint256 constant l = 4;` — those are ML-DSA-44 (NIST Level 2). ML-DSA-65 would be k=6, l=5.
- `ETHDILITHIUM/src/ZKNOX_dilithium.sol:80` hard-codes `z: slice(signature, 32, 2304)` and `h: slice(signature, 2336, 84)` — total 2420 bytes, the ML-DSA-44 signature size.
- `ETHDILITHIUM/js/execute.js:2,32-33` imports `ml_dsa44` from `@noble/post-quantum/ml-dsa.js` and calls `ml_dsa44.keygen(seed)` — the submodule's own reference JS uses ML-DSA-44.
- `ETHDILITHIUM/js/utils_mldsa.js:71-76` decodes a public key using `K = 4` and `T1_POLY_BYTES = 320` → total `32 + 4*320 = 1312` bytes.

DD-7 (`[DISCRETION]`) in `docs/architecture.md:282` explicitly anticipated this: *"Parameter sets — Falcon-512 and ML-DSA-65 as defaults. Adjustable if submodules target different parameter sets."* ETHDILITHIUM targets ML-DSA-44. Story 4-1 adjusts.

**Amended AC values for this story (all three numeric ACs are re-expressed to match reality):**

| AC  | Plan value (ML-DSA-65) | Amended value (ML-DSA-44) |
|-----|------------------------|---------------------------|
| AC-1: `publicKey.length` | 1,952 bytes | **1,312 bytes** |
| AC-2: `signature` size | 3,309-byte blob | **2,420-byte blob** |
| AC-3: `publicKey` init arg | "1,952-byte public key" | **1,312-byte raw key (pre-SSTORE2-encoding)** |

The byte sizes in the "User Story + AC" section above are the plan-verbatim values. Implementation MUST match the ML-DSA-44 values in this table. Log this as a **Rule 2 deviation** at Gate 5 (`docs/amendments.md`): DD-7 realization amendment — parameter set is ML-DSA-44 because the ZKNoxHQ submodule is compiled for k=4,l=4. If the user wants ML-DSA-65, that's a separate story to either (a) bump ETHDILITHIUM to a multi-parameter fork, or (b) patch `ZKNOX_dilithium_utils.sol` constants (rejected by DD-3 LOCKED / NFR-5).

**Per A-003, account-side byte count is the 20-byte SSTORE2 pointer, not 1,312.** The 1,312-byte value is the size of the raw noble-format key that is the INPUT to the encoding bridge; what gets ABI-encoded, SSTORE2-written by `dilithiumVerifier.setKey(...)`, and stored on the account is the 20-byte pointer (amendment A-003 §Architecture amendment).

### Public key flow — THREE layers (critical; differs from Falcon)

ETHDILITHIUM's verifier reads a structured ABI-encoded tuple from SSTORE2, NOT just a raw NIST key blob. From `ZKNOX_dilithium.sol:91-97`:

```solidity
function _readPubKey(address pointer) internal view returns (PubKey memory) {
    (bytes memory aHatEncoded, bytes memory tr, bytes memory t1Encoded) =
        abi.decode(SSTORE2.read(pointer), (bytes, bytes, bytes));
    uint256[][][] memory aHat = abi.decode(aHatEncoded, (uint256[][][]));
    uint256[][] memory t1 = abi.decode(t1Encoded, (uint256[][]));
    return PubKey({aHat: aHat, tr: tr, t1: t1});
}
```

So the payload passed to `setKey(bytes)` MUST be `abi.encode(bytes aHatEncoded, bytes tr, bytes t1Encoded)` where:

1. `aHatEncoded = abi.encode(uint256[K=4][L=4][32])` — the 4×4 matrix `A_hat` recovered via SHAKE128 rejection sampling from `rho`, each polynomial compacted to 32 uint256 words.
2. `tr` — 64 bytes, computed as `SHAKE256(publicKey, 64)`.
3. `t1Encoded = abi.encode(uint256[K=4][32])` — the K=4 polynomials of `t1` decoded from the 10-bit-packed NIST public key, each compacted to 32 uint256 words.

`ETHDILITHIUM/js/pkDeploy.js:8-43` (`preparePublicKeyForDeployment`) does exactly this encoding using `ethers.AbiCoder`. The port to viem uses `encodeAbiParameters`:

```ts
// Port of preparePublicKeyForDeployment, viem-flavored:
const aHatEncoded = encodeAbiParameters([{ type: "uint256[][][]" }], [A_hat_stringified]);
const t1Encoded = encodeAbiParameters([{ type: "uint256[][]" }], [t1_stringified]);
const publicKeyData = encodeAbiParameters(
  [{ type: "bytes" }, { type: "bytes" }, { type: "bytes" }],
  [aHatEncoded, toHex(tr), t1Encoded],
);
```

The bridge that produces `(A_hat_compact, tr, t1_compact)` from noble's raw 1,312-byte publicKey is implemented by porting `ETHDILITHIUM/js/utils_mldsa.js` (see Interfaces below):

- `decodePublicKey(publicKey)` → `{ rho, t1, tr }`
- `recoverAhat(rho, K=4, L=4)` → `A_hat` (4×4 array of 256-coefficient polynomials sampled from `shake128(rho || j || i)`)
- `compact_module_256(A_hat, 32)` → packs each 256-coefficient polynomial into 32 × 256-bit words (23-bit coefficients fit in `m=32` bits).
- `compact_module_256([t1], 32)[0]` → same compaction for the 4 t1 polynomials (`m=32`; note t1 coefficients are only 10 bits but the compaction quantum is 256/8=32 bits).

**Three layers (mirrors and extends A-003's Falcon model):**

| Layer | Field | Type | Bytes | Source |
|-------|-------|------|-------|--------|
| Off-chain (signer) | `Keypair.publicKey` | `Uint8Array` | 1,312 | noble's `ml_dsa44.keygen().publicKey` — raw NIST-encoded ML-DSA-44 pk (`rho(32) || t1_packed(4*320)`) |
| Off-chain (encoding) | encoded payload passed to `setKey` | `bytes` (ABI-encoded `(bytes,bytes,bytes)` of `(aHat_abi, tr, t1_abi)`) | variable (~20KB ABI-encoded) | `preparePublicKeyForDeployment`-ported helper |
| On-chain (account) | `bytes public publicKey` | `bytes` | 20 | SSTORE2 pointer returned by `dilithiumVerifier.setKey(encodedPayload)`, packed via `abi.encodePacked(pointer)` |

Per A-003, the account stores the 20-byte pointer. The raw 1,312-byte key NEVER appears as `_pubkey` in a `verify` call.

### Signature flow — noble produces the on-chain format directly (differs from Falcon!)

This is the one place where ML-DSA is STRICTLY EASIER than Falcon. `@noble/post-quantum/ml-dsa.js`'s `ml_dsa44.sign(msg, secretKey)` output is `cTilde(32) || z(2304) || h(84)` totalling exactly 2,420 bytes — byte-for-byte what `ZKNOX_dilithium.sol:80` slices out:

```solidity
Signature({
    cTilde: slice(signature, 0, 32),
    z: slice(signature, 32, 2304),
    h: slice(signature, 2336, 84)
});
```

No signature-side encoding bridge is needed. `signUserOp` calls noble, returns the resulting `Uint8Array` as hex — that's the signed UserOp's `signature` field. Contrast with Falcon, which needs NTT + Golomb-Rice decoding (Story 3-1 C-007).

### Hash / context domain — zero context

`ZKNOX_dilithium.sol:77` wraps the 32-byte digest in `mPrime = abi.encodePacked(bytes1(0), bytes1(0), m)` — i.e., domain separator `0x00`, ctx length `0x00`, then the 32-byte userOpHash. This matches noble's `ml_dsa44.sign(msg, secretKey)` default path when called with `msg` as a 32-byte `Uint8Array` and NO `ctx` option — noble internally prepends `0x00 || 0x00 || msg` before its SHAKE256 mu computation. **Cross-check during implementation:** sign a fixed 32-byte digest, then call `dilithiumVerifier.verify(pkPointer, digest, sig)` on a deployed Hardhat instance; expect the `verify.selector` return. If it fails with `0xFFFFFFFF`, the ctx-prefix assumption is wrong and the signer must switch to `ml_dsa44.internal` API to control the `mu` input directly (unlikely — noble and ZKNOX both implement the same FIPS 204 §5.2 pseudocode). Document the verification in a comment in `test/signers/mldsa.ts`.

### Verifier deployment (DD-9 LOCKED)

Tests deploy a fresh `ZKNOX_dilithium` instance per setup: `viem.deployContract("ZKNOX_dilithium")`. NOT a singleton. No constructor args. Same pattern as Story 3-1 used for `ZKNOX_falcon`.

### EntryPoint-direct call path (from Story 2-1, reused)

`account.simulate.validateUserOp([signed, userOpHash, 0n], { account: entryPoint.address })` after `testClient.impersonateAccount` + `setBalance`. `simulate` returns the `uint256` without mining a tx. Do NOT use `entryPoint.write.handleOps` — `handleOps` propagates failure via `FailedOp` reverts. Story 5-1 uses `handleOps` for gas; Story 4-1 is numeric-return validation.

### userOpHash source (canonical)

`entryPoint.read.getUserOpHash([packedOp])` on the live EntryPoint. Story 2-1 established this convention; Story 3-1 Task 3 extracted `computeUserOpHash` to keep ECDSA/Falcon/ML-DSA signers hashing the same preimage; the test uses the on-chain getter for the actual `validateUserOp` call to remove drift risk.

### Compile graph

`contracts/imports/DilithiumRef.sol:16-17` already imports `ETHDILITHIUM/src/ZKNOX_dilithium.sol` and `ZKNOX_ethdilithium.sol` — `ZKNOX_dilithium` is already in the compile graph. No `hardhat.config.ts` change expected. `MlDsaAccount.sol` imports via `"../ETHDILITHIUM/src/ZKNOX_dilithium.sol"` (relative submodule path), mirroring what `FalconAccount.sol:8` does for Falcon.

### Failure-class deferred

Happy-path only (AC-3 = success). Wrong-key, bit-flipped, and malformed-format rejections are Story 4-2 (`test/accounts/mldsa-failures.test.ts` or similar, matching Story 3-2's split).

### Unblocks Story 3-1

Per C-007 (`docs/concerns.md:196-266`), Story 3-1 is paused awaiting a JS encoding-bridge template. The `ETHDILITHIUM/js/` reference + this story's viem-ported encoding helper become the template Story 3-1 uses to port Falcon's NTT+Golomb-Rice bridge to TS. Nothing to do in THIS story for 3-1; just ship the pattern cleanly.

> Ref: docs/architecture.md#Smart Contract Interfaces — MlDsaAccount shape (mirror of FalconAccount)
> Ref: docs/architecture.md#Data Models — public key storage (reinterpreted per A-003)
> Ref: docs/architecture.md#Error Handling Strategy — SignatureMalformed rationale
> Ref: docs/architecture.md#Design Rationale — DD-7 [DISCRETION] adjust parameter sets to submodule defaults
> Ref: docs/amendments.md#A-001 — HH3 + viem + node:test (BINDING)
> Ref: docs/amendments.md#A-002 — ERC1967Proxy account deployment (BINDING)
> Ref: docs/amendments.md#A-003 — PQC accounts store SSTORE2 pointer (BINDING)
> Ref: docs/concerns.md#C-007 — Story 3-1 pause; this story unblocks it
> Ref: docs/stories/3-1-falcon-account.md — FalconAccount.sol committed (6cdfc22); userOpHash helper committed (43b331b); shape to mirror
> Ref: docs/stories/2-1-ecdsa-account.md — proxy + impersonate + simulate test pattern
> Ref: ETHDILITHIUM/js/utils_mldsa.js — reference JS for decodePublicKey / recoverAhat / compact_module_256
> Ref: ETHDILITHIUM/js/pkDeploy.js — reference for preparePublicKeyForDeployment ABI encoding
> Ref: ETHDILITHIUM/js/execute.js — full end-to-end flow (noble keygen → decodePublicKey → recoverAhat → compact → preparePublicKey → deployPublicKey)

## Verified Interfaces

### `ZKNOX_dilithium.setKey(bytes)` (upstream — ETHDILITHIUM submodule)
- **Source:** `ETHDILITHIUM/src/ZKNOX_dilithium.sol:23`
- **File hash:** `d6f4ad3c1b67ee51a6538d9037700e315b710d7a3ec8ed89113614d929ddd1ab`
- **Signature:** `function setKey(bytes memory pubkey) external returns (bytes memory)` — calls `SSTORE2.write(pubkey)`, returns `abi.encodePacked(pointer)` (20 bytes).
- **Behavior caveat:** `pubkey` is NOT the raw 1,312-byte noble key. It must be `abi.encode(bytes aHatEncoded, bytes tr, bytes t1Encoded)` per `_readPubKey`'s decode at line 91-97. The encoding bridge (Task 3) produces this.
- **Plan match:** ✓ Matches architecture §Data Models §DD-8 alternatives (SSTORE2 path) and A-003.

### `ZKNOX_dilithium.verify(bytes,bytes32,bytes)` (3-arg ISigVerifier overload)
- **Source:** `ETHDILITHIUM/src/ZKNOX_dilithium.sol:69`
- **File hash:** `d6f4ad3c1b67ee51a6538d9037700e315b710d7a3ec8ed89113614d929ddd1ab`
- **Signature:** `function verify(bytes calldata pk, bytes32 m, bytes calldata signature) external view returns (bytes4)`
- **Behavior:** Reads `pk` as SSTORE2 pointer (first 20 bytes via `shr(96, calldataload(pk.offset))`), decodes stored tuple via `_readPubKey`, builds `mPrime = 0x00 || 0x00 || m` (domain sep + zero-length ctx + digest), slices signature as `(cTilde[0..32], z[32..2336], h[2336..2420])`, runs `verifyInternal`. Returns `ISigVerifier.verify.selector` on success, `0xFFFFFFFF` on cryptographic failure. **REVERTS** on malformed signature (slice out-of-bounds if `signature.length < 2420`) — triggers MlDsaAccount's `SignatureMalformed` catch.
- **Plan match:** ✓ Matches architecture §ZKNoxHQ Verifier Interface.

### `ZKNOX_dilithium.verify(bytes,bytes,bytes,bytes)` (4-arg with-ctx overload — NOT used by MlDsaAccount)
- **Source:** `ETHDILITHIUM/src/ZKNOX_dilithium.sol:38`
- **Signature:** `function verify(bytes memory pk, bytes memory m, bytes memory signature, bytes memory ctx) external view returns (bool)` — returns `bool`, takes `bytes` message (not `bytes32`), takes explicit `ctx`.
- **Selector ambiguity:** The existence of this second `verify` is why `ZKNOX_dilithium.verify.selector` in Solidity is unresolvable by argument-dependent lookup. `MlDsaAccount.sol` must use the keccak-explicit `_VERIFY_SELECTOR` pattern (mirror of `FalconAccount.sol:30-31`). **Do NOT call this 4-arg overload from the account** — it returns `bool`, not `bytes4`, and would require a different integration contract.

### `IEntryPoint` / `PackedUserOperation` / `SimpleAccount` / `SIG_VALIDATION_*` (consumed via @account-abstraction)
- **Source:** `node_modules/@account-abstraction/contracts/samples/SimpleAccount.sol` (constructor `:42`, `initialize`/`_validateSignature` `:90,:105`), `node_modules/@account-abstraction/contracts/interfaces/PackedUserOperation.sol`, `node_modules/@account-abstraction/contracts/core/Helpers.sol`
- **File hashes:**
  - `PackedUserOperation.sol`: `40fcd99da0814312f0353417de64f70805f4cd7ec4cb4573c8b4c4d48540f562`
  - `Helpers.sol`: `4ec549dbe1685def37cbe8699eb5376ce4466dcd0c6ffffd7c0d7e0f7a5b89a3`
- **Signatures:** `uint256 constant SIG_VALIDATION_FAILED = 1;` / `uint256 constant SIG_VALIDATION_SUCCESS = 0;`; SimpleAccount constructor `constructor(IEntryPoint anEntryPoint)`; `_validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash) internal override virtual returns (uint256)`.
- **Plan match:** ✓ Same surface Story 2-1 and Story 3-1 integrated against.

### `ml_dsa44` (upstream — `@noble/post-quantum@^0.6.1`)
- **Source:** `node_modules/@noble/post-quantum/ml-dsa.d.ts:49`
- **File hash:** `e8da43348d681ab4c6abd39821f36a402678aa4e41cf47a564c3a5b2e482cb76`
- **Signature:** `export declare const ml_dsa44: TRet<DSA>` where `DSA = Signer & { internal: TRet<DSAInternal> }`. `Signer` exposes `keygen(seed?)` → `{ publicKey, secretKey }`, `sign(msg, secretKey, opts?)` → `Uint8Array`, `verify(sig, msg, publicKey, opts?)` → `boolean`. Length invariants from FIPS 204 §4: `publicKey.length === 1312`, `secretKey.length === 2560`, `sign(...).length === 2420` (deterministic sig length).
- **Plan match:** ⚠ PARAMETER DEVIATION — plan specifies `ml-dsa` meaning ML-DSA-65 (k=6,l=5). This story uses `ml_dsa44` (k=4,l=4) to match the ZKNOX_dilithium submodule. See Architecture Guardrails §Parameter-set deviation.
- **Note:** Use the default detached-sig path (`ml_dsa44.sign` + `ml_dsa44.verify`). Do NOT use `hybrid` or attached (`seal`/`open`) variants. Noble also exports `ml_dsa65` and `ml_dsa87` at the same file; they are NOT compatible with this ZKNOX verifier's on-chain constants.

### `recoverAhat`, `decodePublicKey`, `compact_module_256` (reference JS — to be ported to TS)
- **Source:** `ETHDILITHIUM/js/utils_mldsa.js:29,70,95`
- **File hash:** `489c5bc5614efdc8911fca2f447312a353852c82750d8ea2f00d54e46f172cd9`
- **Signatures (as exported from the reference file):**
  - `decodePublicKey(publicKey: Uint8Array): { rho: Uint8Array /* 32 */, t1: Int32Array[] /* K=4 polynomials of 256 coeffs */, tr: Uint8Array /* 64 */ }` — slices `rho` off the first 32 bytes, decodes the remaining `4*320` bytes as four 10-bit-packed polynomials of 256 coeffs each, computes `tr = shake256(publicKey, 64)`.
  - `recoverAhat(rho: Uint8Array, K: number, L: number): Int32Array[][]` — samples the K×L matrix of polynomials via `RejectionSamplePoly(rho, i, j)` which uses `shake128` with seed `rho || j || i` and accepts 23-bit candidates `< q = 8380417`.
  - `compact_module_256(data: Int32Array[][], m: number): bigint[][][]` — packs each 256-coefficient polynomial into `256 / (256/m) = m` uint256 words using `m` bits per coefficient. **Caveat:** the function signature is 2-D nested but for `[t1]` you wrap in an extra array and then `[0]`-index (see `execute.js:38-39`). Port MUST preserve this nesting (or un-nest it and document).
- **Port target:** `test/signers/mldsa-encoding.ts` (TypeScript), imports `shake128`/`shake256` from `@noble/hashes/sha3.js` (noble-hashes is a transitive dep of `@noble/post-quantum`; if missing from `package.json`, install `@noble/hashes@^2.0.0` as a devDependency — flag Rule 1 deviation).
- **Plan match:** ✓ No plan equivalent — this is the scheme-specific bridge, greenfield.

### `preparePublicKeyForDeployment` (reference JS — to be ported to TS)
- **Source:** `ETHDILITHIUM/js/pkDeploy.js:8`
- **File hash:** `657675f4d4d1ebf0fd35d21c1c25a3757e21edd141deb69da61fcc84bc68b623`
- **Signature:** `preparePublicKeyForDeployment(A_hat_compact: bigint[][][], trHex: string, t1_compact: bigint[][]): string (hex, 0x-prefixed)`
- **Behavior:** Validates `trHex.length === 64 bytes` (64 bytes = 128 hex chars), stringifies BigInts (ethers doesn't handle BigInt serialization directly), ABI-encodes each of `A_hat_stringified` as `uint256[][][]` and `t1_stringified` as `uint256[][]`, then wraps the three components `(aHatEncoded, trBytes, t1Encoded)` in an outer `abi.encode(bytes,bytes,bytes)`.
- **Port target:** `test/signers/mldsa-encoding.ts` — use viem's `encodeAbiParameters` instead of `ethers.AbiCoder`. BigInt stringification is NOT needed with viem's native BigInt support.

### `computeUserOpHash` (shared helper — Story 3-1 Task 3, committed)
- **Source:** `test/signers/userOpHash.ts:20`
- **File hash:** `b1903d7438791be3ef810a37ecd336d9f9f9c1d2f2baf612b598355d36a21501`
- **Signature:** `export function computeUserOpHash(userOp: UnsignedUserOp, entryPointAddress: string, chainId: bigint): `0x${string}``
- **Plan match:** ✓ Story 4-1's `mldsa.ts` imports this directly — do NOT duplicate the hashing logic. Story 3-1 already extracted it (commit `43b331b`).

### `keygen` / `signUserOp` dispatcher
- **Source:** `test/signers/index.ts:45,56`
- **File hash:** `5f571b4ecbe7d6a709d45df187320a5641c94aa5e2695be649170f6fc1189238`
- **Signature:** `keygen(scheme: Scheme): Keypair`, `signUserOp(scheme, secretKey, userOp, entryPointAddress, chainId): Promise<PackedUserOperation>`. Already routes `scheme === "mldsa"` to `mldsa.keygen()` / `mldsa.signUserOp()`. No edit to `index.ts` required.

### `mldsa.ts` signer module (STUB to be replaced)
- **Source:** `test/signers/ml-dsa.ts`
- **Current file hash:** `1fbbd213ca3c2627a2683557a66419c480ceb12f13001581c01aec73591b9495`
- **Current:** both `keygen()` and `signUserOp(...)` throw `new NotImplementedError("mldsa")`.
- **New target:** `keygen()` returns `{ publicKey: Uint8Array /* 1312 */, secretKey: Uint8Array /* 2560 */ }` from `ml_dsa44.keygen()`. `signUserOp(secretKey, userOp, entryPointAddress, chainId)` computes `userOpHash = computeUserOpHash(userOp, entryPointAddress, chainId)`, calls `ml_dsa44.sign(hexToBytes(userOpHash), secretKey)`, returns `{ ...userOp, signature: bytesToHex(sigBytes) }` (2,420-byte signature).

### `deployEntryPoint()` (consumed)
- **Source:** `test/fixtures/entryPoint.ts:27`
- **File hash:** `95104f6690c0d34496cebe738a0bec1b7f23315c540fab9e6458a0136684e2fd`
- **Signature:** `async function deployEntryPoint(): Promise<{ entryPoint, publicClient, walletClients }>`. Story 1-1 artifact, reused.

### `FalconAccount.sol` reference shape
- **Source:** `contracts/FalconAccount.sol`
- **File hash:** `c9008de9281faa0362c9e15cd1ffec45983566f0604f3f33f44d436d3829f725`
- **Use:** Read for the SPDX / pragma / NatSpec / `_VERIFY_SELECTOR` workaround / try-catch override shape. `MlDsaAccount.sol` is a structural mirror — replace every `falcon` with `dilithium`, every `ZKNOX_falcon` with `ZKNOX_dilithium`, and the SSTORE2-pointer comment block with ML-DSA-specific wording.

### `test/accounts/ecdsa.test.ts` reference structure
- **Source:** `test/accounts/ecdsa.test.ts`
- **File hash:** `cf9a31d6655025e57fef7060f79c66afcef48a72b31197f21c2de0ac1c24ee3b`
- **Use:** Mirror `setup()` (deploy EntryPoint → deploy implementation → encodeFunctionData(initialize) → deploy ERC1967Proxy → getContractAt → impersonate EntryPoint → setBalance → return chainId), `buildUnsignedUserOp`, `canonicalUserOpHash`, `simulateValidateUserOp` helpers exactly. Mirror only AC-1 semantics (happy path returns 0n) — wrong-key (Story 2-1 AC-2) and bit-flip (Story 2-1 AC-3) become Story 4-2.

## Tasks

- [x] **Task 1: `contracts/MlDsaAccount.sol`**
  - Maps to: AC-3, AC-4
  - Files: `contracts/MlDsaAccount.sol` (new)
  - Implement verbatim per the Architecture Guardrails §MlDsaAccount shape snippet. SPDX `GPL-3.0`; `pragma solidity 0.8.34;`. Include: `error SignatureMalformed();`, `bytes4 private constant _VERIFY_SELECTOR = bytes4(keccak256("verify(bytes,bytes32,bytes)"));`, `ZKNOX_dilithium public immutable dilithiumVerifier;`, `bytes public publicKey;`, two-arg constructor, two-arg `initialize(address, bytes calldata _publicKey) public initializer`, `_validateSignature` view override with try/catch.
  - NatSpec mirror FalconAccount (`@title MlDsaAccount`, `@author pqc-4337-laim`, `@notice ERC-4337 v0.7 account that delegates signature verification to a ZKNoxHQ ETHDILITHIUM verifier (DD-9). Stores the SSTORE2-pointer form of the public key (A-003); the raw 1,312-byte ML-DSA-44 key is supplied off-chain via the signer module, ABI-encoded into the (aHat, tr, t1) tuple the verifier's _readPubKey expects, SSTORE2-written by dilithiumVerifier.setKey before initialization.`). Document the `_VERIFY_SELECTOR` dev-comment identically to FalconAccount.sol:25-29 (adjust contract name). Document `error SignatureMalformed()` identically to FalconAccount.sol:19-22.
  - NO `super.initialize(...)` forwarding (first `address` arg intentionally unused — comment matches FalconAccount.sol:57-62).
  - Compile-warnings gate (Story 1-1 §scripts/check-compile-warnings.cjs): zero project-authored warnings tolerated; the known ETHFALCON `slen` warning (C-001) continues to pass through.

- [x] **Task 2: `test/signers/mldsa-encoding.ts` — encoding bridge (TypeScript port of `ETHDILITHIUM/js/utils_mldsa.js` + `pkDeploy.js`)**
  - Maps to: AC-3 (enabling — without this the encoded public key cannot be set, `verify` cannot decode)
  - Files: `test/signers/mldsa-encoding.ts` (new)
  - Dependencies: `@noble/hashes/sha3.js` for `shake128` + `shake256`. If not already resolvable (it's a transitive dep of `@noble/post-quantum`), add `@noble/hashes@^2.0.0` to `devDependencies` and log Rule 1 deviation. Verify first via `node -e "import('@noble/hashes/sha3.js').then(m => console.log(typeof m.shake128))"`.
  - Exports (minimum surface):
    - `decodePublicKey(publicKey: Uint8Array): { rho: Uint8Array; t1: number[][]; tr: Uint8Array }` — port of `utils_mldsa.js:70-93`. `K=4`, `T1_POLY_BYTES=320`, assert `publicKey.length === 1312`. Inner `polyDecode10Bits(bytes: Uint8Array): number[]` (256-length array of 10-bit coeffs). `tr = shake256(publicKey, { dkLen: 64 })`.
    - `recoverAhat(rho: Uint8Array, K: number, L: number): number[][][]` — port of `utils_mldsa.js:29-39`. Inner `RejectionSamplePoly(rho, i, j, N=256, q=8380417)` uses `shake128.create()` + `.update(seed)` + `.xofInto(buf)` (noble-hashes XOF streaming API — verify the exact method names against the installed `@noble/hashes` version; v2 uses `xofInto`, earlier versions used `.xof(len)`). Each call produces a `number[]` of length 256 with coeffs in `[0, q)`.
    - `compactModule256(data: bigint[][][] | number[][][], m: number): bigint[][][]` — port of `utils_mldsa.js:95-104` (iterates rows; for ML-DSA-44 `m=32`, giving 32 uint256 words per polynomial). Internal `compactPoly256(coeffs, m)` per `utils_mldsa.js:107-133`.
    - `preparePublicKeyForDeployment(rawPublicKey: Uint8Array): \`0x${string}\`` — **high-level composition** that does the full noble-format → ABI-encoded payload transform in one call. Internally: (1) `decodePublicKey(rawPublicKey)` → `{rho, t1, tr}`; (2) `recoverAhat(rho, 4, 4)` → `A_hat`; (3) `compactModule256(A_hat, 32)` → `A_hat_compact`; (4) `compactModule256([t1], 32)[0]` → `t1_compact`; (5) `encodeAbiParameters([{type:"uint256[][][]"}], [A_hat_compact])` → `aHatEncoded`; (6) `encodeAbiParameters([{type:"uint256[][]"}], [t1_compact])` → `t1Encoded`; (7) `encodeAbiParameters([{type:"bytes"},{type:"bytes"},{type:"bytes"}], [aHatEncoded, bytesToHex(tr), t1Encoded])` → return. This is the single function the test setup calls.
  - **Unit-style self-checks (optional but recommended):** assert `rho.length === 32`, `tr.length === 64`, `t1.length === 4`, each `t1[i].length === 256`, `A_hat.length === 4 && A_hat[0].length === 4 && A_hat[0][0].length === 256`, `A_hat_compact[0][0].length === 32`, `t1_compact.length === 4 && t1_compact[0].length === 32`.
  - **BigInt consistency:** viem's `encodeAbiParameters` with `uint256[][][]` expects `bigint[][][]`. Ensure compact output is `bigint`, not `number`. The reference JS uses `BigInt` explicitly inside `compact_poly_256` (line 113-115) — preserve.
  - **Do NOT import `ethers`.** The entire project is viem-native (A-001). The port uses `encodeAbiParameters` and `bytesToHex` from viem.

- [x] **Task 3: `test/signers/mldsa.ts` — replace stub with real signer**
  - Maps to: AC-1, AC-2
  - Files: `test/signers/mldsa.ts` (REPLACE the `NotImplementedError`-throwing stub at `test/signers/ml-dsa.ts` — note: the existing file is `ml-dsa.ts` with a hyphen; keep the existing filename so `index.ts`'s `import * as mldsa from "./ml-dsa.js"` line 12 continues to resolve. Do NOT rename.)
  - Imports: `ml_dsa44` from `@noble/post-quantum/ml-dsa.js`; `bytesToHex`, `hexToBytes` from `viem`; types `{ Keypair, PackedUserOperation, UnsignedUserOp } from "./index.js"`; `computeUserOpHash` from `./userOpHash.js`. Drop the existing `NotImplementedError` import entirely (no longer used).
  - `keygen()`:
    - `const { publicKey, secretKey } = ml_dsa44.keygen();`
    - Assert `publicKey.length === 1312` inline (optional — AC-1 catches it loudly).
    - Return `{ publicKey, secretKey }` — raw noble format. The test setup runs `preparePublicKeyForDeployment` on `publicKey` before calling `setKey`.
  - `signUserOp(secretKey, userOp, entryPointAddress, chainId)`:
    - `const userOpHash = computeUserOpHash(userOp, entryPointAddress, chainId);`
    - `const signature = ml_dsa44.sign(hexToBytes(userOpHash), secretKey);` — produces 2,420 bytes directly in ZKNOX-compatible layout (no encoding bridge needed on the signature side).
    - Return `{ ...userOp, signature: bytesToHex(signature) }`.
  - Note: the existing `test/smoke.test.ts` from Story 1-1 asserts `keygen("mldsa")` throws `NOT_IMPLEMENTED`. Once Task 3 lands that smoke test line will FAIL. Update it in Task 5.

- [x] **Task 4: `test/fixtures/mldsa.ts` — ETHDILITHIUM verifier fixture + key registration helper**
  - Maps to: AC-3 (enabling — setup needs a deployed + key-loaded verifier)
  - Files: `test/fixtures/mldsa.ts` (new)
  - Exports:
    - `async function deployDilithiumVerifier()` → `{ dilithiumVerifier, publicClient, walletClients }` — mirror of `test/fixtures/entryPoint.ts` but `viem.deployContract("ZKNOX_dilithium")`. No constructor args.
    - `async function registerPublicKey(dilithiumVerifier, publicClient, rawPublicKey: Uint8Array): Promise<\`0x${string}\`>` — takes a fresh verifier and noble's 1,312-byte raw key; calls `preparePublicKeyForDeployment(rawPublicKey)` from Task 2; then captures the `setKey` return value by `publicClient.simulateContract({address, abi, functionName: "setKey", args: [encoded], account: <deployer>})` FIRST (returns the 20-byte pointer hex as `result.result`), THEN broadcasts via `dilithiumVerifier.write.setKey([encoded])` to actually persist it on-chain. Returns the captured 20-byte pointer bytes as `0x`-prefixed hex (this is what gets passed to `MlDsaAccount.initialize`'s `_publicKey` arg). **Rationale for the simulate-then-write dance:** viem's `write.*` returns the tx hash, not the solidity return value. The reference `ETHDILITHIUM/js/pkDeploy.js` uses ethers where `contract.deploy(...)` returns the contract instance — viem's model forces the two-step capture. Story 3-1 Task 6 documented the same pattern for Falcon (at `docs/stories/3-1-falcon-account.md` Task 6 setup step 6).
  - Self-check inside `registerPublicKey`: assert the pointer bytes are exactly 20 bytes (`hexToBytes(pointer).length === 20`).

- [x] **Task 5: Update `test/smoke.test.ts` for new ML-DSA behavior**
  - Maps to: AC-1 (cross-check)
  - Files: `test/smoke.test.ts` (modify)
  - The Story 1-1 smoke test asserts `keygen("mldsa")` throws `NOT_IMPLEMENTED`. After Task 3 lands, replace with: `it("mldsa keygen returns a 1312-byte publicKey", () => { const { publicKey } = keygen("mldsa"); assert.equal(publicKey.length, 1312); });`.
  - Leave the `falcon keygen throws NOT_IMPLEMENTED` assertion untouched (Story 3-1 will update it when it resumes).
  - Re-run smoke test; verify the modified assertion passes and no other smoke test regresses.

- [x] **Task 6: `test/accounts/mldsa.test.ts` — happy-path acceptance (AC-1/AC-2/AC-3/AC-4)**
  - Maps to: AC-1, AC-2, AC-3, AC-4
  - Files: `test/accounts/mldsa.test.ts` (new)
  - Framework: `node:test` + `node:assert/strict` (A-001). Mirror `test/accounts/ecdsa.test.ts` structure exactly (describe > it blocks; setup helper; buildUnsignedUserOp; canonicalUserOpHash; simulateValidateUserOp).
  - Imports: `describe`, `it` from `"node:test"`; `assert` from `"node:assert/strict"`; `readFile` from `"node:fs/promises"`; `hre` from `"hardhat"`; `bytesToHex`, `encodeFunctionData`, `hexToBytes`, `parseEther` from `"viem"`; `deployEntryPoint` from `"../fixtures/entryPoint.js"`; `deployDilithiumVerifier`, `registerPublicKey` from `"../fixtures/mldsa.js"`; `keygen`, `signUserOp`, types from `"../signers/index.js"`.
  - `setup()` helper:
    1. `const { entryPoint, publicClient } = await deployEntryPoint();`
    2. `const connection = await hre.network.connect(); const { viem } = connection; const testClient = await viem.getTestClient();`
    3. `const { dilithiumVerifier } = await deployDilithiumVerifier();` (or inline `viem.deployContract("ZKNOX_dilithium")`).
    4. `const alice = keygen("mldsa");` // raw 1,312-byte publicKey.
    5. `const pointerHex = await registerPublicKey(dilithiumVerifier, publicClient, alice.publicKey);` // captures 20-byte SSTORE2 pointer; verifier's state now holds the encoded key.
    6. `const implementation = await viem.deployContract("MlDsaAccount", [entryPoint.address, dilithiumVerifier.address]);`
    7. `const initData = encodeFunctionData({ abi: implementation.abi, functionName: "initialize", args: ["0x0000000000000000000000000000000000000000", pointerHex] });`
    8. `const proxy = await viem.deployContract("ERC1967Proxy", [implementation.address, initData]);`
    9. `const account = await viem.getContractAt("MlDsaAccount", proxy.address);`
    10. `await testClient.impersonateAccount({ address: entryPoint.address }); await testClient.setBalance({ address: entryPoint.address, value: parseEther("1") });`
    11. `const chainId = BigInt(await publicClient.getChainId());`
    12. Return `{ entryPoint, account, alice, dilithiumVerifier, chainId, testClient }`.
  - **AC-1 — keygen produces 1,312-byte publicKey:**
    - Standalone test, no setup needed: `const { publicKey } = keygen("mldsa"); assert.equal(publicKey.length, 1312);`
    - Test label: `"AC-1: keygen returns 1312-byte ML-DSA-44 publicKey"`.
    - **Source-level note:** the plan AC text says 1952 bytes / ML-DSA-65; this test asserts 1312 / ML-DSA-44 per the DD-7 realization. Record the divergence in Gate 5's amendment log.
  - **AC-2 — signature is 2,420 bytes:**
    - Setup, build userOp, sign with Alice: `const signed = await signUserOp("mldsa", alice.secretKey, userOp, entryPoint.address, chainId);`
    - Assert: `hexToBytes(signed.signature).length === 2420`.
    - Test label: `"AC-2: signed UserOp signature is 2420 bytes (ML-DSA-44 sig = cTilde(32) + z(2304) + h(84))"`.
  - **AC-3 — valid signature returns SIG_VALIDATION_SUCCESS:**
    - After sign: `const userOpHash = await entryPoint.read.getUserOpHash([signed]);`
    - `const { result } = await account.simulate.validateUserOp([signed, userOpHash, 0n], { account: entryPoint.address });`
    - `assert.equal(result, 0n);` // SIG_VALIDATION_SUCCESS.
    - Test label: `"AC-3: valid ML-DSA signature returns SIG_VALIDATION_SUCCESS"`.
  - **AC-4 — source inspection (mirror Story 2-1 AC-4 / Story 3-1 Task 6 AC-4):**
    - `const source = await readFile("contracts/MlDsaAccount.sol", "utf8");`
    - `assert.ok(source.includes("dilithiumVerifier.verify(publicKey, userOpHash, userOp.signature)"));` (exact call pattern)
    - `assert.ok(source.includes("try"));` AND `assert.ok(source.includes("catch"));` (try/catch wrapping)
    - `assert.ok(source.includes("SignatureMalformed"));` (custom error declared)
    - Test label: `"AC-4: MlDsaAccount.sol wraps dilithiumVerifier.verify in try/catch with SignatureMalformed"`.
  - **Test timing budget:** `ml_dsa44.sign` is in the 10-50ms range; `ZKNOX_dilithium.verify` is heavy (hundreds of ms on Hardhat's EVM simulator, likely >1M gas). If a single test run exceeds 60s, raise Hardhat's test timeout inline via `it("...", { timeout: 120_000 }, async () => {...})`. Acceptable and documented — NFR-4 allows ≤5min wall-clock for the FULL suite.

- [x] **Task 7: Compile + full test gate**
  - Maps to: AC-1, AC-2, AC-3, AC-4
  - Run `npm run compile` — verify zero non-submodule warnings (only the tolerated ETHFALCON `slen` warning per C-001). `ZKNOX_dilithium.sol` is already in the compile graph via `contracts/imports/DilithiumRef.sol`; no `hardhat.config.ts` edit expected. If `MlDsaAccount.sol` triggers warnings, diagnose before proceeding (likely unused variable from the `address` initialize arg — FalconAccount's commit showed this is clean; mirror exactly).
  - Run `npm test` — verify ALL of: (a) Story 1-1 smoke passes (with the Task 5 modification), (b) Story 2-1 `ecdsa.test.ts` still passes (no regressions — Task 2/3 only add NEW files), (c) Story 4-1 `mldsa.test.ts` passes all 4 AC tests, (d) total wall-clock well under 5min (NFR-4).
  - **Gate 5 amendment trigger:** At Gate 5, log the DD-7 parameter-set realization as an `A-004`-style amendment in `docs/amendments.md`:
    - Title: "ML-DSA parameter set is ML-DSA-44, not ML-DSA-65 (DD-7 realization)"
    - Motivation: ETHDILITHIUM submodule is compiled with `k=4, l=4` constants per `ZKNOX_dilithium_utils.sol:44-45`. DD-7 `[DISCRETION]` anticipated adjustment to submodule defaults.
    - Impact: Plan Story 4-1 AC-1/AC-2/AC-3 byte sizes updated (1952→1312, 3309→2420); Story 4-2 inherits the 1312/2420 pair; Story 5-1's benchmark reports ML-DSA as ML-DSA-44 in the comparison table.
    - Status: `accepted`.
  - **Resume signal for Story 3-1:** once Task 7 Gate 5 PASS, per C-007 (`docs/concerns.md:260-263`), Story 3-1 can resume. Orchestrator should flip `docs/sprint-status.yaml` `stories[3-1].status` from `paused` back to `in-progress` and expose the ML-DSA encoding-bridge module (`test/signers/mldsa-encoding.ts`) as the port template.

## must_haves

truths:
  - "`contracts/MlDsaAccount.sol` exists, declares `contract MlDsaAccount is SimpleAccount`, has `ZKNOX_dilithium public immutable dilithiumVerifier` and `bytes public publicKey` fields, a two-arg `initialize(address, bytes calldata _publicKey) public initializer` that assigns `publicKey = _publicKey` (the 20-byte SSTORE2 pointer per A-003, NOT the raw 1,312-byte key), and a view `_validateSignature` override that calls `dilithiumVerifier.verify(publicKey, userOpHash, userOp.signature)` inside try/catch — success path returns SIG_VALIDATION_SUCCESS/FAILED based on `result == _VERIFY_SELECTOR`, catch path reverts `SignatureMalformed()`"
  - "`contracts/MlDsaAccount.sol` declares `error SignatureMalformed();` and `bytes4 private constant _VERIFY_SELECTOR = bytes4(keccak256(\"verify(bytes,bytes32,bytes)\"));` at contract scope (selector-ambiguity workaround because ZKNOX_dilithium has two verify overloads)"
  - "`test/signers/ml-dsa.ts` (existing file, same path) no longer throws `NotImplementedError` — `keygen()` wraps `ml_dsa44.keygen()` from `@noble/post-quantum/ml-dsa.js`, `signUserOp(...)` computes userOpHash via the shared `computeUserOpHash` helper and signs with `ml_dsa44.sign(userOpHashBytes, secretKey)`"
  - "`keygen(\"mldsa\")` returns a `Keypair` whose `publicKey.length === 1312` (ML-DSA-44 raw NIST publicKey) and `secretKey.length === 2560`"
  - "`signUserOp(\"mldsa\", aliceSecretKey, userOp, entryPointAddress, chainId)` returns a `PackedUserOperation` whose `signature` field, when decoded from hex, is exactly 2420 bytes (cTilde(32) + z(2304) + h(84) per `ZKNOX_dilithium.sol:80` slicing)"
  - "`test/signers/mldsa-encoding.ts` exports `preparePublicKeyForDeployment(rawPublicKey: Uint8Array): \`0x${string}\`` which internally runs `decodePublicKey` → `recoverAhat(rho, 4, 4)` → `compactModule256(..., 32)` → `encodeAbiParameters([{type:\"bytes\"},{type:\"bytes\"},{type:\"bytes\"}], [aHatEncoded, trHex, t1Encoded])` and returns ABI-encoded bytes suitable for `ZKNOX_dilithium.setKey(...)`"
  - "`test/fixtures/mldsa.ts` exports `deployDilithiumVerifier()` and `registerPublicKey(verifier, publicClient, rawPublicKey)` that deploys `ZKNOX_dilithium` and captures the 20-byte SSTORE2 pointer returned by `setKey()` via a simulate-then-write pattern (viem's `write.*` returns tx hash, not the Solidity return value)"
  - "`test/accounts/mldsa.test.ts` deploys MlDsaAccount via `ERC1967Proxy` (per A-002) with the 20-byte SSTORE2 pointer bytes as `_publicKey`, then asserts `account.simulate.validateUserOp([signed, userOpHash, 0n], { account: entryPoint.address }).result === 0n` for an Alice-signed UserOp"
  - "`test/accounts/mldsa.test.ts` includes an AC-4 source-inspection assertion that reads `contracts/MlDsaAccount.sol` and asserts the string `dilithiumVerifier.verify(publicKey, userOpHash, userOp.signature)` is present along with `try`/`catch` and `SignatureMalformed`"
  - "`test/smoke.test.ts` no longer asserts `keygen(\"mldsa\")` throws `NOT_IMPLEMENTED` — replaced with a 1312-byte length assertion. The `falcon keygen throws NOT_IMPLEMENTED` assertion remains untouched (Story 3-1 resume territory)"
  - "`npm run compile` and `npm test` both succeed; only the tolerated ETHFALCON `slen` warning (C-001) appears; no test is disabled, skipped, or quarantined; Story 2-1 ecdsa tests and Story 1-1 smoke test still pass"
  - "A Gate-5 amendment (provisional id A-004) is logged in `docs/amendments.md` recording the DD-7 parameter-set realization (ML-DSA-44, not ML-DSA-65) with reference to `ZKNOX_dilithium_utils.sol:44-45` as source of truth for `k=4, l=4`"

artifacts:
  - path: "contracts/MlDsaAccount.sol"
    contains: ["SimpleAccount", "ZKNOX_dilithium", "dilithiumVerifier", "publicKey", "_validateSignature", "SignatureMalformed", "try", "catch", "SIG_VALIDATION_SUCCESS", "SIG_VALIDATION_FAILED", "_VERIFY_SELECTOR"]
  - path: "test/signers/ml-dsa.ts"
    contains: ["ml_dsa44", "keygen", "signUserOp", "computeUserOpHash"]
  - path: "test/signers/mldsa-encoding.ts"
    contains: ["decodePublicKey", "recoverAhat", "compactModule256", "preparePublicKeyForDeployment", "encodeAbiParameters", "shake128", "shake256"]
  - path: "test/fixtures/mldsa.ts"
    contains: ["deployDilithiumVerifier", "registerPublicKey", "ZKNOX_dilithium", "simulateContract", "setKey"]
  - path: "test/accounts/mldsa.test.ts"
    contains: ["deployEntryPoint", "deployDilithiumVerifier", "registerPublicKey", "MlDsaAccount", "ERC1967Proxy", "validateUserOp", "getUserOpHash", "SIG_VALIDATION", "SignatureMalformed", "impersonateAccount"]
  - path: "test/smoke.test.ts"
    contains: ["mldsa", "1312"]
  - path: "docs/amendments.md"
    contains: ["ML-DSA-44", "DD-7"]

key_links:
  - pattern: "is SimpleAccount"
    in: ["contracts/MlDsaAccount.sol"]
  - pattern: "ZKNOX_dilithium public immutable dilithiumVerifier"
    in: ["contracts/MlDsaAccount.sol"]
  - pattern: "bytes public publicKey"
    in: ["contracts/MlDsaAccount.sol"]
  - pattern: "error SignatureMalformed"
    in: ["contracts/MlDsaAccount.sol"]
  - pattern: "_VERIFY_SELECTOR"
    in: ["contracts/MlDsaAccount.sol"]
  - pattern: "dilithiumVerifier.verify(publicKey, userOpHash, userOp.signature)"
    in: ["contracts/MlDsaAccount.sol"]
  - pattern: "import {ZKNOX_dilithium} from \"../ETHDILITHIUM/src/ZKNOX_dilithium.sol\""
    in: ["contracts/MlDsaAccount.sol"]
  - pattern: "from \"@noble/post-quantum/ml-dsa.js\""
    in: ["test/signers/ml-dsa.ts"]
  - pattern: "ml_dsa44.keygen"
    in: ["test/signers/ml-dsa.ts"]
  - pattern: "ml_dsa44.sign"
    in: ["test/signers/ml-dsa.ts"]
  - pattern: "computeUserOpHash"
    in: ["test/signers/ml-dsa.ts"]
  - pattern: "preparePublicKeyForDeployment"
    in: ["test/signers/mldsa-encoding.ts", "test/fixtures/mldsa.ts"]
  - pattern: "recoverAhat"
    in: ["test/signers/mldsa-encoding.ts"]
  - pattern: "decodePublicKey"
    in: ["test/signers/mldsa-encoding.ts"]
  - pattern: "compactModule256"
    in: ["test/signers/mldsa-encoding.ts"]
  - pattern: "shake128"
    in: ["test/signers/mldsa-encoding.ts"]
  - pattern: "shake256"
    in: ["test/signers/mldsa-encoding.ts"]
  - pattern: "deployContract(\"ZKNOX_dilithium\")"
    in: ["test/fixtures/mldsa.ts"]
  - pattern: "deployContract(\"ERC1967Proxy\""
    in: ["test/accounts/mldsa.test.ts"]
  - pattern: "deployContract(\"MlDsaAccount\""
    in: ["test/accounts/mldsa.test.ts"]
  - pattern: "impersonateAccount"
    in: ["test/accounts/mldsa.test.ts"]
  - pattern: "getUserOpHash"
    in: ["test/accounts/mldsa.test.ts"]

## Dev Notes (advisory)

**Dependency note — `@noble/hashes`.** `test/signers/mldsa-encoding.ts` uses `shake128`/`shake256` from `@noble/hashes/sha3.js`. `@noble/hashes` is a transitive dependency of `@noble/post-quantum@^0.6.1`; verify resolvability (`node -e "import('@noble/hashes/sha3.js').then(m=>console.log(!!m.shake128))"`). If unresolved, add `@noble/hashes@^2.0.0` to `package.json` devDependencies — Rule 1 deviation (additive). The noble-hashes v2 XOF API exposes `shake128.create()` + `.update(seed)` + `.xofInto(buf)`; earlier v1 used `.xof(len)` directly. The reference JS (`ETHDILITHIUM/js/utils_mldsa.js:10,17-18`) uses the `.create()` + `.xofInto(buf)` pattern — implement the same way.

**No other new dependencies.** `@noble/post-quantum@^0.6.1` already pinned (package.json:12), provides `ml_dsa44`. All viem helpers are already in place.

**Version status:** all packages pinned from Story 1-1. Implement skill checks `package.json` at audit time — no web search required unless a version drift is proposed.

**Parameter-set choice — why not patch the submodule for ML-DSA-65?** DD-3 [LOCKED] + NFR-5 forbid submodule modifications. Patching `ZKNOX_dilithium_utils.sol` to k=6,l=5 would be a submodule-source change (`git diff` inside `ETHDILITHIUM/` would be non-empty), violating Story 1-1 AC-5's invariant. The alternative — bumping the submodule pin to a ZKNoxHQ branch targeting ML-DSA-65 — requires an upstream branch existing (it does not, as of the pinned commit). Therefore: ship ML-DSA-44, document the DD-7 realization.

**Hash-domain cross-check (do this EARLY in Task 6):** the very first integration assertion should be AC-3's happy-path `result === 0n`. If it returns `0xFFFFFFFF` (via the account's SIG_VALIDATION_FAILED path) rather than success, the `mPrime = 0x00 || 0x00 || userOpHash` assumption is wrong — noble and ZKNOX are prepending different domain-separator bytes. To diagnose: temporarily call `dilithiumVerifier.read.verify([pointerHex, userOpHash, signatureHex])` directly (outside the account) and compare return values. If direct `verify` returns `0xFFFFFFFF` but `ml_dsa44.verify(sig, msg, publicKey)` returns `true` for the same inputs, ML-DSA's internal `µ` computation differs between noble and ZKNOX; fall back to `ml_dsa44.internal.sign(...)` API to expose `µ`. Unlikely — both implement FIPS 204 §5.2 pseudocode — but worth having the debug path documented.

**Signature encoding is direct — do NOT port a signature encoder.** Noble's `ml_dsa44.sign(msg, sk)` output is already `cTilde(32) || z(2304) || h(84)` = 2,420 bytes. `ZKNOX_dilithium.sol:80` slices that layout verbatim. This is the major asymmetry with Falcon (whose signature requires a 666-byte→1,064-byte Golomb-Rice + NTT bridge). Do NOT write an `encodeSignatureForZKNOX` — it would be a no-op.

**Wave-2 parallelism note (orchestrator-relevant):** Story 4-1 consumes `test/signers/userOpHash.ts` which Story 3-1 Task 3 already committed (`43b331b`). Zero hard coupling remaining between 4-1 and paused 3-1. File deltas (no collisions): `contracts/MlDsaAccount.sol`, `test/signers/ml-dsa.ts` (modify existing file), `test/signers/mldsa-encoding.ts`, `test/fixtures/mldsa.ts`, `test/accounts/mldsa.test.ts`, `test/smoke.test.ts` (append-only modification to the mldsa line). No `hardhat.config.ts` or `package.json` changes expected (except possibly `@noble/hashes` addition flagged above).

**What is NOT in this story:**
- Wrong-key, bit-flip, malformed-signature rejection paths — Story 4-2.
- Gas measurement or `handleOps` end-to-end flow — Story 5-1.
- Falcon equivalent — Story 3-1 (paused; resumes after this story).
- ML-DSA-65 parameter set — out of scope; see DD-7 realization.
- Direct `bytes` storage of the raw 1,312-byte key on the account — forbidden by A-003 (would fail the verifier's pk-decode contract).

**C-003 caveat (inherited):** `readFile("contracts/MlDsaAccount.sol", ...)` in Task 6 AC-4 uses a CWD-relative path. Same caveat as Story 2-1 AC-4 / Story 3-1 AC-4. Fix-when-touched; not blocking.

**Assertion library:** `node:assert/strict` only. No chai. Viem's `BaseError` / `ContractFunctionRevertedError` for revert discrimination is available but not needed in this story (happy-path only; Story 4-2 will exercise it heavily).

**Test data:** Fresh keypairs per test (architecture §Test Data). No hardcoded ML-DSA keys. KAT vectors in `ETHDILITHIUM/pythonref/dilithium_py/tests/` are for the submodule's own verification, not our test pipeline — do not copy.

> Ref: test/accounts/ecdsa.test.ts — proxy + impersonate + simulate pattern, buildUnsignedUserOp shape
> Ref: contracts/FalconAccount.sol — file structure, NatSpec style, _VERIFY_SELECTOR workaround, try-catch + view override
> Ref: test/signers/ecdsa.ts — signer module file shape (keygen / signUserOp export convention)
> Ref: test/signers/userOpHash.ts — userOpHash derivation (consume directly; do NOT duplicate)
> Ref: ETHDILITHIUM/js/execute.js — reference for the full end-to-end flow (keygen → decode → recoverAhat → compact → preparePublicKey → deploy)
> Ref: ETHDILITHIUM/js/utils_mldsa.js — decodePublicKey / recoverAhat / compact_module_256 algorithms to port (line-for-line mechanical)
> Ref: ETHDILITHIUM/js/pkDeploy.js — preparePublicKeyForDeployment (ethers → viem port)

## Detected Patterns

Codebase scanned for analogous patterns (5 sample files):

- `contracts/FalconAccount.sol` — sole prior PQC-account contract. PROVIDES the MlDsaAccount file template verbatim (swap Falcon↔Dilithium symbols, `ZKNOX_falcon`↔`ZKNOX_dilithium`). Provides the `_VERIFY_SELECTOR` workaround, `error SignatureMalformed()` placement, NatSpec idiom, view-mutability override pattern.
- `contracts/EcdsaAccount.sol` — baseline; provides SPDX / pragma / file-header convention only (body shape diverges entirely).
- `test/accounts/ecdsa.test.ts` — sole prior account test. PROVIDES `setup()` / `buildUnsignedUserOp` / `canonicalUserOpHash` / `simulateValidateUserOp` patterns verbatim. The MlDsa test is this test + a verifier deployment + a `registerPublicKey` step + different AC labels.
- `test/signers/ecdsa.ts` — sole prior real signer module. Provides the `keygen(): Keypair` and `signUserOp(secretKey, userOp, entryPointAddress, chainId): Promise<PackedUserOperation>` export shape Task 3 must match. Also shows the `computeUserOpHash` consumption pattern.
- `test/fixtures/entryPoint.ts` — sole prior fixture. Provides the `hre.network.connect()` → `viem.deployContract(...)` pattern `test/fixtures/mldsa.ts` mirrors.

| Pattern | Value | Sampled from | Established? |
|---------|-------|-------------|-------------|
| Test runner | `node:test` + `node:assert/strict` | `test/smoke.test.ts`, `test/accounts/ecdsa.test.ts` | ✅ Established |
| ESM relative-import extension | `.js` suffix on TS-source relatives | every `test/**/*.ts` | ✅ Established |
| Account proxy deploy | `viem.deployContract(impl, args)` → `encodeFunctionData(initialize)` → `viem.deployContract("ERC1967Proxy", [implAddr, initData])` → `getContractAt` | `test/accounts/ecdsa.test.ts:56-68` | ✅ Established (A-002 BINDING) |
| EntryPoint impersonation | `testClient.impersonateAccount` + `setBalance(parseEther("1"))` | `test/accounts/ecdsa.test.ts:70-74` | ✅ Established |
| Direct validateUserOp | `account.simulate.validateUserOp([...], { account: entryPoint.address })` returning `{result}` | `test/accounts/ecdsa.test.ts:125-130` | ✅ Established |
| Canonical userOpHash | `entryPoint.read.getUserOpHash([packed])` (live contract, no drift risk) | `test/accounts/ecdsa.test.ts:106-111` | ✅ Established |
| Source-inspection AC | `await readFile("contracts/X.sol", "utf8")` + `assert.ok(source.includes(...))` | `test/accounts/ecdsa.test.ts:241-252` | ✅ Established (C-003 caveat) |
| SPDX / pragma | `// SPDX-License-Identifier: GPL-3.0` + `pragma solidity 0.8.34;` | `contracts/EcdsaAccount.sol:1-2`, `contracts/FalconAccount.sol:1-2` | ✅ Established |
| Submodule import path | `import {X} from "../SUBMODULE/src/...";` (relative through repo) | `contracts/FalconAccount.sol:8`, `contracts/imports/DilithiumRef.sol:16` | ✅ Established |
| PQC account contract shape | `is SimpleAccount` + immutable verifier + `bytes public publicKey` + two-arg `initialize(address, bytes calldata)` + view `_validateSignature` override with try/catch + `_VERIFY_SELECTOR` workaround + `SignatureMalformed` custom error | `contracts/FalconAccount.sol:18-85` | ✅ Established |
| `_VERIFY_SELECTOR` workaround | `bytes4 private constant _VERIFY_SELECTOR = bytes4(keccak256("verify(bytes,bytes32,bytes)"));` | `contracts/FalconAccount.sol:30-31` | ✅ Established (C-004-adjacent; driven by overload ambiguity) |
| SSTORE2 pointer extraction via simulate | `publicClient.simulateContract({..., functionName: "setKey", args: [...]})` returns `{result}` (the 20-byte pointer hex); broadcast separately via `write.setKey` | Not yet in codebase (FalconAccount's analog Task 6 is DEFERRED — see Story 3-1 Task 6 setup step 6) | ⚠ Greenfield — Task 4 prescription is the first occurrence |
| Signer module layout | `test/signers/{scheme}.ts` with `keygen(): Keypair` and `async signUserOp(secretKey, userOp, entryPointAddress, chainId)` | `test/signers/ecdsa.ts:23,33` | ✅ Established (PD-2 LOCKED) |
| Encoding-bridge module | `test/signers/{scheme}-encoding.ts` with pure-function exports for scheme-specific byte-format translation | Not yet in codebase (Falcon's analog Task 4 is DEFERRED) | ⚠ Greenfield — Task 2 is first occurrence |

**Conflicts:** none. Two greenfield patterns (SSTORE2-pointer simulate-then-write; encoding-bridge module) — Task 2 and Task 4 prescriptions are the first occurrence; future stories can reference them.

## Wave Structure

Story 4-1 is Wave 2 (`docs/sprint-status.yaml` line 57) — parallel with Stories 2-1 (done) and 3-1 (paused). Hard dependency only on 1-1 (done). Internal task dependencies:

- **Sub-wave A (parallel):** Task 1 (`MlDsaAccount.sol`) and Task 2 (`mldsa-encoding.ts`) are independent — different files, no shared state. Task 2 is purely off-chain JS/TS; Task 1 is Solidity.
- **Sub-wave B:** Task 3 (`mldsa.ts` signer) depends on Task 2 (consumes `preparePublicKeyForDeployment` indirectly via the test setup, not the signer itself — actually Task 3's signer only depends on `computeUserOpHash` + `ml_dsa44`; it does NOT import Task 2's bridge). **Revised: Task 3 is independent of Task 2** — they can land together in either order.
- **Sub-wave C:** Task 4 (`test/fixtures/mldsa.ts`) depends on Task 2 (consumes `preparePublicKeyForDeployment`) and Task 1 (needs the `ZKNOX_dilithium` contract in the compile graph — already there via `DilithiumRef.sol`, so actually just Task 2).
- **Sub-wave D:** Task 5 (smoke update) depends only on Task 3. Task 3 landing will break `test/smoke.test.ts` — ship Task 5 same commit or immediately after.
- **Sub-wave E:** Task 6 (`test/accounts/mldsa.test.ts`) depends on Tasks 1, 3, 4. Transitively on 2.
- **Sub-wave F:** Task 7 (compile + test gate) — final; depends on everything.

**Ordering recommendation for implement skill:** Task 1 → Task 2 (parallel-ok) → Task 3 → Task 5 (pair with 3) → Task 4 → Task 6 → Task 7. The Task 1 + Task 2 pair can run as two parallel commits if the implementer is going wave-parallel.

**Cross-story wave-independence audit (vs Stories 2-1 done, 3-1 paused):**

| Output file | 2-1 (done) | 3-1 (paused) | 4-1 (this) | Conflict? |
|-------------|-----------|-------------|-----------|-----------|
| `contracts/EcdsaAccount.sol` | CREATES | — | — | — |
| `contracts/FalconAccount.sol` | — | CREATES (Task 1 committed) | — | — |
| `contracts/MlDsaAccount.sol` | — | — | CREATES | None |
| `test/signers/ecdsa.ts` | CREATES | modifies (Task 3 extracted hash helper) | — | — |
| `test/signers/falcon.ts` | — | modifies (deferred) | — | — |
| `test/signers/ml-dsa.ts` | — | — | MODIFIES (stub → real) | None |
| `test/signers/userOpHash.ts` | — | CREATES (Task 3 committed) | CONSUMES | None (hard dep satisfied) |
| `test/signers/mldsa-encoding.ts` | — | — | CREATES | None |
| `test/signers/falcon-encoding.ts` | — | CREATES (deferred) | — | — |
| `test/fixtures/mldsa.ts` | — | — | CREATES | None |
| `test/accounts/ecdsa.test.ts` | CREATES | — | — | — |
| `test/accounts/falcon.test.ts` | — | CREATES (deferred) | — | — |
| `test/accounts/mldsa.test.ts` | — | — | CREATES | None |
| `test/smoke.test.ts` | untouched | Task 5 modifies (deferred) | Task 5 modifies (ml-dsa line) | Line-level disjoint — 3-1 touches the `falcon keygen throws` line, 4-1 touches the `mldsa keygen throws` line. Commutative; no conflict. |
| `hardhat.config.ts` | — | — | — | None |
| `package.json` | — | — | POSSIBLY adds `@noble/hashes` (if unresolved transitively) | Rule 1 deviation if needed |
| `docs/amendments.md` | — | — | APPENDS A-004-equivalent (DD-7 realization) | None |

Zero true conflicts. 4-1 unblocks 3-1's resume (C-007) by providing the encoding-bridge template but does not touch 3-1 files.

---

Story 4-1 | Inlined: 12 sections (AC, MlDsaAccount.sol snippet, parameter-set deviation table, 3-layer pk flow table, signature flow, hash domain, verifier deployment, EntryPoint-direct, userOpHash, compile graph, failure-class scope, unblocks 3-1) | Refs: 14 scoped references | Omitted: 6 patterns (test runner, ESM extensions, proxy deploy, impersonation, simulate pattern, source-inspection — all established by Stories 2-1/3-1 and inherited via codebase scan)

---

## Gate 5 — PASS (2026-04-15)

- AC-1/AC-2/AC-3/AC-4: 4/4 pass (`npx hardhat test` 13/13 green; baseline 9/9 still green; 4 new ML-DSA tests).
- Code review: PASS WITH NOTES — 5 LOW findings; F2 (AC-4 substring → regex) fixed inline (`fd7a8f9`); F1/F3/F4/F5 logged as C-008.1–C-008.4 in `docs/concerns.md` for a future quality-cycle pass.
- Constraints honored: A-001 (HH3 + viem + node:test), A-002 (ERC1967Proxy deploy), A-003 (SSTORE2 pointer in `publicKey`), DD-9 (one verifier per account), NFR-5 (`git diff` inside ETHDILITHIUM/ remains empty).
- Amendments captured: A-004 — DD-7 transitions `[DISCRETION] → [LOCKED]`, ML-DSA-44 (k=4, l=4) confirmed against `ZKNOX_dilithium_utils.sol:44-45`; AC byte sizes corrected (1952→1312, 3309→2420).
- Implementation deviation: `transformT1Poly` (poly-shiftl by `2^d` + forward NTT) added to `mldsa-encoding.ts` — required by ZKNOX's pre-shifted t1 storage (noble `ml-dsa.js:560`, ETHDILITHIUM test vectors at `dilithium.t.sol:543+`); not present in `ETHDILITHIUM/js/pkDeploy.js` reference. Documented in A-004 implementation notes.
- Commits this story: `957b073`, `955d297`, `65d4c0c`, `ddb11b3`, `ff09b37`, `b3954e3`, `d2a093e`, `fd7a8f9`.
- Resume signal: per C-007, Story 3-1 is unpaused. The encoding-bridge module (`test/signers/mldsa-encoding.ts`) and fixture pattern (`test/fixtures/mldsa.ts`) serve as the port template for the Falcon equivalent.
