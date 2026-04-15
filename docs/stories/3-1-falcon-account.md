---
id: "3-1"
slug: falcon-account
status: complete
created: 2026-04-15
paused_at: 2026-04-15
resumed_at: 2026-04-15
completed_at: 2026-04-15
gate5: pass
---

# Story: Falcon signer + FalconAccount + happy-path acceptance

## ▶ RESUMED 2026-04-15 — ML-DSA bridge available as template

Story 4-1 reached Gate 5 PASS (commits `b3954e3..fd7a8f9`). The ML-DSA
encoding bridge (`test/signers/mldsa-encoding.ts`) and verifier fixture
(`test/fixtures/mldsa.ts`) serve as the JS template for the analogous
Falcon work. Resume order per §Wave Structure: Task 4 → Task 2 → Task 5 →
Task 6 → Task 7 (Tasks 1 and 3 already committed).



## User Story
As an engineer, I want a Falcon-signing smart account that validates a correctly-signed UserOp on-chain, so that Falcon is integrated end-to-end.

## Acceptance Criteria

- AC-1: Given `SigningUtils.keygen('falcon')`, When called, Then returns Alice's Falcon-512 keypair via `@noble/post-quantum/falcon` with a 897-byte public key.
- AC-2: Given Alice's Falcon keypair, When calling `signUserOp('falcon', aliceSecretKey, userOp)`, Then returns a `PackedUserOperation` whose `signature` field decodes via `ZKNOX_falcon`'s expected format.
- AC-3: Given a deployed `FalconAccount` initialized with Alice's 897-byte public key and a `ZKNOX_falcon` verifier reference, When Alice's Falcon-signed UserOp is submitted to `validateUserOp`, Then it returns `SIG_VALIDATION_SUCCESS`.
- AC-4: Given `FalconAccount._validateSignature`, When inspected, Then it calls `falconVerifier.verify(publicKey, userOpHash, userOp.signature)` wrapped in try/catch per architecture.

## Architecture Guardrails

**Amendments are binding.** A-001 (HH3 + viem + `node:test`/`node:assert/strict` toolchain) and A-002 (account-under-test deployed via `ERC1967Proxy`, never directly) both apply. Every PQC account in this story uses the proxy setup that Story 2-1 established.

**FalconAccount shape (LOCKED, from architecture §Smart Contract Interfaces):**

```solidity
contract FalconAccount is SimpleAccount {
    ZKNOX_falcon public immutable falconVerifier;
    bytes public publicKey;

    constructor(IEntryPoint entryPoint, ZKNOX_falcon _verifier) SimpleAccount(entryPoint) {
        falconVerifier = _verifier;
    }

    function initialize(address, bytes calldata _publicKey) public initializer { ... }

    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override returns (uint256 validationData) {
        try falconVerifier.verify(publicKey, userOpHash, userOp.signature) returns (bytes4 result) {
            return result == ZKNOX_falcon.verify.selector
                ? SIG_VALIDATION_SUCCESS
                : SIG_VALIDATION_FAILED;
        } catch {
            revert SignatureMalformed();
        }
    }
}
```

**Initializer shadowing:** `SimpleAccount.initialize(address)` is `public virtual initializer`. FalconAccount declares `initialize(address, bytes calldata)` with a DIFFERENT selector — the parent's single-arg `initialize` is NOT overridden (different signature → different selector → no Solidity override clash). The child's `initialize` carries its own `initializer` modifier so the OZ v5 `_initialized` slot is consumed exactly once per proxy. The first arg (`address`) is intentionally unused inside the body — pass `address(0)` or any sentinel from tests; the Falcon path identifies "Alice" via `publicKey`, not via the SimpleAccount `owner` field. Set `owner` only if a downstream story needs `_requireFromEntryPointOrOwner` to recognize an EOA — Story 3-1 does not. (If you decide to thread the `address` through to `super.initialize(anOwner)` for parity with SimpleAccount's owner model, do it explicitly inside the body and document the choice; do NOT silently call the parent.)

**`SignatureMalformed` custom error:** Declare on the contract: `error SignatureMalformed();`. Architecture §Error Handling Strategy — the only standards-compliant way to surface "format/decode failure" without colliding with the EntryPoint's aggregator-address interpretation of `validationData`. Story 3-1 declares it; Story 3-2 asserts on it.

**C-005 RESOLUTION (now governed by A-003) — `publicKey` is split across two layers:**

> **Promoted to project-wide rule:** Amendment **A-003** (`docs/amendments.md`) generalizes the resolution below to every PQC account that integrates an `ISigVerifier`-shaped verifier (Falcon, ML-DSA, future schemes). The Rule 2 deviation language in this section is superseded by A-003 — the architecture data-model row is amended at the architecture level, not reinterpreted at the story level.

| Layer | Field name | Type | Bytes | Source |
|-------|------------|------|-------|--------|
| Off-chain (signer) | `Keypair.publicKey` | `Uint8Array` | 897 | noble's `falcon512.keygen().publicKey` (raw NIST-encoded Falcon-512 public key) |
| On-chain (account) | `bytes public publicKey` | `bytes` | 20 | SSTORE2 pointer address returned by `falconVerifier.setKey(rawPublicKey)`, packed via `abi.encodePacked(pointer)` |

Rationale: ZKNOX_falcon's `verify(bytes _pubkey, bytes32 _digest, bytes _sig)` (the `ISigVerifier`-shape entry point this story consumes) does NOT take the raw 897-byte Falcon public key as `_pubkey` — it interprets the first 20 bytes of `_pubkey` as an SSTORE2 contract address and reads the actual encoded key from there. Storing the raw 897 bytes on the account would (a) waste ~30K gas per validation re-reading them and (b) not match the `verify` calldata contract. **Architecture §Data Models §Public Key Storage row "Falcon-512: 897 bytes — `bytes public publicKey` on FalconAccount" is interpreted as: "the `publicKey` field on the account holds the SSTORE2 pointer to the encoded 897-byte key" (Rule 2 deviation: pattern reinterpretation; not a contract change to the architecture).** The signer module's `Keypair.publicKey` (897-byte raw key) is the input to `setKey()`; the account's `bytes public publicKey` (20-byte SSTORE2 pointer) is what the verifier consumes. The two are NEVER conflated.

`Keypair.publicKey` length differs across schemes (20 for ECDSA, 897 for Falcon, 1952 for ML-DSA) — this is by design and matches noble's per-scheme output. C-005 is RESOLVED by this split: ECDSA's signer publishes "the address" (the on-chain identity primitive), Falcon's signer publishes "the raw NIST-encoded key" (input to `setKey()`).

**Encoding bridge (CRITICAL — architecture gloss):** The architecture says "off-chain signing via `@noble/post-quantum`" and "on-chain verification via ZKNOX_falcon" but there is a NON-TRIVIAL encoding mismatch between the two:

| Surface | noble produces / consumes | ZKNOX_falcon's `verify(bytes,bytes32,bytes)` expects |
|---------|---------------------------|------------------------------------------------------|
| Public key | 897-byte Falcon-512 NIST-encoded (header `0x09` + 14-bit-packed coefficients) | 20-byte SSTORE2 pointer to a `uint256[]` ABI-encoded compacted (16 coefficients × 16 bits per word, 32 words) NTT-domain key |
| Signature | ~666-byte compressed `salt(40) + compressed_s2` (Falcon NIST format, signed by `falcon512.sign(msg, sk)`) | `salt(40) || s2_compact_bytes` where `s2_compact` is `uint256[32]` (1024 bytes), total **1064 bytes** |
| Hash domain | noble signs `msg` directly (no domain separation beyond what Falcon's internal HashToPoint does) | Verifier hashes `(salt, h)` via `hashToPointNIST` where `h = bytes(_digest)` (the 32-byte userOpHash) |

This mismatch implies the Falcon signer module CANNOT be a thin noble wrapper — it must:
1. **For the public key:** call noble's `falcon512.keygen()` to get the 897-byte raw key → run a TS-side decoder (NIST-decompress to 512 coefficients of 14-bit packing → forward NTT → 16-bit-coefficient compact packing into `uint256[32]`) → ABI-encode as `bytes(uint256[])` for SSTORE2 ingestion.
2. **For the signature:** noble's `falcon512.sign(msg, sk)` does an internal `HashToPoint(salt, msg)` and finds an `(s1, s2)` short-vector solution, then emits the Falcon NIST compressed format. To produce a ZKNOX-compatible signature, the signer must either (a) re-implement Falcon signing in TS to control the salt + emit the raw `(salt, s2_compact)` directly, or (b) call noble to sign and then DECODE noble's compressed output to extract `salt` (40 bytes) and `s2` (512 coefficients) → re-encode `s2` into compacted `uint256[32]` form. Option (b) is far simpler and matches ZKNOX's own `pythonref/sig_sol.py` workflow (sign with the canonical implementation, then re-encode for the EVM).
3. **For the hash domain:** `userOpHash` (32 bytes) is passed as the message. The verifier wraps it in `bytes` and calls `hashToPointNIST(salt, h)`. The OFF-CHAIN Falcon signer must ALSO use `hashToPointNIST(salt, userOpHash)` semantics — i.e., sign the same 32-byte digest with the same salt-prepending hash-to-point function ZKNOX uses. If noble's internal HashToPoint differs (likely: noble follows the Falcon NIST spec which uses SHAKE256 over `salt || msg` to produce 512 coefficients mod q), the signature will VERIFY against noble's verifier but FAIL against ZKNOX's. Verify empirically as the very first integration test.

**If empirical verification of step 3 fails** (signatures pass `falcon512.verify` but fail `ZKNOX_falcon.verify`), the encoding bridge must explicitly call `hashToPointNIST(salt, userOpHash)` off-chain (port the Solidity `hashToPointNIST` to TS) and feed the resulting 512-coefficient hashed point into noble's lower-level signing path — this is significantly harder. Fall back: use ETHFALCON's `pythonref/sig_sol.py` via a Node `child_process` shim (last-resort: it works and matches the on-chain hash, but adds a Python dependency). Decide during Task 2 implementation; document the choice in code comments and update Dev Notes.

**Signer dispatch (PD-2 LOCKED, established by Story 1-1):** `test/signers/falcon.ts` replaces the Story-1-1 `NotImplementedError` stub. The dispatcher in `test/signers/index.ts` already routes `scheme === "falcon"` to `falcon.keygen()` / `falcon.signUserOp()` — no change to `index.ts` needed unless the per-scheme `Keypair.publicKey` length forces a type widening (it does not — the type is already `Uint8Array`).

**Verifier deployment (DD-9 LOCKED):** Tests deploy a fresh `ZKNOX_falcon` instance per setup (`viem.deployContract("ZKNOX_falcon")`). NOT a singleton. Architecture is explicit: standalone instance, called externally. Same pattern as Story 1-1's EntryPoint fixture. The verifier has no constructor args.

**EntryPoint-direct call path (from Story 2-1):** Use `account.simulate.validateUserOp([signed, userOpHash, 0n], { account: entryPoint.address })` after impersonating `entryPoint.address` via `testClient.impersonateAccount` + `setBalance`. `simulate` returns the `uint256` validationData without mining a tx. Same pattern Story 2-1 established and Story 5-1 will reuse. Do NOT use `entryPoint.write.handleOps` for AC-3 — `handleOps` propagates failure via `FailedOp` revert reasons rather than the raw return.

**`userOpHash` source (canonical):** Compute via `entryPoint.read.getUserOpHash([packedOp])` on the live EntryPoint, not via a hand-rolled duplicate of the v0.7 hashing logic. Story 2-1 establishes this convention. Removes any drift between the signer's internal hash, the on-chain verifier's expected digest, and the test fixture.

**Compile-graph entry:** `contracts/imports/FalconRef.sol` already imports `ETHFALCON/src/ZKNOX_falcon.sol` — `ZKNOX_falcon` is already in the compile graph. No `hardhat.config.ts` change for that. **However**, `FalconAccount.sol` will import `ZKNOX_falcon` directly via a relative path through `contracts/imports/FalconRef.sol`'s established convention, OR via the bare submodule path `"../ETHFALCON/src/ZKNOX_falcon.sol"`. Use the relative submodule path to mirror what `FalconRef.sol` already does; don't introduce a new resolution mode. `npmFilesToBuild` already lists `EntryPoint.sol` and `ERC1967Proxy.sol`; no additions needed unless compile fails to find an artifact (then add and log Rule 1 deviation per code-standards.md).

**Failure-class deferred:** This story is happy-path only (AC-3 = success). Wrong-key, bit-flipped, and malformed-format rejections are Story 3-2 (separate file `test/accounts/falcon-failures.test.ts` per PD-2 wave-isolation principle).

> Ref: docs/architecture.md#Smart Contract Interfaces — FalconAccount shape and verifier interface
> Ref: docs/architecture.md#Data Models — public key storage row (REINTERPRETED here for C-005)
> Ref: docs/architecture.md#Error Handling Strategy — `SignatureMalformed` rationale and `validationData` packing constraint
> Ref: docs/architecture.md#Testing Strategy — fresh keypair per test, file naming
> Ref: docs/amendments.md#A-001 — HH3 + viem + node:test (BINDING)
> Ref: docs/amendments.md#A-002 — ERC1967Proxy account deployment (BINDING)
> Ref: docs/amendments.md#A-003 — PQC accounts store SSTORE2 pointer, not raw key (BINDING; supersedes per-story C-005 reinterpretation)
> Ref: docs/concerns.md#C-005 — publicKey field type — RESOLVED via A-003
> Ref: docs/stories/2-1-ecdsa-account.md — proxy setup, impersonation, canonical userOpHash patterns to mirror

## Verified Interfaces

### `keygen("falcon")` — to be DEFINED by this story
- **Source:** `test/signers/falcon.ts` (currently a `NotImplementedError` stub — to be replaced)
- **Current signature:** `export function keygen(): Keypair` — throws `new NotImplementedError("falcon")`
- **Current file hash:** `c84ab6fa228cc2008ac83649cb61b77a483834c649e22181242295e5de040cfb`
- **New signature (target):** `export function keygen(): Keypair` — returns `{ publicKey: Uint8Array /* 897 bytes, raw Falcon-512 NIST-encoded */, secretKey: Uint8Array /* noble's secret key bytes */ }`
- **Plan match:** ✓ Matches plan §Interface Contracts; AC-1 asserts `publicKey.length === 897`

### `signUserOp("falcon", secretKey, userOp, entryPointAddress, chainId)` — to be DEFINED by this story
- **Source:** `test/signers/falcon.ts` (currently a stub)
- **Current signature:** stub throws
- **New signature (target):** `export async function signUserOp(secretKey: Uint8Array, userOp: UnsignedUserOp, entryPointAddress: string, chainId: bigint): Promise<PackedUserOperation>` — returns a `PackedUserOperation` whose `signature` field is the 1064-byte `salt(40) || s2_compact_bytes(1024)` blob the ZKNOX verifier expects.
- **Plan match:** ✓ Matches plan §Interface Contracts. AC-2 asserts the signature decodes via the ZKNOX format.

### `falcon512` (upstream — `@noble/post-quantum@^0.6.1`)
- **Source:** `node_modules/@noble/post-quantum/falcon.d.ts:45` (export declaration), `falcon.js:2312` (definition)
- **Signature:** `falcon512: Signer & { attached: FalconAttached }` where `Signer.keygen(seed?)` → `{ publicKey, secretKey }`, `Signer.sign(msg, secretKey, opts?)` → `Uint8Array`, `Signer.verify(sig, msg, publicKey, opts?)` → `boolean`. `falcon512.lengths.publicKey === 897`, `falcon512.lengths.signature` per Falcon-512 spec (variable-length compressed, max 666 bytes).
- **Plan match:** ✓ VERIFIED — package present at `@noble/post-quantum@^0.6.1` (per `package.json:12`)
- **Note:** Detached signature path (`sign` / `verify`) is the one this story uses. Do NOT use the `attached` API (`seal` / `open`) — that bundles the message into the signature, which is incompatible with the userOpHash-driven flow.

### `ZKNOX_falcon.verify(bytes,bytes32,bytes)` (upstream — ETHFALCON submodule)
- **Source:** `ETHFALCON/src/ZKNOX_falcon.sol:81`
- **File hash:** `9e84d5dadcbd654d2217472e8e52be2fa69bf83b89a5c13a291cebbd4c3a8a74`
- **Signature:** `function verify(bytes calldata _pubkey, bytes32 _digest, bytes calldata _sig) external view returns (bytes4)`
- **Behavior:** Reads first 20 bytes of `_pubkey` as an SSTORE2 contract address; calls `SSTORE2.read(addr)` and ABI-decodes as `uint256[]` (the compacted NTT-domain key); parses `_sig` as `salt(40) || s2_uint256[]` packed bytes; calls the inner 4-arg `verify(message, salt, s2, pkc)` where `message = abi.encodePacked(_digest)`. Returns `verify.selector` on success, `0xFFFFFFFF` on cryptographic failure. **REVERTS** with `"invalid salt length"` / `"invalid s2 length"` / `"invalid ntth length"` / decoder failures on malformed input — this is what triggers FalconAccount's `SignatureMalformed` (AC-4 try/catch path; Story 3-2 AC-3 asserts).
- **Plan match:** ✓ Matches architecture §ZKNoxHQ Verifier Interface. The `bytes calldata _pubkey` parameter shape (SSTORE2-pointer-as-bytes) is the source of the C-005 split documented above.

### `ZKNOX_falcon.setKey(bytes)` (upstream — ETHFALCON submodule)
- **Source:** `ETHFALCON/src/ZKNOX_falcon.sol:36`
- **Signature:** `function setKey(bytes memory pubkey) external returns (bytes memory)` — accepts a `bytes` blob, calls `SSTORE2.write(pubkey)`, returns `abi.encodePacked(pointer)` (20 bytes representing the deployed pointer contract's address).
- **Behavior caveat:** The input `pubkey` is not validated for shape. The READ path in `verify(bytes,bytes32,bytes)` later does `abi.decode(SSTORE2.read(pointer), (uint256[]))` — so what `setKey` receives MUST be `abi.encode(uint256[])` form (length prefix + words), NOT the raw 897 NIST bytes. The off-chain encoding bridge is responsible for producing this ABI-encoded compacted-key bytes before calling `setKey`.
- **Plan match:** ✓ Architecture §Data Models §DD-8 alternatives mentions SSTORE2 — this is the actual on-chain mechanism.

### `keygen`/`signUserOp` dispatcher (consumed, not modified)
- **Source:** `test/signers/index.ts:45,56`
- **File hash:** `5f571b4ecbe7d6a709d45df187320a5641c94aa5e2695be649170f6fc1189238`
- **Signature:** `keygen(scheme: Scheme): Keypair` and `signUserOp(scheme, secretKey, userOp, entryPointAddress, chainId): Promise<PackedUserOperation>` — already routes `scheme === "falcon"` to this story's new functions; no edit needed.
- **Plan match:** ✓ Established Story 1-1.

### `deployEntryPoint()` (consumed, not modified)
- **Source:** `test/fixtures/entryPoint.ts:27`
- **File hash:** `95104f6690c0d34496cebe738a0bec1b7f23315c540fab9e6458a0136684e2fd`
- **Signature:** `async function deployEntryPoint(): Promise<{ entryPoint, publicClient, walletClients }>` — established Story 1-1; reused as-is.

### `EcdsaAccount.sol` reference shape
- **Source:** `contracts/EcdsaAccount.sol`
- **File hash:** `a897bd0d4e8a10fcca506ba3ef741576ecd48b01fd1af28163ca47045ff9cf49`
- **Use:** Read this for the SPDX header / pragma / NatSpec layout convention. FalconAccount mirrors the file shape but adds an immutable verifier ref + storage publicKey + initializer + `_validateSignature` override.

### `test/accounts/ecdsa.test.ts` reference structure
- **Source:** `test/accounts/ecdsa.test.ts`
- **File hash:** `cf9a31d6655025e57fef7060f79c66afcef48a72b31197f21c2de0ac1c24ee3b`
- **Use:** Mirror the `setup()` helper shape (deploy EntryPoint → deploy implementation → encodeFunctionData(initialize) → deploy ERC1967Proxy → getContractAt → impersonate EntryPoint → setBalance → return chainId). Mirror AC-1 only — wrong-key (AC-2) and bit-flip (AC-3) ECDSA tests are NOT analogues of Story 3-1 ACs (those become Story 3-2).

## Tasks

- [x] **Task 1: `contracts/FalconAccount.sol`** (commit 6cdfc22)
  - Maps to: AC-3, AC-4
  - Files: `contracts/FalconAccount.sol` (new)
  - SPDX `GPL-3.0` (match `EcdsaAccount.sol`); `pragma solidity 0.8.34;`
  - Imports:
    - `{SimpleAccount} from "@account-abstraction/contracts/samples/SimpleAccount.sol";`
    - `{IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";`
    - `{PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";`
    - `{SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "@account-abstraction/contracts/core/Helpers.sol";`
    - `{ZKNOX_falcon} from "../ETHFALCON/src/ZKNOX_falcon.sol";`
  - Body — exactly the architecture-prescribed shape (see Architecture Guardrails for the full snippet). Include: `error SignatureMalformed();`, `ZKNOX_falcon public immutable falconVerifier;`, `bytes public publicKey;`, the two-arg `initialize(address, bytes calldata _publicKey)` with `initializer` modifier setting `publicKey = _publicKey`, and the `_validateSignature` override with the try/catch returning success/failed and reverting `SignatureMalformed()` on catch.
  - NatSpec: `@title FalconAccount`, `@author pqc-4337-laim`, `@notice ERC-4337 v0.7 account that delegates signature verification to a ZKNoxHQ ETHFALCON verifier (DD-9). Stores the SSTORE2-pointer form of the public key (C-005 resolution); the raw 897-byte Falcon-512 key is supplied off-chain via the signer module, encoded by the test setup, and written into the verifier's SSTORE2 storage before initialization.` Document `error SignatureMalformed()` with `@notice Reverts when the verifier fails to decode the signature (format error). Cryptographic failure returns SIG_VALIDATION_FAILED via the standard validationData path instead.`
  - The `address` first arg of `initialize` is intentionally unused — annotate `// solhint-disable-next-line no-unused-vars` only if a linter complains; otherwise omit. Do NOT call `super.initialize(...)` (the Falcon path does not use SimpleAccount's owner field; threading address through would create a misleading dual-identity model).
  - Compile-warnings gate (Story 1-1 §scripts/check-compile-warnings.cjs): zero project-authored warnings tolerated; the known ETHFALCON `slen` warning (C-001) passes through.

- [ ] **Task 2: `test/signers/falcon.ts` — replace stub with real signer + encoding bridge**
  - Maps to: AC-1, AC-2
  - Files: `test/signers/falcon.ts` (REPLACE the existing `NotImplementedError`-throwing stub)
  - Imports: `falcon512` from `@noble/post-quantum/falcon`; viem helpers (`encodeAbiParameters`, `bytesToHex`, etc.) only if needed for the s2-encode path; types `{ Keypair, PackedUserOperation, UnsignedUserOp } from "./index.js"`. Do NOT remove the existing import of `NotImplementedError` from `./errors.js` if it's no longer needed — drop it entirely so the file has zero dead imports.
  - `keygen()`:
    - Call `const { publicKey, secretKey } = falcon512.keygen()` — noble emits a 897-byte `publicKey` and noble-format `secretKey`.
    - Return `{ publicKey, secretKey }` directly (both `Uint8Array`). NO encoding here — the raw NIST-format key is what gets handed to the test setup, which then runs the encoding bridge before calling `falconVerifier.setKey()`.
    - Self-verify: `assert(publicKey.length === 897)` inline (or rely on AC-1 to fail loudly). Story 1-1's smoke test will continue to expect `keygen("falcon")` to throw — once Task 2 lands, Story 1-1's `falcon keygen throws NotImplementedError` smoke test WILL FAIL. **Update `test/smoke.test.ts`** to remove that single-line expectation and replace with a `falcon keygen returns 897-byte publicKey` assertion (Task 5).
  - `signUserOp(secretKey, userOp, entryPointAddress, chainId)`:
    - Compute `userOpHash` using the SAME `keccak256(abi.encode(inner, entryPointAddress, chainId))` derivation that `test/signers/ecdsa.ts:53` uses. Extract the userOpHash computation into a shared helper (`test/signers/userOpHash.ts`) if both ECDSA and Falcon would otherwise inline the same 35 lines — see Task 3.
    - Sign: `const sig = falcon512.sign(userOpHashBytes, secretKey)` where `userOpHashBytes` is the 32-byte digest as a `Uint8Array` (use `hexToBytes(userOpHash)`). This produces a Falcon NIST compressed-format signature (variable length, ≤666 bytes typically).
    - **Encoding bridge — convert noble's signature to ZKNOX's expected `salt(40) || s2_compact(1024)` packed bytes:** delegated to a new helper module (Task 4) `test/signers/falcon-encoding.ts` exporting `encodeSignatureForZKNOX(nobleSig: Uint8Array): Uint8Array` (returns 1064-byte packed signature).
    - Return `{ ...userOp, signature: bytesToHex(packedSignatureBytes) }`.
  - **Empirical verification (do this BEFORE marking AC-2 satisfied):** write a one-shot script or top-of-file `import.meta.main`-guarded sanity check that (a) generates a noble keypair, (b) signs a 32-byte digest, (c) feeds noble's signature through `encodeSignatureForZKNOX`, (d) feeds the encoded public key through the encoding bridge, (e) calls a deployed `ZKNOX_falcon.verify(packedPubkeyPointer, digest, encodedSig)` on a Hardhat instance, (f) asserts the return is `verify.selector`. If this fails, you've hit the hash-domain mismatch flagged in Architecture Guardrails — fall back to invoking ETHFALCON's `pythonref/sig_sol.py` via `child_process` (acceptable PoC fallback; document in Dev Notes); update Task 4 accordingly.

- [x] **Task 3: Extract shared `computeUserOpHash` helper** (commit 43b331b)
  - Maps to: AC-2 (enabling — keeps Falcon and ECDSA using identical hash derivation)
  - Files: `test/signers/userOpHash.ts` (new); `test/signers/ecdsa.ts` (refactor to consume); `test/signers/falcon.ts` (consume from Task 2)
  - Move the 35-line `inner = keccak256(...)` + `userOpHash = keccak256(...)` block out of `test/signers/ecdsa.ts:53-83` into `test/signers/userOpHash.ts`. Export `computeUserOpHash(userOp: UnsignedUserOp, entryPointAddress: string, chainId: bigint): \`0x${string}\``.
  - This is a **Rule 2 deviation** (extracting shared helper from previously single-use code) — log it in the implement skill's deviation log. Justification: Story 4-1 will need the same helper, so extracting now avoids three copies. The change is byte-for-byte equivalent; ECDSA tests should still pass without modification.
  - Re-run the full test suite — Story 1-1 smoke and Story 2-1 ecdsa.test must still pass.

- [ ] **Task 4: `test/signers/falcon-encoding.ts` — encoding bridge**
  - Maps to: AC-2 (the bridge is the difference between AC-2 passing and the wrong-format signature reverting)
  - Files: `test/signers/falcon-encoding.ts` (new)
  - Two exported functions:
    - `encodePublicKeyForZKNOX(rawPublicKey: Uint8Array): \`0x${string}\`` — input: 897-byte raw NIST Falcon-512 public key. Steps: (a) verify byte 0 is `0x09` (NIST header — see `ZKNOX_falcon_encodings.sol:107`); (b) decompress 14-bit-packed 512 coefficients per `_ZKNOX_NTT_Decompress` (port to TS — the pythonref equivalent is in `ETHFALCON/pythonref/encoding.py`); (c) apply forward-NTT in the Falcon ring (q=12289, n=512) to get the NTT-domain key — port `ZKNOX_NTT.sol`'s NTT to TS, OR sidestep by providing the key via ETHFALCON's deploy script which already does this transform; (d) compact 512 × 16-bit coefficients into 32 × 256-bit words per `_ZKNOX_NTT_Compact`; (e) ABI-encode as `bytes(uint256[])` via viem's `encodeAbiParameters([{type: "uint256[]"}], [compactWords])`. Return as a `0x...` hex string suitable for passing to `falconVerifier.write.setKey([encodedKey])`.
    - `encodeSignatureForZKNOX(nobleSig: Uint8Array): \`0x${string}\`` — input: noble's compressed Falcon-512 signature. Steps: (a) extract the 40-byte salt (noble's signature format puts salt at the start; verify against `node_modules/@noble/post-quantum/falcon.js`'s `splitCoder` definition — search for `salt` in falcon.js and confirm offset); (b) decompress the s2 component to 512 coefficients per `_decompress_sig` in `ZKNOX_falcon_encodings.sol:17`; (c) compact to 32 × uint256 words per `_ZKNOX_NTT_Compact`; (d) pack as `salt(40) || s2_uint256[32]_as_bytes(1024)` totaling **1064 bytes**. Return as hex.
  - **Fallback if porting NTT/decompression to TS proves intractable within the story budget:** invoke `ETHFALCON/pythonref/sig_sol.py` via `node:child_process` (`spawnSync(pythonExe, [...])`). The script returns ABI-encoded `(uint256[32], bytes, uint256[32])` (see `ZKNOX_PythonSigner.sol:36`) which can be decoded directly. Cost: adds a Python-virtualenv setup step to local-dev (document in `docs/local-dev.md` if creating one; otherwise note in Dev Notes here). Decision is deferred to implementation time — pick the route that lands fastest while keeping AC-1/AC-2/AC-3 green.
  - Add unit-style assertions in the file (or in a colocated `falcon-encoding.test.ts` if implementer prefers) that round-trip noble's outputs through the encoders and assert byte-length invariants (encoded sig === 1064 bytes; encoded public key, after `abi.decode`, has `uint256[]` of length 32).

- [ ] **Task 5: Update `test/smoke.test.ts` for new Falcon behavior**
  - Maps to: AC-1 (cross-check)
  - Files: `test/smoke.test.ts` (modify)
  - The current smoke test (Story 1-1 line 73-81) asserts `keygen("falcon")` throws `NOT_IMPLEMENTED`. After Task 2 lands this assertion is wrong. Replace with: `it("falcon keygen returns a 897-byte publicKey", () => { const { publicKey } = keygen("falcon"); assert.equal(publicKey.length, 897); });`
  - Leave the `mldsa keygen throws` assertion untouched — Story 4-1 handles that one.
  - Re-run the smoke test; verify the modified assertion passes and no other smoke test regresses.

- [ ] **Task 6: `test/accounts/falcon.test.ts` — happy-path acceptance**
  - Maps to: AC-1, AC-2, AC-3, AC-4
  - Files: `test/accounts/falcon.test.ts` (new)
  - Framework: `node:test` + `node:assert/strict` (mirrors Story 2-1).
  - Imports: `deployEntryPoint` from `../fixtures/entryPoint.js`; `keygen`, `signUserOp`, types from `../signers/index.js`; `encodePublicKeyForZKNOX` from `../signers/falcon-encoding.js`; viem helpers (`bytesToHex`, `encodeFunctionData`, `parseEther`, `BaseError`, `ContractFunctionRevertedError`); `hre` from `"hardhat"`; `readFile` from `"node:fs/promises"`.
  - `setup()` helper:
    1. `const { entryPoint, publicClient } = await deployEntryPoint();`
    2. `const connection = await hre.network.connect(); const { viem } = connection; const testClient = await viem.getTestClient();`
    3. `const falconVerifier = await viem.deployContract("ZKNOX_falcon");`
    4. `const alice = keygen("falcon");` // raw 897-byte publicKey
    5. `const encodedPubkey = encodePublicKeyForZKNOX(alice.publicKey);`
    6. `const setKeyTx = await falconVerifier.write.setKey([encodedPubkey]); ... `await publicClient.waitForTransactionReceipt(...)` to get the returned 20-byte SSTORE2 pointer bytes. **NOTE:** `setKey` returns `bytes memory` from a non-view call — viem's `write` returns the tx hash, not the return value. Use `publicClient.simulateContract({ ..., functionName: "setKey", args: [encodedPubkey] })` FIRST to capture the return value (`result.result` will be the 20-byte pointer bytes), THEN broadcast via `write.setKey` to actually persist. Capture both. The captured 20-byte pointer bytes are what we'll pass to `initialize` as `_publicKey`.
    7. Deploy `FalconAccount` implementation: `await viem.deployContract("FalconAccount", [entryPoint.address, falconVerifier.address])`.
    8. Encode init data: `encodeFunctionData({ abi: implementation.abi, functionName: "initialize", args: ["0x0000000000000000000000000000000000000000", pointerBytes] })`. The first arg (address) is unused per the contract design (see Architecture Guardrails — initializer shadowing); pass `0x0`.
    9. Deploy `ERC1967Proxy` with `[implementation.address, initData]`.
    10. `const account = await viem.getContractAt("FalconAccount", proxy.address);`
    11. Impersonate EntryPoint + set balance (mirror Story 2-1 lines 70-74).
    12. `const chainId = BigInt(await publicClient.getChainId());`
    13. Return `{ entryPoint, account, alice, falconVerifier, chainId, testClient }`.
  - **AC-1 — keygen produces 897-byte publicKey:**
    - `const { publicKey } = keygen("falcon"); assert.equal(publicKey.length, 897);`
    - Standalone test — does not need full setup.
  - **AC-2 — signature decodes via ZKNOX format:**
    - Build minimal `UnsignedUserOp` (mirror Story 2-1 `buildUnsignedUserOp`).
    - `const signed = await signUserOp("falcon", alice.secretKey, userOp, entryPoint.address, chainId);`
    - Assertion: `signed.signature` decodes to exactly 1064 bytes (40 salt + 1024 s2_compact). Use `hexToBytes(signed.signature).length === 1064`. This is the strict structural check; the cryptographic decode succeeds iff AC-3 passes.
  - **AC-3 — happy-path validateUserOp returns 0:**
    - Setup, build userOp, sign with Alice's secretKey, compute `userOpHash` via `entryPoint.read.getUserOpHash([signed])`.
    - `const { result } = await account.simulate.validateUserOp([signed, userOpHash, 0n], { account: entryPoint.address });`
    - `assert.equal(result, 0n);`  // SIG_VALIDATION_SUCCESS
  - **AC-4 — source inspection (mirror Story 2-1 AC-4):**
    - `const source = await readFile("contracts/FalconAccount.sol", "utf8");`
    - Assert: `source.includes("falconVerifier.verify(publicKey, userOpHash, userOp.signature)")` (exact call pattern)
    - Assert: `source.includes("try")` AND `source.includes("catch")` (try/catch wrapping)
    - Assert: `source.includes("SignatureMalformed")` (custom error declared)
  - Suggested test labels: `"AC-1: keygen returns 897-byte Falcon-512 publicKey"`, `"AC-2: signed UserOp signature is 1064 bytes (salt + s2_compact)"`, `"AC-3: valid Falcon signature returns SIG_VALIDATION_SUCCESS"`, `"AC-4: contract source uses try/catch around falconVerifier.verify with SignatureMalformed"`

- [ ] **Task 7: Compile + full test gate**
  - Maps to: AC-1, AC-2, AC-3, AC-4
  - Run `npm run compile` — verify zero non-submodule warnings (only the tolerated ETHFALCON `slen` warning per C-001 may appear). If `FalconAccount.sol` triggers warnings, diagnose before proceeding (likely unused variable from the `address` initialize arg — annotate or document).
  - Run `npm test` — verify ALL of: (a) Story 1-1 smoke (with the Task 5 modification), (b) Story 2-1 `ecdsa.test.ts` still passes (Task 3 refactor must be byte-equivalent), (c) Story 3-1 `falcon.test.ts` passes all 4 AC tests.
  - Sub-wave parallelism check vs Story 4-1: 4-1 will touch `test/signers/ml-dsa.ts`, `test/signers/ml-dsa-encoding.ts`, `test/accounts/mldsa.test.ts`, `contracts/MlDsaAccount.sol`. **Story 3-1's Task 3 (extracting `userOpHash.ts`) creates a shared file Story 4-1 will also import.** This is the only cross-wave coupling — flag at orchestrator level: 3-1 must complete (or at least Task 3) before 4-1's signer task starts, OR 4-1 inlines the hash again with a follow-up extraction in a later story. Recommend: complete 3-1 Task 3 in isolation as the first commit of this story; 4-1 then consumes it cleanly.

## must_haves

truths:
  - "`contracts/FalconAccount.sol` exists, declares `contract FalconAccount is SimpleAccount`, has an immutable `ZKNOX_falcon public immutable falconVerifier` field, a `bytes public publicKey` storage field, an `initialize(address, bytes calldata _publicKey) public initializer` that assigns `publicKey = _publicKey` (the 20-byte SSTORE2 pointer per C-005 resolution, NOT the raw 897-byte key), and a `_validateSignature` override that calls `falconVerifier.verify(publicKey, userOpHash, userOp.signature)` inside a try/catch returning `SIG_VALIDATION_SUCCESS` / `SIG_VALIDATION_FAILED` and reverting `SignatureMalformed()` on catch"
  - "`contracts/FalconAccount.sol` declares `error SignatureMalformed();` at contract scope"
  - "`test/signers/falcon.ts` no longer throws `NotImplementedError` — both `keygen()` and `signUserOp(...)` are real implementations backed by `@noble/post-quantum/falcon`'s `falcon512` API"
  - "`keygen(\"falcon\")` returns a `Keypair` whose `publicKey.length === 897` and whose `secretKey` is noble-encoded Falcon-512 secret-key bytes"
  - "`signUserOp(\"falcon\", aliceSecretKey, userOp, entryPointAddress, chainId)` returns a `PackedUserOperation` whose `signature` field, when decoded from hex, is exactly 1064 bytes (40-byte salt + 1024-byte s2_compact = 32 × uint256 words)"
  - "`test/signers/falcon-encoding.ts` exports `encodePublicKeyForZKNOX(rawPublicKey: Uint8Array)` and `encodeSignatureForZKNOX(nobleSig: Uint8Array)`; both produce ZKNOX-compatible byte layouts (encoded pubkey = ABI-encoded `uint256[32]`; encoded sig = 1064 bytes)"
  - "`test/signers/userOpHash.ts` exports `computeUserOpHash(userOp, entryPointAddress, chainId)`; both `test/signers/ecdsa.ts` and `test/signers/falcon.ts` import and use it (no inline duplication of the EIP-4337 v0.7 hashing logic)"
  - "`test/accounts/falcon.test.ts` deploys FalconAccount via `ERC1967Proxy` (per A-002), funds the SSTORE2 pointer via `falconVerifier.setKey()`, and asserts `account.simulate.validateUserOp([signed, userOpHash, 0n], { account: entryPoint.address }).result === 0n` for an Alice-signed UserOp"
  - "`test/accounts/falcon.test.ts` includes an AC-4 source-inspection assertion that reads `contracts/FalconAccount.sol` and asserts the string `falconVerifier.verify(publicKey, userOpHash, userOp.signature)` is present along with a `try`/`catch` and a `SignatureMalformed` reference"
  - "`test/smoke.test.ts` no longer asserts that `keygen(\"falcon\")` throws `NOT_IMPLEMENTED` — replaced with a 897-byte length assertion. The `mldsa keygen throws NOT_IMPLEMENTED` assertion is untouched"
  - "`npm run compile` and `npm test` both succeed; only the tolerated ETHFALCON `slen` warning (C-001) appears; no story disables, skips, or quarantines tests"

artifacts:
  - path: "contracts/FalconAccount.sol"
    contains: ["SimpleAccount", "ZKNOX_falcon", "falconVerifier", "publicKey", "_validateSignature", "SignatureMalformed", "try", "catch", "SIG_VALIDATION_SUCCESS", "SIG_VALIDATION_FAILED"]
  - path: "test/signers/falcon.ts"
    contains: ["falcon512", "keygen", "signUserOp", "encodeSignatureForZKNOX", "computeUserOpHash"]
  - path: "test/signers/falcon-encoding.ts"
    contains: ["encodePublicKeyForZKNOX", "encodeSignatureForZKNOX"]
  - path: "test/signers/userOpHash.ts"
    contains: ["computeUserOpHash", "encodeAbiParameters", "keccak256"]
  - path: "test/signers/ecdsa.ts"
    contains: ["computeUserOpHash"]
  - path: "test/accounts/falcon.test.ts"
    contains: ["deployEntryPoint", "FalconAccount", "ZKNOX_falcon", "encodePublicKeyForZKNOX", "ERC1967Proxy", "validateUserOp", "getUserOpHash", "SIG_VALIDATION", "SignatureMalformed"]
  - path: "test/smoke.test.ts"
    contains: ["falcon", "897"]

key_links:
  - pattern: "is SimpleAccount"
    in: ["contracts/FalconAccount.sol"]
  - pattern: "ZKNOX_falcon public immutable falconVerifier"
    in: ["contracts/FalconAccount.sol"]
  - pattern: "bytes public publicKey"
    in: ["contracts/FalconAccount.sol"]
  - pattern: "error SignatureMalformed"
    in: ["contracts/FalconAccount.sol"]
  - pattern: "falconVerifier.verify(publicKey, userOpHash, userOp.signature)"
    in: ["contracts/FalconAccount.sol"]
  - pattern: "import \"../ETHFALCON/src/ZKNOX_falcon.sol\""
    in: ["contracts/FalconAccount.sol"]
  - pattern: "from \"@noble/post-quantum/falcon\""
    in: ["test/signers/falcon.ts"]
  - pattern: "falcon512.keygen"
    in: ["test/signers/falcon.ts"]
  - pattern: "falcon512.sign"
    in: ["test/signers/falcon.ts"]
  - pattern: "encodeSignatureForZKNOX"
    in: ["test/signers/falcon.ts", "test/signers/falcon-encoding.ts"]
  - pattern: "encodePublicKeyForZKNOX"
    in: ["test/signers/falcon-encoding.ts", "test/accounts/falcon.test.ts"]
  - pattern: "computeUserOpHash"
    in: ["test/signers/userOpHash.ts", "test/signers/ecdsa.ts", "test/signers/falcon.ts"]
  - pattern: "deployContract(\"ZKNOX_falcon\")"
    in: ["test/accounts/falcon.test.ts"]
  - pattern: "deployContract(\"ERC1967Proxy\""
    in: ["test/accounts/falcon.test.ts"]
  - pattern: "setKey"
    in: ["test/accounts/falcon.test.ts"]
  - pattern: "impersonateAccount"
    in: ["test/accounts/falcon.test.ts"]
  - pattern: "getUserOpHash"
    in: ["test/accounts/falcon.test.ts"]

## Dev Notes (advisory)

**No new package dependencies for this story.** `@noble/post-quantum@^0.6.1` is already installed (Story 1-1 / package.json:12). All viem helpers and HH3 toolbox are in place. No `hardhat.config.ts` change unless compile fails to find a `ZKNOX_falcon` artifact (very unlikely — `FalconRef.sol` already pulls it in).

**Library version status:** `@noble/post-quantum@^0.6.1` — VERIFIED present in `package.json:12`. Per story-creator protocol no web-search was performed since the package is already pinned by the consuming project. If implement skill detects a compatibility gap with `^0.6.x` (e.g., signature format changed between minor versions), search npm for the latest stable Falcon-512-supporting release before proposing a bump — DO NOT silently update; surface as a Rule 2 deviation.

**Encoding bridge — implementation strategy decision tree:**

```
Try: pure-TS port of _ZKNOX_NTT_Decompress + _Compact + NTT
  ├─ Works → ship. Compact (no extra runtime deps). Verifier byte-equivalence test green.
  └─ Doesn't work or burns >50% of story budget on it
       └─ Fallback: child_process spawn ETHFALCON/pythonref/sig_sol.py
            └─ Document: requires `python3 -m venv ETHFALCON/pythonref/myenv && pip install -r ETHFALCON/pythonref/requirements.txt` as a one-time local-dev step (add to `docs/local-dev.md` if creating it; otherwise note in this Dev Notes section under a "Falcon signer setup" subheading)
            └─ `test/signers/falcon-encoding.ts` becomes a thin wrapper around the Python invocation; the public function signatures don't change
```

**hashToPointNIST risk (read carefully):** Noble's Falcon-512 internally hashes the message via SHAKE256 over `salt || msg` to produce the 512 hashed-point coefficients. ZKNOX's `hashToPointNIST(salt, h)` (called inside `verify`) does the same NIST-spec algorithm. They SHOULD agree byte-for-byte when given identical `(salt, msg)` inputs. **If they don't,** the encoding bridge produces structurally valid signatures that the on-chain verifier rejects cryptographically (validationData = 1). The first thing to check when AC-3 fails is: does ZKNOX's `verify` produce `0xFFFFFFFF` (crypto failure → likely hash mismatch) or revert with one of the `"invalid * length"` strings (format failure → encoding bridge bug)? Add a temporary `console.log` of the raw return inside the test to discriminate; remove before committing.

**Wave-2 parallelism note (orchestrator-relevant):** Story 3-1 Task 3 introduces `test/signers/userOpHash.ts` — a NEW file Story 4-1 will also import. Unless 3-1 lands first, 4-1 will need to either (a) duplicate the hash logic and accept a follow-up refactor commit, or (b) wait for 3-1 Task 3. The remaining wave-2 collisions are zero: `test/signers/{falcon,ml-dsa}.ts`, `test/signers/{falcon,ml-dsa}-encoding.ts`, `contracts/{Falcon,MlDsa}Account.sol`, `test/accounts/{falcon,mldsa}.test.ts` are all disjoint between 3-1 and 4-1.

**`npmFilesToBuild` note:** `hardhat.config.ts:16-19` already lists `EntryPoint.sol` and `ERC1967Proxy.sol`. Story 3-1 should NOT need to add anything — `ZKNOX_falcon` reaches the compile graph via `contracts/imports/FalconRef.sol` (Story 1-1 §Architecture Guardrails). If Hardhat fails to find `ZKNOX_falcon`'s artifact at deploy time, log a Rule 1 deviation and add the explicit submodule path (or reorganize FalconRef.sol's imports) — do not silently work around it.

**Assertion library:** `node:assert/strict` only. No chai. Story 2-1's pattern of using viem's `BaseError`/`ContractFunctionRevertedError` for revert discrimination is the established convention — reuse it for any revert-class assertions in Story 3-1's tests (Story 3-2 will exercise this surface more heavily).

**Test data:** Fresh keypairs per test (architecture §Test Data). No hardcoded secret keys or signatures. The test vectors in `ETHFALCON/test/falcon.t.sol` are reference-only — do NOT copy them into Story 3-1 tests; they prove the verifier works in isolation, not that our pipeline produces compatible bytes.

**What is NOT in this story:**
- Wrong-key, bit-flip, malformed-signature rejection paths — Story 3-2.
- Gas measurement or `handleOps` end-to-end flow — Story 5-1.
- ML-DSA equivalent — Story 4-1.
- SSTORE2 alternative encodings (e.g., direct `bytes` storage of the 897-byte raw key) — DD-8 [DISCRETION] permits this in principle, but the architecture's chosen verifier interface forces SSTORE2 for Falcon. Out of scope to revisit.

> Ref: test/accounts/ecdsa.test.ts — proxy + impersonate + simulate pattern to mirror
> Ref: test/signers/ecdsa.ts — userOpHash derivation to extract into shared helper (Task 3)
> Ref: ETHFALCON/test/falcon.t.sol — reference of expected `(salt, s2, pkc)` shape the verifier consumes (do NOT copy values into our tests)
> Ref: ETHFALCON/pythonref/sig_sol.py — fallback path if pure-TS encoding bridge proves intractable

## Detected Patterns

Codebase scanned for analogous patterns (4 sample files):

- `contracts/EcdsaAccount.sol` — sole prior account contract; provides SPDX/pragma/NatSpec template. Body shape diverges (Falcon adds verifier ref + storage + initialize + override) so only the file-header convention transfers.
- `test/accounts/ecdsa.test.ts` — sole prior account test; provides `setup()` / `buildUnsignedUserOp` / `canonicalUserOpHash` / `simulateValidateUserOp` patterns to mirror exactly.
- `test/signers/ecdsa.ts` — provides the userOpHash derivation that Task 3 extracts; provides the `signUserOp(secretKey, userOp, entryPointAddress, chainId): Promise<PackedUserOperation>` shape Task 2 must match.
- `test/fixtures/entryPoint.ts` — provides the `hre.network.connect()` → `viem.deployContract` pattern. `ZKNOX_falcon` deploys the same way (no constructor args); a separate verifier fixture is NOT needed since each test deploys its own instance per DD-9.

| Pattern | Value | Sampled from | Established? |
|---------|-------|-------------|-------------|
| Test runner | `node:test` + `node:assert/strict` | `test/smoke.test.ts`, `test/accounts/ecdsa.test.ts` | Established |
| ESM relative-import extension | `.js` suffix on TS-source relatives | every `test/**/*.ts` file in tree | Established |
| Account proxy deploy | `viem.deployContract(impl, args)` → `encodeFunctionData(initialize)` → `viem.deployContract("ERC1967Proxy", [implAddr, initData])` → `getContractAt` | `test/accounts/ecdsa.test.ts:56-68` | Established (A-002 BINDING) |
| EntryPoint impersonation | `testClient.impersonateAccount` + `setBalance(parseEther("1"))` | `test/accounts/ecdsa.test.ts:70-74` | Established |
| Direct validateUserOp | `account.simulate.validateUserOp([...], { account: entryPoint.address })` returning `{result}` | `test/accounts/ecdsa.test.ts:119-130` | Established |
| Canonical userOpHash | `entryPoint.read.getUserOpHash([packed])` (live contract — no drift risk) | `test/accounts/ecdsa.test.ts:106-111` | Established |
| Source-inspection AC | `await readFile("contracts/X.sol", "utf8")` + `assert.ok(source.includes(...))` | `test/accounts/ecdsa.test.ts:241-252` | Established (C-003 caveat: CWD-relative; same caveat applies here) |
| Custom-revert discrimination | `BaseError.walk(e => e instanceof ContractFunctionRevertedError)` → `revert.data.errorName` | `test/accounts/ecdsa.test.ts:215-233` | Established (Story 3-2 will exercise heavily; Story 3-1 happy-path doesn't need it) |
| SPDX / pragma | `// SPDX-License-Identifier: GPL-3.0` + `pragma solidity 0.8.34;` | `contracts/EcdsaAccount.sol:1-2` | Established |
| Submodule import path | `import "../ETHFALCON/src/..."` (relative through repo) | `contracts/imports/FalconRef.sol:19-22` | Established |

No conflicts detected. Falcon-encoding bridge has no analogue in the existing codebase — greenfield (Inline Decision List rule 3 default: inline the prescription above).

## Wave Structure

Story 3-1 is Wave 2 (`docs/plan.md` §Wave Assignments) — parallel with Stories 2-1 (done) and 4-1 (pending). The 7 internal tasks have these dependencies:

- **Sub-wave A (parallel):** Task 1 (`FalconAccount.sol`) and Task 3 (extract `userOpHash.ts`) are independent — different files, no shared state. Task 2 (real `falcon.ts`) depends on Task 3 (consumes `computeUserOpHash`).
- **Sub-wave B:** Task 4 (`falcon-encoding.ts`) is independent of Tasks 1–3 in principle (pure helper) but is consumed by Task 2's `signUserOp`. Land Task 4 before Task 2's verification step, OR stub Task 4's exports first and fill them in iteratively.
- **Sub-wave C:** Task 5 (smoke-test update) depends only on Task 2 — landing Task 2 will break the smoke test until Task 5 lands. They should ship in the same commit (or back-to-back) to keep the suite green.
- **Sub-wave D:** Task 6 (`falcon.test.ts`) depends on Tasks 1, 2, 4 (and transitively 3). It's the integration gate.
- **Sub-wave E:** Task 7 (compile + test gate) — final, depends on everything.

**Ordering recommendation for the implement skill:** Task 3 → Task 1 → Task 4 (with stubbed exports) → Task 2 → Task 5 → flesh out Task 4 with real encoders if not done → Task 6 → Task 7. Task 3 first protects Wave-2 sibling Story 4-1; the rest is local to this story.

**Cross-story wave-independence audit (vs Story 4-1):**

| Output file | 3-1 | 4-1 | Conflict? |
|-------------|-----|-----|-----------|
| `contracts/{X}Account.sol` | `FalconAccount.sol` | `MlDsaAccount.sol` | None (disjoint) |
| `test/signers/{X}.ts` | `falcon.ts` | `ml-dsa.ts` | None |
| `test/signers/{X}-encoding.ts` | `falcon-encoding.ts` | `ml-dsa-encoding.ts` (likely needed for ML-DSA too) | None |
| `test/signers/userOpHash.ts` | CREATES + consumes | CONSUMES | **Soft dependency** — see Dev Notes wave-2 parallelism note |
| `test/accounts/{X}.test.ts` | `falcon.test.ts` | `mldsa.test.ts` | None |
| `test/smoke.test.ts` | Task 5 modifies the falcon-throws assertion | Task 5-equivalent modifies the mldsa-throws assertion | Append-only edits, commutative; no real conflict |
| `hardhat.config.ts` | No edit expected | No edit expected | None |
| `package.json` | No edit | No edit | None |

The only true coupling is `userOpHash.ts`. Recommendation propagated to orchestrator above.
