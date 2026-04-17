---
status: complete
feature: pqc-4337
phase: 3
created: 2026-04-12
---

# Architecture: PQC-4337

## Goals & Constraints

**Architecture drivers (from NFRs):**

- NFR-1: All three accounts pass identical ERC-4337 `validateUserOp` entry-point calls
- NFR-2: PQC accounts differ from baseline only in signature validation logic
- NFR-3: Deterministic gas (<1% variance across repeated runs)
- NFR-4: Full benchmark suite completes in ≤ 5 minutes wall-clock on a standard developer workstation
- NFR-5: PQC libraries consumed as read-only git submodules with zero source modifications

**Terminology:** "FN-DSA" is NIST's draft name (FIPS 206, pending) for the Falcon signature scheme. Since the standard is not finalized, this architecture uses "Falcon" throughout for the Round-3 submission that both `@noble/post-quantum` and ZKNoxHQ/ETHFALCON implement. "ML-DSA" (FIPS 204) is final and used as-is.

**Non-negotiable boundaries:**

- Local Hardhat Network only — no testnet/mainnet deployment
- Inherit eth-infinitism `SimpleAccount` — no custom account abstraction base
- Three accounts exactly: ECDSA (baseline), Falcon, ML-DSA
- Off-chain signing in JS/TS via `@noble/post-quantum`
- On-chain verification via ZKNoxHQ standard Solidity verifiers

## Component Decomposition

### Smart Contracts

| Component         | Responsibility                                                        | Dependencies                   |
| ----------------- | --------------------------------------------------------------------- | ------------------------------ |
| `EcdsaAccount`    | Baseline ERC-4337 account. Uses `ecrecover` for signature validation. | SimpleAccount (eth-infinitism) |
| `FalconAccount`   | Falcon signature validation via external verifier call.               | SimpleAccount, ZKNOX_falcon    |
| `MlDsaAccount`    | ML-DSA signature validation via external verifier call.               | SimpleAccount, ZKNOX_dilithium |
| `ZKNOX_falcon`    | Falcon signature verification (read-only submodule).                  | ETHFALCON lib                  |
| `ZKNOX_dilithium` | ML-DSA signature verification (read-only submodule).                  | ETHDILITHIUM lib               |

### Test & Tooling

| Component         | Responsibility                                                                       |
| ----------------- | ------------------------------------------------------------------------------------ |
| `SigningUtils`    | Off-chain UserOp signing for all three schemes using ethers.js + @noble/post-quantum |
| `BenchmarkSuite`  | Hardhat test suite that deploys, signs, validates, and records gas per scheme        |
| `ValidationSuite` | Hardhat test suite for valid/invalid signature acceptance/rejection per scheme       |
| `ReportGenerator` | Script that formats hardhat-gas-reporter output into the comparison markdown report  |

### Dependency Direction

```
Tests (Benchmark/Validation)
  → SigningUtils (off-chain signing)
  → Account Contracts (on-chain)
    → SimpleAccount (eth-infinitism, inherited)
    → ZKNOX verifiers (external call, submodules)
```

No reverse dependencies. Verifier submodules are leaf dependencies with no knowledge of the accounts.

## Smart Contract Interfaces

### Account Contracts

All three accounts share the same inherited interface from SimpleAccount. Only `_validateSignature` differs.

**EcdsaAccount** (baseline — minimal wrapper):

```solidity
contract EcdsaAccount is SimpleAccount {
    constructor(IEntryPoint entryPoint) SimpleAccount(entryPoint) {}

    // Inherits default _validateSignature using ecrecover
    // No override needed — this IS the baseline SimpleAccount behavior
}
```

**FalconAccount:**

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
            // Verifier reverted on decode/format — distinct from crypto failure
            revert SignatureMalformed();
        }
    }
}
```

**MlDsaAccount** — same pattern as FalconAccount, calling `ZKNOX_dilithium.verify`.

### ZKNoxHQ Verifier Interface (ISigVerifier)

The `ISigVerifier` interface is already defined inside the ZKNoxHQ submodules (`ETHFALCON/src/` and `ETHDILITHIUM/src/`). Account contracts import the submodule types directly — **we do not create or duplicate an ISigVerifier.sol file in this repo**. Both verifiers expose the same EIP-style interface:

```solidity
function verify(
    bytes calldata pk,
    bytes32 m,
    bytes calldata signature
) external view returns (bytes4);
// Returns function selector on success, 0xFFFFFFFF on failure
```

Accounts type their verifier field as the concrete submodule contract (`ZKNOX_falcon`, `ZKNOX_dilithium`). If a shared abstraction proves useful later, it will be introduced by importing the submodule's interface — never by redefining it here.

## Data Models

### UserOp Signature Field

The `userOp.signature` field carries scheme-specific bytes:

| Scheme     | Signature size        | Content                                       |
| ---------- | --------------------- | --------------------------------------------- |
| ECDSA      | 65 bytes              | `r (32) + s (32) + v (1)`                     |
| Falcon-512 | ~666 bytes (variable) | Falcon compact signature (salt + s2 encoding) |
| ML-DSA-65  | 3,309 bytes           | ML-DSA signature blob                         |

### Public Key Storage

| Scheme     | Key size           | Storage                                   |
| ---------- | ------------------ | ----------------------------------------- |
| ECDSA      | 20 bytes (address) | `owner` (inherited from SimpleAccount)    |
| Falcon-512 | 897 bytes          | `bytes public publicKey` on FalconAccount |
| ML-DSA-65  | 1,952 bytes        | `bytes public publicKey` on MlDsaAccount  |

PQC public keys are stored on-chain in the account contract. For the PoC this is set once during `initialize()`. The ZKNoxHQ verifiers also support `setKey()` for SSTORE2-based storage, but direct storage is simpler for benchmarking.

### Parameter Sets

| Scheme | Parameter set | Security level | Rationale                                      |
| ------ | ------------- | -------------- | ---------------------------------------------- |
| ECDSA  | secp256k1     | ~128-bit       | EVM native, baseline                           |
| Falcon | Falcon-512    | ~128-bit       | Standard submission, matches ETHFALCON default |
| ML-DSA | ML-DSA-65     | ~192-bit       | NIST recommended, matches ETHDILITHIUM default |

DD-7: Parameter sets are Falcon-512 and ML-DSA-65. If the submodules support different defaults, adjust at implementation time. [DISCRETION]

## Key Workflows

### WF-1: Gas Benchmark (Happy Path)

1. Hardhat compiles all contracts (accounts + verifiers)
2. Test deploys EntryPoint, ZKNOX_falcon verifier, ZKNOX_dilithium verifier
3. Test deploys EcdsaAccount, FalconAccount (with falcon verifier ref), MlDsaAccount (with dilithium verifier ref)
4. For each scheme: `SigningUtils` generates a keypair and signs a UserOp off-chain
5. For each scheme: test calls `entryPoint.handleOps([signedUserOp])` (or direct `validateUserOp`)
6. `hardhat-gas-reporter` captures gas consumed per call
7. `ReportGenerator` reads gas data, computes relative overhead vs ECDSA baseline, writes markdown

**Error path — signature validation failure:** The scheme's `_validateSignature` returns `SIG_VALIDATION_FAILED`. Test records the failure and continues to remaining schemes. Report marks that scheme as failed with reason (AC-U-1).

### WF-2: Signature Rejection (Invalid Input)

1. Deploy all accounts (same as WF-1 steps 2-3)
2. For each scheme: construct a UserOp with a corrupted signature (bit-flip)
3. Submit to `validateUserOp` — assert `SIG_VALIDATION_FAILED` returned
4. For each scheme: construct a UserOp signed with a wrong key
5. Submit to `validateUserOp` — assert `SIG_VALIDATION_FAILED` returned

### WF-3: Valid Signature Acceptance

1. Deploy all accounts (same as WF-1 steps 2-3)
2. For each scheme: generate keypair, sign UserOp with correct key
3. Submit to `validateUserOp` — assert `SIG_VALIDATION_SUCCESS` returned

### WF-4: Calldata vs Computation Decomposition (AC-A-1)

1. After WF-1, for each scheme:
2. Compute calldata cost: count non-zero and zero bytes in `userOp.signature`, apply EVM calldata gas pricing (16 gas/non-zero byte, 4 gas/zero byte)
3. Compute execution cost: total gas minus calldata cost minus base transaction overhead
4. Report both components separately per scheme

## Error Handling Strategy

### On-chain Errors

| Error class                        | Indicator                             | Source          |
| ---------------------------------- | ------------------------------------- | --------------- |
| Malformed signature format         | Revert from verifier (decode failure) | ZKNOX verifiers |
| Cryptographic verification failure | `0xFFFFFFFF` return from verifier     | ZKNOX verifiers |
| Valid signature                    | Function selector return              | ZKNOX verifiers |

**Propagation in accounts:**

- Verifier returns selector → account returns `SIG_VALIDATION_SUCCESS` (`0`)
- Verifier returns `0xFFFFFFFF` (crypto failure) → account returns `SIG_VALIDATION_FAILED` (`1`)
- Verifier reverts (malformed/decode error) → account reverts with `SignatureMalformed()` custom error

**Why not encode error class in `validationData`?** The ERC-4337 `_validateSignature` return value is a packed `uint256`: low 20 bytes are the `authorizer` address (where `0 = success`, `1 = failed`, any other value = aggregator contract address), middle 6 bytes are `validUntil`, high 6 bytes are `validAfter`. Returning e.g. `2` for "malformed" would be interpreted by the EntryPoint as an aggregator at address `0x02`, breaking the standard. The only standards-compliant way to surface a distinct malformed-format class is to revert with a custom error; crypto failure continues to return `SIG_VALIDATION_FAILED`. Tests call `validateUserOp` (or `_validateSignature` via a thin test harness) directly and distinguish the two cases by `revert` vs non-zero return (AC-D-1).

### Off-chain Errors (Test Suite)

- Key generation failure → test fails with descriptive error, scheme marked as failed in report
- Signing failure → same handling
- No silent failures — every scheme produces either gas data or an explicit failure reason

### Error Classes for AC-D-1

Two distinguishable failure classes per PQC account:

| Class                              | Indicator                                  | How tests assert                                                           |
| ---------------------------------- | ------------------------------------------ | -------------------------------------------------------------------------- |
| Malformed signature format         | `revert SignatureMalformed()`              | `expect(...).to.be.revertedWithCustomError(account, 'SignatureMalformed')` |
| Cryptographic verification failure | Return value `SIG_VALIDATION_FAILED` (`1`) | `expect(await account.validateUserOp(...)).to.equal(1)`                    |

```solidity
error SignatureMalformed();   // Verifier reverted (format/decode issue)
// Crypto failure uses the ERC-4337 return value, not a revert — see Error Handling Strategy
```

## Testing Strategy

### Framework & Tools

- **Runner:** Hardhat + hardhat-gas-reporter
- **Language:** TypeScript (Hardhat tests)
- **Assertion:** Chai + @nomicfoundation/hardhat-chai-matchers
- **Signing:** ethers.js (ECDSA), @noble/post-quantum (Falcon, ML-DSA)

### Test Structure

```
test/
  accounts/
    EcdsaAccount.test.ts     — valid sig, invalid sig, wrong-key sig
    FalconAccount.test.ts    — valid sig, invalid sig, wrong-key sig, malformed sig
    MlDsaAccount.test.ts     — valid sig, invalid sig, wrong-key sig, malformed sig
  benchmark/
    gas-benchmark.test.ts    — all three schemes, gas capture
    gas-variance.test.ts     — 3x repeated runs for NFR-3 (<1% variance)
```

### Coverage Approach

- Every FR covered by at least one test file (see Traceability Matrix in spec)
- Gas benchmark tests serve dual purpose: FR-5 (benchmarking) + data collection
- NFR-2 (minimal override) verified by human review — PQC account contracts are ~20 lines of glue over SimpleAccount

### Test Data

- Each test generates fresh keypairs via `keygen()` — no hardcoded keys
- Invalid signatures created by bit-flipping byte 0 of a valid signature
- Wrong-key signatures created by signing with a second independently generated keypair

## Security

**Depth: Low** — internal PoC, no production deployment, no PII, no financial transactions.

- **Dependency scanning:** `npm audit` on JS dependencies; review ZKNoxHQ submodule commit hashes (pinned, not floating)
- **Input sanitization:** Signature bytes are passed directly to ZKNoxHQ verifiers which handle their own validation. Accounts do not parse signature internals.
- **Secret management:** Test keypairs are ephemeral (generated per test run). No private keys stored on disk or in git.
- **Submodule integrity:** Pin submodules to specific commit SHAs, not branches. Verify commit hashes against ZKNoxHQ releases.

## Design Rationale

DD-1: Use Hardhat for testing and gas benchmarking — JS/TS aligns with browser signing needs [LOCKED]
DD-2: Inherit eth-infinitism SimpleAccount as base ERC-4337 implementation [LOCKED]
DD-3: PQC implementations sourced from external repos as read-only git submodules [LOCKED]
DD-4: Three accounts: ECDSA (baseline), Falcon, ML-DSA [LOCKED]
DD-5: On-chain verifiers from ZKNoxHQ (ETHFALCON standard variant, ETHDILITHIUM standard variant); off-chain signing from @noble/post-quantum (falcon, ml-dsa) [LOCKED]
DD-6: Benchmark output as markdown report via hardhat-gas-reporter [LOCKED]
DD-7: Parameter sets — Falcon-512 and ML-DSA-65 as defaults. Adjustable if submodules target different parameter sets. [DISCRETION]
DD-8: PQC public keys stored directly in account contract storage (not SSTORE2) — simpler for PoC, gas cost of key storage is not part of the benchmark since it's a one-time setup cost. [DISCRETION]
DD-9: Verifier contracts deployed as standalone instances, called externally by PQC accounts — keeps submodule code unmodified. [LOCKED]
DD-10: EcdsaAccount is a minimal wrapper (or alias) around SimpleAccount with no override — ensures the baseline measures the exact same code path as eth-infinitism's implementation. [LOCKED]

### Alternatives Considered

**DD-5 alternatives:**

- Use LACNet/sol-falcon-verify for Falcon → rejected: ZKNoxHQ provides both schemes from one org with consistent ISigVerifier interface
- Use @noble/post-quantum for ML-DSA off-chain + custom signer for on-chain → rejected: noble implements NIST standard ML-DSA, compatible with ETHDILITHIUM standard variant

**DD-8 alternatives:**

- Use SSTORE2 via ZKNoxHQ's `setKey()` → deferred to implementation if direct storage proves too expensive for deployment. For benchmarking validation gas, storage method doesn't affect the measured path.

**DD-9 alternatives:**

- Inline verifier logic into account contracts → rejected: violates NFR-5 (zero modifications to PQC source)
- Use library linking → rejected: external call is simpler and keeps submodule contracts unmodified

**DD-10 alternatives:**

- Override `_validateSignature` in EcdsaAccount with identical logic → rejected: any difference, even identical reimplementation, risks measuring something other than the true baseline
