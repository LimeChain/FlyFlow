---
feature: pqc-4337
created: 2026-04-14
---

# Amendments

## A-001: Migrate to Hardhat 3 + viem toolbox

**Date:** 2026-04-14
**Phase at time of amendment:** Phase 5 (Implement), Story 1-1 in-progress, 4 tasks committed on HH2
**Decided by:** user `[X] Change Direction` during Story 1-1 Task 3 checkpoint

### Motivation
Hardhat 3.3.0 is the current stable release (`latest` dist-tag); `hardhat@2.28.6` is on the legacy `hh2` tag. Project is in its scaffolding phase — lowest-cost time to migrate. User explicitly chose to upgrade now rather than defer.

### Architecture amendments

**DD-1 [LOCKED]** in `docs/architecture.md`:

- BEFORE: "Hardhat + TypeScript is the testing/benchmarking toolchain."
- AFTER: "Hardhat 3.x + TypeScript + viem is the testing/benchmarking toolchain. Use `@nomicfoundation/hardhat-toolbox-viem@^5.0.3`. Drop TypeChain (no HH3 release); rely on viem's native codegen."

### Plan amendments

**Story 5-1 AC-1** in `docs/plan.md`:

- BEFORE: "Given all three deployed accounts, When the benchmark test runs `entryPoint.handleOps([signedUserOp])` for each scheme, Then `hardhat-gas-reporter` captures per-scheme gas used."
- AFTER: "Given all three deployed accounts, When the benchmark test runs `entryPoint.handleOps([signedUserOp])` for each scheme, Then Hardhat 3's built-in gas tracking captures per-scheme gas used (e.g., via `publicClient.estimateGas` on the transaction or `network.provider`'s gas measurements)."

**Rationale:** `hardhat-gas-reporter@2.3.0` declares `peerDependencies: { hardhat: '^2.16.0' }` and has no HH3 release as of 2026-04. HH3 provides equivalent functionality natively.

**`@typechain/hardhat`** dropped from the stack — peer-depends on HH2 (`^2.9.9`). Viem's code generation provides equivalent contract typings.

### Story 1-1 amendments

Story 1-1 must be **regenerated** on HH3 + viem assumptions:

1. `package.json`: `"type": "module"` (HH3 is ESM-only); replace `@nomicfoundation/hardhat-toolbox` with `@nomicfoundation/hardhat-toolbox-viem@^5.0.3`; drop `@typechain/hardhat`, `typechain`, `@typechain/ethers-v6`; consider dropping `ethers` in favor of viem (decide in regeneration).
2. `hardhat.config.ts`: ESM syntax, HH3 config schema, Solidity `0.8.34` (verify on throwaway compile).
3. `test/signers/ecdsa.ts`: rewrite from ethers v6 `Wallet.signMessage(getBytes(hash))` to viem equivalent (`privateKeyToAccount(...).signMessage({ message: { raw: hash } })`). The EIP-191 prefix requirement stays the same — SimpleAccount's `toEthSignedMessageHash().recover()` doesn't change.
4. `test/fixtures/entryPoint.ts`: rewrite `ethers.getContractFactory` pattern to HH3 + viem pattern (e.g., `hre.viem.deployContract("EntryPoint")`).
5. `scripts/link-submodule-libs.ts`: re-validate under HH3's config load semantics (HH3 config is async; side-effect imports may behave differently).
6. Warnings-as-errors gate (`scripts/check-compile-warnings.js`): re-validate against HH3's compile output format.
7. Tasks 1–5 must be re-executed; Task 6 smoke test rewritten for viem assertion style (`assertEqual` / viem-native matchers).

### Rollback plan

Before regenerating Story 1-1:

```
git reset --hard e24bf53~1   # drops Tasks 1, 2, 4, 5 (commits e24bf53..c858e5c)
# or, if you want to keep the submodule pinning as a separate commit to cherry-pick later:
git reset --hard 330fc15     # keeps Tasks 1 + 2; drops 4, 5
# then revert Task 1 pieces that clash with ESM
```

The four commits being dropped:
- `c858e5c` feat(signers): ECDSA impl + PQC stubs (ethers v6 — incompatible)
- `89a06ac` feat(fixtures): EntryPoint fixture (ethers.getContractFactory — incompatible)
- `330fc15` chore(submodules): ETHFALCON + ETHDILITHIUM pinning (salvageable — same URLs/SHAs apply)
- `e24bf53` chore(scaffold): HH2 + TypeChain + ethers package set (incompatible)

The staged (uncommitted) Task 3 files must all be discarded:
- `hardhat.config.ts` (HH2 CJS syntax — rewrite required)
- `package.json` (HH2 deps — rewrite required)
- `contracts/imports/FalconRef.sol`, `DilithiumRef.sol` (salvageable — paths stay valid under HH3)
- `scripts/link-submodule-libs.ts` (re-validate)
- `scripts/check-compile-warnings.js` (re-validate)
- `docs/concerns.md` C-001 (ETHFALCON unused-var warning — still applies; keep)

### Execution plan (for next session)

1. Read this amendment and `docs/architecture.md` DD-1 context.
2. Verify Hardhat 3 + Solidity 0.8.34 + viem toolbox compose cleanly on a throwaway branch or `/tmp` dir before touching the repo.
3. `git reset --hard e24bf53~1` (drop all 4 HH2 commits).
4. `git stash` or discard the Task 3 staged files (the salvageable ones — `FalconRef.sol`, `DilithiumRef.sol`, `docs/concerns.md` — can be re-added after regeneration).
5. Reset sprint-status.yaml Story 1-1 status to `in-progress` (already is) and reset `storiesDone` to 0 (already is).
6. Re-spawn `story-creator-agent` for Story 1-1 with the HH3 + viem assumptions — agent must read this amendment and treat DD-1 amendment as binding.
7. Proceed through Tasks 1–6 under the new toolchain.
8. Gate 5 for Story 1-1 must verify this amendment's migration goals are met (all AC still satisfied, HH3 running cleanly).

### Status
`accepted` — awaiting execution in a fresh session.

---

## A-002: Deploy accounts via ERC1967Proxy (not direct instance)

**Date:** 2026-04-14
**Phase at time of amendment:** Phase 5 (Implement), Story 2-1 Task 2
**Decided by:** implementation forced by `InvalidInitialization()` revert at test time

### Motivation

Story 2-1's draft plan assumed a test setup that (a) deploys `EcdsaAccount`
directly via `viem.deployContract("EcdsaAccount", [entryPoint])`, then
(b) calls `account.write.initialize([alice])`. This fails:

```
reverted with custom error 'InvalidInitialization()'
  at EcdsaAccount.initializer (@openzeppelin/contracts/proxy/utils/Initializable.sol:121)
  at EcdsaAccount.initialize (@account-abstraction/contracts/samples/SimpleAccount.sol:90)
```

`SimpleAccount`'s constructor calls `_disableInitializers()`, which in
OpenZeppelin v5 writes `_initialized = type(uint64).max` into the
deployed instance's storage — blocking any subsequent `initializer`-gated
call. This is intentional: SimpleAccount is designed to be a logic
contract behind an ERC-1967 proxy (as the upstream `SimpleAccountFactory`
does). Direct-instance initialization is not a supported flow.

The story's speculation that "_disableInitializers() locks calls on the
*logic* contract reached via delegatecall — not relevant here since we're
not using a proxy" was incorrect for OZ v5.

### Architecture / plan amendment

**PD-3 (testing pattern)** in `docs/architecture.md` is AMENDED:
account-under-test setup in all `test/accounts/*.test.ts` files MUST
deploy a proxy, not the implementation directly. Canonical helper shape:

```ts
const implementation = await viem.deployContract("{Scheme}Account", [entryPoint.address]);
const initData = encodeFunctionData({
  abi: implementation.abi,
  functionName: "initialize",
  args: [ownerAddress],
});
const proxy = await viem.deployContract("ERC1967Proxy", [
  implementation.address,
  initData,
]);
const account = await viem.getContractAt("{Scheme}Account", proxy.address);
```

This matches production deployment (users deploy via a factory that
creates an `ERC1967Proxy` pointing at one shared implementation). It
also preserves the gas-measurement fidelity DD-10 was written to
protect — Story 5-1's benchmark will see the real DELEGATECALL + SLOAD
proxy overhead every production 4337 account pays.

### Repo changes

- `hardhat.config.ts`: append
  `"@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol"` to
  `solidity.npmFilesToBuild` so the proxy bytecode is emitted.
- `test/accounts/ecdsa.test.ts`: uses the proxy setup (Story 2-1 Task 2).

### Downstream impact

Stories **3-1**, **4-1**, and **5-1** must use the proxy setup. Stories
3-1 and 4-1 haven't been written yet — the story-creator-agent for each
should read this amendment. Story 5-1's gas benchmark is unaffected in
its comparison semantics (proxy overhead is identical across schemes),
but the absolute gas numbers will include DELEGATECALL + SLOAD cost,
which is the correct production-reflective measurement.

Stories 3-2 and 4-2 (failure-class tests) inherit the same setup.

### Status
`accepted` — applied in Story 2-1 Task 2.

---

## A-003: PQC accounts store the SSTORE2 pointer, not the raw public key

**Date:** 2026-04-15
**Phase at time of amendment:** Phase 5 (Implement), Story 3-1 pre-execution
**Decided by:** user `[X] Change Direction` resolving C-005 generally (was scoped to Falcon-only in Story 3-1 draft)

### Motivation

Story 3-1's draft resolved C-005 (`publicKey` field type differs across schemes) for Falcon by splitting the field across two layers — off-chain `Keypair.publicKey` holds noble's raw NIST key (897 bytes for Falcon-512); on-chain `bytes public publicKey` holds the 20-byte SSTORE2 pointer returned by the verifier's `setKey`. The same resolution applies to ML-DSA (and any future PQC scheme) verbatim: both `ZKNOX_falcon` and `ZKNOX_dilithium` implement the **same** `ISigVerifier` interface (`ETHFALCON/lib/InterfaceVerifier/src/IVerifier.sol`):

```solidity
interface ISigVerifier {
    function setKey(bytes calldata key) external returns (bytes memory);
    function verify(bytes calldata key, bytes32 hash, bytes calldata signature) external view returns (bytes4);
}
```

`verify`'s `_pubkey` parameter is interpreted as a 20-byte SSTORE2 pointer in **both** implementations — the raw key NEVER appears as `_pubkey`. Storing the raw key on-chain would (a) fail `verify`'s decode contract and (b) waste ~30K gas per validation. Promoting this from a Falcon-specific story-level deviation to a project-wide rule prevents Story 4-1 (ML-DSA) from re-litigating the same decision and locks the contract shape for any future PQC scheme that integrates a `ISigVerifier`-shaped verifier.

### Architecture amendment

**Architecture §Data Models — "Public Key Storage" row** is AMENDED to:

> All PQC accounts (FalconAccount, MlDsaAccount, future PQC accounts) store `bytes public publicKey` — the 20-byte SSTORE2 pointer returned by the corresponding `ISigVerifier.setKey(rawKey)`, NOT the raw NIST-encoded public key.
>
> The signer module's `Keypair.publicKey` continues to hold the raw NIST-encoded key (897 bytes for Falcon-512, 1952 bytes for ML-DSA-65) — that is the input handed to `setKey()`, not the value the account stores.
>
> Per-scheme byte counts in the original architecture row ("Falcon-512: 897 bytes", "ML-DSA-65: 1952 bytes") describe the **off-chain key the signer module exposes**, not the on-chain storage size. On-chain storage is uniformly 20 bytes per account (the SSTORE2 pointer) plus the `setKey`-deployed pointer contract's data.

The original row's intent (size budgeting, validation cost reasoning) is preserved by reading the byte counts as "size of the encoded blob that gets SSTORE2-written and then dereferenced by the verifier" rather than "size of the storage slot on the account."

### Plan / story amendments

**Story 3-1** — already incorporates this resolution (Architecture Guardrails §C-005 RESOLUTION). The Rule 2 deviation logged inside the story for "pattern reinterpretation" is now redundant — A-003 promotes the reinterpretation to an architecture-level rule. The story-creator-agent for any future story can treat A-003 as binding without re-deriving it.

**Story 4-1** (ML-DSA, not yet written) — story-creator-agent must read A-003 and apply it directly. MlDsaAccount's `bytes public publicKey` is the 20-byte SSTORE2 pointer returned by `dilithiumVerifier.setKey(rawKey)`, where `rawKey` is the 1952-byte raw ML-DSA-65 key from `mlDsa65.keygen()`. The encoding-bridge problem (noble format vs ZKNOX expected `uint256[]` form) recurs in a scheme-specific shape — Story 4-1 owns its own bridge.

**Stories 5-1, 3-2, 4-2** — no contract-shape change needed. Inherit through 3-1 and 4-1.

### Repo changes

None directly required by this amendment — Story 3-1 already implements the rule. Forward stories inherit it.

### Status
`accepted` — applied prospectively to Story 3-1; binding for Story 4-1 and beyond.

---

## A-004: ML-DSA-44 (FIPS 204 Level 2), not ML-DSA-65

**Date:** 2026-04-15
**Phase at time of amendment:** Phase 5 (Implement), Story 4-1 Task 6 complete (all 4 ACs passing)
**Decided by:** binding constraint — `ETHDILITHIUM/src/ZKNOX_dilithium_utils.sol:44-45` hard-codes `k=4, l=4`, the ML-DSA-44 parameter set. The plan's "ML-DSA-65" target is unrealizable on the chosen verifier. DD-7 [DISCRETION] anticipated this adjustment.

### Motivation
ZKNOX's `ZKNOX_dilithium` verifier is parameter-locked to ML-DSA-44 (NIST FIPS 204 Level 2): `k=4, l=4`, `GAMMA_1=131072 (2^17)`, `OMEGA=80`, `TAU=39`. Targeting ML-DSA-65 would require a separate verifier the submodule does not provide. Story 4-1 implementation used noble's `ml_dsa44` and shipped a ZKNOX-compatible encoding bridge; AC-3 verifies a real signature on-chain.

### Architecture amendments

**`docs/architecture.md` §136 (signature blob row), §144 (publicKey storage row), §154 (security row), DD-7 (lines 156, 282):**

- BEFORE: "ML-DSA-65 — 3,309 bytes signature, 1,952 bytes publicKey, ~192-bit security"
- AFTER: "ML-DSA-44 — 2,420 bytes signature (cTilde 32 + z 2304 + h 84), 1,312 bytes raw publicKey (off-chain) / 20-byte SSTORE2 pointer on-chain (per A-003), ~128-bit (NIST Level 2) security"

DD-7 transitions from `[DISCRETION]` to `[LOCKED]`: "Parameter sets are Falcon-512 and ML-DSA-44 (NIST FIPS 204 Level 2). ML-DSA-44 chosen because ETHDILITHIUM hard-codes k=4, l=4 at `ZKNOX_dilithium_utils.sol:44-45`."

### Plan amendments

**Story 4-1 AC-1, AC-2 in `docs/plan.md` (lines 99-100):**

- AC-1 BEFORE: "...returns Alice's ML-DSA-65 keypair via `@noble/post-quantum/ml-dsa` with a 1,952-byte public key."
- AC-1 AFTER: "...returns Alice's ML-DSA-44 keypair via `@noble/post-quantum/ml-dsa44` with a 1,312-byte public key and 2,560-byte secret key."

- AC-2 BEFORE: "...whose `signature` field is a 3,309-byte ML-DSA-65 blob."
- AC-2 AFTER: "...whose `signature` field is a 2,420-byte ML-DSA-44 blob (cTilde 32 + z 2304 + h 84)."

### Implementation notes

The encoding bridge (`test/signers/mldsa-encoding.ts#preparePublicKeyForDeployment`) deviates from ETHDILITHIUM/js/pkDeploy.js in one respect: t1 polynomials are NOT shipped raw. They are pre-shifted by `2^d` (d=13, FIPS 204 Power2Round) and forward-NTT transformed before bit-packing. ZKNOX_dilithium_core.sol#dilithiumCore2 fuses `A*z - c*t1` directly using the stored values (line 199), and the on-chain test vectors at `ETHDILITHIUM/test/dilithium.t.sol:543+` (values up to ~2^23, far outside raw 10-bit range) confirm this storage form. Noble's verifier mirrors the transform inline at `ml-dsa.js:560`. The JS reference (`ETHDILITHIUM/js/pkDeploy.js`) appears not to have been E2E tested.

### Repo changes

- `test/signers/ml-dsa.ts`: uses `@noble/post-quantum/ml-dsa.js#ml_dsa44`.
- `test/signers/mldsa-encoding.ts`: bridges noble's 1,312-byte raw key to the ZKNOX `(uint256[][][] aHat, bytes tr, uint256[][] t1)` ABI tuple, with t1 transformed via `polyShiftl + NTT.encode`.
- `contracts/MlDsaAccount.sol`: validates against `ZKNOX_dilithium` (deployed once per test setup per DD-9 LOCKED).

### Status
`accepted` — implemented in Story 4-1; verified by mldsa.test.ts (AC-1..AC-4 all pass).
