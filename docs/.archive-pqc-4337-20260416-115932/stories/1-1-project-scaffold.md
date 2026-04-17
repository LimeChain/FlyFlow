---
id: "1-1"
slug: project-scaffold
status: ready
created: 2026-04-14
---

# Story: Project scaffold + submodules + signer harness

## User Story
As an engineer, I want a Hardhat project with PQC submodules and a shared signing harness ready to go, so that scheme-specific stories can plug in without reinventing setup.

## Acceptance Criteria

- AC-1: Given a fresh clone, When running `npm install && git submodule update --init`, Then `ETHFALCON/src/ZKNOX_falcon.sol` and `ETHDILITHIUM/src/ZKNOX_dilithium.sol` exist at expected paths pinned to specific commit SHAs.
- AC-2: Given submodules initialized, When running `npx hardhat compile`, Then all submodule verifiers and project contracts compile with zero warnings treated as errors.
- AC-3: Given the EntryPoint fixture, When calling `deployEntryPoint()`, Then a deployed eth-infinitism `EntryPoint` instance is returned for reuse across tests.
- AC-4: Given the signer module at `test/signers/`, When inspected, Then it contains `index.ts` (exports `Scheme`, `Keypair`, `keygen`, `signUserOp`), `ecdsa.ts` (complete implementation), `falcon.ts` (stub throwing `NotImplementedError`), and `ml-dsa.ts` (stub throwing `NotImplementedError`). `index.ts` dispatches on the `scheme` parameter.
- AC-5: Given submodule directories, When running `git diff` inside either submodule, Then output is empty (NFR-5).

## Architecture Guardrails

**Toolchain (DD-1 LOCKED, AMENDED by A-001):** Hardhat 3.x + TypeScript + viem. Use `@nomicfoundation/hardhat-toolbox-viem@^5.0.3`. No TypeChain (no HH3 release), no ethers, no `hardhat-gas-reporter` (HH2 peer dep), no non-viem `hardhat-toolbox`. HH3 is **ESM-only** — `package.json` must declare `"type": "module"` and all `.ts`/`.js` sources must use ESM syntax.

**Solidity target:** `0.8.34` (AMENDED by A-001; verify on throwaway compile). EVM version: `cancun` — required because ETHDILITHIUM uses `mcopy`. Optimizer enabled, runs: `200`.

**Submodules (DD-3, DD-5 LOCKED, NFR-5):** Consumed read-only. Zero source modifications. Pinned commits (already in `.gitmodules` + tree):
- ETHFALCON → `03ed0d60c67087527de7c4a3c1c469b89611bd68`
- ETHDILITHIUM → `b9ca7f72526ecc696230d3c774a6e2c12c9b37c2`

**Submodule compile-graph entry (DD-9 LOCKED):** Project contracts must not duplicate verifier code. `contracts/imports/FalconRef.sol`, `DilithiumRef.sol`, and `EntryPointRef.sol` (already on disk) surface the submodule + eth-infinitism contracts to Hardhat's compile graph via import side-effects only. They must remain.

**Bare-import resolution:** ETHFALCON submodule sources use bare imports (`import "sstore2/SSTORE2.sol"` and `import "InterfaceVerifier/IVerifier.sol"`). Hardhat resolves these via `node_modules/<pkg>/` lookups. Since NFR-5 forbids editing submodule imports, `scripts/link-submodule-libs.ts` (already on disk) stages `node_modules/sstore2/` and `node_modules/InterfaceVerifier/` as symlink stubs pointing into `ETHFALCON/lib/`. The script is imported from `hardhat.config.ts` for its side effect. Re-validate under HH3's async config load — if side-effect import is unreliable, switch to an npm `postinstall` hook or a `prepare` script.

**Warnings-as-errors gate (NFR-5 support):** Project-authored Solidity contracts must compile with zero warnings. Submodule-originated warnings are tolerated (NFR-5 — we cannot edit the source). Concern C-001 documents the known ETHFALCON `slen` unused-variable warning — still applies post-migration. Use `scripts/check-compile-warnings.js` (already on disk) to parse compile logs and fail on any non-submodule warning. Re-validate against HH3's compile output format — HH3's solc driver may reformat `-->` location lines.

**Signer module layout (PD-2 LOCKED):** `test/signers/{index,ecdsa,falcon,ml-dsa}.ts` plus `errors.ts`. Per-scheme files enable Wave 2 parallelism (Stories 2-1, 3-1, 4-1 touch disjoint signer files). `index.ts` is the only dispatcher.

**Signer contract (from plan §Interface Contracts, LOCKED):**
```typescript
type Scheme = "ecdsa" | "falcon" | "mldsa";
type Keypair = { publicKey: Uint8Array; secretKey: Uint8Array };

export function keygen(scheme: Scheme): Keypair;
export function signUserOp(
  scheme: Scheme,
  secretKey: Uint8Array,
  userOp: UnsignedUserOp,
  entryPointAddress: string,
  chainId: bigint,
): Promise<PackedUserOperation>;
```

**ECDSA signing (A-001 §3):** Use viem `privateKeyToAccount(pk).signMessage({ message: { raw: hash } })`. The EIP-191 prefix behavior is unchanged — SimpleAccount's `toEthSignedMessageHash().recover()` still works. `{ message: { raw: ... } }` tells viem to prefix the raw bytes (not sign them as a prehash); matches ethers' `signMessage(getBytes(hash))` semantics byte-for-byte.

**Not-implemented error (Story 1-1 only implements ECDSA):** `NotImplementedError extends Error` with `code: "NOT_IMPLEMENTED"` and a `scheme` field. Stubs for `falcon.ts` and `ml-dsa.ts` throw from both `keygen` and `signUserOp`. Defined in `test/signers/errors.ts` and consumed by both PQC stubs.

**EntryPoint fixture (A-001 §4):** Use `hre.viem.deployContract("EntryPoint")` — HH3 + viem deploys and returns a typed contract instance with `address` and `abi`. Fixture returns `{ entryPoint, publicClient, walletClients }` for test reuse. `contracts/imports/EntryPointRef.sol` (already on disk) re-exports `@account-abstraction/contracts/core/EntryPoint.sol` into the compile graph — keep it.

**What is NOT in this story:** The three Account contracts (EcdsaAccount, FalconAccount, MlDsaAccount) are defined in Stories 2-1, 3-1, 4-1 respectively. This story must not create them.

> Ref: docs/architecture.md#Testing Strategy — test-file layout conventions
> Ref: docs/architecture.md#Design Rationale — DD-1…DD-10 rationale (DD-1 AMENDED, see amendments.md A-001)
> Ref: docs/amendments.md#A-001 — migration goals and rollback plan (BINDING)
> Ref: docs/concerns.md#C-001 — tolerated ETHFALCON submodule warning

## Verified Interfaces

**Note:** Story 1-1 is the first story. No prior implementations exist to verify against. Upstream interfaces (ZKNOX verifiers, eth-infinitism EntryPoint) are consumed in later stories — this story only imports them for the compile graph. All signatures below come from the plan's `Interface Contracts` section or upstream sources as placeholders. The implement skill should web-search versions at audit time and flag any version drift.

### `keygen(scheme)` — to be DEFINED by this story
- **Source:** `test/signers/index.ts` (to be created)
- **Signature (from plan):** `function keygen(scheme: Scheme): Keypair`
- **Plan match:** ⚠ UNVERIFIED — source not yet implemented, using plan contract

### `signUserOp(scheme, secretKey, userOp, entryPointAddress, chainId)` — to be DEFINED by this story
- **Source:** `test/signers/index.ts` (to be created)
- **Signature (from plan):** `function signUserOp(scheme: Scheme, secretKey: Uint8Array, userOp: UnsignedUserOp, entryPointAddress: string, chainId: bigint): Promise<PackedUserOperation>`
- **Plan match:** ⚠ UNVERIFIED — source not yet implemented, using plan contract

### `deployEntryPoint()` — to be DEFINED by this story
- **Source:** `test/fixtures/entryPoint.ts` (to be created)
- **Signature:** `async function deployEntryPoint(): Promise<{ entryPoint: GetContractReturnType, publicClient: PublicClient, walletClients: WalletClient[] }>`
- **Plan match:** ⚠ UNVERIFIED — source not yet implemented; shape derived from HH3 viem-toolbox conventions

### `ZKNOX_falcon.verify` (upstream, consumed in later stories)
- **Source:** `ETHFALCON/src/ZKNOX_falcon.sol:81`
- **Signature:** `function verify(bytes calldata _pubkey, bytes32 _digest, bytes calldata _sig) external view returns (bytes4)`
- **File hash:** skipped — read-only submodule pinned at `03ed0d60c67087527de7c4a3c1c469b89611bd68`
- **Plan match:** ✓ Matches architecture `ISigVerifier` shape

### `ZKNOX_dilithium.verify` (upstream, consumed in later stories)
- **Source:** `ETHDILITHIUM/src/ZKNOX_dilithium.sol:69`
- **Signature:** `function verify(bytes calldata pk, bytes32 m, bytes calldata signature) external view returns (bytes4)`
- **File hash:** skipped — read-only submodule pinned at `b9ca7f72526ecc696230d3c774a6e2c12c9b37c2`
- **Plan match:** ✓ Matches architecture `ISigVerifier` shape

## Tasks

- [ ] **Task 1: `package.json` + `tsconfig.json` (HH3 ESM)**
  - Maps to: AC-2, AC-4
  - Files: `package.json`, `tsconfig.json`, `.gitignore` (additions)
  - `package.json` must include:
    - `"type": "module"` (HH3 ESM-only)
    - `devDependencies`: `hardhat@^3.3.0`, `@nomicfoundation/hardhat-toolbox-viem@^5.0.3`, `viem@^2.x`, `typescript@^5.x`, `@types/node@^22.x`, `@account-abstraction/contracts@^0.7.0`, `@noble/post-quantum@^0.5.4`
    - `scripts.compile`: `hardhat compile 2>&1 | tee compile.log && node scripts/check-compile-warnings.js compile.log`
    - `scripts.test`: `hardhat test`
    - **DO NOT** include: `ethers`, `@typechain/hardhat`, `typechain`, `@typechain/ethers-v6`, `hardhat-gas-reporter`, `@nomicfoundation/hardhat-toolbox` (non-viem variant)
  - `tsconfig.json`: ES2022 target, NodeNext module, NodeNext moduleResolution, strict true, esModuleInterop true, skipLibCheck true, resolveJsonModule true
  - All library versions marked ⚠ VERSION NOT VERIFIED — implement skill must web-search at audit time and record verified versions before commit

- [ ] **Task 2: Submodule bootstrap verification**
  - Maps to: AC-1, AC-5
  - Files: none authored; verify on-disk state
  - `.gitmodules`, `ETHFALCON/`, `ETHDILITHIUM/` already present. Verify `git submodule update --init --recursive` succeeds end-to-end from a clean state and that `ETHFALCON/src/ZKNOX_falcon.sol` + `ETHDILITHIUM/src/ZKNOX_dilithium.sol` resolve to the pinned SHAs (ETHFALCON: `03ed0d60…`, ETHDILITHIUM: `b9ca7f72…`)
  - Also verify `ETHFALCON/lib/sstore2/contracts/` and `ETHFALCON/lib/InterfaceVerifier/src/` exist (required by `link-submodule-libs.ts`)
  - `git diff` run inside each submodule must produce zero output (NFR-5)

- [ ] **Task 3: `hardhat.config.ts` (HH3 + viem ESM)**
  - Maps to: AC-2
  - Files: `hardhat.config.ts`
  - ESM syntax: `import "@nomicfoundation/hardhat-toolbox-viem"` + `import "./scripts/link-submodule-libs.js"` (after TS compile the path is `.js`; verify HH3's async config loader executes side-effect imports before Hardhat's resolver runs — if it does not, move the link stub staging into a `prepare` / `postinstall` npm script)
  - Export default config with:
    - `solidity.version: "0.8.34"`
    - `solidity.settings.optimizer: { enabled: true, runs: 200 }`
    - `solidity.settings.evmVersion: "cancun"`
  - Sources path: `./contracts`. Include `contracts/imports/` in compile graph via the existing `FalconRef.sol`, `DilithiumRef.sol`, `EntryPointRef.sol` files (no config change needed if default sources glob picks them up)
  - `scripts/check-compile-warnings.js` (already on disk) is invoked from the `compile` npm script, not from the Hardhat config — re-validate its regex (`/^Error:/`, `/^Warning:/`, `/-->\s+(\S+?):\d+:\d+:?/`) matches HH3's solc driver output format. If HH3 reformats location lines, patch the regex; do not change the tolerated-prefix list (`ETHFALCON/`, `ETHDILITHIUM/`)
  - Throwaway compile must succeed with only submodule warnings tolerated (C-001 expected)

- [ ] **Task 4: EntryPoint fixture (`hre.viem.deployContract` pattern)**
  - Maps to: AC-3
  - Files: `test/fixtures/entryPoint.ts`
  - Exports `async function deployEntryPoint()` using `hre.viem.deployContract("EntryPoint")` (the `EntryPoint` contract name is resolved by Hardhat from `@account-abstraction/contracts/core/EntryPoint.sol` via `EntryPointRef.sol`)
  - Return value exposes a typed contract instance plus `publicClient` and `walletClients` from `hre.viem.getPublicClient()` / `hre.viem.getWalletClients()` for test reuse
  - Do NOT import from `typechain-types/` — viem generates types via its deploy API
  - Do NOT import `ethers` or use `ethers.getContractFactory`

- [ ] **Task 5: Signer module — ECDSA impl + PQC stubs**
  - Maps to: AC-4
  - Files: `test/signers/index.ts`, `test/signers/ecdsa.ts`, `test/signers/falcon.ts`, `test/signers/ml-dsa.ts`, `test/signers/errors.ts`
  - `errors.ts`: exports `NotImplementedError` extending `Error`, with `code: "NOT_IMPLEMENTED"` (literal string) and a `scheme: Scheme` field set from the constructor
  - `index.ts`: re-exports `Scheme`, `Keypair` types; exports `keygen(scheme)` and `signUserOp(scheme, …)` dispatching to the three scheme modules; no business logic inline
  - `ecdsa.ts`: complete implementation
    - `keygen()`: generate a secp256k1 keypair using viem's `generatePrivateKey()` + `privateKeyToAccount()`; return `{ publicKey, secretKey }` as `Uint8Array`s (publicKey is the 20-byte account address bytes; secretKey is the 32-byte private key bytes)
    - `signUserOp(secretKey, userOp, entryPointAddress, chainId)`: compute the ERC-4337 userOpHash over the PackedUserOperation fields per EIP-4337 v0.7 (keccak256 of packed fields, hashed again with `(hash, entryPointAddress, chainId)`); sign via `privateKeyToAccount(secretKey).signMessage({ message: { raw: userOpHash } })` — this applies the EIP-191 prefix which SimpleAccount's `toEthSignedMessageHash().recover()` expects; return a `PackedUserOperation` with the 65-byte signature `r||s||v` populated
  - `falcon.ts`: stub — both `keygen` and `signUserOp` throw `new NotImplementedError("falcon")` with code `NOT_IMPLEMENTED`. The real implementation is Story 3-1
  - `ml-dsa.ts`: stub — same pattern as `falcon.ts`, scheme `"mldsa"`. The real implementation is Story 4-1

- [ ] **Task 6: Smoke test (viem assertions)**
  - Maps to: AC-2, AC-3, AC-4
  - Files: `test/smoke.test.ts`
  - Must: (a) implicitly exercise `hardhat compile` via the test runner, (b) call `deployEntryPoint()` and assert the returned contract has a non-zero `address`, (c) call `keygen("ecdsa")` and assert `publicKey.length === 20` and `secretKey.length === 32`, (d) call `signUserOp("ecdsa", …)` on a minimal constructed UserOp and assert the returned `signature` is 65 bytes, (e) call `keygen("falcon")` and `keygen("mldsa")` wrapped in try/catch, assert each throws with `err.code === "NOT_IMPLEMENTED"`
  - Use viem / node:assert assertion style (e.g., `assert.equal`, `assert.strictEqual`, `assert.rejects`, `assert.throws`). Do NOT use Chai or `hardhat-chai-matchers` — they belong to the non-viem toolbox

## must_haves

truths:
  - "`package.json` declares `\"type\": \"module\"` and lists `hardhat@^3.x` + `@nomicfoundation/hardhat-toolbox-viem@^5.0.3` in devDependencies; does NOT list `ethers`, `typechain`, `@typechain/hardhat`, `@typechain/ethers-v6`, `hardhat-gas-reporter`, or `@nomicfoundation/hardhat-toolbox` (non-viem)"
  - "`hardhat.config.ts` targets Solidity `0.8.34` with optimizer runs `200` and `evmVersion: 'cancun'`"
  - "`npx hardhat compile` succeeds with zero non-submodule warnings; only the known ETHFALCON `slen` warning (C-001) is tolerated"
  - "`ETHFALCON` submodule pinned at commit `03ed0d60c67087527de7c4a3c1c469b89611bd68`; `ETHDILITHIUM` pinned at `b9ca7f72526ecc696230d3c774a6e2c12c9b37c2`; `git diff` inside each submodule returns empty (NFR-5)"
  - "`deployEntryPoint()` returns a deployed `EntryPoint` instance via `hre.viem.deployContract(\"EntryPoint\")`; no usage of `ethers.getContractFactory` or `typechain-types` anywhere in the tree"
  - "`test/signers/ecdsa.ts` uses `privateKeyToAccount(pk).signMessage({ message: { raw: hash } })` (viem) for EIP-191 prefixed signing; returns a 65-byte `r||s||v` signature"
  - "`test/signers/falcon.ts` and `test/signers/ml-dsa.ts` throw `NotImplementedError` with `code === \"NOT_IMPLEMENTED\"` from both `keygen` and `signUserOp`"
  - "`test/signers/index.ts` exports `Scheme`, `Keypair`, `keygen`, `signUserOp` and dispatches on the `scheme` string; contains no per-scheme signing logic inline"
  - "`test/smoke.test.ts` passes end-to-end: deploys EntryPoint, generates ECDSA keypair, signs a UserOp, and verifies PQC stubs throw `NOT_IMPLEMENTED`"

artifacts:
  - path: "package.json"
    contains: ["\"type\": \"module\"", "hardhat", "@nomicfoundation/hardhat-toolbox-viem", "@account-abstraction/contracts", "@noble/post-quantum", "viem"]
  - path: "tsconfig.json"
    contains: ["strict", "NodeNext"]
  - path: "hardhat.config.ts"
    contains: ["0.8.34", "cancun", "200", "@nomicfoundation/hardhat-toolbox-viem", "link-submodule-libs"]
  - path: "contracts/imports/EntryPointRef.sol"
    contains: ["@account-abstraction/contracts/core/EntryPoint.sol"]
  - path: "contracts/imports/FalconRef.sol"
    contains: ["ETHFALCON/src/ZKNOX_falcon.sol"]
  - path: "contracts/imports/DilithiumRef.sol"
    contains: ["ETHDILITHIUM/src/ZKNOX_dilithium.sol"]
  - path: "scripts/link-submodule-libs.ts"
    contains: ["sstore2", "InterfaceVerifier"]
  - path: "scripts/check-compile-warnings.js"
    contains: ["ETHFALCON/", "ETHDILITHIUM/"]
  - path: "test/fixtures/entryPoint.ts"
    contains: ["deployEntryPoint", "hre.viem.deployContract", "EntryPoint"]
  - path: "test/signers/index.ts"
    contains: ["Scheme", "Keypair", "keygen", "signUserOp"]
  - path: "test/signers/ecdsa.ts"
    contains: ["privateKeyToAccount", "signMessage", "raw"]
  - path: "test/signers/falcon.ts"
    contains: ["NotImplementedError"]
  - path: "test/signers/ml-dsa.ts"
    contains: ["NotImplementedError"]
  - path: "test/signers/errors.ts"
    contains: ["NotImplementedError", "NOT_IMPLEMENTED"]
  - path: "test/smoke.test.ts"
    contains: ["deployEntryPoint", "keygen", "signUserOp", "NOT_IMPLEMENTED"]

key_links:
  - pattern: "from \"viem/accounts\""
    in: ["test/signers/ecdsa.ts"]
  - pattern: "privateKeyToAccount"
    in: ["test/signers/ecdsa.ts"]
  - pattern: "{ raw:"
    in: ["test/signers/ecdsa.ts"]
  - pattern: "hre.viem.deployContract"
    in: ["test/fixtures/entryPoint.ts"]
  - pattern: "@nomicfoundation/hardhat-toolbox-viem"
    in: ["hardhat.config.ts", "package.json"]
  - pattern: "NotImplementedError"
    in: ["test/signers/errors.ts", "test/signers/falcon.ts", "test/signers/ml-dsa.ts"]
  - pattern: "NOT_IMPLEMENTED"
    in: ["test/signers/errors.ts", "test/smoke.test.ts"]
  - pattern: "\"type\": \"module\""
    in: ["package.json"]

## Dev Notes (advisory)

**Amendment A-001 is binding.** Read `docs/amendments.md` before starting any task. If any task implementation decision appears to conflict with A-001, A-001 wins — DD-1 in `docs/architecture.md` is AMENDED per A-001.

**Library versions — all ⚠ VERSION NOT VERIFIED at story creation.** Implement skill must web-search latest stable at audit time and record verified versions in the Dev Notes or the eventual state file. Suggested targets per A-001:
- `hardhat@^3.3.0` (current stable on `latest` dist-tag; HH2 is on `hh2`)
- `@nomicfoundation/hardhat-toolbox-viem@^5.0.3`
- `@account-abstraction/contracts@^0.7.0` (v0.7 EntryPoint — `PackedUserOperation`)
- `@noble/post-quantum@^0.5.4`
- `viem@^2.x` (latest 2.x)
- `typescript@^5.x`
- `solidity: 0.8.34` (verify latest patch; fall back only if 0.8.34 is not yet released — do NOT drop below 0.8.29)

**Rollback context:** Per A-001 rollback plan, four HH2-era commits were dropped (`c858e5c`, `89a06ac`, `330fc15`, `e24bf53`). Salvageable files already on disk (`.gitmodules`, submodule checkouts, `contracts/imports/*.sol`, `scripts/link-submodule-libs.ts`, `scripts/check-compile-warnings.js`, `docs/concerns.md`, `README.md`) must NOT be recreated — only re-validated under HH3.

**HH3 ESM gotchas (re-validation checklist):**
- `scripts/link-submodule-libs.ts` uses `import * as fs from "node:fs"` — already ESM-compatible. It does however use `__dirname` (line 49), which does not exist in ESM. **Replace** `path.resolve(__dirname, "..")` with `path.dirname(fileURLToPath(import.meta.url))` or `path.resolve(import.meta.dirname, "..")` (Node 20.11+).
- `scripts/check-compile-warnings.js` is CJS (uses `require` and `"use strict"`). HH3 does not execute this file — it is run via `node` from the `compile` npm script. With `"type": "module"` in `package.json`, **rename to `.cjs`** (or convert to ESM). The safer minimum change is rename to `check-compile-warnings.cjs` and update the `compile` script.
- HH3 config is async — if side-effect import of `./scripts/link-submodule-libs.js` from `hardhat.config.ts` does not reliably stage the `node_modules/` stubs before Hardhat resolves imports, move the staging to an npm `prepare` script and remove the config-time import. Verify empirically during Task 3.

**Local dev:** No `docs/local-dev.md`, no `docs/infrastructure.md`, no `docs/design-system.md`, no `docs/test-strategy.md`. No external services — Hardhat Network runs in-process. Tests run via `npm test` (which invokes `hardhat test`).

**Test standards (first story — establishing):**
- Test files live under `test/` in `.ts`
- Test naming: `*.test.ts`
- Fixtures under `test/fixtures/`
- Signers under `test/signers/`
- Assertions: Node's `node:assert/strict` or viem-native matchers. **Do not** pull in `chai` or `@nomicfoundation/hardhat-chai-matchers` — they are part of the non-viem toolbox and add dependency surface area this project does not need

**NFR-5 enforcement (AC-5):** `git diff` inside each submodule must be empty. The compile-warnings gate is the second safety net: it tolerates submodule warnings to avoid any pressure to patch them.

**Interface consumers in later stories:** The `Scheme`, `Keypair`, `keygen`, `signUserOp` signatures are LOCKED by PD-2 — Stories 2-1/3-1/4-1 depend on this story's exports being stable. Any signature change in this story requires an amendment.

## Detected Patterns

Story 1-1 is the first story on a clean slate (post-rollback per A-001). No prior project-authored files exist. Greenfield for every component type in this story — scaffolding, config, fixtures, signers, tests. Per Inline Decision List rule 3 default: when no analogous files exist, all relevant patterns are INLINED above from architecture + A-001.

| Pattern | Value | Sampled from | Established? |
|---------|-------|-------------|-------------|
| n/a | first story | — | — (greenfield) |

## Wave Structure

This story is Wave 1 (no story dependencies — see `sprint-status.yaml`). Internally the 6 tasks have dependencies:

- **Sub-wave A:** Task 1 (`package.json` + `tsconfig.json`) and Task 2 (submodule verification) — independent
- **Sub-wave B:** Task 3 (`hardhat.config.ts`) — depends on Task 1 (needs `package.json` deps) and Task 2 (needs submodule bootstrap for compile)
- **Sub-wave C:** Task 4 (EntryPoint fixture) and Task 5 (signers) — both depend on Task 3 (need working compile for type resolution) but are independent of each other (disjoint files, disjoint imports)
- **Sub-wave D:** Task 6 (smoke test) — depends on Tasks 4 and 5

Wave independence audit: within each sub-wave, no shared output files, no shared state, no shared fixtures. Task 4 writes `test/fixtures/entryPoint.ts`; Task 5 writes `test/signers/*.ts` — fully disjoint.
