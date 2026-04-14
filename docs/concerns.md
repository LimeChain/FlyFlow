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
