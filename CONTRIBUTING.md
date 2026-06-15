# Contributing to FlyFlow

FlyFlow integrates post-quantum signature verifiers (FALCON, ML-DSA) into ERC-4337 account abstraction. It's a focused research/integration repo, so this guide is short. The one rule that matters: **all changes land through a reviewed pull request — nothing is pushed straight to `main`.**

## How changes get in

1. Branch off `main` (or fork the repo if you don't have write access). Name the change, not yourself — `feat/...`, `fix/...`, `docs/...`, `refactor/...`, `chore/...`.
2. Make your change. Keep the PR small and focused on one thing.
3. Use [Conventional Commits](https://www.conventionalcommits.org/) for messages (`feat(falcon-eth): ...`, `fix(mldsa): ...`, `docs(gas-report): ...`) — it matches the existing history.
4. Open a pull request against `main`.
5. A code owner (see [`CODEOWNERS`](.github/CODEOWNERS)) reviews it. **Their approval is required** before the PR can merge.
6. Once approved and the build is clean, it merges into `main`.

`main` is the protected default branch: direct pushes are blocked, and a code-owner review is mandatory. Don't merge your own PR without an approving review.

## Working on it

Clone with submodules, install, and verify the suite before you start:

```bash
git clone <repo-url>
cd flyflow
git submodule update --init --recursive   # pulls ETHFALCON + ETHDILITHIUM
npm install
npm run compile                           # compiles + fails on any solc warning
npm test                                  # full acceptance/rejection + gas suite
```

The repo has two layers:

- **`contracts/`** — Solidity (0.8.34) ERC-4337 account modules wrapping the ZKNox verifiers. Built and tested with Hardhat 3.
- **TypeScript** (`test/`, `scripts/`) — signers, fixtures, the gas benchmark, and tooling. Run with `npm`.

There is no CI yet, so **the local checks are the gate**: before opening a PR, make sure `npm run compile` and `npm test` both pass for whatever you touched.

**Submodules are pinned, never modified in-tree (NFR-5).** `ETHFALCON/` and `ETHDILITHIUM/` are pinned to specific commit SHAs. Don't edit submodule sources, and don't bump a pin casually — if a bump is genuinely needed, follow the procedure in the [README](README.md) and update the pin table with the new SHA and rationale in the same PR.

## A few expectations

- Write a PR description that says **what** changed and **why**, and note any **gas impact** for verifier or signature-layout changes (re-run `npx hardhat test test/bench/gas-benchmark.test.ts` and refresh [`docs/gas-report.md`](docs/gas-report.md) via `npm run report`).
- **Every behavioral change includes tests** — cover both acceptance (valid signature passes) and rejection (tampered/invalid signature fails). Don't skip or delete tests to make the build pass.
- You own everything you submit, including AI-assisted code — if you can't explain a line, don't ship it.

## High-risk areas — extra care

On-chain code is irreversible and this is cryptographic code, so some areas get extra scrutiny:

- The PQC verifiers, signature layouts, low-S invariants, and the `validateUserOp` validation paths. The Keccak-based ETH variants (`FalconEthAccount`, `MlDsaEthAccount`) are marked `@custom:experimental` and are **not yet audited** — treat changes there accordingly.
- **Never commit secrets, private keys, or mnemonics.** `.env` is git-ignored; keep keys out of the tree and out of test fixtures.
- Found a security issue? Don't open a public issue — report it privately to a code owner ([`CODEOWNERS`](.github/CODEOWNERS)) first.

That's it. Thanks for contributing.
