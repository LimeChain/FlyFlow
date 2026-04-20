/**
 * Shared dual-path walker for asserting a `SignatureMalformed()` revert
 * bound to a specific account address.
 *
 * THIS IS THE CONTRACT-LAYER REJECTION ORACLE for the malformed-signature
 * path. `MlDsaAccount`, `FalconAccount`, `MlDsaEthAccount`, and
 * `FalconEthAccount` all declare `error SignatureMalformed()` with the
 * same 4-byte selector (`0x2c3c2fe1` — `keccak256("SignatureMalformed()")`
 * truncated to 4 bytes). Without address-binding, a test-setup mistake
 * routing to the wrong account would satisfy the predicate spuriously.
 *
 * Dual-path rationale:
 *   - Canonical viem path: `BaseError.walk` locates a
 *     `ContractFunctionRevertedError` with a decoded
 *     `data.errorName === "SignatureMalformed"`. `errorName` is ABI-name
 *     scoped (not address scoped), so we AND with the address check.
 *   - HH3 EDR fallback: the revert surfaces as a `SolidityError` at the
 *     chain tail and viem's decoder sometimes does NOT populate
 *     `errorName`. The EDR's message text deterministically contains
 *     `custom error 'SignatureMalformed()'` — match via regex on the
 *     chain-tail message, still AND-ed with the address bind.
 *
 * Extracted from `test/accounts/mldsa-eth-failures.test.ts` at Story 2-4
 * Task T5 time to avoid the two-copy silent-drift risk flagged by
 * `.claude/rules/retrospect/typescript.md` §"[2026-04-20] Duplicated
 * test-file code". The previous inline copy lived inside the AC-5-5 `it`
 * block; this helper is imported from both
 * `test/accounts/mldsa-eth-failures.test.ts` and
 * `test/accounts/falcon-eth-failures.test.ts`.
 *
 * @param accountAddress The deployed account address. Lower-cased inside
 *   the helper; the predicate matches case-insensitively against the
 *   revert's message text on BOTH paths.
 * @returns A predicate suitable for `node:assert`'s `assert.rejects`
 *   second argument. Returns `true` on match; re-throws any
 *   non-`BaseError` so assertion-framework noise bubbles up unchanged.
 */

import { BaseError, ContractFunctionRevertedError } from "viem";

export function assertSignatureMalformedForAccount(
  accountAddress: string,
): (err: unknown) => boolean {
  const bound = accountAddress.toLowerCase();
  return (err: unknown) => {
    if (!(err instanceof BaseError)) throw err;
    const message = err.message.toLowerCase();
    const boundToAccount = message.includes(bound);

    // Canonical viem path — decoded ContractFunctionRevertedError.
    const revert = err.walk(
      (e) => e instanceof ContractFunctionRevertedError,
    ) as ContractFunctionRevertedError | null;
    if (revert?.data?.errorName === "SignatureMalformed" && boundToAccount) {
      return true;
    }

    // HH3 EDR fallback — message-regex (viem doesn't populate errorName).
    return (
      /custom error 'signaturemalformed\(\)'/.test(message) && boundToAccount
    );
  };
}
