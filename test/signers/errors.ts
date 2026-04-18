import type { Scheme } from "./index.js";

/**
 * Error thrown by signer modules that have not been implemented yet.
 *
 * `falcon.ts` and `ml-dsa.ts` throw this from both `keygen` and `signUserOp`
 * until Stories 3-1 and 4-1 land the real implementations.
 */
export class NotImplementedError extends Error {
  readonly code = "NOT_IMPLEMENTED" as const;
  readonly scheme: Scheme;

  constructor(scheme: Scheme) {
    super(`${scheme} signing is not yet implemented`);
    this.scheme = scheme;
    this.name = "NotImplementedError";
  }
}

/**
 * Discriminant codes for {@link SignerInputError}. Tests assert on `err.code`
 * (established convention shared with `PrgLifecycleError`, `KatFixtureError`,
 * `NotImplementedError`), NEVER on `err.message` strings.
 */
export type SignerInputErrorCode =
  | "INVALID_SECRET_KEY_LENGTH"
  | "INVALID_MESSAGE";

/**
 * Caller-provided input failed a pre-signing validation check (Story 4 —
 * AC-4-3, AC-4-4). Raised by {@link import("./ml-dsa-eth.kat-internal").signWithRnd}
 * before any cryptographic work — malformed inputs never reach the core
 * `signWithXof` fork.
 */
export class SignerInputError extends Error {
  readonly code: SignerInputErrorCode;

  constructor(code: SignerInputErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = "SignerInputError";
  }
}
