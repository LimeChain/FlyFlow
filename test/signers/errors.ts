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
 *
 * `INVALID_SECRET_KEY_LENGTH` + `INVALID_MESSAGE` are raised by the ML-DSA
 * KAT surface (`signWithRnd`) before any cryptographic work.
 * `INVALID_CTX_LENGTH` + `INVALID_RND_LENGTH` are raised by the ML-DSA shared
 * core (`signWithXofInstrumented`) — unreachable from today's callers
 * (production `signUserOp` always passes empty ctx and a 32-byte hedged rnd;
 * `signWithRnd` defaults ctx to empty and forwards the caller's rnd) but the
 * core is an exported symbol consumed directly by the G2 KAT test, so the
 * taxonomy covers misuse paths there.
 *
 * Falcon-ETH-specific codes (`INVALID_INNER_SEED_LENGTH`,
 * `SIGNING_BYTES_EXHAUSTED`) were removed when the Falcon-ETH crypto surface
 * moved to the fork's `utils-eth` subpath. Seed-length validation now flows
 * through noble's `abytes` (raises `TypeError` / `RangeError`), and the
 * signing-randomness budget guard was dropped — Falcon's randomness request
 * size is fixed by construction.
 */
export type SignerInputErrorCode =
  | "INVALID_SECRET_KEY_LENGTH"
  | "INVALID_MESSAGE"
  | "INVALID_CTX_LENGTH"
  | "INVALID_RND_LENGTH";

/**
 * Caller-provided input failed a pre-cryptographic validation check. Raised
 * by ML-DSA signer-surface functions (`signWithRnd`, `signUserOp`) before
 * any cryptographic work, when caller-provided inputs fail length or type
 * checks. See {@link SignerInputErrorCode} for the exhaustive error-code
 * union covering message/secret-key length and ctx/rnd invariants
 * (shared core).
 */
export class SignerInputError extends Error {
  readonly code: SignerInputErrorCode;

  constructor(code: SignerInputErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = "SignerInputError";
  }
}
