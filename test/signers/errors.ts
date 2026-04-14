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
