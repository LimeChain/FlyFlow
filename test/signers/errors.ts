import type { Scheme } from "./index.js";

/**
 * Error thrown by signer modules that have not been implemented yet.
 *
 * Historically this file also exported `SignerInputError` with an ML-DSA-
 * specific code taxonomy (`INVALID_SECRET_KEY_LENGTH`, `INVALID_MESSAGE`,
 * `INVALID_CTX_LENGTH`, `INVALID_RND_LENGTH`) plus Falcon-ETH-specific
 * codes (`INVALID_INNER_SEED_LENGTH`, `SIGNING_BYTES_EXHAUSTED`). Those
 * all vanished as the two ETH signer surfaces moved into the fork at
 * `@noble/post-quantum`: Falcon-ETH first (seed-length validation now
 * flows through noble's `abytes`), then ML-DSA-ETH (length + shape
 * validation now flows through noble's `abytes_` / `splitCoder.decode`,
 * raising native `TypeError` / `Error`). The last standing consumer was
 * `ml-dsa-eth.kat-internal.ts#signWithRnd`, removed alongside the T5
 * deletions of the four ml-dsa-eth / mldsa-encoding / keccak-prg modules.
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
