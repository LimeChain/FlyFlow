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
 * `INVALID_SECRET_KEY_LENGTH` + `INVALID_MESSAGE` are raised by the public
 * KAT surface (`signWithRnd`) before any cryptographic work. `INVALID_CTX_LENGTH`
 * + `INVALID_RND_LENGTH` are raised by the shared core (`signWithXofInstrumented`)
 * — unreachable from today's callers (production `signUserOp` always passes
 * empty ctx and a 32-byte hedged rnd; `signWithRnd` defaults ctx to empty
 * and forwards the caller's rnd) but the core is an exported symbol consumed
 * directly by the G2 KAT test, so the taxonomy covers misuse paths there.
 *
 * `INVALID_INNER_SEED_LENGTH` is raised by the Falcon-ETH KAT surface
 * (`keygenInternal` in `falcon-eth.kat-internal.ts`) when the supplied
 * `innerSeed` is not a 48-byte `Uint8Array` (Story 2-1 AC-3).
 *
 * `SIGNING_BYTES_EXHAUSTED` is raised by the Falcon-ETH signer surfaces
 * (`signWithKatBytes` in `falcon-eth.kat-internal.ts` — KAT path;
 * `signUserOp` in `falcon-eth.ts` — production path) when the supplied
 * `BytesReader` is over-drawn past the 88 B signing randomness budget (40 B
 * salt + 48 B FFSampler seed per `docs/amendments.md` §A-005 "signingDrbg
 * byte decomposition"). In the KAT path, over-draw indicates TS-side signer
 * divergence from the ETHFALCON DRBG consumption contract; in the
 * production path, it indicates an exhausted CSPRNG source (Story 2-3 AC-5).
 */
export type SignerInputErrorCode =
  | "INVALID_SECRET_KEY_LENGTH"
  | "INVALID_MESSAGE"
  | "INVALID_CTX_LENGTH"
  | "INVALID_RND_LENGTH"
  | "INVALID_INNER_SEED_LENGTH"
  | "SIGNING_BYTES_EXHAUSTED";

/**
 * Caller-provided input failed a pre-cryptographic validation check. Raised
 * by signer-surface functions — `signWithRnd`, `signUserOp`,
 * `keygenInternal`, `signWithKatBytes` — before any cryptographic work (or,
 * for `SIGNING_BYTES_EXHAUSTED`, at the randomness-source boundary inside
 * the signing call), when caller-provided inputs fail length or type
 * checks. See {@link SignerInputErrorCode} for the exhaustive error-code
 * union covering message/secret-key length, ctx/rnd invariants (shared
 * core), Falcon-ETH inner-seed length (Story 2-1 AC-3), and Falcon-ETH
 * signer randomness-budget over-draw (Story 2-3 AC-5 — raised from both
 * `signWithKatBytes` and `signUserOp`).
 */
export class SignerInputError extends Error {
  readonly code: SignerInputErrorCode;

  constructor(code: SignerInputErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = "SignerInputError";
  }
}
