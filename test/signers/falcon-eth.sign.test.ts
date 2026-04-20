/**
 * Story 2-3 Task T3 — Falcon-ETH signer surface unit tests (AC-2 / AC-3 /
 * AC-5 / AC-7).
 *
 * Covers the non-G4 acceptance surface for the Falcon-ETH signer module set:
 *
 * - **AC-2 — Hedged production sign.** Two `signUserOp` calls with
 *   identical `(sk, userOp, entryPoint, chainId)` produce signatures whose
 *   first 40 B (salt) differ. Full end-to-end verify against the 1064 B
 *   ZKNOX layout is deferred to Story 2-4 Gate G6 (on-chain
 *   `ZKNOX_falcon.verify(bytes,bytes32,bytes)`); this test asserts the
 *   hedging invariant + structural-length invariant (1064 B → 2130 hex
 *   chars) only. Byte-identity against `.rsp` vectors is covered E2E by
 *   the G4 KAT at `falcon-eth.sign.kat.test.ts` (Story 2-3 T4).
 * - **AC-3 — Deterministic KAT sign.** Two `signWithKatBytes` calls with
 *   identical `(sk, msg)` and two independent `BytesReader` instances
 *   seeded identically produce byte-identical 1064 B output — establishes
 *   the determinism predicate that G4 KAT byte-identity rests on (without
 *   iterating the full `.rsp` corpus here).
 * - **AC-5 — Input validation (3 cases).** `signWithKatBytes` rejects:
 *   wrong-length sk with `INVALID_SECRET_KEY_LENGTH`; empty msg with
 *   `INVALID_MESSAGE`; reader over-draw (returned-chunk length exceeds
 *   the 88 B KAT budget) with `SIGNING_BYTES_EXHAUSTED`.
 * - **AC-7 — Interface + import boundary.** Structural export-surface
 *   check (`BytesReader`, `signWithKatBytes`, `signUserOp` are wired where
 *   the must_haves specify) + runtime grep that `test/signers/index.ts`
 *   and every file under `test/bench/` do NOT import from
 *   `falcon-eth.kat-internal`.
 *
 * Assertion style: `err instanceof SignerInputError && err.code === "..."`
 * — NEVER `err.message.includes(...)`. Per `.claude/rules/test-integrity.md`
 * and the error-discriminant convention established by Story 2-1 at
 * `falcon-eth.test.ts` AC-3.
 *
 * Framework: `node:test` + `node:assert/strict` — matches sibling unit
 * tests (`falcon-eth.test.ts`, `ml-dsa-eth.sign.test.ts`).
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { type Hex, hexToBytes } from "viem";

import { bytesEqual } from "../utils/assert-bytes.js";
import { listTsFiles } from "../utils/fs-walk.js";
import { SignerInputError } from "./errors.js";
import { keygen, signUserOp } from "./falcon-eth.js";
import {
  type BytesReader,
  keygenInternal,
  signWithKatBytes,
} from "./falcon-eth.kat-internal.js";
import type { UnsignedUserOp } from "./index.js";

const THIS_FILE = fileURLToPath(import.meta.url);
const SIGNERS_DIR = path.dirname(THIS_FILE);
const TEST_DIR = path.resolve(SIGNERS_DIR, "..");
const BENCH_DIR = path.join(TEST_DIR, "bench");
const INDEX_FILE = path.join(SIGNERS_DIR, "index.ts");

/** String-based import detector for `falcon-eth.kat-internal` (AC-7).
 *  Mirrors the Story 2-1 AC-5 detector at `falcon-eth.test.ts` verbatim —
 *  catches both double- and single-quoted variants, with or without the
 *  `.js` suffix. */
const KAT_INTERNAL_IMPORT_RE =
  /from\s+["'][^"']*falcon-eth\.kat-internal[^"']*["']/;

// === AC-2 fixtures ========================================================

const ZERO_BYTES32 = `0x${"00".repeat(32)}` as Hex;
const SENDER: `0x${string}` = "0x0000000000000000000000000000000000000001";
// Any valid 20-byte address works — computeUserOpHash only needs it for
// hashing; these tests assert on signature format + hedge divergence +
// length invariants, not on ERC-4337 on-chain validity (Story 2-4 G6).
const ENTRY_POINT: `0x${string}` = "0x0000000000000000000000000000000000000002";
const CHAIN_ID = 31337n;

function buildUserOp(): UnsignedUserOp {
  return {
    sender: SENDER,
    nonce: 0n,
    initCode: "0x",
    callData: "0x",
    accountGasLimits: ZERO_BYTES32,
    preVerificationGas: 0n,
    gasFees: ZERO_BYTES32,
    paymasterAndData: "0x",
  };
}

/**
 * Build a `BytesReader` over a fixed buffer with an independent offset. Two
 * calls to this factory return two independent readers — the second's
 * offset is not shared with the first's, so AC-3 determinism checks can
 * run back-to-back without cross-contamination.
 */
function bufferReader(buffer: Uint8Array): BytesReader {
  let offset = 0;
  return {
    read: (n: number): Uint8Array => {
      const chunk = buffer.subarray(offset, offset + n);
      offset += n;
      return chunk;
    },
  };
}

describe("Falcon-ETH signer surfaces (Story 2-3 T3 · AC-2 / AC-3 / AC-5 / AC-7)", () => {
  // === AC-2: Hedged production sign =======================================

  describe("AC-2: signUserOp hedging", () => {
    it("two calls with identical inputs return signatures with DIFFERENT salts", async () => {
      const { secretKey } = keygen();
      const userOp = buildUserOp();
      const a = await signUserOp(secretKey, userOp, ENTRY_POINT, CHAIN_ID);
      const b = await signUserOp(secretKey, userOp, ENTRY_POINT, CHAIN_ID);

      // The on-chain Falcon-ETH signature layout is `salt(40) ||
      // s2_compact(1024)` — the first 40 B MUST differ between two hedged
      // signs (collision probability ≈ 2⁻³²⁰ — equality means the CSPRNG
      // is mocked).
      const aBytes = hexToBytes(a.signature);
      const bBytes = hexToBytes(b.signature);
      const saltA = aBytes.subarray(0, 40);
      const saltB = bBytes.subarray(0, 40);
      assert.ok(
        !bytesEqual(saltA, saltB),
        "two hedged signUserOp calls returned identical 40 B salts",
      );
    });

    it("returns a 2130-char 0x-prefixed hex signature (1064 B · spread preserved)", async () => {
      const { secretKey } = keygen();
      const userOp = buildUserOp();
      const signed = await signUserOp(secretKey, userOp, ENTRY_POINT, CHAIN_ID);

      // 1064 B × 2 hex chars + 2 prefix chars = 2130.
      assert.equal(signed.signature.length, 2130);
      assert.ok(signed.signature.startsWith("0x"));
      // Spread preserves every UnsignedUserOp field verbatim.
      assert.equal(signed.sender, userOp.sender);
      assert.equal(signed.nonce, userOp.nonce);
      assert.equal(signed.initCode, userOp.initCode);
      assert.equal(signed.callData, userOp.callData);
      assert.equal(signed.accountGasLimits, userOp.accountGasLimits);
      assert.equal(signed.preVerificationGas, userOp.preVerificationGas);
      assert.equal(signed.gasFees, userOp.gasFees);
      assert.equal(signed.paymasterAndData, userOp.paymasterAndData);
    });
  });

  // === AC-3: Deterministic KAT sign =======================================

  describe("AC-3: signWithKatBytes determinism", () => {
    it("two calls with identical (sk, msg) and independently-seeded readers produce byte-identical 1064 B output", () => {
      // Deterministic inputs — two independent 88 B buffers with identical
      // byte contents drive two independent `BytesReader` instances. Each
      // reader MUST own its entropy buffer: noble's `signRaw` zeroes the
      // 48 B sampler seed in place after use (via `cleanBytes` — see
      // `@noble/post-quantum/falcon.js:signRaw`), so sharing one buffer
      // across two signs would hand the second sign all-zeros for bytes
      // [40..88) and diverge. The fix is per-call buffers, not per-call
      // chunk-copies (fill two buffers, hand one to each reader).
      const { secretKey } = keygenInternal(new Uint8Array(48).fill(0x42));
      const msg = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
      const entropyA = new Uint8Array(88).fill(0xa5);
      const entropyB = new Uint8Array(88).fill(0xa5);

      const readerA = bufferReader(entropyA);
      const readerB = bufferReader(entropyB);

      const sigA = signWithKatBytes(secretKey, msg, readerA);
      const sigB = signWithKatBytes(secretKey, msg, readerB);

      assert.equal(sigA.length, 1064, "sigA length");
      assert.equal(sigB.length, 1064, "sigB length");
      assert.ok(
        bytesEqual(sigA, sigB),
        "two signWithKatBytes calls with identically-seeded readers diverged",
      );
    });
  });

  // === AC-5: Input validation =============================================

  describe("AC-5: signWithKatBytes input validation", () => {
    const validSk = keygenInternal(new Uint8Array(48).fill(0x11)).secretKey;
    const validMsg = new Uint8Array([0xfa, 0x1c, 0x07]);
    const validEntropy = new Uint8Array(88).fill(0x33);

    it("INVALID_SECRET_KEY_LENGTH: rejects 1280 B sk (one byte short)", () => {
      assert.throws(
        () =>
          signWithKatBytes(
            new Uint8Array(1280),
            validMsg,
            bufferReader(validEntropy),
          ),
        (e: unknown) =>
          e instanceof SignerInputError &&
          e.code === "INVALID_SECRET_KEY_LENGTH",
      );
    });

    it("INVALID_MESSAGE: rejects empty Uint8Array msg (length 0)", () => {
      assert.throws(
        () =>
          signWithKatBytes(validSk, new Uint8Array(0), bufferReader(validEntropy)),
        (e: unknown) =>
          e instanceof SignerInputError && e.code === "INVALID_MESSAGE",
      );
    });

    it("SIGNING_BYTES_EXHAUSTED: rejects a reader that returns more bytes than requested (cumulative over-draw past 88 B)", () => {
      // Reader that returns a chunk larger than requested — simulates a
      // buggy reader implementation whose cumulative byte spend exceeds
      // the 88 B Falcon signing budget. Noble's happy path asks for
      // `random(40)`; the reader below returns 100 B, so the guard fires
      // on the FIRST call (0 consumed + 100 returned > 88 budget) before
      // any cryptographic work completes.
      const overShooter: BytesReader = {
        read: (_n: number): Uint8Array => new Uint8Array(100),
      };
      assert.throws(
        () => signWithKatBytes(validSk, validMsg, overShooter),
        (e: unknown) =>
          e instanceof SignerInputError &&
          e.code === "SIGNING_BYTES_EXHAUSTED",
      );
    });
  });

  // === AC-7: Interface + import boundary ==================================

  describe("AC-7: exported surfaces + kat-internal import boundary", () => {
    it("signWithKatBytes is a function (exported from falcon-eth.kat-internal)", () => {
      assert.equal(typeof signWithKatBytes, "function");
    });

    it("signUserOp is a function (exported from falcon-eth.ts)", () => {
      assert.equal(typeof signUserOp, "function");
    });

    it("test/signers/index.ts does not import from falcon-eth.kat-internal", () => {
      const contents = readFileSync(INDEX_FILE, "utf8");
      const match = contents.match(KAT_INTERNAL_IMPORT_RE);
      assert.equal(
        match,
        null,
        `test/signers/index.ts must not import from falcon-eth.kat-internal — matched: ${String(match?.[0])}`,
      );
    });

    it("no file under test/bench/ imports from falcon-eth.kat-internal", () => {
      const benchFiles = listTsFiles(BENCH_DIR);
      for (const file of benchFiles) {
        const contents = readFileSync(file, "utf8");
        const match = contents.match(KAT_INTERNAL_IMPORT_RE);
        assert.equal(
          match,
          null,
          `${path.relative(TEST_DIR, file)} must not import from falcon-eth.kat-internal — matched: ${String(match?.[0])}`,
        );
      }
    });
  });
});
