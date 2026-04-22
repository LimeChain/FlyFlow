/**
 * Task 4 (Story 3-1) self-test — post-fork-extraction.
 *
 * Validates structural invariants of the ZKNOX wire-format encoders now
 * owned by the `@noble/post-quantum/utils-eth.js` fork subpath. The full
 * cryptographic round-trip (sign → encode → on-chain verify returns
 * `verify.selector`) is covered by the account-level integration tests
 * against a deployed `ZKNOX_falcon`.
 *
 * Framework: `node:test` + `node:assert/strict`.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { falcon512 } from "@noble/post-quantum/falcon.js";
import {
  encodeFalconPublicKey,
  encodeFalconSignature,
} from "@noble/post-quantum/utils-eth.js";
import { decodeAbiParameters } from "viem";

describe("Falcon-512 encoding bridge (utils-eth)", () => {
  it("encodes a 897-byte public key into ABI-encoded uint256[32]", () => {
    const { publicKey } = falcon512.keygen();
    assert.equal(publicKey.length, 897);

    const encoded = encodeFalconPublicKey(publicKey);
    assert.equal(encoded.length, 32 + 32 + 32 * 32, "expected 1088 B ABI envelope");
    const [compact] = decodeAbiParameters(
      [{ type: "uint256[]" }],
      encoded,
    ) as [readonly bigint[]];

    assert.equal(compact.length, 32, "expected 32 compacted NTT words");
    const maxWord = (1n << 256n) - 1n;
    for (const w of compact) {
      assert.ok(w >= 0n && w <= maxWord, `word ${w} out of uint256 range`);
    }
  });

  it("encodes a noble detached signature into 1064-byte salt||s2_compact", () => {
    const { publicKey, secretKey } = falcon512.keygen();
    const msg = new Uint8Array(32).fill(0x42);
    const sig = falcon512.sign(msg, secretKey);
    // Confirm our assumption about noble's detached-sig shape: the structural
    // check should still pass over valid signatures even though we do not
    // re-verify cryptographically here.
    assert.ok(falcon512.verify(sig, msg, publicKey));

    const encoded = encodeFalconSignature(sig);
    assert.equal(encoded.length, 1064, "expected salt(40) + 32 uint256 words = 1064 bytes");
  });

  it("rejects public keys with the wrong length", () => {
    assert.throws(
      () => encodeFalconPublicKey(new Uint8Array(896)),
      /expected 897 bytes/,
    );
  });

  it("rejects public keys with the wrong header byte", () => {
    const bad = new Uint8Array(897);
    bad[0] = 0x00;
    assert.throws(
      () => encodeFalconPublicKey(bad),
      /expected header byte 0x9/,
    );
  });

  it("rejects signatures with the wrong header byte", () => {
    const bad = new Uint8Array(700);
    bad[0] = 0x00;
    assert.throws(
      () => encodeFalconSignature(bad),
      /expected header byte 0x39/,
    );
  });
});
