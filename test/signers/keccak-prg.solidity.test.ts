/**
 * Keccak-PRG G0-prime Solidity cross-check (Story 2, Task 3).
 *
 * Closes the JS ≡ Solidity loop for the 4 Layer-2 `python-ref-extended`
 * PRG fixtures. Layer-1 (`zhenfei-canonical-*`) is already witnessed
 * C-Ref-equivalent-to-Solidity upstream by ZKNox's own Forge test
 * (`ETHDILITHIUM/test/keccak_prng.t.sol`) — re-running Layer-1 here
 * adds only redundant coverage, so we intentionally iterate Layer-2
 * only (per architecture §"Testing Strategy" §"G0-prime" row + DD-11
 * oracle chain argument).
 *
 * For each Layer-2 fixture:
 *   1. Concatenate all `injects[]` into one `bytes` input (Solidity
 *      `initPrng` is one-shot absorb; AC-2-3 guarantees byte-identity
 *      between the multi-inject + concat paths).
 *   2. Compute `totalOutLen = sum(extracts[])`.
 *   3. Call `harness.read.extract([input, totalOutLen])` — the
 *      `KeccakPrngHarness` wraps the free functions from
 *      `ETHDILITHIUM/src/ZKNOX_keccak_prng.sol` (`initPrng` + `refill`
 *      + `prng.pool`) and returns the concatenated stream output.
 *   4. Drive a fresh JS `createKeccakPrg()` with the same sequence
 *      (preserving the original multi-inject + sub-block extract
 *      chunking), then concatenate JS outputs and byte-compare.
 *
 * ACs covered: AC-2-6 (G0-prime Solidity cross-check — required).
 *
 * Framework: `node:test` + `node:assert/strict` + Hardhat viem
 * (`hre.network.connect()` → `viem.deployContract`). Matches
 * `test/accounts/ecdsa.test.ts` integration pattern.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import hre from "hardhat";
import { bytesToHex, hexToBytes } from "viem";

import { loadPrgVectors } from "../fixtures/kat/index.js";
import { createKeccakPrg } from "@noble/post-quantum/utils-eth.js";

describe("Keccak-PRG G0-prime Solidity cross-check (JS ≡ ZKNOX_keccak_prng.sol)", () => {
  it("drives KeccakPrngHarness for each Layer-2 fixture and asserts byte-identity vs JS createKeccakPrg", async () => {
    const { viem } = await hre.network.connect();
    const harness = await viem.deployContract("KeccakPrngHarness");

    const vectors = loadPrgVectors();
    const layer2 = vectors.filter((v) => v.source === "python-ref-extended");
    assert.ok(
      layer2.length > 0,
      "expected at least one python-ref-extended fixture for G0-prime",
    );

    for (const vector of layer2) {
      // Concatenate all injects into one buffer for Solidity's one-shot
      // absorb. AC-2-3 (absorb concatenation) guarantees this is
      // semantically equivalent to the JS multi-inject path.
      const injectBuffers = vector.injects.map((h) =>
        hexToBytes(h as `0x${string}`),
      );
      const absorbedLen = injectBuffers.reduce((a, b) => a + b.length, 0);
      const absorbed = new Uint8Array(absorbedLen);
      {
        let offset = 0;
        for (const buf of injectBuffers) {
          absorbed.set(buf, offset);
          offset += buf.length;
        }
      }

      // Total bytes requested = sum of extracts array.
      const totalOutLen = vector.extracts.reduce((a, b) => a + b, 0);

      // --- Solidity side ---
      const solHex = (await harness.read.extract([
        bytesToHex(absorbed),
        BigInt(totalOutLen),
      ])) as `0x${string}`;

      // --- JS side ---
      // Drive the ORIGINAL multi-inject + multi-extract sequence (not the
      // concatenated form) to exercise the actual production code path.
      // The concatenated stream output should still match byte-for-byte —
      // JS sub-block extract chunking is transparent once outputs are
      // concatenated, and the multi-inject path is invariant-equivalent.
      const prg = createKeccakPrg();
      for (const buf of injectBuffers) {
        prg.inject(buf);
      }
      prg.flip();
      const jsChunks: Uint8Array[] = [];
      for (const n of vector.extracts) {
        jsChunks.push(prg.extract(n));
      }
      const jsOut = new Uint8Array(totalOutLen);
      {
        let offset = 0;
        for (const chunk of jsChunks) {
          jsOut.set(chunk, offset);
          offset += chunk.length;
        }
      }

      assert.equal(
        solHex,
        bytesToHex(jsOut),
        `${vector.id}: Solidity extract(${totalOutLen}) ≠ JS createKeccakPrg stream (${totalOutLen} B)`,
      );
    }
  });
});
