// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {KeccakPrng, initPrng, refill} from "../../ETHDILITHIUM/src/ZKNOX_keccak_prng.sol";

/// @title KeccakPrngHarness
/// @author FlyFlow
/// @notice Thin viem-deployable wrapper around the free functions exported
///         by `ETHDILITHIUM/src/ZKNOX_keccak_prng.sol`. The ZKNox source
///         declares `struct KeccakPrng` + free functions `initPrng`,
///         `refill`, `nextByte` at file scope — solc emits no standalone
///         artifact for a free-functions-only file, so viem cannot call
///         them directly. This harness exposes a single `extract` entry
///         point sufficient for the Story 2 / AC-2-6 G0-prime cross-check
///         (JS `createKeccakPrg` equivalent to Solidity `ZKNOX_keccak_prng` on
///         the Layer-2 fixtures).
/// @dev    Solidity's `initPrng` is one-shot absorb — it hashes a single
///         `bytes memory input` argument. Multi-inject fixtures
///         (e.g., `prg-multi-inject`) must be pre-concatenated by the
///         caller; the AC-2-3 absorb-concatenation invariant guarantees
///         `keccak256(a ‖ b) == keccak256(concat_buffer)` after
///         `inject(a); inject(b); flip()`, so this is semantically
///         equivalent to the JS multi-inject-then-flip path. Test-only
///         contract — not deployed to production.
///
///         `ZKNOX_keccak_prng.sol` also exports `nextByte(KeccakPrng) ->
///         (uint8, KeccakPrng)` for single-byte reads. It is intentionally
///         NOT exposed here: AC-2-6 only requires block-stream byte-
///         identity for Layer-2 fixtures, and the `extract` entry point
///         already drives the same state-machine transitions (`initPrng`
///         + `refill` + `pool` reads). Adding a `nextByte` passthrough
///         would duplicate state-tracking semantics without strengthening
///         any AC — defer to a Story 3+ story if rejection-sampling
///         call-sites need byte-granular Solidity parity.
contract KeccakPrngHarness {
    /// @notice Drive the Keccak-PRG state machine: `initPrng(input)` +
    ///         pool-reads with `refill` between 32-byte blocks, returning
    ///         the concatenated stream output.
    /// @dev    `initPrng` pre-computes block 0 (`counter=0`) into `pool`
    ///         and advances the internal counter to 1, so the first
    ///         iteration consumes `pool` directly — subsequent iterations
    ///         call `refill` first. The final partial block (if
    ///         `outLen % 32 != 0`) is sliced to the requested length.
    ///         Equivalent to JS `createKeccakPrg(); inject(input); flip();
    ///         extract(outLen)` on byte-for-byte identical output.
    /// @param  input  Bytes to absorb (single chunk). Callers concatenate
    ///                multi-inject sequences off-chain.
    /// @param  outLen Number of pseudorandom bytes to emit.
    /// @return out    The `outLen`-byte stream output.
    function extract(bytes calldata input, uint256 outLen)
        external
        pure
        returns (bytes memory out)
    {
        out = new bytes(outLen);
        if (outLen == 0) {
            return out;
        }

        KeccakPrng memory prng = initPrng(input);
        uint256 written = 0;
        bool firstBlock = true;
        while (written < outLen) {
            if (!firstBlock) {
                refill(prng);
            }
            firstBlock = false;

            uint256 remaining = outLen - written;
            uint256 chunk = remaining >= 32 ? 32 : remaining;
            bytes32 pool = prng.pool;
            // Copy `chunk` bytes (MSB-first) from `pool` into `out[written..]`.
            for (uint256 i = 0; i < chunk; i++) {
                // forge-lint: disable-next-line(unsafe-typecast)
                out[written + i] = bytes1(uint8(uint256(pool) >> (248 - 8 * i)));
            }
            written += chunk;
        }
    }
}
