# Amendments

Architecture corrections discovered during implementation. Each amendment is a binding override of the frozen architecture document — the story-creator-agent and implementers MUST treat amended values as authoritative over the original architecture.md text.

---

## A-001: DD-7 `reshapedPublicKey` ABI — `tr` is `bytes` (64 B), not `bytes32`

- **Story:** 1 (Fixture-gen CLI)
- **Task:** 3 (Core generation path — CLI surfaces this via `Dilithium2.pk_for_eth` invocation)
- **Date:** 2026-04-18
- **Classification:** Rule 3 (Significant — interface/contract correction)
- **Affects:** DD-7 LOCKED (architecture §"Data Models" → "ETHDilithium public key (reshaped)"); architecture §"Signature payload at Solidity boundary" (by association — only the `reshapedPublicKey` side changes; signature ABI `abi.encode(bytes cTilde, bytes z, bytes h)` is unchanged)

### Original (architecture.md:53-57)

```
Produced by `preparePublicKeyForDeployment(rawPk, xof)` → SSTORE2 payload:
abi.encode(bytes aHatEncoded, bytes32 tr, bytes t1Encoded)

`aHatEncoded` = 4×4 NTT-domain matrix, 32-bit compact-packed.
`tr` = `Keccak256(ρ ∥ t1)`.
`t1Encoded` = Power2Round (`<<D=13`) + NTT + compact-packed.
```

### Actual (verified against pinned submodule `b9ca7f72526ecc696230d3c774a6e2c12c9b37c2`)

```
Produced by `preparePublicKeyForDeployment(rawPk, xofFactory)` → SSTORE2 payload:
abi.encode(bytes aHatEncoded, bytes tr, bytes t1Encoded)

`aHatEncoded` = 4×4 NTT-domain matrix, 32-bit compact-packed.
`tr` = Keccak256PRNG-derived 64-byte stream of `pk` (i.e., `h(pk, outLen=64)` where the
      XOF is the Keccak-PRG stream construction, NOT native 32-byte Keccak-256).
`t1Encoded` = Power2Round (`<<D=13`) + NTT + compact-packed.
```

### Evidence

1. **Python reference** — `ETHDILITHIUM/pythonref/dilithium_py/dilithium/dilithium.py:568-576`:
   ```python
   def pk_for_eth(self, pk, _xof=Keccak256PRNG, _xof2=Keccak256PRNG, zk=False):
       rho, t1 = self._unpack_pk(pk)
       tr = self._h(pk, 64, _xof=_xof)   # ← 64 bytes via Keccak-PRG stream
       A_hat = self._expand_matrix_from_seed(rho, _xof=_xof2, zk=zk)
       t1_new = t1.scale(1 << self.d).to_ntt()
       return A_hat, tr, t1_new
   ```

2. **Solidity struct** — `ETHDILITHIUM/src/ZKNOX_dilithium_utils.sol:427-431`:
   ```solidity
   struct PubKey {
       uint256[][][] aHat;
       bytes tr;                          // ← variable-length, not bytes32
       uint256[][] t1;
   }
   ```

3. **Solidity SSTORE2 reader** — `ETHDILITHIUM/src/ZKNOX_ethdilithium.sol:182-188`:
   ```solidity
   function _readPubKey(address pointer) internal view returns (PubKey memory) {
       (bytes memory aHatEncoded, bytes memory tr, bytes memory t1Encoded) =
           abi.decode(SSTORE2.read(pointer), (bytes, bytes, bytes));  // ← (bytes, bytes, bytes)
       ...
   }
   ```

### Impact

- **Story 1 Task 3** (this task): CLI's Python batch ABI-encodes `(bytes, bytes, bytes)` rather than `(bytes, bytes32, bytes)`. Fixture `reshapedPublicKey` bytes reflect this choice. Spot-check: `cast abi-decode "f(bytes,bytes,bytes)" 0x...` returns arrays of lengths `(16384, 64, 4096)` for `aHat` / `tr` / `t1_new` — matches Solidity expectations.
- **Story 3** (XOF refactor + keygen): `preparePublicKeyForDeployment`'s implementation must emit `(bytes, bytes, bytes)` ABI tuple — the refactor already implies this since `tr` is computed via the XofFactory (which for the ETH path yields 64-B Keccak-PRG output).
- **Story 5** (pk-transform + G3 + account): G3 KAT tests byte-identity against fixture `reshapedPublicKey`. The 64-B `tr` flows through to the account's `publicKeyPointer` (via `setKey`) and is consumed by `_readPubKey` — all cross-references remain valid.
- **DD-7 `c_tilde_bytes`**: `cTilde` in the signature payload is still 32 bytes (native Keccak-256 challenge digest) — unaffected. DD-8 (signature ABI) is unchanged: `abi.encode(bytes cTilde, bytes z, bytes h)`.

### Rationale

Architecture DD-7 was drafted referencing the NIST spec's `tr` (32 B via `H(pk)` where H is SHAKE-256 → truncated). The ETH variant replaces the native hash with a Keccak-PRG stream AND doubles the output length to 64 B for domain-separation hardening inside the signer (see `tr + m` composition at `dilithium.py:299` where 64-B `tr` prefixes the message hash). Architecture phase missed this detail because it treated the XOF swap (DD-1) as purely a hash-function substitution without tracking the `outLen` argument change in `_h(pk, 64)`.

### Resolution

- Task 3's CLI uses `abi.encode(bytes, bytes, bytes)` — correct per the sources above. **No change to Task 3 implementation.**
- Story 1's inlined DD-7 description in `docs/stories/1-fixture-gen-cli.md` (Dev Notes §"DD-7 LOCKED") is updated to reference this amendment.
- Downstream story files (Stories 3, 5) will pick up the corrected schema via the story-creator-agent reading both architecture.md AND this amendments.md — the agent is contracted to use amended values where they conflict.
