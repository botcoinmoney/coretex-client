# CoreTex Merkleization Spec

## Purpose

Defines the exact Merkle tree shape, leaf encoding, hash function, and pad policy used to compute the **state root** from a 1024-word CortexState. Both reference implementations MUST produce byte-identical roots from the same state.

---

## Hash function

`keccak256` — the standard Keccak-256 hash, as defined in Ethereum's yellow paper and implemented in `node:crypto` (`createHash('sha3-256')` is SHA-3, not Keccak; use `ethereum-cryptography/keccak` or a compatible implementation that matches EVM `keccak256`).

Specifically: `keccak256(data: Uint8Array): Uint8Array` producing 32 bytes, matching the Solidity `keccak256(...)` built-in.

**Implementation note**: Node.js `crypto.createHash('sha3-256')` uses the NIST SHA-3 standard which differs in padding from Keccak-256. The correct Keccak-256 implementation for on-chain parity can be obtained via:
- `ethereum-cryptography` npm package (`import { keccak256 } from 'ethereum-cryptography/keccak.js'`), which is a pure-JS implementation with no native deps.
- Or a manual implementation using the `node:crypto` `createHash` with the `previous` keccak variant if available.

For this Phase 1 implementation, we use the `ethereum-cryptography` package's keccak256. It is listed as a devDependency or direct dependency only in `@botcoin/coretex`.

---

## Leaf encoding

Each leaf corresponds to one 256-bit word from the state array.

**Leaf `i`** (for `i` ∈ [0, 1023]) is:

```
leaf[i] = keccak256(bigEndian32(words[i]))
```

where `bigEndian32(n)` is the 32-byte big-endian encoding of `n`. This matches the EVM convention of `keccak256(abi.encode(words[i]))` for `uint256 words[i]`.

The leaf hash domain-separates the raw word value via a single hash, preventing second-preimage confusion between internal nodes and leaves.

---

## Tree shape

**1024 leaves → exactly 1024 leaves**. 1024 = 2^10, so the tree is a **perfect binary tree with depth 10**. No padding is required because the leaf count is already a power of two.

Tree construction (bottom-up):

1. Level 0 (leaves): `L[0][i] = leaf[i]` for `i` ∈ [0, 1023]. Array has 1024 elements.
2. Level 1: `L[1][i] = keccak256(L[0][2i] ‖ L[0][2i+1])` for `i` ∈ [0, 511]. Array has 512 elements.
3. Level 2: `L[2][i] = keccak256(L[1][2i] ‖ L[1][2i+1])` for `i` ∈ [0, 255]. Array has 256 elements.
4. Continue through level 10: array has 1 element.
5. **Root** = `L[10][0]`.

`‖` denotes concatenation: `L[k][2i] ‖ L[k][2i+1]` is 64 bytes (two 32-byte hashes concatenated left-to-right).

---

## Internal node formula

```
node = keccak256(leftChild ‖ rightChild)
```

Both children are 32-byte values. Concatenation is 64 bytes.

**No sorting**: children are NOT sorted. The left child is always the lower-indexed subtree. This is a position-indexed tree, not an unordered Merkle set.

---

## Root

The root is a 32-byte value (`bytes32`). It uniquely commits to the entire ordered 1024-word state.

---

## Reference pseudocode

```
function merkleizeState(words: bigint[1024]): bytes32 {
  level: bytes32[] = [leaf(words[0]), leaf(words[1]), ..., leaf(words[1023])]  // 1024 elements
  while level.length > 1:
    next: bytes32[] = []
    for i in 0 .. level.length/2 - 1:
      next.push(keccak256(level[2*i] ++ level[2*i+1]))
    level = next
  return level[0]
}

function leaf(word: bigint): bytes32 {
  return keccak256(bigEndian32(word))
}
```

---

## Determinism requirements

1. Same 1024-word state → same root on every platform and language.
2. Big-endian word encoding is mandatory; little-endian produces different roots.
3. keccak256 must match on-chain `keccak256` exactly (Keccak, not SHA-3 NIST).
4. No randomness, no timestamps, no platform-specific primitives.

---

## Cross-implementation parity

The Phase 1 requirement is that this TypeScript implementation and a future second reference implementation (to be delivered in a follow-up PR) compute byte-identical roots from the same state. The second implementation cross-check is **not** a gate for this PR — see PR body for note.

---

## Test vectors

The E2E test suite generates 1 000 randomised states and verifies that the root produced by this spec matches the root produced by independently re-running the algorithm from scratch (internal self-parity). Full cross-impl parity deferred to the second impl PR.

---

## See also

- `packing_spec.md` — byte layout (pack input to each leaf)
- `patch_format.md` — patch carries `parentStateRoot` (a root from this spec)
