# CoreTex Packing Spec

## Purpose

Defines the byte-level pack/unpack rules for CoreTex state. Round-trip invariant: `pack(unpack(state)) === state` byte-for-byte. Both reference implementations MUST produce identical packings.

---

## State representation

A CortexState is an ordered array of **1024 uint256 words** (`words[0]` through `words[1023]`).

**Packed bytes**: `state.pack()` serialises to exactly **32 768 bytes** (1024 × 32 bytes each). Word `i` occupies bytes `[32i, 32i + 31]` in big-endian order (MSB at byte offset 0).

**Memory layout**: word `i` bit `b` (where bit 255 is MSB, bit 0 is LSB) occupies byte `⌊(255 − b) / 8⌋` within the word's 32-byte slice, at bit position `b mod 8` counting from the byte's LSB.

---

## Pack algorithm

```
function pack(state: CortexState): Uint8Array {
  out = new Uint8Array(32768)
  for i in 0..1023:
    wordBytes = bigEndian32(state.words[i])  // 32 bytes
    out[32*i .. 32*i+31] = wordBytes
  return out
}
```

`bigEndian32(n: bigint): Uint8Array` — writes `n` as a big-endian 256-bit unsigned integer, zero-padded to 32 bytes.

---

## Unpack algorithm

```
function unpack(bytes: Uint8Array): CortexState {
  assert bytes.length === 32768, "ERR_WRONG_LENGTH"
  words = new Array(1024)
  for i in 0..1023:
    words[i] = readBigEndian32(bytes, 32*i)
  return { words }
}
```

`readBigEndian32(bytes, offset)` — reads 32 bytes at `offset` as a big-endian 256-bit unsigned integer.

---

## Sub-word field extraction

Field at `(word, bitsHi, bitsLo)` — both inclusive, `bitsHi ≥ bitsLo`, values are 0–255 with 255 = MSB:

```
mask  = (1n << BigInt(bitsHi - bitsLo + 1)) - 1n
value = (words[word] >> BigInt(bitsLo)) & mask
```

Field set:
```
mask    = (1n << BigInt(bitsHi - bitsLo + 1)) - 1n
cleared = words[word] & ~(mask << BigInt(bitsLo))
words[word] = cleared | ((value & mask) << BigInt(bitsLo))
```

---

## Reserved-bit enforcement

After unpack and before any use, a validator MUST check that every reserved bit (any bit position in any word that is not covered by a named field in `coretex_schema.json`) is zero.

Reserved range (words 992–1023): every bit in all 32 words must be zero.

Reserved bits within individual words (e.g. bits 191:0 of word 0, bits 127:0 of word 1, bits 63:0 of word 8) must also be zero.

Sub-field reserved flags (e.g. FLAGS bits 15:1, VALIDITY_FLAGS bits 15:3) must be zero.

On any violation: return error `RESERVED_BIT_SET` (E04).

---

## Canonical zero check

A "zero word" is `0n` (BigInt). The canonical empty/uninitialized state has all words = 0 **except** for valid header fields. A state whose reserved words are non-zero is always invalid regardless of other fields.

---

## Endianness note

All multi-byte fields inside a word are defined MSB-first (big-endian). When a bytes32 field occupies the entire 256 bits of a word, its first byte (index 0) maps to bits 255:248.

---

## Round-trip test requirement

The canonical pack/unpack checks now live in `packages/coretex/test/unit/codec.test.mjs`.

---

## See also

- `coretex_state.md` — field definitions
- `coretex_schema.json` — machine-readable field registry
- `merkleization_spec.md` — Merkle root derivation (builds on packed bytes)
