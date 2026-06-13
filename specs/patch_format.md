# CoreTex Patch Wire Format

## Purpose

Defines the binary wire format for a CortexState patch. Old words are **omitted from the wire** — they are reconstructed from the parent state during evaluation. A matching `parentStateRoot` already implies old-word correctness.

---

## Wire-size budget

99th-percentile patch wire size on a 10 000-sample fuzz run MUST be ≤ 200 bytes for the 4-word case. CI fails on regression.

---

## Varint encoding: LEB128

Target word indices are encoded using **unsigned LEB128** (Little-Endian Base 128), the same scheme used in WASM and protocol-buffers for variable-length unsigned integers.

**Encoding**:
```
function encodeLEB128(n: number): Uint8Array {
  bytes = []
  while true:
    b = n & 0x7F
    n >>= 7
    if n != 0: b |= 0x80   // more bytes follow
    bytes.push(b)
    if n == 0: break
  return Uint8Array.from(bytes)
}
```

**Decoding**:
```
function decodeLEB128(bytes, offset): { value: number, bytesRead: number } {
  result = 0, shift = 0
  while true:
    b = bytes[offset++]
    result |= (b & 0x7F) << shift
    shift += 7
    if (b & 0x80) == 0: break
  return { value: result, bytesRead: shift/7 }
}
```

Word indices 0–1023 require at most 2 bytes in LEB128 (indices ≥ 128 use 2 bytes; indices 0–127 use 1 byte).

---

## Wire format (binary, field-by-field)

```
Patch wire = [
  PATCH_TYPE        : 1 byte   — see patch type table
  WORD_COUNT        : 1 byte   — number of words changed (1–4)
  SCORE_DELTA_HI    : 4 bytes  — score delta × 1e6, big-endian uint32, high word
  SCORE_DELTA_LO    : 4 bytes  — score delta × 1e6, big-endian uint32, low word
                                 (combined: int64 = SCORE_DELTA_HI << 32 | SCORE_DELTA_LO)
  PARENT_STATE_ROOT : 32 bytes — keccak256 Merkle root of the parent CortexState
  [for each word in 0..WORD_COUNT-1]:
    INDEX           : 1–2 bytes — LEB128-encoded word index (0–1023)
    NEW_WORD        : 32 bytes  — new value for the word at INDEX
]
```

Total for a 4-word patch (all indices < 128):
- 1 (type) + 1 (count) + 8 (score delta) + 32 (parent root) + 4×(1+32) = 42 + 132 = **174 bytes**

Total for a 4-word patch (all indices ≥ 128, 2-byte LEB128):
- 1 + 1 + 8 + 32 + 4×(2+32) = 42 + 136 = **178 bytes**

Both are well under the 200-byte budget.

---

## Patch types

| Code   | Name             | Description                                        |
|--------|------------------|----------------------------------------------------|
| `0x01` | KEY_UPDATE       | Words in RetrievalKeys range (384–671)             |
| `0x02` | SLOT_REPLACE     | Words in MemoryIndex range (32–383)                |
| `0x03` | TEMPORAL_UPDATE  | Words in Temporal range (800–895)                  |
| `0x04` | RELATION_UPDATE  | Words in Relations range (672–799)                 |
| `0x05` | CODEBOOK_UPDATE  | Words in Codebook range (896–991)                  |
| `0x06` | HEADER_UPDATE    | Words in Header range (0–31) — restricted          |
| `0xFF` | MIXED            | Targets words in more than one range               |

The `patchType` in the wire encoding is advisory/descriptive for index routing. Actual validation checks each target index against the schema.

---

## Rejection taxonomy (stable error codes)

| Code  | Name              | Trigger condition                                                           |
|-------|-------------------|-----------------------------------------------------------------------------|
| `E01` | WRONG_PARENT_ROOT | `patch.parentStateRoot` does not match `merkleizeState(currentState)`      |
| `E02` | WRONG_TYPE_FIELD  | A target word index falls in the Reserved range (992–1023) or in a range incompatible with the declared `patchType` (strict: MIXED overrides) |
| `E03` | OVER_BUDGET       | `patch.wordCount > 4` (current max budget)                                      |
| `E04` | RESERVED_BIT_SET  | Applying the patch would produce a state with a non-zero reserved bit      |
| `E05` | NOOP_PATCH        | Every `newWord[i] === currentState.words[index[i]]` — no actual change     |

These codes are stable across versions. A higher-level consumer may surface additional context, but the `code` field value is immutable.

---

## Apply algorithm

```
function applyPatch(state: CortexState, patch: Patch): CortexState | PatchError {
  // 1. Budget check
  if patch.wordCount < 1 || patch.wordCount > 4: return { error: 'E03', code: 'OVER_BUDGET' }

  // 2. Parent-root check
  currentRoot = merkleizeState(state)
  if patch.parentStateRoot !== currentRoot: return { error: 'E01', code: 'WRONG_PARENT_ROOT' }

  // 3. No-op check
  allNoOp = true
  for i in 0..patch.wordCount-1:
    if state.words[patch.indices[i]] !== patch.newWords[i]: allNoOp = false
  if allNoOp: return { error: 'E05', code: 'NOOP_PATCH' }

  // 4. Apply words
  newWords = [...state.words]
  for i in 0..patch.wordCount-1:
    idx = patch.indices[i]
    // 4a. Type/range check: reserved range forbidden
    if idx >= 992 && idx <= 1023: return { error: 'E02', code: 'WRONG_TYPE_FIELD' }
    newWords[idx] = patch.newWords[i]

  // 5. Reserved-bit check on resulting state
  if hasNonZeroReservedBits({ words: newWords }): return { error: 'E04', code: 'RESERVED_BIT_SET' }

  return { words: newWords }
}
```

---

## Old-word reconstruction

During evaluation, the evaluator reconstructs old words as:
```
oldWord[i] = parentState.words[patch.indices[i]]
```

Because `patch.parentStateRoot === merkleizeState(parentState)` is already checked, the parent state is the unique state with that root, so old-word values are implied. Putting them on the wire would be redundant.

The E2E "old-words reconstruction parity" test verifies that a patch with old words explicitly present produces the same evaluation result as the wire format without old words, given the same `parentState`.

---

## Encode/decode round-trip

`encode(decode(wireBytes)) === wireBytes` must hold exactly for all valid patches.

---

## Patch hash domains

Two distinct hashes are derived from the same `wireBytes`. They serve
different purposes and are NOT interchangeable:

| Hash name | Definition | Domain prefix | Used by |
|-----------|-----------|----------------|---------|
| `patchBytesHash` | `keccak256(wireBytes)` | (none, raw) | On-chain `CoretexPatchBytes` event topic; replay state-root continuity (`replay/v4.ts`); patch dedup at the contract level |
| `evalPatchHash` | `keccak256("coretex-patch-hash-v1" \|\| wireBytes)` | `coretex-patch-hash-v1` | Per-patch eval seed derivation (`seed-derivation.ts:computePatchHash`); receipts; replay verification of per-patch decisions |

Both are deterministic functions of `wireBytes`, so a watcher with the
patch bytes can reproduce either. The distinct domains exist so that
a value computed for one purpose cannot be silently substituted for
the other (replay forgery defense — see
`docs/CORETEX_V4_ONCHAIN_RANDOMNESS_PLAN.md` §"Domain Separation").

In code, both currently appear under the name `patchHash`. Naming will
be tightened in a future commit; the canonical definitions above are
the source of truth.

---

## See also

- `coretex_state.md` — field definitions and rejection error codes
- `merkleization_spec.md` — computing `parentStateRoot`
- `packing_spec.md` — word serialization
- `docs/CORETEX_V4_ONCHAIN_RANDOMNESS_PLAN.md` — per-patch eval-seed derivation, dual-pack confirmation
