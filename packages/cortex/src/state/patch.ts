/**
 * Patch wire-format encode/decode and applyPatch for CortexState V0.
 * Per patch_format_v0.md:
 *   - LEB128 varint-encoded indices
 *   - Old words omitted from wire (reconstructed from parent state)
 *   - 99th-pct ≤ 200 bytes for 4-word patch
 */

import type { CortexState, Patch, PatchError, PatchResult } from './types.js';
import { ERROR_NAMES, RANGES } from './types.js';
import { writeBigEndian32, readBigEndian32 } from './codec.js';
import { merkleizeState } from './merkle.js';
import { hasNonZeroReservedBits } from './validate.js';

// ─── LEB128 varint ────────────────────────────────────────────────────────────

/**
 * Encode an unsigned integer as LEB128.
 * For word indices (0–1023), this is at most 2 bytes.
 */
export function encodeLEB128(n: number): Uint8Array {
  if (n < 0) throw new RangeError('encodeLEB128: negative value');
  const bytes: number[] = [];
  do {
    let b = n & 0x7f;
    n >>>= 7;
    if (n !== 0) b |= 0x80;
    bytes.push(b);
  } while (n !== 0);
  return new Uint8Array(bytes);
}

/**
 * Decode an LEB128 unsigned integer from `data` starting at `offset`.
 * Returns the decoded value and number of bytes consumed.
 */
export function decodeLEB128(data: Uint8Array, offset: number): { value: number; bytesRead: number } {
  let result = 0;
  let shift = 0;
  let bytesRead = 0;
  while (true) {
    if (offset + bytesRead >= data.length) {
      throw new RangeError('decodeLEB128: unexpected end of data');
    }
    const b = data[offset + bytesRead]!;
    bytesRead++;
    result |= (b & 0x7f) << shift;
    shift += 7;
    if ((b & 0x80) === 0) break;
    if (shift >= 35) throw new RangeError('decodeLEB128: varint too long');
  }
  return { value: result >>> 0, bytesRead };
}

// ─── Patch wire encode/decode ─────────────────────────────────────────────────

/**
 * Wire format (per patch_format_v0.md):
 *   [1]  patchType
 *   [1]  wordCount
 *   [4]  scoreDeltaHi (big-endian uint32)
 *   [4]  scoreDeltaLo (big-endian uint32)
 *   [32] parentStateRoot
 *   for each word: [1-2] LEB128 index + [32] newWord
 */
export function encodePatch(patch: Patch): Uint8Array {
  // Validate wordCount
  if (patch.wordCount < 1 || patch.wordCount > 4) {
    throw new RangeError(`encodePatch: wordCount must be 1–4, got ${patch.wordCount}`);
  }
  if (patch.indices.length !== patch.wordCount || patch.newWords.length !== patch.wordCount) {
    throw new RangeError('encodePatch: indices/newWords length mismatch with wordCount');
  }

  // Encode indices
  const encodedIndices = patch.indices.map((idx) => encodeLEB128(idx));
  const indexBytes = encodedIndices.reduce((sum, arr) => sum + arr.length, 0);

  // Total size: 1 + 1 + 4 + 4 + 32 + indexBytes + wordCount * 32
  const totalSize = 42 + indexBytes + patch.wordCount * 32;
  const out = new Uint8Array(totalSize);
  let offset = 0;

  // patchType (1 byte)
  out[offset++] = patch.patchType & 0xff;

  // wordCount (1 byte)
  out[offset++] = patch.wordCount;

  // scoreDelta as int64, split into hi/lo uint32 big-endian
  // scoreDelta is a bigint; clamp to int64 range
  const sd = BigInt.asIntN(64, patch.scoreDelta);
  const sdUnsigned = BigInt.asUintN(64, sd);
  const sdHi = Number(sdUnsigned >> 32n) >>> 0;
  const sdLo = Number(sdUnsigned & 0xffffffffn) >>> 0;
  out[offset++] = (sdHi >>> 24) & 0xff;
  out[offset++] = (sdHi >>> 16) & 0xff;
  out[offset++] = (sdHi >>> 8) & 0xff;
  out[offset++] = sdHi & 0xff;
  out[offset++] = (sdLo >>> 24) & 0xff;
  out[offset++] = (sdLo >>> 16) & 0xff;
  out[offset++] = (sdLo >>> 8) & 0xff;
  out[offset++] = sdLo & 0xff;

  // parentStateRoot (32 bytes)
  if (patch.parentStateRoot.length !== 32) {
    throw new RangeError('encodePatch: parentStateRoot must be 32 bytes');
  }
  out.set(patch.parentStateRoot, offset);
  offset += 32;

  // For each word: LEB128 index + 32-byte newWord
  for (let i = 0; i < patch.wordCount; i++) {
    const idxBytes = encodedIndices[i]!;
    out.set(idxBytes, offset);
    offset += idxBytes.length;

    writeBigEndian32(out, offset, patch.newWords[i] ?? 0n);
    offset += 32;
  }

  return out;
}

/**
 * Decode a patch from its wire representation.
 * Throws on malformed input.
 */
export function decodePatch(data: Uint8Array): Patch {
  if (data.length < 42) {
    throw new RangeError(`decodePatch: too short (${data.length} bytes, min 42)`);
  }
  let offset = 0;

  const patchType = data[offset++]!;
  const wordCount = data[offset++]!;

  if (wordCount < 1 || wordCount > 4) {
    throw new RangeError(`decodePatch: invalid wordCount ${wordCount}`);
  }

  // scoreDelta: read hi+lo uint32, reconstruct int64
  const sdHi = ((data[offset]! << 24) | (data[offset + 1]! << 16) | (data[offset + 2]! << 8) | data[offset + 3]!) >>> 0;
  const sdLo = ((data[offset + 4]! << 24) | (data[offset + 5]! << 16) | (data[offset + 6]! << 8) | data[offset + 7]!) >>> 0;
  offset += 8;
  const sdUnsigned = (BigInt(sdHi) << 32n) | BigInt(sdLo);
  const scoreDelta = BigInt.asIntN(64, sdUnsigned);

  // parentStateRoot
  const parentStateRoot = data.slice(offset, offset + 32);
  offset += 32;

  // indices and newWords
  const indices: number[] = [];
  const newWords: bigint[] = [];

  for (let i = 0; i < wordCount; i++) {
    const { value: idx, bytesRead } = decodeLEB128(data, offset);
    offset += bytesRead;

    if (offset + 32 > data.length) {
      throw new RangeError('decodePatch: truncated at newWord');
    }
    const newWord = readBigEndian32(data, offset);
    offset += 32;

    indices.push(idx);
    newWords.push(newWord);
  }

  return { patchType, wordCount, scoreDelta, parentStateRoot, indices, newWords };
}

// ─── Apply patch ──────────────────────────────────────────────────────────────

function patchError(code: PatchError['code']): PatchError {
  return { ok: false, code, message: `${code}: ${ERROR_NAMES[code]}` };
}

/**
 * Apply a patch to a state, returning the new state or a rejection error.
 *
 * Rejection taxonomy (stable error codes):
 *   E01 WRONG_PARENT_ROOT   — patch.parentStateRoot ≠ merkleizeState(state)
 *   E02 WRONG_TYPE_FIELD    — target index is in the Reserved range (992–1023)
 *   E03 OVER_BUDGET         — wordCount > 4
 *   E04 RESERVED_BIT_SET    — resulting state has non-zero reserved bit
 *   E05 NOOP_PATCH          — every new word equals the current word
 */
export function applyPatch(state: CortexState, patch: Patch): PatchResult {
  // 1. Budget check
  if (patch.wordCount < 1 || patch.wordCount > 4) {
    return patchError('E03');
  }

  // 2. Parent-root check
  const currentRoot = merkleizeState(state);
  if (!bytesEqual(patch.parentStateRoot, currentRoot)) {
    return patchError('E01');
  }

  // 3. No-op check
  let anyChange = false;
  for (let i = 0; i < patch.wordCount; i++) {
    if ((state.words[patch.indices[i]!] ?? 0n) !== (patch.newWords[i] ?? 0n)) {
      anyChange = true;
      break;
    }
  }
  if (!anyChange) {
    return patchError('E05');
  }

  // 4. Apply words (with range check)
  const newWords: bigint[] = [...state.words];
  for (let i = 0; i < patch.wordCount; i++) {
    const idx = patch.indices[i]!;
    // 4a. Reserved range check
    if (idx >= RANGES.RESERVED_START && idx <= RANGES.RESERVED_END) {
      return patchError('E02');
    }
    if (idx < 0 || idx >= RANGES.WORD_COUNT) {
      return patchError('E02');
    }
    newWords[idx] = patch.newWords[i] ?? 0n;
  }

  // 5. Reserved-bit check on resulting state
  const resultState: CortexState = { words: newWords };
  if (hasNonZeroReservedBits(resultState)) {
    return patchError('E04');
  }

  return { ok: true, state: resultState };
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
