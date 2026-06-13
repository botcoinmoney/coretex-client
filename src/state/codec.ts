/**
 * Pack/unpack (encode/decode) for CoreTex state.
 * Per packing_spec.md: 1024 words × 32 bytes each = 32768 bytes, big-endian.
 */

import type { CortexState } from './types.js';
import { RANGES } from './types.js';

export const PACKED_SIZE = 32_768; // 1024 × 32

/**
 * Pack a CortexState into 32 768 bytes (big-endian uint256 words).
 */
export function pack(state: CortexState): Uint8Array {
  if (state.words.length !== RANGES.WORD_COUNT) {
    throw new TypeError(`pack: expected ${RANGES.WORD_COUNT} words, got ${state.words.length}`);
  }
  const out = new Uint8Array(PACKED_SIZE);
  for (let i = 0; i < RANGES.WORD_COUNT; i++) {
    writeBigEndian32(out, i * 32, state.words[i] ?? 0n);
  }
  return out;
}

/**
 * Unpack 32 768 bytes into a CortexState (does NOT validate reserved bits).
 * Throws on wrong length.
 */
export function unpack(bytes: Uint8Array): CortexState {
  if (bytes.length !== PACKED_SIZE) {
    throw new RangeError(`unpack: expected ${PACKED_SIZE} bytes, got ${bytes.length}`);
  }
  const words: bigint[] = new Array(RANGES.WORD_COUNT);
  for (let i = 0; i < RANGES.WORD_COUNT; i++) {
    words[i] = readBigEndian32(bytes, i * 32);
  }
  return { words };
}

// ─── Bit-field helpers ────────────────────────────────────────────────────────

/**
 * Extract a sub-field from a word.
 * @param word  - the uint256 word (bigint)
 * @param bitsHi - most-significant bit index (0–255, where 255 = MSB)
 * @param bitsLo - least-significant bit index (0–255)
 */
export function getField(word: bigint, bitsHi: number, bitsLo: number): bigint {
  const width = bitsHi - bitsLo + 1;
  const mask = (1n << BigInt(width)) - 1n;
  return (word >> BigInt(bitsLo)) & mask;
}

/**
 * Set a sub-field in a word (returns new word).
 */
export function setField(word: bigint, bitsHi: number, bitsLo: number, value: bigint): bigint {
  const width = bitsHi - bitsLo + 1;
  const mask = (1n << BigInt(width)) - 1n;
  const shift = BigInt(bitsLo);
  return (word & ~(mask << shift)) | ((value & mask) << shift);
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Write a bigint as a big-endian 32-byte value into `out` at `offset`.
 */
export function writeBigEndian32(out: Uint8Array, offset: number, value: bigint): void {
  let v = BigInt.asUintN(256, value);
  for (let b = 31; b >= 0; b--) {
    out[offset + b] = Number(v & 0xffn);
    v >>= 8n;
  }
}

/**
 * Read 32 bytes at `offset` from `bytes` as a big-endian uint256 bigint.
 */
export function readBigEndian32(bytes: Uint8Array, offset: number): bigint {
  let result = 0n;
  for (let b = 0; b < 32; b++) {
    result = (result << 8n) | BigInt(bytes[offset + b] ?? 0);
  }
  return result;
}
