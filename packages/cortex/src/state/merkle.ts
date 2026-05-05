/**
 * Merkleization for CortexState V0.
 * Per merkleization_spec_v0.md:
 *   - 1024 leaves → perfect binary tree depth 10
 *   - leaf[i] = keccak256(bigEndian32(words[i]))
 *   - internal: keccak256(leftChild ‖ rightChild)
 *   - No sorting; position-indexed tree
 */

import type { CortexState } from './types.js';
import { RANGES } from './types.js';
import { writeBigEndian32 } from './codec.js';
import { keccak256 } from './keccak256.js';

/**
 * Compute the Merkle root of a CortexState.
 * Returns 32 bytes matching the on-chain keccak256 root.
 */
export function merkleizeState(state: CortexState): Uint8Array {
  if (state.words.length !== RANGES.WORD_COUNT) {
    throw new TypeError(`merkleizeState: expected ${RANGES.WORD_COUNT} words, got ${state.words.length}`);
  }

  // Build leaf level
  const wordBuf = new Uint8Array(32);
  let level: Uint8Array[] = new Array(RANGES.WORD_COUNT);
  for (let i = 0; i < RANGES.WORD_COUNT; i++) {
    writeBigEndian32(wordBuf, 0, state.words[i] ?? 0n);
    level[i] = keccak256(wordBuf.slice(0)); // leaf[i] = keccak256(bigEndian32(word))
  }

  // Reduce up to root (depth 10, so 10 iterations)
  const pairBuf = new Uint8Array(64);
  while (level.length > 1) {
    const nextLevel: Uint8Array[] = new Array(level.length / 2);
    for (let i = 0; i < level.length / 2; i++) {
      pairBuf.set(level[2 * i]!, 0);
      pairBuf.set(level[2 * i + 1]!, 32);
      nextLevel[i] = keccak256(pairBuf);
    }
    level = nextLevel;
  }

  return level[0]!;
}

/**
 * Hex-encode a 32-byte Uint8Array to a 0x-prefixed hex string.
 */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = '0x';
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Decode a 0x-prefixed hex string to a Uint8Array.
 */
export function hexToBytes(hex: string): Uint8Array {
  const s = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (s.length % 2 !== 0) throw new RangeError('hexToBytes: odd-length hex string');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
