/**
 * Merkleization for CoreTex state.
 * Per merkleization_spec.md:
 *   - 1024 leaves → perfect binary tree depth 10
 *   - leaf[i] = keccak256(bigEndian32(words[i]))
 *   - internal: keccak256(leftChild ‖ rightChild)
 *   - No sorting; position-indexed tree
 */

import type { CortexState } from './types.js';
import { RANGES } from './types.js';
import { writeBigEndian32 } from './codec.js';
import { keccak256 } from './keccak256.js';

export interface MerkleTreeCache {
  /** levels[0] are the 1024 leaves; levels[10][0] is the root. */
  readonly levels: readonly (readonly Uint8Array[])[];
  readonly root: Uint8Array;
}

export interface MerkleWordUpdate {
  readonly index: number;
  readonly word: bigint;
}

/**
 * Compute the Merkle root of a CortexState.
 * Returns 32 bytes matching the on-chain keccak256 root.
 */
export function merkleizeState(state: CortexState): Uint8Array {
  return buildMerkleCache(state).root;
}

/**
 * Build and cache every level of the canonical CortexState Merkle tree.
 */
export function buildMerkleCache(state: CortexState): MerkleTreeCache {
  if (state.words.length !== RANGES.WORD_COUNT) {
    throw new TypeError(`buildMerkleCache: expected ${RANGES.WORD_COUNT} words, got ${state.words.length}`);
  }

  const levels: Uint8Array[][] = [];
  const wordBuf = new Uint8Array(32);
  let level: Uint8Array[] = new Array(RANGES.WORD_COUNT);
  for (let i = 0; i < RANGES.WORD_COUNT; i++) {
    writeBigEndian32(wordBuf, 0, state.words[i] ?? 0n);
    level[i] = keccak256(wordBuf);
  }
  levels.push(level);

  const pairBuf = new Uint8Array(64);
  while (level.length > 1) {
    const nextLevel: Uint8Array[] = new Array(level.length / 2);
    for (let i = 0; i < level.length / 2; i++) {
      pairBuf.set(level[i * 2]!, 0);
      pairBuf.set(level[i * 2 + 1]!, 32);
      nextLevel[i] = keccak256(pairBuf);
    }
    level = nextLevel;
    levels.push(level);
  }

  return { levels, root: level[0]! };
}

/**
 * Return a new Merkle cache after applying a small set of word updates.
 *
 * The tree shape and hash function are identical to merkleizeState(); this only
 * recomputes the affected leaf-to-root paths. For the current patch budget (1-4
 * words), this is roughly 40 hashes instead of rebuilding all 2047 nodes.
 */
export function updateMerkleCache(
  cache: MerkleTreeCache,
  updates: readonly MerkleWordUpdate[],
): MerkleTreeCache {
  if (cache.levels.length !== 11 || cache.levels[0]?.length !== RANGES.WORD_COUNT) {
    throw new TypeError('updateMerkleCache: invalid cache shape');
  }
  if (updates.length === 0) {
    return cache;
  }

  const deduped = new Map<number, bigint>();
  for (const update of updates) {
    if (!Number.isInteger(update.index) || update.index < 0 || update.index >= RANGES.WORD_COUNT) {
      throw new RangeError(`updateMerkleCache: index out of range ${update.index}`);
    }
    deduped.set(update.index, update.word);
  }

  const levels: Uint8Array[][] = cache.levels.map((level) => [...level]);
  const dirtyByLevel: Set<number>[] = [];
  dirtyByLevel[0] = new Set<number>();

  const wordBuf = new Uint8Array(32);
  for (const [index, word] of deduped) {
    writeBigEndian32(wordBuf, 0, word);
    levels[0]![index] = keccak256(wordBuf);
    dirtyByLevel[0]!.add(index);
  }

  const pairBuf = new Uint8Array(64);
  for (let depth = 0; depth < levels.length - 1; depth++) {
    const dirty = dirtyByLevel[depth] ?? new Set<number>();
    const parents = new Set<number>();
    for (const childIndex of dirty) {
      parents.add(childIndex >> 1);
    }

    const currentLevel = levels[depth]!;
    const nextLevel = levels[depth + 1]!;
    for (const parentIndex of parents) {
      const left = currentLevel[parentIndex * 2]!;
      const right = currentLevel[parentIndex * 2 + 1]!;
      pairBuf.set(left, 0);
      pairBuf.set(right, 32);
      nextLevel[parentIndex] = keccak256(pairBuf);
    }
    dirtyByLevel[depth + 1] = parents;
  }

  return { levels, root: levels[levels.length - 1]![0]! };
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
