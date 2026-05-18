/**
 * Reserved-bit enforcement for CoreTex state.
 * Per cortex_state.md: any non-zero reserved bit → reject with E04.
 */

import type { CortexState, PatchError } from './types.js';
import { RANGES } from './types.js';

// ─── Reserved-bit masks per word ─────────────────────────────────────────────
// A "reserved mask" for word i is the set of bits that MUST be zero.
// Non-reserved bits are the named fields per cortex_state.md.

const UINT256_MAX = (1n << 256n) - 1n;

/** Compute the reserved (must-be-zero) mask for a given word index. */
function reservedMask(wordIdx: number): bigint {
  // Range G: words 992–1023 — every bit reserved
  if (wordIdx >= RANGES.RESERVED_START && wordIdx <= RANGES.RESERVED_END) {
    return UINT256_MAX;
  }

  // Header range: per-word masks
  if (wordIdx >= RANGES.HEADER_START && wordIdx <= RANGES.HEADER_END) {
    return headerReservedMask(wordIdx);
  }

  // MemoryIndex range (words 32–383): 8-word slots
  if (wordIdx >= RANGES.MEMORY_INDEX_START && wordIdx <= RANGES.MEMORY_INDEX_END) {
    const slotWord = (wordIdx - RANGES.MEMORY_INDEX_START) % 8;
    return memoryIndexSlotReservedMask(slotWord);
  }

  // RetrievalKeys range (words 384–671): 8-word slots
  if (wordIdx >= RANGES.RETRIEVAL_KEYS_START && wordIdx <= RANGES.RETRIEVAL_KEYS_END) {
    const slotWord = (wordIdx - RANGES.RETRIEVAL_KEYS_START) % 8;
    return retrievalKeySlotReservedMask(slotWord);
  }

  // Relations range (words 672–799): 1-word entries
  if (wordIdx >= RANGES.RELATIONS_START && wordIdx <= RANGES.RELATIONS_END) {
    // Retrieval-benchmark relation entries use high control bits plus compact
    // low-byte source/target fields. Semantic validation lives in the decoder.
    return 0n;
  }

  // Temporal range (words 800–895): 1-word entries
  if (wordIdx >= RANGES.TEMPORAL_START && wordIdx <= RANGES.TEMPORAL_END) {
    // bits 31:0 reserved
    return (1n << 32n) - 1n;
  }

  // Codebook range (words 896–991): 2-word entries
  if (wordIdx >= RANGES.CODEBOOK_START && wordIdx <= RANGES.CODEBOOK_END) {
    const slotWord = (wordIdx - RANGES.CODEBOOK_START) % 2;
    return codebookSlotReservedMask(slotWord);
  }

  return 0n; // no reserved bits for unrecognised ranges (shouldn't happen)
}

function headerReservedMask(wordIdx: number): bigint {
  switch (wordIdx) {
    case 0:
      // Named: bits 255:240 (MAGIC), 239:224 (SCHEMA_VERSION), 223:208 (WORD_COUNT), 207:192 (FLAGS)
      // FLAGS: only bit 192 is named (bit 0 = genesis), bits 207:193 are reserved within FLAGS field
      // So word 0 reserved = bits 191:0 AND FLAGS bits 207:193
      // FLAGS occupies bits 207:192 (16 bits). Bit 0 of FLAGS = bit 192. Bits 1–15 of FLAGS = bits 207:193.
      // Reserved in FLAGS: bits 207:193 = mask from 193 to 207
      {
        const reservedLow = (1n << 192n) - 1n; // bits 191:0
        const flagsReserved = flagsMask(207, 193); // bits 207:193
        return reservedLow | flagsReserved;
      }
    case 1:
      // Named: bits 255:192 (EPOCH), 191:128 (EPOCH_START_TIMESTAMP)
      // Reserved: bits 127:0
      return (1n << 128n) - 1n;
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
      // Full 256-bit fields (bytes32 / uint256) — no reserved bits
      return 0n;
    case 7:
      // Named: bits 255:192 (SCORE_ACCUMULATOR), 191:128 (SCORE_EPOCH_BASELINE),
      //        127:64 (PATCH_COUNT_EPOCH), 63:0 (PATCH_COUNT_TOTAL)
      // No reserved bits in word 7
      return 0n;
    case 8:
      // Named: bits 255:192 (LAST_SNAPSHOT_EPOCH), 191:128 (SNAPSHOT_INTERVAL),
      //        127:64 (REDUCER_NONCE)
      // Reserved: bits 63:0
      return (1n << 64n) - 1n;
    case 9:
    case 10:
      // Full 256-bit fields — no reserved bits
      return 0n;
    default:
      // Words 11–31: entirely reserved
      return UINT256_MAX;
  }
}

function memoryIndexSlotReservedMask(slotWord: number): bigint {
  switch (slotWord) {
    case 0:
      // Retrieval-benchmark semantics use all 256 bits of word 0:
      // recordId(128), family+domain(64), flags(16), retrievalSlot(8),
      // expiryEpoch(40). Semantic validation lives in retrieval-decoder.ts.
      return 0n;
    case 1:
      // Named: bits 255:128 (CHECKSUM), 127:64 (CORPUS_EPOCH), 63:0 (EXPIRY_EPOCH)
      // No reserved bits
      return 0n;
    default:
      // Words 2–7: PAYLOAD_WORDS — no reserved bits
      return 0n;
  }
}

function retrievalKeySlotReservedMask(slotWord: number): bigint {
  void slotWord;
  // Retrieval-key slots are 256-byte packed vector records. Header and vector
  // semantics are enforced by retrieval-decoder.ts, not the previous mask.
  return 0n;
}

function codebookSlotReservedMask(slotWord: number): bigint {
  void slotWord;
  // Codebook payload bits are meaningful under retrieval-benchmark semantics.
  // Decode-level validation rejects malformed code/type/flag combinations.
  return 0n;
}

/** Build a mask covering bits hiInclusive down to loInclusive. */
function flagsMask(hiInclusive: number, loInclusive: number): bigint {
  if (hiInclusive < loInclusive) return 0n;
  const width = hiInclusive - loInclusive + 1;
  return ((1n << BigInt(width)) - 1n) << BigInt(loInclusive);
}

// ─── Pre-computed reserved masks ─────────────────────────────────────────────

const RESERVED_MASKS: bigint[] = new Array(1024).fill(0n);
for (let i = 0; i < 1024; i++) {
  RESERVED_MASKS[i] = reservedMask(i);
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Returns true if any reserved bit in the state is non-zero.
 */
export function hasNonZeroReservedBits(state: CortexState): boolean {
  for (let i = 0; i < RANGES.WORD_COUNT; i++) {
    const mask = RESERVED_MASKS[i] ?? 0n;
    if (mask !== 0n && ((state.words[i] ?? 0n) & mask) !== 0n) {
      return true;
    }
  }
  return false;
}

/**
 * Validate reserved bits; return an error if violated.
 */
export function validateReservedBits(state: CortexState): PatchError | null {
  if (hasNonZeroReservedBits(state)) {
    return {
      ok: false,
      code: 'E04',
      message: 'RESERVED_BIT_SET: one or more reserved bits are non-zero',
    };
  }
  return null;
}

/** Exported for testing. */
export { RESERVED_MASKS };
