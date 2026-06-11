/**
 * Core types for CoreTex state.
 * All word values are bigint (uint256).
 */

/** A CortexState is exactly 1024 uint256 words. */
export interface CortexState {
  readonly words: readonly bigint[];
}

/** Mutable version for building states. */
export interface MutableCortexState {
  words: bigint[];
}

/** Patch error with stable error code. */
export interface PatchError {
  readonly ok: false;
  readonly code: PatchErrorCode;
  readonly message: string;
}

/** Patch success result. */
export interface PatchSuccess {
  readonly ok: true;
  readonly state: CortexState;
}

export type PatchResult = PatchSuccess | PatchError;

/** Stable patch error codes (immutable across versions). */
export type PatchErrorCode =
  | 'E01' // WRONG_PARENT_ROOT
  | 'E02' // WRONG_TYPE_FIELD
  | 'E03' // OVER_BUDGET
  | 'E04' // RESERVED_BIT_SET
  | 'E05'; // NOOP_PATCH

export const ERROR_NAMES: Record<PatchErrorCode, string> = {
  E01: 'WRONG_PARENT_ROOT',
  E02: 'WRONG_TYPE_FIELD',
  E03: 'OVER_BUDGET',
  E04: 'RESERVED_BIT_SET',
  E05: 'NOOP_PATCH',
};

/** Patch type codes per patch_format.md. */
export const PATCH_TYPE = {
  KEY_UPDATE:      0x01,
  SLOT_REPLACE:    0x02,
  TEMPORAL_UPDATE: 0x03,
  RELATION_UPDATE: 0x04,
  CODEBOOK_UPDATE: 0x05,
  HEADER_UPDATE:   0x06,
  POLICY_UPDATE:   0x07, // r5 typed PolicyAtom write (evidence-bundle / conflict / abstention)
  MIXED:           0xFF,
} as const;

export type PatchTypeCode = (typeof PATCH_TYPE)[keyof typeof PATCH_TYPE];

/** A decoded patch object. */
export interface Patch {
  /** Patch type code. */
  readonly patchType: number;
  /** Number of words changed (1–4). */
  readonly wordCount: number;
  /** Score delta × 1e6 as signed 64-bit integer (bigint). */
  readonly scoreDelta: bigint;
  /** Parent state root (32 bytes). */
  readonly parentStateRoot: Uint8Array;
  /** Target word indices. Length === wordCount. */
  readonly indices: readonly number[];
  /** New word values. Length === wordCount. */
  readonly newWords: readonly bigint[];
}

/** Word-range constants. */
export const RANGES = {
  HEADER_START:        0,
  HEADER_END:          31,
  MEMORY_INDEX_START:  32,
  MEMORY_INDEX_END:    383,
  RETRIEVAL_KEYS_START:384,
  RETRIEVAL_KEYS_END:  671,
  RELATIONS_START:     672,
  RELATIONS_END:       799,
  TEMPORAL_START:      800,
  TEMPORAL_END:        895,
  CODEBOOK_START:      896,
  CODEBOOK_END:        991,
  RESERVED_START:      992,
  RESERVED_END:        1023,
  WORD_COUNT:          1024,
  // ── r5 PolicyAtom regions (NEW PROTOCOL EPOCH coretex-retrieval-v2-policy-r5) ──
  // These OVERLAY the reclaimed words. r4 (lens) profiles read 384–671 as RetrievalKeys
  // and 896–991 as Codebook; r5 (policy) profiles read them as typed PolicyAtoms. The
  // active interpretation is decided HARD by pipelineVersion / profile — never silently.
  // The static reclaimed forms (dense lens, static EvidencePolicy) failed; r5 reclaims
  // their WORDS for a typed, bounded, query-local policy grammar. Stride-1: 1 word/atom.
  POLICY_EVIDENCE_START:    384,  POLICY_EVIDENCE_END:    511,  // 128 evidence-bundle/answer-density atoms
  POLICY_CONFLICT_START:    512,  POLICY_CONFLICT_END:    639,  // 128 conflict_lifecycle atoms
  POLICY_ABSTENTION_START:  640,  POLICY_ABSTENTION_END:  671,  //  32 abstention_missing atoms
  POLICY_RESERVED_START:    896,  POLICY_RESERVED_END:    991,  //  96w reserved r5 policy capacity (MUST be zero)
} as const;

/**
 * THE patch-type → word-range descriptor table (audit Q2). Single source of
 * truth shared by the TS codec (`patchTypeRange`) and the TS↔Solidity parity
 * test, which parses `_wordMatchesPatchType` out of BotcoinMiningV4.sol and
 * asserts it matches THIS table — cross-language drift becomes a failing
 * test, not an audit finding. MIXED (0xFF) is intentionally absent: it spans
 * every non-reserved word (0 .. RESERVED_START-1) and is special-cased by
 * both sides.
 */
export const PATCH_TYPE_RANGE_TABLE: ReadonlyArray<{
  readonly name: keyof typeof PATCH_TYPE;
  readonly typeByte: number;
  readonly start: number;
  readonly end: number;
}> = [
  { name: 'KEY_UPDATE',      typeByte: PATCH_TYPE.KEY_UPDATE,      start: RANGES.RETRIEVAL_KEYS_START,  end: RANGES.RETRIEVAL_KEYS_END },
  { name: 'SLOT_REPLACE',    typeByte: PATCH_TYPE.SLOT_REPLACE,    start: RANGES.MEMORY_INDEX_START,    end: RANGES.MEMORY_INDEX_END },
  { name: 'TEMPORAL_UPDATE', typeByte: PATCH_TYPE.TEMPORAL_UPDATE, start: RANGES.TEMPORAL_START,        end: RANGES.TEMPORAL_END },
  { name: 'RELATION_UPDATE', typeByte: PATCH_TYPE.RELATION_UPDATE, start: RANGES.RELATIONS_START,       end: RANGES.RELATIONS_END },
  { name: 'CODEBOOK_UPDATE', typeByte: PATCH_TYPE.CODEBOOK_UPDATE, start: RANGES.CODEBOOK_START,        end: RANGES.CODEBOOK_END },
  { name: 'HEADER_UPDATE',   typeByte: PATCH_TYPE.HEADER_UPDATE,   start: RANGES.HEADER_START,          end: RANGES.HEADER_END },
  // r5: the three contiguous PolicyAtom regions (evidence 384–511, conflict
  // 512–639, abstention 640–671). The reserved r5 policy region (896–991) is
  // intentionally NOT writable via POLICY_UPDATE — it must stay zero (no
  // miner spam surface).
  { name: 'POLICY_UPDATE',   typeByte: PATCH_TYPE.POLICY_UPDATE,   start: RANGES.POLICY_EVIDENCE_START, end: RANGES.POLICY_ABSTENTION_END },
];

/** Schema magic constant for word 0. */
export const MAGIC = 0xC07En;
export const SCHEMA_VERSION_CoreTex = 0x0000n;
export const WORD_COUNT_VALUE = 1024n;
