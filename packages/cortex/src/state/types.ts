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

/** Schema magic constant for word 0. */
export const MAGIC = 0xC07En;
export const SCHEMA_VERSION_CoreTex = 0x0000n;
export const WORD_COUNT_VALUE = 1024n;
