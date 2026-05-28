/**
 * CoreTex retrieval substrate decoder.
 *
 * Decodes the 1024-uint256 packed substrate body into typed structures the
 * production retrieval scorer reads. Spec: specs/substrate_retrieval_semantics.md.
 *
 * The contract layer (`CortexState.acceptTransition`) is agnostic to byte
 * semantics; this module is the off-chain source of truth. Decode failures
 * are surfaced as null slot entries plus a counter so structuralValidity
 * can score the substrate's decode quality.
 */

import type { CortexState } from '../state/types.js';
import { RANGES } from '../state/types.js';
import { keccak256 } from '../state/keccak256.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export type RelationEdgeType =
  | 'supports'
  | 'supersedes'
  | 'coreference_of'
  | 'causes'
  | 'derived_from'
  | 'co_occurs_with';

export type SubstrateFamily =
  | 'near_collision'
  | 'temporal'
  | 'long_horizon'
  | 'multi_hop_relation';

export interface MemoryIndexSlot {
  readonly slotIndex: number;
  readonly recordId: bigint;          // 128-bit corpus record id
  readonly family: SubstrateFamily;
  readonly domainBits: bigint;        // low 60 bits
  readonly valid: boolean;
  readonly revoked: boolean;
  readonly protected: boolean;
  readonly policyAnchor?: boolean;    // r5: resolvable as a PolicyAtom anchor, but NOT anchor-mandatory-injected
  readonly retrievalSlot: number;     // 0..35
  readonly expiryEpoch: bigint;
}

export interface RetrievalKeySlot {
  readonly slotIndex: number;
  readonly modelIdHash: string;       // 0x-prefixed 8-hex (4-byte prefix)
  readonly l2Norm: number;            // pre-quantization L2 norm
  readonly versionTag: number;        // current 1
  readonly quantizedBytes: Uint8Array;// raw quantized vector bytes
}

export interface RelationEdge {
  readonly entryIndex: number;
  readonly weight: number;
  readonly edgeType: RelationEdgeType;
  readonly sourceSlot: number;        // 0..43
  readonly targetSlot: number;        // 0..43
}

/**
 * Phase B category-lens entry. The substrate's Relations region (128 entries)
 * shares its budget with previous anchor-to-anchor edges. A category-lens entry
 * tells the scorer: "for any stage-1 candidate doc, follow its corpus-native
 * event.relations whose edgeType matches this lens's edgeType, and add the
 * related event's truth docs to the candidate pool." This gives the substrate
 * a corpus-scale retrieval policy beyond the 352-anchor cap (Tier-2 stride-1 MemoryIndex).
 *
 * Wire encoding lives in the same 256-bit word as previous edges; the high bit
 * of the bits 223..208 reserved field (bit 223) is the mode flag. When set,
 * bits 191..0 must be zero — the entry is not pointing at any specific
 * MemoryIndex slot. See `decodeRelations` for full validation.
 */
export interface RelationCategoryLens {
  readonly entryIndex: number;
  readonly weight: number;
  readonly edgeType: RelationEdgeType;
}

export interface TemporalRecord {
  readonly recordIndex: number;
  readonly memorySlot: number;
  readonly supersededBy: number;      // 0xFF = none
  readonly validFromEpoch: bigint;
  readonly validUntilEpoch: bigint;
  readonly currentStaleFlag: boolean;
}

export interface CodebookEntry {
  readonly entryIndex: number;
  readonly code: number;              // 16-bit
  readonly codeType: 'int8_scale_zero' | 'pq';
  readonly valid: boolean;
  readonly payload: bigint;           // raw payload word (208 low bits of word 0)
  readonly payloadCont: bigint;       // word 1
}

export interface LensDiversityCheck {
  readonly ok: boolean;
  readonly reason?: 'lens-diversity-collapse';
  readonly meanPairwiseCosine?: number;
}

// ─── r5 PolicyAtoms (typed, bounded, query-local policy grammar) ───────────────

export type PolicyAtomFamily = 'evidence_bundle' | 'conflict_lifecycle' | 'abstention';
export type PolicyAction = 'include' | 'boost' | 'suppress' | 'bundle' | 'abstain';
export type PolicyScope = 'entity' | 'owner' | 'relation_path' | 'temporal_chain' | 'conflict_set' | 'aspect';

/** Selector = the query-predicate type that gates when an atom applies (8-bit code). */
export const POLICY_SELECTOR = {
  RELATION_PATH_PRESENT: 0x1, // query resolves to a public support/bridge path (evidence-bundle)
  CONFLICT_SET_MEMBER:   0x2, // query's subject has a public conflict set (conflict_lifecycle)
  MISSING_EVIDENCE:      0x3, // query has no public evidence path (abstention)
  ANSWER_DENSITY:        0x4, // query's anchor has high public support-in-degree (evidence-bundle)
} as const;
/** EvidenceFeature = which PUBLIC Memory-IR / corpus feature the atom reads (8-bit code). */
export const POLICY_EVIDENCE_FEATURE = {
  SUPPORT_IN_DEGREE:       0x1,
  BRIDGE_HOP:              0x2,
  LIFECYCLE_STATE:         0x3, // resolved/candidate
  CONTRADICTS_EDGE:        0x4,
  SCOPE_DIFFERS_EDGE:      0x5,
  TOP1_SCORE:              0x6, // calibrated top score (paired with profile threshold)
  NO_PUBLIC_EVIDENCE_PATH: 0x7,
} as const;
/** Abstention atom flag bits. */
export const POLICY_FLAG = {
  REQUIRE_NO_EVIDENCE_PATH: 0x01, // abstention: only abstain when public evidence path is absent
} as const;

const VALID_SELECTOR = new Set<number>(Object.values(POLICY_SELECTOR));
const VALID_EVIDENCE_FEATURE = new Set<number>(Object.values(POLICY_EVIDENCE_FEATURE));

export interface PolicyAtom {
  readonly atomIndex: number;          // slot index within its region
  readonly family: PolicyAtomFamily;   // implicit from which region the atom lives in
  readonly selector: number;           // POLICY_SELECTOR code
  readonly evidenceFeature: number;    // POLICY_EVIDENCE_FEATURE code
  readonly action: PolicyAction;
  readonly scope: PolicyScope;
  readonly targetSlot: number;         // MemoryIndex slot anchor (< 352); 0xFFFF = none (abstention)
  readonly budget: number;             // bounded effect magnitude 0..65535 (profile caps per family)
  readonly flags: number;              // 8-bit per-family flags
  readonly validFromEpoch: bigint;     // atom active from (0 = genesis)
  readonly expiryEpoch: bigint;        // atom expires at (0 = never); frontier-churn retirement hook
}

export const POLICY_TARGET_NONE = 0xffff;
/**
 * Max addressable PolicyAtom anchor slot. MemoryIndex decodes 352 slots, but slot REFERENCES
 * elsewhere (temporal memorySlot, relation source/target) are 8-bit (0..255). To keep anchors
 * cross-referenceable and avoid "decoded-but-unaddressable" anchors, an atom's targetSlot is
 * restricted to 0..255 (a non-abstain atom must point into this range).
 */
export const POLICY_ANCHOR_SLOT_LIMIT = 256;

export interface DecodedSubstrate {
  readonly memoryIndex: ReadonlyArray<MemoryIndexSlot | null>;     // length 352 (Tier-2 stride-1)
  readonly retrievalKeys: ReadonlyArray<RetrievalKeySlot | null>;  // length 36
  readonly relations: ReadonlyArray<RelationEdge>;                 // anchor-to-anchor (Phase A)
  readonly categoryLenses: ReadonlyArray<RelationCategoryLens>;    // corpus-native edge-type filters (Phase B)
  readonly temporal: ReadonlyArray<TemporalRecord>;                // sparse
  readonly codebook: ReadonlyArray<CodebookEntry | null>;          // length 48
  readonly decodedSlots: number;
  readonly decodeFailures: number;
  readonly decodeAttempts: number;
  /**
   * §6.4 lens-diversity floor result. Present only when `lensDiversityFloor`
   * and `retrievalKeyLayout` are supplied via DecoderOptions; otherwise the
   * check is skipped and this field is absent. When `ok: false`, the
   * substrate fails structural-validity (see `structuralValidity()`).
   */
  readonly lensDiversityCheck?: LensDiversityCheck;
  /**
   * §6.4 relation-edge domain-share predicate: count of relation edges
   * dropped during decode because their source/target MemoryIndex slots
   * did not share at least one domain bit (or had no domain set). Telemetry
   * only; not a failure (the substrate remains structurally valid).
   */
  readonly relationsDroppedByDomainPredicate: number;
  // ── r5 PolicyAtoms (populated only when DecoderOptions.policyAtomsMode; else empty) ──
  readonly evidenceBundleAtoms: ReadonlyArray<PolicyAtom>;
  readonly conflictLifecycleAtoms: ReadonlyArray<PolicyAtom>;
  readonly abstentionAtoms: ReadonlyArray<PolicyAtom>;
  /** Count of non-zero words in the reserved r5 policy region (896–991); >0 = invalid-for-reward. */
  readonly policyReservedNonZeroWords: number;
}

export interface DecoderOptions {
  /**
   * r5 mode: read the reclaimed RetrievalKeys (384–671) + Codebook (896–991) words as typed
   * PolicyAtoms instead of as a dense lens / codebook. HARD gate (set from the bundle
   * pipelineVersion / profile). When true, RetrievalKeys + Codebook are NOT decoded (so r4
   * lens semantics cannot leak under r5); when false (r4), PolicyAtom arrays are empty (zero
   * effect) so r5 atoms cannot leak under r4. No silent reinterpretation.
   */
  readonly policyAtomsMode?: boolean;
  /**
   * Bundle-pinned bi-encoder model id hash (first 4 bytes of
   * keccak256(modelId || revision || mode), 0x-prefixed 8-hex).
   * When provided, retrieval-key slots whose `modelIdHash` does not match
   * are zeroed during decode.
   */
  readonly biEncoderModelIdHash?: string;
  /**
   * Bundle-pinned retrieval-key layout: header bytes consumed before the
   * vector payload starts.
   */
  readonly retrievalKeyHeaderBytes?: number;
  /**
   * §6.4 lens-diversity floor: maximum allowed mean pairwise cosine across
   * active retrieval-key (lens) vectors. When supplied alongside
   * `retrievalKeyLayout`, `decodeSubstrate` runs `checkLensDiversity` and
   * populates `lensDiversityCheck` on the result. When the measured mean
   * pairwise cosine exceeds the floor (strict >), the substrate fails
   * structural-validity (per §6.4 the substrate is rejected). Mean cosine
   * exactly equal to the floor passes (the floor is the upper bound the
   * miner is allowed to operate at).
   */
  readonly lensDiversityFloor?: number;
  /**
   * Full retrieval-key layout (dim + headerBytes + quantization). Required
   * for the lens-diversity check to dequantize active lens vectors. When
   * omitted, the diversity check is skipped even if `lensDiversityFloor`
   * is provided.
   */
  readonly retrievalKeyLayout?: {
    readonly dim: number;
    readonly headerBytes: number;
    readonly quantization: 'int8' | 'bf16';
  };
}

// ─── Family enum ──────────────────────────────────────────────────────────────

const FAMILY_BY_BITS: Record<number, SubstrateFamily> = {
  0x0: 'near_collision',
  0x1: 'temporal',
  0x2: 'long_horizon',
  0x3: 'multi_hop_relation',
};

const RELATION_TYPE_BY_BITS: Record<number, RelationEdgeType> = {
  0x1: 'supports',
  0x2: 'supersedes',
  0x3: 'coreference_of',
  0x4: 'causes',
  0x5: 'derived_from',
  0x6: 'co_occurs_with',
};

const CODE_TYPE_BY_BITS: Record<number, CodebookEntry['codeType']> = {
  0x1: 'int8_scale_zero',
  0x2: 'pq',
};

// ─── Bit helpers ──────────────────────────────────────────────────────────────

const MASK_4: bigint = (1n << 4n) - 1n;
const MASK_8: bigint = (1n << 8n) - 1n;
const MASK_16: bigint = (1n << 16n) - 1n;
const MASK_112: bigint = (1n << 112n) - 1n;
const MASK_40: bigint = (1n << 40n) - 1n;
const MASK_60: bigint = (1n << 60n) - 1n;
const MASK_96: bigint = (1n << 96n) - 1n;
const MASK_128: bigint = (1n << 128n) - 1n;
const MASK_152: bigint = (1n << 152n) - 1n;
const MASK_208: bigint = (1n << 208n) - 1n;

function field(word: bigint, shift: number, mask: bigint): bigint {
  return (word >> BigInt(shift)) & mask;
}

function nthByte(word: bigint, byteOffset: number): number {
  // byteOffset 0 = most-significant byte
  const shift = (31 - byteOffset) * 8;
  return Number((word >> BigInt(shift)) & 0xffn);
}

function wordsToBytes(words: readonly bigint[], startWord: number, wordCount: number): Uint8Array {
  const out = new Uint8Array(wordCount * 32);
  for (let w = 0; w < wordCount; w++) {
    const word = words[startWord + w] ?? 0n;
    for (let b = 0; b < 32; b++) {
      out[w * 32 + b] = nthByte(word, b);
    }
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '0x';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

function readFloat32BE(bytes: Uint8Array, offset: number): number {
  const dv = new DataView(bytes.buffer, bytes.byteOffset + offset, 4);
  return dv.getFloat32(0, false);
}

// ─── Slot decoders ────────────────────────────────────────────────────────────

// Tier-2 decoupling (TEMPORAL_DECOUPLING_DESIGN.md): MemoryIndex repacked to STRIDE-1.
// Each slot is 1 word (only word 0 was ever used; words 1-7 were zero padding). The region
// (words 32-383 = 352 words) now holds up to 352 slots instead of 44, lifting the temporal
// current/stale PAIR cap from the MemoryIndex-bound 22 toward the Temporal region's 96-record
// ceiling. 8-bit slot-reference fields (temporal memorySlot/supersededBy, relation
// source/targetSlot) cap referencible slots at 0-255 — ample for 96 pairs (≤192 slots).
// NEW PROTOCOL EPOCH — bump pipelineVersion before launch.
const MEMORY_INDEX_SLOT_COUNT = 352;
const MEMORY_INDEX_WORDS_PER_SLOT = 1;
const RETRIEVAL_KEY_SLOT_COUNT = 36;
const RETRIEVAL_KEY_WORDS_PER_SLOT = 8;
const RETRIEVAL_KEY_BYTES_PER_SLOT = RETRIEVAL_KEY_WORDS_PER_SLOT * 32; // 256
const RELATIONS_ENTRY_COUNT = 128;
// Temporal capacity: the TEMPORAL range (words 800–895 = 96 words) holds one record
// PER WORD. A record's payload is a single word (see encodeTemporalRecord); the prior
// 8-word stride reserved 7 padding words per record and capped capacity at 12, which was
// the temporal runway bottleneck. Stride 1 exposes the full 96-record capacity the state
// format + validator already support (decoder/index.ts TEMPORAL_COUNT=96; validate.ts
// treats the range as 1-word entries). No range change; eval encode+decode stay symmetric.
const TEMPORAL_WORDS_PER_RECORD = 1;
const TEMPORAL_RECORD_COUNT = (RANGES.TEMPORAL_END - RANGES.TEMPORAL_START + 1) / TEMPORAL_WORDS_PER_RECORD; // 96
const CODEBOOK_ENTRY_COUNT = 48;
const CODEBOOK_WORDS_PER_ENTRY = 2;

export function decodeMemoryIndex(state: CortexState): {
  slots: ReadonlyArray<MemoryIndexSlot | null>;
  attempts: number;
  failures: number;
} {
  const slots: Array<MemoryIndexSlot | null> = [];
  let attempts = 0;
  let failures = 0;

  for (let s = 0; s < MEMORY_INDEX_SLOT_COUNT; s++) {
    const base = RANGES.MEMORY_INDEX_START + s * MEMORY_INDEX_WORDS_PER_SLOT;
    const w0 = state.words[base] ?? 0n;
    if (w0 === 0n) {
      slots.push(null);
      continue;
    }
    attempts++;
    let nonZeroPayload = false;
    for (let off = 1; off < MEMORY_INDEX_WORDS_PER_SLOT; off++) {
      if ((state.words[base + off] ?? 0n) !== 0n) {
        nonZeroPayload = true;
        break;
      }
    }
    if (nonZeroPayload) {
      failures++;
      slots.push(null);
      continue;
    }

    const recordId = field(w0, 128, MASK_128);
    if (recordId === 0n) {
      failures++;
      slots.push(null);
      continue;
    }

    const familyBits = Number(field(w0, 124, 0xfn));
    const family = FAMILY_BY_BITS[familyBits];
    if (!family) {
      failures++;
      slots.push(null);
      continue;
    }

    const domainBits = field(w0, 64, MASK_60);
    const flags = Number(field(w0, 48, MASK_16));
    const valid = (flags & 0x0001) !== 0;
    const revoked = (flags & 0x0002) !== 0;
    const isProtected = (flags & 0x0004) !== 0;
    // r5: a policy-anchor slot is RESOLVABLE (its event anchors a PolicyAtom) but is EXCLUDED
    // from anchor-mandatory routing + relation BFS seeding — it does NOT inject its docs into
    // every query's pool. This lets a query-local PolicyAtom reference an anchor without the
    // anchor-mandatory flood (the atom's reach comes from the anchor's public-edge neighbours
    // that the query already retrieved, not from the anchor's own docs).
    const policyAnchor = (flags & 0x0008) !== 0;

    const retrievalSlot = Number(field(w0, 40, MASK_8));
    if (retrievalSlot >= RETRIEVAL_KEY_SLOT_COUNT) {
      failures++;
      slots.push(null);
      continue;
    }

    const expiryEpoch = field(w0, 0, MASK_40);

    if (!valid) {
      // Inactive entries do not earn nor fail — they zero out.
      slots.push(null);
      continue;
    }

    slots.push({
      slotIndex: s,
      recordId,
      family,
      domainBits,
      valid,
      revoked,
      protected: isProtected,
      policyAnchor,
      retrievalSlot,
      expiryEpoch,
    });
  }
  return { slots, attempts, failures };
}

export function decodeRetrievalKeys(
  state: CortexState,
  opts: DecoderOptions = {},
): {
  slots: ReadonlyArray<RetrievalKeySlot | null>;
  attempts: number;
  failures: number;
} {
  const slots: Array<RetrievalKeySlot | null> = [];
  let attempts = 0;
  let failures = 0;
  const headerBytes = opts.retrievalKeyHeaderBytes ?? 9;
  const expectedHash = opts.biEncoderModelIdHash?.toLowerCase();

  for (let s = 0; s < RETRIEVAL_KEY_SLOT_COUNT; s++) {
    const base = RANGES.RETRIEVAL_KEYS_START + s * RETRIEVAL_KEY_WORDS_PER_SLOT;
    const w0 = state.words[base] ?? 0n;
    let any = false;
    for (let off = 0; off < RETRIEVAL_KEY_WORDS_PER_SLOT; off++) {
      if ((state.words[base + off] ?? 0n) !== 0n) {
        any = true;
        break;
      }
    }
    if (!any) {
      slots.push(null);
      continue;
    }
    attempts++;

    const slotBytes = wordsToBytes(state.words, base, RETRIEVAL_KEY_WORDS_PER_SLOT);
    const versionTag = slotBytes[0]!;
    if (versionTag !== 0x01) {
      failures++;
      slots.push(null);
      continue;
    }
    const modelIdBytes = slotBytes.subarray(1, 5);
    const modelIdHash = bytesToHex(modelIdBytes);
    if (expectedHash !== undefined && modelIdHash.toLowerCase() !== expectedHash) {
      failures++;
      slots.push(null);
      continue;
    }
    const l2Norm = readFloat32BE(slotBytes, 5);
    if (!Number.isFinite(l2Norm) || l2Norm <= 0) {
      failures++;
      slots.push(null);
      continue;
    }
    if (headerBytes < 9 || headerBytes > RETRIEVAL_KEY_BYTES_PER_SLOT) {
      failures++;
      slots.push(null);
      continue;
    }
    // Reserved bytes between byte 9 and the start of quantized data
    // MUST be zero. The inner `continue` only skipped the next
    // byte index — it did not skip the outer slot, so a malformed
    // header used to push null AND then fall through to push the
    // real slot below, corrupting slot indexing.
    let badHeader = false;
    for (let i = 9; i < headerBytes; i++) {
      if (slotBytes[i] !== 0) {
        badHeader = true;
        break;
      }
    }
    if (badHeader) {
      failures++;
      slots.push(null);
      continue;
    }
    const quantizedBytes = slotBytes.subarray(headerBytes);
    void w0;

    slots.push({
      slotIndex: s,
      modelIdHash,
      l2Norm,
      versionTag,
      quantizedBytes,
    });
  }
  return { slots, attempts, failures };
}

export function decodeRelations(state: CortexState): {
  edges: ReadonlyArray<RelationEdge>;
  categoryLenses: ReadonlyArray<RelationCategoryLens>;
  attempts: number;
  failures: number;
} {
  const edges: RelationEdge[] = [];
  const categoryLenses: RelationCategoryLens[] = [];
  let attempts = 0;
  let failures = 0;

  for (let i = 0; i < RELATIONS_ENTRY_COUNT; i++) {
    const word = state.words[RANGES.RELATIONS_START + i] ?? 0n;
    if (word === 0n) continue;
    attempts++;

    const weight = Number(field(word, 240, MASK_16));
    if (weight === 0) {
      // weight 0 with non-empty bits → malformed
      failures++;
      continue;
    }
    const edgeBits = Number(field(word, 224, MASK_16));
    const edgeType = RELATION_TYPE_BY_BITS[edgeBits];
    if (!edgeType) {
      failures++;
      continue;
    }

    // Phase B: bit 223 = category-lens mode flag (high bit of the 223..208
    // reserved field). When set, the entry encodes a category-lens (no
    // source/target slot, follows corpus-native edges of `edgeType`). When
    // clear, the entry is a previous anchor-to-anchor edge and the remaining
    // 15 reserved bits + bits 207..192 must be zero.
    const reservedField208 = field(word, 208, MASK_16);
    const isCategoryLens = (reservedField208 >> 15n) === 1n;
    const remainingReserved208 = reservedField208 & 0x7FFFn;
    if (remainingReserved208 !== 0n) {
      failures++;
      continue;
    }
    if (field(word, 192, MASK_16) !== 0n) {
      failures++;
      continue;
    }

    if (isCategoryLens) {
      // Category-lens mode: bits 191..0 must be entirely zero — the lens
      // does not point at any MemoryIndex slot. It expands stage-1
      // candidates by corpus-native edge type.
      if (field(word, 96, MASK_96) !== 0n || field(word, 0, MASK_96) !== 0n) {
        failures++;
        continue;
      }
      categoryLenses.push({ entryIndex: i, weight, edgeType });
      continue;
    }

    // Stale anchor-to-anchor edge.
    const sourceField = field(word, 96, MASK_96);
    const targetField = field(word, 0, MASK_96);
    if (sourceField >> 8n !== 0n) {
      failures++;
      continue;
    }
    if (targetField >> 8n !== 0n) {
      failures++;
      continue;
    }
    const sourceSlot = Number(sourceField & MASK_8);
    const targetSlot = Number(targetField & MASK_8);
    if (sourceSlot >= MEMORY_INDEX_SLOT_COUNT || targetSlot >= MEMORY_INDEX_SLOT_COUNT) {
      failures++;
      continue;
    }
    edges.push({ entryIndex: i, weight, edgeType, sourceSlot, targetSlot });
  }
  return { edges, categoryLenses, attempts, failures };
}

export function decodeTemporal(state: CortexState): {
  records: ReadonlyArray<TemporalRecord>;
  attempts: number;
  failures: number;
} {
  const records: TemporalRecord[] = [];
  let attempts = 0;
  let failures = 0;

  for (let r = 0; r < TEMPORAL_RECORD_COUNT; r++) {
    const base = RANGES.TEMPORAL_START + r * TEMPORAL_WORDS_PER_RECORD;
    const w0 = state.words[base] ?? 0n;
    if (w0 === 0n) continue;
    attempts++;
    let nonZeroPayload = false;
    for (let off = 1; off < TEMPORAL_WORDS_PER_RECORD; off++) {
      if ((state.words[base + off] ?? 0n) !== 0n) {
        nonZeroPayload = true;
        break;
      }
    }
    if (nonZeroPayload) {
      failures++;
      continue;
    }
    const memorySlot = Number(field(w0, 248, MASK_8));
    const supersededBy = Number(field(w0, 240, MASK_8));
    const validFromEpoch = field(w0, 200, MASK_40);
    const validUntilEpoch = field(w0, 160, MASK_40);
    const flags = Number(field(w0, 152, MASK_8));
    if (field(w0, 0, MASK_152) !== 0n) {
      failures++;
      continue;
    }
    if (memorySlot >= MEMORY_INDEX_SLOT_COUNT) {
      failures++;
      continue;
    }
    if (validFromEpoch > validUntilEpoch) {
      failures++;
      continue;
    }
    const currentStaleFlag = (flags & 0x01) !== 0;
    records.push({
      recordIndex: r,
      memorySlot,
      supersededBy,
      validFromEpoch,
      validUntilEpoch,
      currentStaleFlag,
    });
  }
  return { records, attempts, failures };
}

export function decodeCodebook(state: CortexState): {
  entries: ReadonlyArray<CodebookEntry | null>;
  attempts: number;
  failures: number;
} {
  const entries: Array<CodebookEntry | null> = [];
  let attempts = 0;
  let failures = 0;

  for (let i = 0; i < CODEBOOK_ENTRY_COUNT; i++) {
    const base = RANGES.CODEBOOK_START + i * CODEBOOK_WORDS_PER_ENTRY;
    const w0 = state.words[base] ?? 0n;
    const w1 = state.words[base + 1] ?? 0n;
    if (w0 === 0n && w1 === 0n) {
      entries.push(null);
      continue;
    }
    attempts++;
    const code = Number(field(w0, 240, MASK_16));
    const codeTypeBits = Number(field(w0, 224, MASK_16));
    const flags = Number(field(w0, 208, MASK_16));
    const codeType = CODE_TYPE_BY_BITS[codeTypeBits];
    if (!codeType) {
      failures++;
      entries.push(null);
      continue;
    }
    if (code === 0) {
      failures++;
      entries.push(null);
      continue;
    }
    const valid = (flags & 0x0001) !== 0;
    if (!valid) {
      failures++;
      entries.push(null);
      continue;
    }
    const payload = field(w0, 0, MASK_208);
    entries.push({
      entryIndex: i,
      code,
      codeType,
      valid,
      payload,
      payloadCont: w1,
    });
  }
  return { entries, attempts, failures };
}

// ─── r5 PolicyAtom decode / encode ─────────────────────────────────────────────

const POLICY_ACTION_BY_BITS: Record<number, PolicyAction> = {
  0x1: 'include', 0x2: 'boost', 0x3: 'suppress', 0x4: 'bundle', 0x5: 'abstain',
};
const POLICY_ACTION_TO_BITS: Record<PolicyAction, number> = {
  include: 0x1, boost: 0x2, suppress: 0x3, bundle: 0x4, abstain: 0x5,
};
const POLICY_SCOPE_BY_BITS: Record<number, PolicyScope> = {
  0x1: 'entity', 0x2: 'owner', 0x3: 'relation_path', 0x4: 'temporal_chain', 0x5: 'conflict_set', 0x6: 'aspect',
};
const POLICY_SCOPE_TO_BITS: Record<PolicyScope, number> = {
  entity: 0x1, owner: 0x2, relation_path: 0x3, temporal_chain: 0x4, conflict_set: 0x5, aspect: 0x6,
};

interface PolicyRegionSpec { readonly start: number; readonly count: number; readonly allowed: ReadonlySet<PolicyAction>; }
export const POLICY_REGIONS: Record<PolicyAtomFamily, PolicyRegionSpec> = {
  evidence_bundle:    { start: RANGES.POLICY_EVIDENCE_START,   count: RANGES.POLICY_EVIDENCE_END   - RANGES.POLICY_EVIDENCE_START   + 1, allowed: new Set(['include', 'boost', 'suppress', 'bundle']) },
  conflict_lifecycle: { start: RANGES.POLICY_CONFLICT_START,   count: RANGES.POLICY_CONFLICT_END   - RANGES.POLICY_CONFLICT_START   + 1, allowed: new Set(['boost', 'suppress']) },
  abstention:         { start: RANGES.POLICY_ABSTENTION_START, count: RANGES.POLICY_ABSTENTION_END - RANGES.POLICY_ABSTENTION_START + 1, allowed: new Set(['abstain']) },
};

/**
 * Decode one PolicyAtom region (1 word/atom). Fail-closed per atom: a structurally
 * invalid atom (bad enum, disallowed action, out-of-range anchor, non-zero reserved bits,
 * inverted validity window) is DROPPED + counted as a failure — never silently rewarded.
 * The atom carries NO answer/qrel reference; its effect set is reconstructed by the scorer
 * from PUBLIC edges out of `targetSlot` (answer-density = public structure, not answer id).
 */
export function decodePolicyAtomRegion(state: CortexState, family: PolicyAtomFamily): {
  atoms: ReadonlyArray<PolicyAtom>;
  attempts: number;
  failures: number;
} {
  const reg = POLICY_REGIONS[family];
  const atoms: PolicyAtom[] = [];
  let attempts = 0;
  let failures = 0;
  for (let k = 0; k < reg.count; k++) {
    const w0 = state.words[reg.start + k] ?? 0n;
    if (w0 === 0n) continue;
    attempts++;
    const selector = Number(field(w0, 248, MASK_8));
    const evidenceFeature = Number(field(w0, 240, MASK_8));
    const action = POLICY_ACTION_BY_BITS[Number(field(w0, 236, MASK_4))];
    const scope = POLICY_SCOPE_BY_BITS[Number(field(w0, 232, MASK_4))];
    const targetSlot = Number(field(w0, 216, MASK_16));
    const budget = Number(field(w0, 200, MASK_16));
    const flags = Number(field(w0, 192, MASK_8));
    const validFromEpoch = field(w0, 152, MASK_40);
    const expiryEpoch = field(w0, 112, MASK_40);
    if (field(w0, 0, MASK_112) !== 0n) { failures++; continue; }          // reserved bits MUST be zero
    if (!action || !scope) { failures++; continue; }                       // unknown action/scope enum
    if (!reg.allowed.has(action)) { failures++; continue; }                // action not allowed for this family
    if (!VALID_SELECTOR.has(selector) || !VALID_EVIDENCE_FEATURE.has(evidenceFeature)) { failures++; continue; }
    if (action === 'abstain') {
      if (targetSlot !== POLICY_TARGET_NONE && targetSlot >= POLICY_ANCHOR_SLOT_LIMIT) { failures++; continue; }
    } else {
      if (targetSlot === POLICY_TARGET_NONE || targetSlot >= POLICY_ANCHOR_SLOT_LIMIT) { failures++; continue; } // non-abstain needs a real, 8-bit-addressable public anchor (0..255)
    }
    if (validFromEpoch > 0n && expiryEpoch > 0n && validFromEpoch > expiryEpoch) { failures++; continue; }
    atoms.push({ atomIndex: k, family, selector, evidenceFeature, action, scope, targetSlot, budget, flags, validFromEpoch, expiryEpoch });
  }
  return { atoms, attempts, failures };
}

/** Count non-zero words in the reserved r5 policy region (896–991). >0 ⇒ invalid-for-reward. */
export function policyReservedNonZeroWords(state: CortexState): number {
  let n = 0;
  for (let w = RANGES.POLICY_RESERVED_START; w <= RANGES.POLICY_RESERVED_END; w++) {
    if ((state.words[w] ?? 0n) !== 0n) n++;
  }
  return n;
}

/** Encode one PolicyAtom into its single packed word (round-trip side; patch builders + tests). */
export function encodePolicyAtom(atom: PolicyAtom): bigint {
  if (!Number.isInteger(atom.selector) || atom.selector <= 0 || atom.selector > 0xff) throw new Error('encodePolicyAtom: selector out of range');
  if (!Number.isInteger(atom.evidenceFeature) || atom.evidenceFeature <= 0 || atom.evidenceFeature > 0xff) throw new Error('encodePolicyAtom: evidenceFeature out of range');
  const actionBits = POLICY_ACTION_TO_BITS[atom.action];
  const scopeBits = POLICY_SCOPE_TO_BITS[atom.scope];
  if (!actionBits) throw new Error('encodePolicyAtom: bad action');
  if (!scopeBits) throw new Error('encodePolicyAtom: bad scope');
  if (atom.targetSlot !== POLICY_TARGET_NONE && (atom.targetSlot < 0 || atom.targetSlot >= POLICY_ANCHOR_SLOT_LIMIT)) throw new Error('encodePolicyAtom: targetSlot out of range (0..255 or POLICY_TARGET_NONE)');
  if (atom.budget < 0 || atom.budget > 0xffff) throw new Error('encodePolicyAtom: budget out of range');
  if (atom.flags < 0 || atom.flags > 0xff) throw new Error('encodePolicyAtom: flags out of range');
  if (atom.validFromEpoch >> 40n !== 0n || atom.expiryEpoch >> 40n !== 0n) throw new Error('encodePolicyAtom: epoch exceeds 40 bits');
  return (
    (BigInt(atom.selector) << 248n) |
    (BigInt(atom.evidenceFeature) << 240n) |
    (BigInt(actionBits) << 236n) |
    (BigInt(scopeBits) << 232n) |
    (BigInt(atom.targetSlot) << 216n) |
    (BigInt(atom.budget) << 200n) |
    (BigInt(atom.flags) << 192n) |
    (atom.validFromEpoch << 152n) |
    (atom.expiryEpoch << 112n)
  );
}

// ─── §6.4 lens-diversity floor ────────────────────────────────────────────────

/**
 * Dequantize a retrieval-key slot's payload bytes into a unit-scaled Float32
 * vector. Mirrors the int8/bf16 decoders used by `eval/bi-encoder.ts` and
 * `eval/public-corpus-index.ts`; kept inline here so the substrate decoder
 * has no upward dependency on the eval layer.
 *
 * For int8: assumes a leading float32 BE scale (4 bytes) immediately before
 * the per-dim int8 codes, matching the per-vector layout used by the public
 * corpus index. The `headerBytes` value pins where the int8 codes start in
 * the *slot*-relative byte stream — but the scale lives at the front of the
 * post-header payload, not at slot byte 0.
 */
function dequantizeKeyVector(
  bytes: Uint8Array,
  layout: { readonly dim: number; readonly quantization: 'int8' | 'bf16' },
): Float32Array {
  const dim = layout.dim;
  const out = new Float32Array(dim);
  if (layout.quantization === 'int8') {
    if (bytes.length < 4 + dim) return out; // structurally short → zero vector
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const scale = dv.getFloat32(0, false);
    for (let i = 0; i < dim; i++) {
      const raw = bytes[4 + i]!;
      const signed = raw < 128 ? raw : raw - 256;
      out[i] = signed * scale;
    }
    return out;
  }
  // bf16
  if (bytes.length < dim * 2) return out;
  const tmp = new ArrayBuffer(4);
  const tmpDv = new DataView(tmp);
  for (let i = 0; i < dim; i++) {
    const hi = bytes[i * 2]!;
    const lo = bytes[i * 2 + 1]!;
    tmpDv.setUint32(0, (hi << 24) | (lo << 16), false);
    out[i] = tmpDv.getFloat32(0, false);
  }
  return out;
}

function cosineSim(a: Float32Array, b: Float32Array): number {
  let dot = 0;
  let na = 0;
  let nb = 0;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a[i]!;
    const y = b[i]!;
    dot += x * y;
    na += x * x;
    nb += y * y;
  }
  if (na <= 0 || nb <= 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

/**
 * §6.4 lens-diversity floor.
 *
 * Computes the mean pairwise cosine across active retrieval-key (lens)
 * vectors. Returns `ok: false` with `reason: 'lens-diversity-collapse'`
 * when the mean exceeds the supplied floor (strict greater-than). A mean
 * equal to the floor is admitted — the floor is the upper bound the miner
 * is allowed to operate at.
 *
 * If fewer than two active keys are present, the check is a no-op
 * (`{ ok: true }`) — there is no pairwise mean to compute. The
 * `meanPairwiseCosine` field is always populated when there is at least
 * one pair, regardless of pass/fail, for telemetry.
 *
 * Spec: specs/substrate_retrieval_semantics.md.
 */
export function checkLensDiversity(
  retrievalKeys: ReadonlyArray<RetrievalKeySlot | null>,
  lensDiversityFloor: number,
  layout: { readonly dim: number; readonly headerBytes: number; readonly quantization: 'int8' | 'bf16' },
): LensDiversityCheck {
  const active: RetrievalKeySlot[] = [];
  for (const k of retrievalKeys) {
    if (k) active.push(k);
  }
  if (active.length < 2) return { ok: true };

  const vecs: Float32Array[] = active.map((k) => dequantizeKeyVector(k.quantizedBytes, layout));

  let sum = 0;
  let pairs = 0;
  for (let i = 0; i < vecs.length; i++) {
    for (let j = i + 1; j < vecs.length; j++) {
      sum += cosineSim(vecs[i]!, vecs[j]!);
      pairs++;
    }
  }
  const meanPairwiseCosine = pairs > 0 ? sum / pairs : 0;
  if (meanPairwiseCosine > lensDiversityFloor) {
    return { ok: false, reason: 'lens-diversity-collapse', meanPairwiseCosine };
  }
  return { ok: true, meanPairwiseCosine };
}

// ─── §6.4 relation-edge domain-share predicate ────────────────────────────────

/**
 * Returns true when both endpoints of `edge` resolve to active MemoryIndex
 * slots that share at least one domain bit. Edges that fail this predicate
 * are dropped silently by `decodeSubstrate` (the substrate as a whole stays
 * structurally valid; the offending edge simply does not contribute to BFS
 * expansion downstream).
 *
 * Spec: specs/substrate_retrieval_semantics.md.
 */
export function relationEdgeValid(
  edge: RelationEdge,
  memoryIndex: ReadonlyArray<MemoryIndexSlot | null>,
): boolean {
  const src = memoryIndex[edge.sourceSlot];
  const tgt = memoryIndex[edge.targetSlot];
  if (!src || !tgt) return false;
  if (!src.valid || !tgt.valid) return false;
  if (src.domainBits === 0n || tgt.domainBits === 0n) return false;
  return (src.domainBits & tgt.domainBits) !== 0n;
}

// ─── Composite ────────────────────────────────────────────────────────────────

export function decodeSubstrate(state: CortexState, opts: DecoderOptions = {}): DecodedSubstrate {
  const policyMode = opts.policyAtomsMode === true;
  const memory = decodeMemoryIndex(state);
  const relations = decodeRelations(state);
  const temporal = decodeTemporal(state);
  // HARD gate: r5 reads the reclaimed words as PolicyAtoms (RetrievalKeys/Codebook NOT decoded
  // → no dense-lens leak under r5); r4 decodes keys/codebook and leaves PolicyAtoms empty
  // (→ no policy-atom leak under r4). Either side is zeroed, never both interpreted.
  const keys = policyMode ? { slots: [] as ReadonlyArray<RetrievalKeySlot | null>, attempts: 0, failures: 0 } : decodeRetrievalKeys(state, opts);
  const codebook = policyMode ? { entries: [] as ReadonlyArray<CodebookEntry | null>, attempts: 0, failures: 0 } : decodeCodebook(state);
  let evidenceBundleAtoms: ReadonlyArray<PolicyAtom> = [];
  let conflictLifecycleAtoms: ReadonlyArray<PolicyAtom> = [];
  let abstentionAtoms: ReadonlyArray<PolicyAtom> = [];
  let policyReservedNonZero = 0;
  let policyAttempts = 0;
  let policyFailures = 0;
  if (policyMode) {
    const eb = decodePolicyAtomRegion(state, 'evidence_bundle');
    const cl = decodePolicyAtomRegion(state, 'conflict_lifecycle');
    const ab = decodePolicyAtomRegion(state, 'abstention');
    evidenceBundleAtoms = eb.atoms;
    conflictLifecycleAtoms = cl.atoms;
    abstentionAtoms = ab.atoms;
    policyReservedNonZero = policyReservedNonZeroWords(state);
    // reserved-region writes are decode failures (invalid-for-reward; not a miner surface).
    policyAttempts = eb.attempts + cl.attempts + ab.attempts + policyReservedNonZero;
    policyFailures = eb.failures + cl.failures + ab.failures + policyReservedNonZero;
  }

  // Cross-region invariants:
  //   - currentStaleFlag in temporal requires the referenced MemoryIndex slot's revoked bit to be set.
  //   - relations entries reference slots that must exist in the active memory index for credit;
  //     decoder accepts the entry but caller (scorer) may filter.
  let crossFailures = 0;
  let crossAttempts = 0;
  const filteredTemporal: TemporalRecord[] = [];
  for (const t of temporal.records) {
    crossAttempts++;
    const slot = memory.slots[t.memorySlot];
    if (!slot) {
      crossFailures++;
      continue;
    }
    if (t.currentStaleFlag && !slot.revoked) {
      crossFailures++;
      continue;
    }
    filteredTemporal.push(t);
  }

  // §6.4 relation-edge domain-share predicate. Drop edges where the two
  // endpoints do not share at least one domainBits bit. This is *not* a
  // decode failure — the substrate remains structurally valid; the edge
  // is simply not part of the decoded graph.
  const filteredRelations: RelationEdge[] = [];
  let relationsDroppedByDomainPredicate = 0;
  for (const e of relations.edges) {
    if (relationEdgeValid(e, memory.slots)) {
      filteredRelations.push(e);
    } else {
      relationsDroppedByDomainPredicate++;
    }
  }

  const decodeAttempts =
    memory.attempts + keys.attempts + relations.attempts + temporal.attempts + codebook.attempts + crossAttempts + policyAttempts;
  const decodeFailures =
    memory.failures + keys.failures + relations.failures + temporal.failures + codebook.failures + crossFailures + policyFailures;
  const decodedSlots = decodeAttempts - decodeFailures;

  // §6.4 lens-diversity floor. Only runs when both floor and layout are
  // supplied (otherwise we cannot dequantize the lens vectors). When the
  // check fails, the result lives on `decoded.lensDiversityCheck` and the
  // existing `structuralValidity()` helper drives it to 0 — that is the
  // single wire-level diagnostic miners see (per spec §6.4).
  let lensDiversityCheck: LensDiversityCheck | undefined;
  if (typeof opts.lensDiversityFloor === 'number' && opts.retrievalKeyLayout) {
    lensDiversityCheck = checkLensDiversity(keys.slots, opts.lensDiversityFloor, opts.retrievalKeyLayout);
  }

  return {
    memoryIndex: memory.slots,
    retrievalKeys: keys.slots,
    relations: filteredRelations,
    categoryLenses: relations.categoryLenses,
    temporal: filteredTemporal,
    codebook: codebook.entries,
    decodedSlots,
    decodeFailures,
    decodeAttempts,
    ...(lensDiversityCheck ? { lensDiversityCheck } : {}),
    relationsDroppedByDomainPredicate,
    evidenceBundleAtoms,
    conflictLifecycleAtoms,
    abstentionAtoms,
    policyReservedNonZeroWords: policyReservedNonZero,
  };
}

// ─── Encoder (round-trip side, used by patch builders + property tests) ───────

export function encodeMemoryIndexSlot(slot: MemoryIndexSlot): bigint[] {
  if (slot.recordId >> 128n !== 0n) {
    throw new Error('encodeMemoryIndexSlot: recordId exceeds 128 bits');
  }
  if (slot.domainBits >> 60n !== 0n) {
    throw new Error('encodeMemoryIndexSlot: domainBits exceeds 60 bits');
  }
  const familyBits = familyToBits(slot.family);
  const familyDomain = (BigInt(familyBits) << 60n) | slot.domainBits;
  const flags =
    (slot.valid ? 0x0001n : 0n) | (slot.revoked ? 0x0002n : 0n) | (slot.protected ? 0x0004n : 0n) | (slot.policyAnchor ? 0x0008n : 0n);
  if (slot.retrievalSlot < 0 || slot.retrievalSlot >= RETRIEVAL_KEY_SLOT_COUNT) {
    throw new Error('encodeMemoryIndexSlot: retrievalSlot out of range');
  }
  if (slot.expiryEpoch >> 40n !== 0n) {
    throw new Error('encodeMemoryIndexSlot: expiryEpoch exceeds 40 bits');
  }
  const w0 =
    (slot.recordId << 128n) |
    (familyDomain << 64n) |
    (flags << 48n) |
    (BigInt(slot.retrievalSlot) << 40n) |
    slot.expiryEpoch;
  return [w0, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
}

export function encodeRetrievalKeySlot(
  slot: RetrievalKeySlot,
  opts: { readonly retrievalKeyHeaderBytes?: number } = {},
): bigint[] {
  const headerBytes = opts.retrievalKeyHeaderBytes ?? 9;
  const out = new Uint8Array(RETRIEVAL_KEY_BYTES_PER_SLOT);
  out[0] = slot.versionTag & 0xff;
  // modelIdHash is 0x + 8 hex
  const hashHex = slot.modelIdHash.startsWith('0x') ? slot.modelIdHash.slice(2) : slot.modelIdHash;
  if (hashHex.length !== 8) throw new Error('encodeRetrievalKeySlot: modelIdHash must be 4 bytes');
  for (let i = 0; i < 4; i++) out[1 + i] = parseInt(hashHex.slice(i * 2, i * 2 + 2), 16);
  // l2Norm float32 BE
  const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
  dv.setFloat32(5, slot.l2Norm, false);
  // header pad zeros 9..headerBytes
  // (Uint8Array initialized to zero — nothing to do)
  // payload
  if (slot.quantizedBytes.length > RETRIEVAL_KEY_BYTES_PER_SLOT - headerBytes) {
    throw new Error('encodeRetrievalKeySlot: quantizedBytes too long for layout');
  }
  out.set(slot.quantizedBytes, headerBytes);

  const words: bigint[] = [];
  for (let w = 0; w < RETRIEVAL_KEY_WORDS_PER_SLOT; w++) {
    let val = 0n;
    for (let b = 0; b < 32; b++) {
      val = (val << 8n) | BigInt(out[w * 32 + b]!);
    }
    words.push(val);
  }
  return words;
}

export function encodeRelationEdge(edge: RelationEdge): bigint {
  if (edge.weight <= 0 || edge.weight > 0xffff) throw new Error('encodeRelationEdge: weight out of range');
  if (edge.sourceSlot < 0 || edge.sourceSlot >= MEMORY_INDEX_SLOT_COUNT)
    throw new Error('encodeRelationEdge: sourceSlot out of range');
  if (edge.targetSlot < 0 || edge.targetSlot >= MEMORY_INDEX_SLOT_COUNT)
    throw new Error('encodeRelationEdge: targetSlot out of range');
  const edgeBits = relationTypeToBits(edge.edgeType);
  return (
    (BigInt(edge.weight) << 240n) |
    (BigInt(edgeBits) << 224n) |
    (BigInt(edge.sourceSlot) << 96n) |
    BigInt(edge.targetSlot)
  );
}

/**
 * Encode a Phase B category-lens entry. Same Relations region, different
 * mode (bit 223 = 1). Bits 191..0 are zero — the lens does not target any
 * MemoryIndex slot; instead the scorer follows corpus-native event.relations
 * matching `edgeType` from each stage-1 candidate, expanding the pool by
 * the lens weight.
 */
export function encodeRelationCategoryLens(lens: RelationCategoryLens): bigint {
  if (lens.weight <= 0 || lens.weight > 0xffff) throw new Error('encodeRelationCategoryLens: weight out of range');
  const edgeBits = relationTypeToBits(lens.edgeType);
  const modeBit = 1n << 223n;
  return (
    (BigInt(lens.weight) << 240n) |
    (BigInt(edgeBits) << 224n) |
    modeBit
  );
}

export function encodeTemporalRecord(rec: TemporalRecord): bigint[] {
  if (rec.memorySlot < 0 || rec.memorySlot >= MEMORY_INDEX_SLOT_COUNT)
    throw new Error('encodeTemporalRecord: memorySlot out of range');
  if (rec.supersededBy < 0 || rec.supersededBy > 0xff)
    throw new Error('encodeTemporalRecord: supersededBy out of range');
  if (rec.validFromEpoch > rec.validUntilEpoch)
    throw new Error('encodeTemporalRecord: validFromEpoch > validUntilEpoch');
  if (rec.validFromEpoch >> 40n !== 0n || rec.validUntilEpoch >> 40n !== 0n)
    throw new Error('encodeTemporalRecord: epoch exceeds 40 bits');
  const flags = rec.currentStaleFlag ? 0x01n : 0n;
  const w0 =
    (BigInt(rec.memorySlot) << 248n) |
    (BigInt(rec.supersededBy) << 240n) |
    (rec.validFromEpoch << 200n) |
    (rec.validUntilEpoch << 160n) |
    (flags << 152n);
  // One record == one word. (The decoder reads at stride TEMPORAL_WORDS_PER_RECORD; any
  // padding words it expects beyond w0 must be zero, which a 1-length array satisfies.)
  const out: bigint[] = new Array(TEMPORAL_WORDS_PER_RECORD).fill(0n);
  out[0] = w0;
  return out;
}

export function encodeCodebookEntry(entry: CodebookEntry): bigint[] {
  if (entry.code <= 0 || entry.code > 0xffff)
    throw new Error('encodeCodebookEntry: code out of range');
  const codeTypeBits = entry.codeType === 'int8_scale_zero' ? 0x1n : 0x2n;
  const flags = entry.valid ? 0x0001n : 0n;
  if (entry.payload >> 208n !== 0n)
    throw new Error('encodeCodebookEntry: payload exceeds 208 bits');
  const w0 = (BigInt(entry.code) << 240n) | (codeTypeBits << 224n) | (flags << 208n) | entry.payload;
  return [w0, entry.payloadCont];
}

function familyToBits(f: SubstrateFamily): number {
  switch (f) {
    case 'near_collision': return 0x0;
    case 'temporal': return 0x1;
    case 'long_horizon': return 0x2;
    case 'multi_hop_relation': return 0x3;
  }
}

function relationTypeToBits(t: RelationEdgeType): number {
  switch (t) {
    case 'supports': return 0x1;
    case 'supersedes': return 0x2;
    case 'coreference_of': return 0x3;
    case 'causes': return 0x4;
    case 'derived_from': return 0x5;
    case 'co_occurs_with': return 0x6;
  }
}

// ─── Bi-encoder model id hash helper ─────────────────────────────────────────

export function biEncoderModelIdHash(modelId: string, revision: string, mode: string): string {
  const input = `${modelId}|${revision}|${mode}`;
  const digest = keccak256(new TextEncoder().encode(input));
  let hex = '0x';
  for (let i = 0; i < 4; i++) hex += digest[i]!.toString(16).padStart(2, '0');
  return hex;
}
