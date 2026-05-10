/**
 * CoreTex retrieval substrate decoder.
 *
 * Decodes the 1024-uint256 packed substrate body into typed structures the
 * production retrieval scorer reads. Spec: specs/substrate_retrieval_semantics_v0.md.
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

export interface DecodedSubstrate {
  readonly memoryIndex: ReadonlyArray<MemoryIndexSlot | null>;     // length 44
  readonly retrievalKeys: ReadonlyArray<RetrievalKeySlot | null>;  // length 36
  readonly relations: ReadonlyArray<RelationEdge>;                 // sparse (only populated entries)
  readonly temporal: ReadonlyArray<TemporalRecord>;                // sparse
  readonly codebook: ReadonlyArray<CodebookEntry | null>;          // length 48
  readonly decodedSlots: number;
  readonly decodeFailures: number;
  readonly decodeAttempts: number;
}

export interface DecoderOptions {
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

const MASK_8: bigint = (1n << 8n) - 1n;
const MASK_16: bigint = (1n << 16n) - 1n;
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

const MEMORY_INDEX_SLOT_COUNT = 44;
const MEMORY_INDEX_WORDS_PER_SLOT = 8;
const RETRIEVAL_KEY_SLOT_COUNT = 36;
const RETRIEVAL_KEY_WORDS_PER_SLOT = 8;
const RETRIEVAL_KEY_BYTES_PER_SLOT = RETRIEVAL_KEY_WORDS_PER_SLOT * 32; // 256
const RELATIONS_ENTRY_COUNT = 128;
const TEMPORAL_RECORD_COUNT = 12;
const TEMPORAL_WORDS_PER_RECORD = 8;
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
    for (let i = 9; i < headerBytes; i++) {
      if (slotBytes[i] !== 0) {
        failures++;
        slots.push(null);
        continue;
      }
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
  attempts: number;
  failures: number;
} {
  const edges: RelationEdge[] = [];
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
    // Two reserved 16-bit slots at 223..208 and 207..192 must be zero.
    if (field(word, 208, MASK_16) !== 0n) {
      failures++;
      continue;
    }
    if (field(word, 192, MASK_16) !== 0n) {
      failures++;
      continue;
    }
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
  return { edges, attempts, failures };
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

// ─── Composite ────────────────────────────────────────────────────────────────

export function decodeSubstrate(state: CortexState, opts: DecoderOptions = {}): DecodedSubstrate {
  const memory = decodeMemoryIndex(state);
  const keys = decodeRetrievalKeys(state, opts);
  const relations = decodeRelations(state);
  const temporal = decodeTemporal(state);
  const codebook = decodeCodebook(state);

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

  const decodeAttempts =
    memory.attempts + keys.attempts + relations.attempts + temporal.attempts + codebook.attempts + crossAttempts;
  const decodeFailures =
    memory.failures + keys.failures + relations.failures + temporal.failures + codebook.failures + crossFailures;
  const decodedSlots = decodeAttempts - decodeFailures;

  return {
    memoryIndex: memory.slots,
    retrievalKeys: keys.slots,
    relations: relations.edges,
    temporal: filteredTemporal,
    codebook: codebook.entries,
    decodedSlots,
    decodeFailures,
    decodeAttempts,
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
    (slot.valid ? 0x0001n : 0n) | (slot.revoked ? 0x0002n : 0n) | (slot.protected ? 0x0004n : 0n);
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
  return [w0, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
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
