/**
 * Phase 3 — Typed-slot decoder for CoreTex state.
 *
 * Responsibilities (§4):
 *   1. Parse 1024-word CortexState into typed slots.
 *   2. Build retrieval keys and routes from the state.
 *   3. Resolve temporal validity / revocation.
 */

import type { CortexState } from '../state/index.js';
import { RANGES, MAGIC, SCHEMA_VERSION_CoreTex, WORD_COUNT_VALUE } from '../state/index.js';
import { getField } from '../state/codec.js';

// ─── Types ────────────────────────────────────────────────────────────────────

/** Decoded protocol header (words 0–10). */
export interface DecodedHeader {
  readonly magic: number;
  readonly schemaVersion: number;
  readonly wordCount: number;
  readonly flags: number;
  readonly genesisState: boolean;
  readonly epoch: bigint;
  readonly epochStartTimestamp: bigint;
  readonly stateRootPrev: bigint;
  readonly coreVersionHash: bigint;
  readonly schemaHashLo: bigint;
  readonly experienceCorpusRoot: bigint;
  readonly benchmarkCommitment: bigint;
  readonly scoreAccumulator: bigint;
  readonly scoreEpochBaseline: bigint;
  readonly patchCountEpoch: bigint;
  readonly patchCountTotal: bigint;
  readonly lastSnapshotEpoch: bigint;
  readonly snapshotInterval: bigint;
  readonly reducerNonce: bigint;
  readonly patchSetRoot: bigint;
  readonly scoreRoot: bigint;
}

/** A single memory-index slot (8-word entry). */
export interface MemoryIndexSlot {
  readonly slotIndex: number;        // 0–43 (44 slots = 352 words / 8)
  readonly wordBase: number;         // absolute word index of first word in slot
  readonly eventId: bigint;          // bits 255:128 of word 0
  readonly domainCode: number;       // bits 127:96 of word 0
  readonly objType: number;          // bits 95:80 of word 0
  readonly validityFlags: number;    // bits 79:64 of word 0 (only bit 0 named: VALID)
  readonly valid: boolean;
  readonly revoked: boolean;         // bit 1 of validityFlags
  readonly checksum: bigint;         // bits 255:128 of word 1
  readonly corpusEpoch: bigint;      // bits 127:64 of word 1
  readonly expiryEpoch: bigint;      // bits 63:0 of word 1
  readonly payloadWords: readonly bigint[]; // words 2–7 (6 words)
}

/** A single retrieval-key slot (8-word entry). */
export interface RetrievalKeySlot {
  readonly slotIndex: number;        // 0–35 (36 slots = 288 words / 8)
  readonly wordBase: number;
  readonly keyId: bigint;            // bits 255:128 of word 0
  readonly keyType: number;          // bits 127:112 of word 0
  readonly keyDim: number;           // bits 111:96 of word 0
  readonly keyFlags: number;         // bits 95:80 of word 0 (only bit 0 named: ACTIVE)
  readonly active: boolean;
  readonly keyVector: readonly bigint[]; // words 1–7 (7 words)
}

/** A single relation/routing entry (1-word entry). */
export interface RelationEntry {
  readonly entryIndex: number;
  readonly wordIndex: number;
  readonly fromDomain: number;   // bits 255:240
  readonly toDomain: number;     // bits 239:224
  readonly relationType: number; // bits 223:208
  readonly weight: number;       // bits 207:192
}

/** A single temporal-validity entry (1-word entry). */
export interface TemporalEntry {
  readonly entryIndex: number;
  readonly wordIndex: number;
  readonly eventId: bigint;    // bits 255:96 (160 bits)
  readonly validFrom: number;  // bits 95:64
  readonly validUntil: number; // bits 63:32
  readonly revoked: boolean;   // bit 0 of bits 31:0
}

/** A single codebook entry (2-word entry). */
export interface CodebookEntry {
  readonly entryIndex: number;
  readonly wordBase: number;
  readonly code: number;       // bits 255:240 of word 0
  readonly codeType: number;   // bits 239:224 of word 0
  readonly codeFlags: number;  // bits 223:208 of word 0 (bit 0: ACTIVE)
  readonly active: boolean;
  readonly codeData: bigint;   // word 1 (full 256-bit)
}

/** Fully decoded CortexState. */
export interface DecodedCortexState {
  readonly header: DecodedHeader;
  readonly memoryIndex: readonly MemoryIndexSlot[];
  readonly retrievalKeys: readonly RetrievalKeySlot[];
  readonly relations: readonly RelationEntry[];
  readonly temporal: readonly TemporalEntry[];
  readonly codebook: readonly CodebookEntry[];
  /** Active retrieval routes: key slotIndex → list of memory slotIndex */
  readonly routes: ReadonlyMap<number, readonly number[]>;
  /** Revoked event IDs as a Set of bigint */
  readonly revokedEventIds: ReadonlySet<bigint>;
}

/** Validation error for decoding */
export interface DecodeError {
  readonly ok: false;
  readonly code: 'DECODE_WRONG_MAGIC' | 'DECODE_WRONG_VERSION' | 'DECODE_WRONG_WORD_COUNT' | 'DECODE_WRONG_LENGTH';
  readonly message: string;
}
export interface DecodeSuccess {
  readonly ok: true;
  readonly decoded: DecodedCortexState;
}
export type DecodeResult = DecodeSuccess | DecodeError;

// ─── Header decoder ───────────────────────────────────────────────────────────

function decodeHeader(words: readonly bigint[]): DecodedHeader {
  const w0 = words[0] ?? 0n;
  const magic = Number(getField(w0, 255, 240));
  const schemaVersion = Number(getField(w0, 239, 224));
  const wordCount = Number(getField(w0, 223, 208));
  const flags = Number(getField(w0, 207, 192));
  const genesisState = (flags & 1) !== 0;

  const w1 = words[1] ?? 0n;
  const epoch = getField(w1, 255, 192);
  const epochStartTimestamp = getField(w1, 191, 128);

  const w7 = words[7] ?? 0n;
  const scoreAccumulator = getField(w7, 255, 192);
  const scoreEpochBaseline = getField(w7, 191, 128);
  const patchCountEpoch = getField(w7, 127, 64);
  const patchCountTotal = getField(w7, 63, 0);

  const w8 = words[8] ?? 0n;
  const lastSnapshotEpoch = getField(w8, 255, 192);
  const snapshotInterval = getField(w8, 191, 128);
  const reducerNonce = getField(w8, 127, 64);

  return {
    magic,
    schemaVersion,
    wordCount,
    flags,
    genesisState,
    epoch,
    epochStartTimestamp,
    stateRootPrev: words[2] ?? 0n,
    coreVersionHash: words[3] ?? 0n,
    schemaHashLo: words[4] ?? 0n,
    experienceCorpusRoot: words[5] ?? 0n,
    benchmarkCommitment: words[6] ?? 0n,
    scoreAccumulator,
    scoreEpochBaseline,
    patchCountEpoch,
    patchCountTotal,
    lastSnapshotEpoch,
    snapshotInterval,
    reducerNonce,
    patchSetRoot: words[9] ?? 0n,
    scoreRoot: words[10] ?? 0n,
  };
}

// ─── MemoryIndex decoder ──────────────────────────────────────────────────────

const MEMORY_INDEX_SLOTS = 44; // (383 - 32 + 1) / 8 = 352/8 = 44

function decodeMemoryIndex(words: readonly bigint[]): MemoryIndexSlot[] {
  const slots: MemoryIndexSlot[] = [];
  for (let s = 0; s < MEMORY_INDEX_SLOTS; s++) {
    const base = RANGES.MEMORY_INDEX_START + s * 8;
    const w0 = words[base] ?? 0n;
    const w1 = words[base + 1] ?? 0n;

    const eventId = getField(w0, 255, 128);
    const domainCode = Number(getField(w0, 127, 96));
    const objType = Number(getField(w0, 95, 80));
    const validityFlags = Number(getField(w0, 79, 64));
    const valid = (validityFlags & 0x01) !== 0;
    const revoked = (validityFlags & 0x02) !== 0;

    const checksum = getField(w1, 255, 128);
    const corpusEpoch = getField(w1, 127, 64);
    const expiryEpoch = getField(w1, 63, 0);

    const payloadWords: bigint[] = [];
    for (let p = 2; p < 8; p++) {
      payloadWords.push(words[base + p] ?? 0n);
    }

    slots.push({
      slotIndex: s,
      wordBase: base,
      eventId,
      domainCode,
      objType,
      validityFlags,
      valid,
      revoked,
      checksum,
      corpusEpoch,
      expiryEpoch,
      payloadWords,
    });
  }
  return slots;
}

// ─── RetrievalKeys decoder ────────────────────────────────────────────────────

const RETRIEVAL_KEY_SLOTS = 36; // (671 - 384 + 1) / 8 = 288/8 = 36

function decodeRetrievalKeys(words: readonly bigint[]): RetrievalKeySlot[] {
  const slots: RetrievalKeySlot[] = [];
  for (let s = 0; s < RETRIEVAL_KEY_SLOTS; s++) {
    const base = RANGES.RETRIEVAL_KEYS_START + s * 8;
    const w0 = words[base] ?? 0n;

    const keyId = getField(w0, 255, 128);
    const keyType = Number(getField(w0, 127, 112));
    const keyDim = Number(getField(w0, 111, 96));
    const keyFlags = Number(getField(w0, 95, 80));
    const active = (keyFlags & 0x01) !== 0;

    const keyVector: bigint[] = [];
    for (let v = 1; v < 8; v++) {
      keyVector.push(words[base + v] ?? 0n);
    }

    slots.push({
      slotIndex: s,
      wordBase: base,
      keyId,
      keyType,
      keyDim,
      keyFlags,
      active,
      keyVector,
    });
  }
  return slots;
}

// ─── Relations decoder ────────────────────────────────────────────────────────

const RELATIONS_COUNT = RANGES.RELATIONS_END - RANGES.RELATIONS_START + 1; // 128

function decodeRelations(words: readonly bigint[]): RelationEntry[] {
  const entries: RelationEntry[] = [];
  for (let i = 0; i < RELATIONS_COUNT; i++) {
    const wordIndex = RANGES.RELATIONS_START + i;
    const w = words[wordIndex] ?? 0n;
    // Bits 255:192 used (64 bits of relation data; bits 191:0 are reserved/zero)
    const fromDomain = Number(getField(w, 255, 240));
    const toDomain = Number(getField(w, 239, 224));
    const relationType = Number(getField(w, 223, 208));
    const weight = Number(getField(w, 207, 192));
    entries.push({ entryIndex: i, wordIndex, fromDomain, toDomain, relationType, weight });
  }
  return entries;
}

// ─── Temporal decoder ─────────────────────────────────────────────────────────

const TEMPORAL_COUNT = RANGES.TEMPORAL_END - RANGES.TEMPORAL_START + 1; // 96

function decodeTemporal(words: readonly bigint[]): TemporalEntry[] {
  const entries: TemporalEntry[] = [];
  for (let i = 0; i < TEMPORAL_COUNT; i++) {
    const wordIndex = RANGES.TEMPORAL_START + i;
    const w = words[wordIndex] ?? 0n;
    // bits 255:96 = eventId (160 bits), bits 95:64 = validFrom, bits 63:32 = validUntil
    // bits 31:0 reserved except bit 0 = revoked
    const eventId = getField(w, 255, 96);
    const validFrom = Number(getField(w, 95, 64));
    const validUntil = Number(getField(w, 63, 32));
    const revoked = (Number(getField(w, 0, 0))) !== 0;
    entries.push({ entryIndex: i, wordIndex, eventId, validFrom, validUntil, revoked });
  }
  return entries;
}

// ─── Codebook decoder ─────────────────────────────────────────────────────────

const CODEBOOK_ENTRIES = (RANGES.CODEBOOK_END - RANGES.CODEBOOK_START + 1) / 2; // 48

function decodeCodebook(words: readonly bigint[]): CodebookEntry[] {
  const entries: CodebookEntry[] = [];
  for (let e = 0; e < CODEBOOK_ENTRIES; e++) {
    const base = RANGES.CODEBOOK_START + e * 2;
    const w0 = words[base] ?? 0n;
    const code = Number(getField(w0, 255, 240));
    const codeType = Number(getField(w0, 239, 224));
    const codeFlags = Number(getField(w0, 223, 208));
    const active = (codeFlags & 0x01) !== 0;
    const codeData = words[base + 1] ?? 0n;
    entries.push({ entryIndex: e, wordBase: base, code, codeType, codeFlags, active, codeData });
  }
  return entries;
}

// ─── Route builder ────────────────────────────────────────────────────────────

/**
 * Build retrieval routes: active key slots → active memory slots with matching domainCode.
 * Uses keyType as route discriminator: key.keyType === slot.objType
 */
function buildRoutes(
  keys: readonly RetrievalKeySlot[],
  memory: readonly MemoryIndexSlot[],
): Map<number, number[]> {
  const routes = new Map<number, number[]>();
  const activeKeys = keys.filter((k) => k.active);
  for (const key of activeKeys) {
    const targets: number[] = [];
    for (const slot of memory) {
      if (slot.valid && !slot.revoked && slot.objType === key.keyType) {
        targets.push(slot.slotIndex);
      }
    }
    if (targets.length > 0) {
      routes.set(key.slotIndex, targets);
    }
  }
  return routes;
}

// ─── Revocation resolver ──────────────────────────────────────────────────────

function buildRevokedSet(temporal: readonly TemporalEntry[]): Set<bigint> {
  const revoked = new Set<bigint>();
  for (const entry of temporal) {
    if (entry.revoked && entry.eventId !== 0n) {
      revoked.add(entry.eventId);
    }
  }
  return revoked;
}

// ─── Main decode entry point ──────────────────────────────────────────────────

/**
 * Decode a CortexState into typed slots.
 * Validates magic, schemaVersion, wordCount.
 * Does NOT validate reserved bits (use validateReservedBits for that).
 */
export function decodeCortexState(state: CortexState): DecodeResult {
  if (state.words.length !== RANGES.WORD_COUNT) {
    return {
      ok: false,
      code: 'DECODE_WRONG_LENGTH',
      message: `Expected ${RANGES.WORD_COUNT} words, got ${state.words.length}`,
    };
  }

  const words = state.words;
  const w0 = words[0] ?? 0n;
  const magic = Number(getField(w0, 255, 240));
  if (magic !== Number(MAGIC)) {
    return {
      ok: false,
      code: 'DECODE_WRONG_MAGIC',
      message: `Invalid magic: expected 0x${Number(MAGIC).toString(16).toUpperCase()}, got 0x${magic.toString(16).toUpperCase()}`,
    };
  }

  const schemaVersion = Number(getField(w0, 239, 224));
  if (schemaVersion !== Number(SCHEMA_VERSION_CoreTex)) {
    return {
      ok: false,
      code: 'DECODE_WRONG_VERSION',
      message: `Unknown schema version: 0x${schemaVersion.toString(16)}`,
    };
  }

  const wordCountField = Number(getField(w0, 223, 208));
  if (wordCountField !== Number(WORD_COUNT_VALUE)) {
    return {
      ok: false,
      code: 'DECODE_WRONG_WORD_COUNT',
      message: `Invalid word count field: ${wordCountField}`,
    };
  }

  const header = decodeHeader(words);
  const memoryIndex = decodeMemoryIndex(words);
  const retrievalKeys = decodeRetrievalKeys(words);
  const relations = decodeRelations(words);
  const temporal = decodeTemporal(words);
  const codebook = decodeCodebook(words);
  const routes = buildRoutes(retrievalKeys, memoryIndex);
  const revokedEventIds = buildRevokedSet(temporal);

  return {
    ok: true,
    decoded: {
      header,
      memoryIndex,
      retrievalKeys,
      relations,
      temporal,
      codebook,
      routes,
      revokedEventIds,
    },
  };
}

/**
 * Check temporal validity of a memory slot at the given epoch.
 * A slot is temporally valid if:
 *   - valid bit is set
 *   - not revoked (in memory or temporal map)
 *   - current epoch is within [slot.corpusEpoch, slot.expiryEpoch) if expiryEpoch != 0
 */
export function isTemporallyValid(
  slot: MemoryIndexSlot,
  currentEpoch: bigint,
  revokedEventIds: ReadonlySet<bigint>,
): boolean {
  if (!slot.valid || slot.revoked) return false;
  if (revokedEventIds.has(slot.eventId)) return false;
  if (slot.expiryEpoch !== 0n && currentEpoch >= slot.expiryEpoch) return false;
  if (slot.corpusEpoch !== 0n && currentEpoch < slot.corpusEpoch) return false;
  return true;
}
