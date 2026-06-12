/**
 * Patch wire-format encode/decode and applyPatch for CoreTex state.
 * Per patch_format.md:
 *   - LEB128 varint-encoded indices
 *   - Old words omitted from wire (reconstructed from parent state)
 *   - 99th-pct ≤ 200 bytes for 4-word patch
 */

import type { CortexState, Patch, PatchError, PatchResult } from './types.js';
import { ERROR_NAMES, PATCH_TYPE, PATCH_TYPE_RANGE_TABLE, RANGES } from './types.js';
import { writeBigEndian32, readBigEndian32 } from './codec.js';
import { merkleizeState } from './merkle.js';
import { hasNonZeroReservedBits, validatePolicyRegions } from './validate.js';

// On-chain cap for the wire scoreDelta: BotcoinMiningV4._validateCompactPatch reads it as a
// big-endian uint64 and reverts when the top bit is set, so only non-negative int64 values
// (0 .. 2^63-1) are serializable. The TS codec enforces the same range instead of silently
// wrapping via two's complement.
const MAX_WIRE_SCORE_DELTA = (1n << 63n) - 1n;

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
 * Decode a canonical compact-patch word index from `data` starting at `offset`.
 * Solidity accepts only 1-byte indices 0..127 and canonical 2-byte indices
 * 128..1023.
 */
export function decodeLEB128(data: Uint8Array, offset: number): { value: number; bytesRead: number } {
  if (offset >= data.length) {
    throw new RangeError('decodeLEB128: unexpected end of data');
  }
  const first = data[offset]!;
  let value = first & 0x7f;
  if ((first & 0x80) === 0) {
    return { value, bytesRead: 1 };
  }
  if (offset + 1 >= data.length) {
    throw new RangeError('decodeLEB128: unexpected end of data');
  }
  const second = data[offset + 1]!;
  if ((second & 0x80) !== 0) {
    throw new RangeError('decodeLEB128: varint too long');
  }
  value |= (second & 0x7f) << 7;
  if (value < 128) {
    throw new RangeError('decodeLEB128: non-canonical word index');
  }
  if (value >= RANGES.WORD_COUNT) {
    throw new RangeError('decodeLEB128: word index out of range');
  }
  return { value, bytesRead: 2 };
}

// ─── Patch wire encode/decode ─────────────────────────────────────────────────

/**
 * Wire format (per patch_format.md):
 *   [1]  patchType
 *   [1]  wordCount
 *   [4]  scoreDeltaHi (big-endian uint32; top bit must be clear — non-negative int64)
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
  const typeValidation = validatePatchType(patch.patchType, patch.indices);
  if (!typeValidation.ok) {
    throw new RangeError(`encodePatch: ${typeValidation.reason}`);
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

  // scoreDelta as non-negative int64 (uint64 with top bit clear — the representation the
  // on-chain validator requires), split into hi/lo uint32 big-endian
  if (patch.scoreDelta < 0n || patch.scoreDelta > MAX_WIRE_SCORE_DELTA) {
    throw new RangeError(`encodePatch: scoreDelta ${patch.scoreDelta} outside non-negative int64 range`);
  }
  const sdUnsigned = patch.scoreDelta;
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

  // scoreDelta: read hi+lo uint32, reconstruct non-negative int64 (Solidity reverts when the
  // top bit is set, so a set top bit is a wire validity error here too)
  const sdHi = ((data[offset]! << 24) | (data[offset + 1]! << 16) | (data[offset + 2]! << 8) | data[offset + 3]!) >>> 0;
  const sdLo = ((data[offset + 4]! << 24) | (data[offset + 5]! << 16) | (data[offset + 6]! << 8) | data[offset + 7]!) >>> 0;
  offset += 8;
  const scoreDelta = (BigInt(sdHi) << 32n) | BigInt(sdLo);
  if (scoreDelta > MAX_WIRE_SCORE_DELTA) {
    throw new RangeError('decodePatch: scoreDelta outside non-negative int64 range');
  }

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

  if (offset !== data.length) {
    throw new RangeError('decodePatch: trailing bytes');
  }
  const typeValidation = validatePatchType(patchType, indices);
  if (!typeValidation.ok) {
    throw new RangeError(`decodePatch: ${typeValidation.reason}`);
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
export function applyPatch(state: CortexState, patch: Patch, policyAtomsMode = false): PatchResult {
  // 1. Budget check
  if (patch.wordCount < 1 || patch.wordCount > 4) {
    return patchError('E03');
  }

  // 2. Parent-root check
  const currentRoot = merkleizeState(state);
  if (!bytesEqual(patch.parentStateRoot, currentRoot)) {
    return patchError('E01');
  }

  if (!validatePatchType(patch.patchType, patch.indices).ok) {
    return patchError('E02');
  }
  // r5 byte canonicalization:
  //   - pure PolicyAtom writes use POLICY_UPDATE (0x07);
  //   - cross-region writes that include PolicyAtoms use MIXED (0xff);
  //   - KEY_UPDATE/CODEBOOK_UPDATE aliases are rejected under policyAtomsMode.
  //
  // The MIXED case must include a changed MemoryIndex/Relation/Temporal companion word. This preserves
  // the reclaimed-surface bootstrap path without allowing pure atom writes padded with no-op words.
  if (policyAtomsMode && !policyWriteIsCanonicalForState(state, patch)) {
    return patchError('E02');
  }
  // r5 header freeze (audit F7): words 0–31 are protocol metadata
  // (MAGIC/SCHEMA/EPOCH/SCORE_ACCUMULATOR/...), not a minable surface. The
  // reserved-bit masks only zero RESERVED bits — the named fields were freely
  // settable, so a miner could piggyback header corruption onto a genuinely
  // improving MIXED patch (the composite gate never reads header words).
  // Under policyAtomsMode NO patch type may touch the header region; the
  // chain stays permissive (safe direction — the coordinator won't sign).
  if (policyAtomsMode && patchTouchesHeader(patch)) {
    return patchError('E02');
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
  // r5 hard-fail: under policyAtomsMode the reclaimed regions are typed PolicyAtoms
  // (RetrievalKeys/Codebook masks stay 0 for r4-compat, so hasNonZeroReservedBits does
  // NOT cover the 896–991 reserved-zero region or the per-atom grammar — validatePolicyRegions does).
  if (policyAtomsMode) {
    const policyErr = validatePolicyRegions(resultState);
    if (policyErr) return policyErr;
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

// ─── Reducer-only apply path ──────────────────────────────────────────────────
//
// Every screener-pass patch in an epoch carries the same `parentStateRoot` —
// the EPOCH parent root. The reducer validates each patch's parentStateRoot
// against the epoch parent root ONCE (before sorting/applying), then applies
// non-overlapping word writes onto the running `current` state without
// re-validating parent root (which has already advanced).
//
// applyPatchOntoCurrent does the writes only:
//   - wordCount in [1, 4]                    → E03 OVER_BUDGET
//   - target indices outside reserved range  → E02 WRONG_TYPE_FIELD
//   - resulting state respects reserved bits → E04 RESERVED_BIT_SET
//   - patch is not a no-op vs current state  → E05 NOOP_PATCH
//
// It does NOT validate parentStateRoot. Use applyPatch() for any non-reducer
// apply where the caller has not already validated parent root.

/**
 * Apply a patch onto `current` for the reducer. Skips the parent-root check
 * (the reducer pre-validates parent against the epoch parent root via
 * checkPatchParentRoot or applyPatch on the parent state).
 */
export function applyPatchOntoCurrent(current: CortexState, patch: Patch, policyAtomsMode = false): PatchResult {
  if (patch.wordCount < 1 || patch.wordCount > 4) {
    return patchError('E03');
  }

  if (!validatePatchType(patch.patchType, patch.indices).ok) {
    return patchError('E02');
  }
  // r5 byte canonicalization (see applyPatch).
  if (policyAtomsMode && patchTouchesHeader(patch)) {
    return patchError('E02');
  }
  if (policyAtomsMode && !policyWriteIsCanonicalForState(current, patch)) {
    return patchError('E02');
  }

  let anyChange = false;
  for (let i = 0; i < patch.wordCount; i++) {
    if ((current.words[patch.indices[i]!] ?? 0n) !== (patch.newWords[i] ?? 0n)) {
      anyChange = true;
      break;
    }
  }
  if (!anyChange) {
    return patchError('E05');
  }

  const newWords: bigint[] = [...current.words];
  for (let i = 0; i < patch.wordCount; i++) {
    const idx = patch.indices[i]!;
    if (idx >= RANGES.RESERVED_START && idx <= RANGES.RESERVED_END) {
      return patchError('E02');
    }
    if (idx < 0 || idx >= RANGES.WORD_COUNT) {
      return patchError('E02');
    }
    newWords[idx] = patch.newWords[i] ?? 0n;
  }

  const resultState: CortexState = { words: newWords };
  if (hasNonZeroReservedBits(resultState)) {
    return patchError('E04');
  }
  if (policyAtomsMode) {
    const policyErr = validatePolicyRegions(resultState);
    if (policyErr) return policyErr;
  }

  return { ok: true, state: resultState };
}

/**
 * Pre-validate that `patch.parentStateRoot` matches the epoch parent root.
 * Used by the reducer to gate patches before applying onto the running
 * `current` state.
 */
export function patchMatchesEpochParent(
  patch: Patch,
  epochParentRoot: Uint8Array,
): boolean {
  return bytesEqual(patch.parentStateRoot, epochParentRoot);
}

export function validatePatchType(
  patchType: number,
  indices: readonly number[],
): { ok: true } | { ok: false; reason: string } {
  const seen = new Set<number>();
  for (const idx of indices) {
    if (!Number.isInteger(idx) || idx < 0 || idx >= RANGES.WORD_COUNT) {
      return { ok: false, reason: `index ${idx} is outside state word range` };
    }
    if (idx >= RANGES.RESERVED_START && idx <= RANGES.RESERVED_END) {
      return { ok: false, reason: `index ${idx} is reserved` };
    }
    // Duplicate word indices are a validity error (mirrors the Solidity validator), not
    // last-write-wins.
    if (seen.has(idx)) {
      return { ok: false, reason: `duplicate word index ${idx}` };
    }
    seen.add(idx);
  }

  if (patchType === PATCH_TYPE.MIXED) {
    return { ok: true };
  }

  const range = patchTypeRange(patchType);
  if (!range) {
    return { ok: false, reason: `unknown patchType ${patchType}` };
  }

  for (const idx of indices) {
    if (idx < range.start || idx > range.end) {
      return {
        ok: false,
        reason: `patchType ${patchType} cannot target index ${idx}`,
      };
    }
  }
  return { ok: true };
}

// Exported as the CANONICAL patch-type → writable-word-range authority so harnesses (miner-API
// challenge, screener allowedPatchTypes) call this instead of hand-mirroring the switch (drift hazard).
export function patchTypeRange(patchType: number): { start: number; end: number } | undefined {
  // Derived from the single descriptor table in state/types.ts — the same
  // table the TS↔Solidity parity test checks against _wordMatchesPatchType.
  const row = PATCH_TYPE_RANGE_TABLE.find((r) => r.typeByte === patchType);
  return row ? { start: row.start, end: row.end } : undefined;
}

/**
 * CANONICAL allowed-patch-type table for the miner-facing challenge: each concrete patch type with
 * its byte code and writable word-index range, derived from PATCH_TYPE + patchTypeRange (the single
 * grammar authority). Harnesses (miner-API challenge, screener) MUST call this instead of
 * hand-mirroring the switch (drift hazard). PIPELINE-AWARE: under r5
 * (pipelineVersion === 'coretex-retrieval-v2-policy-r5') the RetrievalKeys region 384-671 IS the typed
 * PolicyAtom region — pure atom writes use POLICY_UPDATE (0x07), NOT raw KEY_UPDATE (0x01) — and 896-991
 * is reserved-zero. So under r5 we SUPPRESS KEY_UPDATE (would alias the policy region) and
 * CODEBOOK_UPDATE (reserved-zero). MIXED remains advertised for true cross-region patches, including
 * MemoryIndex+Temporal and MemoryIndex/Relation+PolicyAtom compiles. This advertises what the GRAMMAR
 * accepts; which surfaces are reward-ACTIVE is separate (activeSubstrateSurfaces).
 */
/**
 * r5 byte canonicalization:
 *   - pure PolicyAtom writes are canonical only as POLICY_UPDATE;
 *   - true cross-region writes touching PolicyAtoms are canonical as MIXED;
 *   - KEY_UPDATE/CODEBOOK_UPDATE aliases into reclaimed r5 words are never canonical.
 *
 * This rejects the policy-only MIXED/KEY aliases while keeping reclaimed-surface compiles mineable when
 * they need to atomically introduce an anchor/lens and the atom that points at it. The apply path adds
 * the state-dependent check that the companion word actually changes, so no-op padding cannot reopen the
 * pure-policy alias.
 */
/** r5: true when any targeted index falls in the header region (words 0–31). */
export function patchTouchesHeader(patch: { readonly indices: readonly number[]; readonly wordCount: number }): boolean {
  for (let i = 0; i < patch.wordCount; i++) {
    const idx = patch.indices[i]!;
    if (idx >= RANGES.HEADER_START && idx <= RANGES.HEADER_END) return true;
  }
  return false;
}

export function policyWriteIsCanonical(patch: { readonly patchType: number; readonly indices: readonly number[]; readonly wordCount: number }): boolean {
  let touchesPolicy = false;
  let touchesCompanion = false;
  for (let i = 0; i < patch.wordCount; i++) {
    const idx = patch.indices[i]!;
    if (idx >= RANGES.POLICY_EVIDENCE_START && idx <= RANGES.POLICY_ABSTENTION_END) touchesPolicy = true;
    else if (isPolicyMixedCompanionIndex(idx)) touchesCompanion = true;
  }
  if (!touchesPolicy) return true;
  if (patch.patchType === PATCH_TYPE.POLICY_UPDATE) return true;
  if (patch.patchType === PATCH_TYPE.MIXED) return touchesCompanion;
  return false;
}

function policyWriteIsCanonicalForState(state: CortexState, patch: Patch): boolean {
  if (!policyWriteIsCanonical(patch)) return false;
  let touchesPolicy = false;
  let changedCompanion = false;
  for (let i = 0; i < patch.wordCount; i++) {
    const idx = patch.indices[i]!;
    if (idx >= RANGES.POLICY_EVIDENCE_START && idx <= RANGES.POLICY_ABSTENTION_END) touchesPolicy = true;
    if (isPolicyMixedCompanionIndex(idx) && (state.words[idx] ?? 0n) !== (patch.newWords[i] ?? 0n)) {
      changedCompanion = true;
    }
  }
  if (!touchesPolicy || patch.patchType !== PATCH_TYPE.MIXED) return true;
  return changedCompanion;
}

function isPolicyMixedCompanionIndex(idx: number): boolean {
  return (
    (idx >= RANGES.MEMORY_INDEX_START && idx <= RANGES.MEMORY_INDEX_END)
    || (idx >= RANGES.RELATIONS_START && idx <= RANGES.RELATIONS_END)
    || (idx >= RANGES.TEMPORAL_START && idx <= RANGES.TEMPORAL_END)
  );
}

export function buildAllowedPatchTypes(opts?: { readonly pipelineVersion?: string }): ReadonlyArray<{ readonly name: string; readonly byte: number; readonly wordIndexRange: readonly [number, number] }> {
  const r5 = opts?.pipelineVersion === 'coretex-retrieval-v2-policy-r5';
  // r5 suppresses KEY_UPDATE (its entire range IS the reclaimed PolicyAtom region 384-671) and
  // CODEBOOK_UPDATE (896-991 reserved-zero). MIXED is KEPT — it is the calibration-derived type for
  // atomic cross-region compiles: temporal pair (MemoryIndex+Temporal, e.g. [32,33,800]) and reclaimed
  // PolicyAtom surfaces that need to introduce an anchor/lens in the same patch. Pure policy writes via
  // MIXED are still rejected by policyWriteIsCanonical, so the policy-only alias stays closed.
  // r5 additionally suppresses HEADER_UPDATE (audit F7): words 0–31 are
  // protocol metadata, frozen against miner writes under policyAtomsMode
  // (applyPatch rejects E02), so they are no longer advertised either.
  const r5Suppressed = new Set<number>([PATCH_TYPE.KEY_UPDATE, PATCH_TYPE.CODEBOOK_UPDATE, PATCH_TYPE.HEADER_UPDATE]);
  const out: Array<{ name: string; byte: number; wordIndexRange: [number, number] }> = [];
  for (const [name, byte] of Object.entries(PATCH_TYPE)) {
    if (r5 && r5Suppressed.has(byte)) continue;
    if (byte === PATCH_TYPE.MIXED) {
      // Under r5 the header region is not minable: MIXED advertises from the
      // MemoryIndex start instead of word 0.
      out.push({ name, byte, wordIndexRange: [r5 ? RANGES.MEMORY_INDEX_START : 0, RANGES.CODEBOOK_END] });
      continue;
    }
    const r = patchTypeRange(byte);
    if (r) out.push({ name, byte, wordIndexRange: [r.start, r.end] });
  }
  return out;
}
