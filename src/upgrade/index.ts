/**
 * Phase 3 — Core version upgrade semantics.
 *
 * Per §9 Phase 3: Core upgrades publish a state_translation_patch mapping
 * V_n → V_{n+1} OR explicitly reset the organism. Either path is implemented.
 * Ambiguity is forbidden.
 *
 * Two paths:
 *   A. state_translation_patch: a special patch set with patchType = 0xF0 (UPGRADE)
 *      that re-encodes the state under the new Core version semantics.
 *      Published by the Core maintainer; applied by `coretex-client upgrade`.
 *
 *   B. explicit reset: the current epoch is finalized with a RESET event;
 *      the state is set to the new Core's genesis state.
 *      Emits CORTEX_RESET in the transition record.
 *
 * Wire format for state_translation_patch:
 *   [1]  UPGRADE_MAGIC = 0xF0
 *   [1]  fromVersion (uint8)
 *   [1]  toVersion (uint8)
 *   [32] fromCoreVersionHash
 *   [32] toCoreVersionHash
 *   [N]  encoded word-by-word replacements (same wire format as normal patches)
 *
 * This is a reader + validator for that wire format, plus the explicit-reset path.
 */

import type { CortexState } from '../state/index.js';
import { applyPatch, merkleizeState, bytesToHex, hexToBytes } from '../state/index.js';
import { decodePatch, encodePatch } from '../state/patch.js';
import type { Patch } from '../state/types.js';

// ─── Constants ────────────────────────────────────────────────────────────────

export const UPGRADE_MAGIC = 0xF0;
export const RESET_EVENT_MARKER = 'CORTEX_RESET';

// ─── State translation patch wire format ──────────────────────────────────────

export interface StatTranslationPatch {
  /** Source Core version byte. */
  readonly fromVersion: number;
  /** Target Core version byte. */
  readonly toVersion: number;
  /** keccak256 of source Core version string (32 bytes, 0x-prefixed hex). */
  readonly fromCoreVersionHash: string;
  /** keccak256 of target Core version string (32 bytes, 0x-prefixed hex). */
  readonly toCoreVersionHash: string;
  /** Decoded word patches to apply in sequence. */
  readonly patches: readonly Patch[];
}

export interface UpgradeParseError {
  readonly ok: false;
  readonly code: 'BAD_MAGIC' | 'TOO_SHORT' | 'PATCH_DECODE_ERROR';
  readonly message: string;
}

export interface UpgradeParseSuccess {
  readonly ok: true;
  readonly translation: StatTranslationPatch;
}

export type UpgradeParseResult = UpgradeParseSuccess | UpgradeParseError;

/**
 * Parse a state_translation_patch wire payload.
 *
 * Wire format:
 *   [0]     UPGRADE_MAGIC (0xF0)
 *   [1]     fromVersion
 *   [2]     toVersion
 *   [3:35]  fromCoreVersionHash (32 bytes)
 *   [35:67] toCoreVersionHash (32 bytes)
 *   [67:]   sequence of normal patch wire payloads, each preceded by a
 *           big-endian uint16 length field.
 */
export function parseStatTranslationPatch(data: Uint8Array): UpgradeParseResult {
  if (data.length < 67) {
    return { ok: false, code: 'TOO_SHORT', message: `Too short: ${data.length} bytes (min 67)` };
  }
  if (data[0] !== UPGRADE_MAGIC) {
    return {
      ok: false,
      code: 'BAD_MAGIC',
      message: `Expected upgrade magic 0x${UPGRADE_MAGIC.toString(16)}, got 0x${(data[0] ?? 0).toString(16)}`,
    };
  }

  const fromVersion = data[1] ?? 0;
  const toVersion = data[2] ?? 0;
  const fromCoreVersionHash = bytesToHex(data.subarray(3, 35));
  const toCoreVersionHash = bytesToHex(data.subarray(35, 67));

  const patches: Patch[] = [];
  let offset = 67;
  while (offset < data.length) {
    if (offset + 2 > data.length) break;
    const patchLen = ((data[offset]! << 8) | data[offset + 1]!) >>> 0;
    offset += 2;
    if (offset + patchLen > data.length) {
      return {
        ok: false,
        code: 'TOO_SHORT',
        message: `Patch segment truncated at offset ${offset}: need ${patchLen} bytes, have ${data.length - offset}`,
      };
    }
    const patchBytes = data.subarray(offset, offset + patchLen);
    try {
      const patch = decodePatch(patchBytes);
      patches.push(patch);
    } catch (err: unknown) {
      return {
        ok: false,
        code: 'PATCH_DECODE_ERROR',
        message: `Patch decode error at offset ${offset}: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
    offset += patchLen;
  }

  return {
    ok: true,
    translation: { fromVersion, toVersion, fromCoreVersionHash, toCoreVersionHash, patches },
  };
}

// ─── Apply state_translation_patch ───────────────────────────────────────────

export interface UpgradeApplyError {
  readonly ok: false;
  readonly code: 'VERSION_HASH_MISMATCH' | 'PATCH_APPLY_ERROR';
  readonly message: string;
}

export interface UpgradeApplySuccess {
  readonly ok: true;
  /** New state after applying all translation patches. */
  readonly state: CortexState;
  /** New state root (0x-prefixed hex). */
  readonly newStateRoot: string;
  /** Number of patches applied. */
  readonly patchesApplied: number;
}

export type UpgradeApplyResult = UpgradeApplySuccess | UpgradeApplyError;

/**
 * Apply a parsed state_translation_patch to produce V_{n+1} state.
 *
 * @param state  Current V_n state.
 * @param translation  Parsed upgrade payload.
 * @param currentCoreVersionHash  keccak256 of the current Core version string.
 *   If provided, validated against translation.fromCoreVersionHash.
 */
export function applyStatTranslationPatch(
  state: CortexState,
  translation: StatTranslationPatch,
  currentCoreVersionHash?: string,
): UpgradeApplyResult {
  // Validate version hash if provided
  if (currentCoreVersionHash !== undefined) {
    if (currentCoreVersionHash.toLowerCase() !== translation.fromCoreVersionHash.toLowerCase()) {
      return {
        ok: false,
        code: 'VERSION_HASH_MISMATCH',
        message: `fromCoreVersionHash mismatch: state has ${currentCoreVersionHash}, translation expects ${translation.fromCoreVersionHash}`,
      };
    }
  }

  // Apply patches in sequence
  let current = state;
  let applied = 0;
  for (const patch of translation.patches) {
    const result = applyPatch(current, patch);
    if (!result.ok) {
      return {
        ok: false,
        code: 'PATCH_APPLY_ERROR',
        message: `Patch ${applied} rejected: ${result.code} ${result.message}`,
      };
    }
    current = result.state;
    applied++;
  }

  const newRoot = merkleizeState(current);
  return {
    ok: true,
    state: current,
    newStateRoot: bytesToHex(newRoot),
    patchesApplied: applied,
  };
}

// ─── Explicit reset path ──────────────────────────────────────────────────────

export interface ResetEvent {
  /** Marker string. Always 'CORTEX_RESET'. */
  readonly marker: typeof RESET_EVENT_MARKER;
  /** Epoch at which the reset occurs. */
  readonly epoch: bigint;
  /** keccak256 of old Core version string (0x-prefixed hex). */
  readonly oldCoreVersionHash: string;
  /** keccak256 of new Core version string (0x-prefixed hex). */
  readonly newCoreVersionHash: string;
  /** Old state root (0x-prefixed hex). */
  readonly oldStateRoot: string;
  /** New genesis state root (0x-prefixed hex). */
  readonly newGenesisStateRoot: string;
}

/**
 * Execute an explicit Core reset: replace the current state with the new
 * Core version's genesis state. Emits a ResetEvent record.
 *
 * The genesis state for the new version must be provided by the Core maintainer.
 */
export function executeReset(
  currentState: CortexState,
  newGenesisState: CortexState,
  epoch: bigint,
  oldCoreVersionHash: string,
  newCoreVersionHash: string,
): { event: ResetEvent; state: CortexState } {
  const oldStateRoot = bytesToHex(merkleizeState(currentState));
  const newGenesisStateRoot = bytesToHex(merkleizeState(newGenesisState));

  const event: ResetEvent = {
    marker: RESET_EVENT_MARKER,
    epoch,
    oldCoreVersionHash,
    newCoreVersionHash,
    oldStateRoot,
    newGenesisStateRoot,
  };

  return { event, state: newGenesisState };
}

// ─── Encode state_translation_patch ──────────────────────────────────────────

/**
 * Encode a StatTranslationPatch to wire bytes.
 * Inverse of parseStatTranslationPatch.
 */
export function encodeStatTranslationPatch(translation: StatTranslationPatch): Uint8Array {
  // Encode each patch
  const patchBuffers: Uint8Array[] = translation.patches.map((p) => encodePatch(p));
  const patchTotalSize = patchBuffers.reduce((sum, b) => sum + 2 + b.length, 0);

  const totalSize = 67 + patchTotalSize;
  const out = new Uint8Array(totalSize);
  let offset = 0;

  out[offset++] = UPGRADE_MAGIC;
  out[offset++] = translation.fromVersion;
  out[offset++] = translation.toVersion;

  const fromHash = hexToBytes(translation.fromCoreVersionHash);
  const toHash = hexToBytes(translation.toCoreVersionHash);
  out.set(fromHash, offset); offset += 32;
  out.set(toHash, offset); offset += 32;

  for (const patchBytes of patchBuffers) {
    const len = patchBytes.length;
    out[offset++] = (len >>> 8) & 0xff;
    out[offset++] = len & 0xff;
    out.set(patchBytes, offset);
    offset += len;
  }

  return out;
}
