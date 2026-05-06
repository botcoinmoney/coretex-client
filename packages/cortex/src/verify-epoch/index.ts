/**
 * Phase 3 — verify-epoch: reproduce newStateRoot from chain alone.
 *
 * Reconstructs epoch state from:
 *   1. A snapshot (CortexStateSnapshot event) or genesis state.
 *   2. All CortexPatchAccepted events for the target epoch.
 *   3. CortexEpochFinalized event for the target epoch.
 *
 * Reducer order per reducer_v0.md (deterministic):
 *   Sort by (scoreDelta desc, wordCount asc, patchHash asc).
 *   Apply; skip patches with conflicting indices or stale parentStateRoot.
 *
 * Modes:
 *   - Local/anvil: accepts pre-fetched event arrays (no live RPC).
 *   - RPC: fetches logs via eth_getLogs (gated on BASE_RPC_URL env var).
 *
 * Phase 3 E2E gate: local synthetic chain with fixture events.
 * Full Base mainnet fork is gated on BASE_RPC_URL and self-skips when absent.
 */

import { unpack } from '../state/codec.js';
import { decodePatch, applyPatchOntoCurrent } from '../state/patch.js';
import { merkleizeState, bytesToHex, hexToBytes } from '../state/index.js';
import { keccak256 } from '../state/keccak256.js';
import type { CortexState } from '../state/types.js';

// ─── Chain event types ────────────────────────────────────────────────────────

export interface PatchAcceptedEvent {
  readonly epoch: bigint;
  readonly miner: string;
  readonly parentStateRoot: string;
  readonly patchHash: string;
  readonly evalReportHash: string;
  readonly compactPatchBytes: Uint8Array;
}

export interface EpochFinalizedEvent {
  readonly epoch: bigint;
  readonly parentStateRoot: string;
  readonly patchSetRoot: string;
  readonly newStateRoot: string;
  readonly coreVersionHash: string;
  readonly experienceCorpusRoot: string;
}

export interface StateSnapshotEvent {
  readonly epoch: bigint;
  readonly stateRoot: string;
  readonly fullStateBytes: Uint8Array;
}

// ─── Event topic signatures ───────────────────────────────────────────────────

function keccak256Hex(sig: string): string {
  const encoded = new TextEncoder().encode(sig);
  const hash = keccak256(encoded);
  let hex = '';
  for (const b of hash) hex += b.toString(16).padStart(2, '0');
  return hex;
}

// EVENT_TOPICS moved to ../event-topics.ts as the canonical source of truth.
// Re-export here for back-compat.
export { EVENT_TOPICS } from '../event-topics.js';

// ─── ABI log decoders (no external deps) ─────────────────────────────────────

function readSlice32(data: Uint8Array, offset: number): Uint8Array {
  return data.subarray(offset, offset + 32);
}

function readBigEndian32From(data: Uint8Array, offset: number): bigint {
  let result = 0n;
  for (let b = 0; b < 32; b++) {
    result = (result << 8n) | BigInt(data[offset + b] ?? 0);
  }
  return result;
}

/** Decode address from padded 32-byte topic or data word. */
function decodeAddress(padded: string): string {
  const s = padded.startsWith('0x') ? padded.slice(2) : padded;
  return '0x' + s.slice(-40).toLowerCase();
}

/**
 * Decode a CortexPatchAccepted log.
 * topics[0] = sig, topics[1] = epoch (uint64 indexed), topics[2] = miner (address indexed)
 * data = abi.encode(parentStateRoot, patchHash, evalReportHash, compactPatchBytes)
 */
export function decodePatchAcceptedLog(
  topics: readonly string[],
  data: string,
): PatchAcceptedEvent {
  const epoch = BigInt(topics[1] ?? '0x0');
  const miner = decodeAddress(topics[2] ?? '0x' + '00'.repeat(32));
  const dataBytes = hexToBytes(data.startsWith('0x') ? data : '0x' + data);

  const parentStateRoot = bytesToHex(readSlice32(dataBytes, 0));
  const patchHash = bytesToHex(readSlice32(dataBytes, 32));
  const evalReportHash = bytesToHex(readSlice32(dataBytes, 64));
  // compactPatchBytes is ABI-encoded bytes (dynamic): offset at [96], then length, then data
  const dynamicOffset = Number(readBigEndian32From(dataBytes, 96));
  const byteLen = Number(readBigEndian32From(dataBytes, dynamicOffset));
  const compactPatchBytes = dataBytes.subarray(dynamicOffset + 32, dynamicOffset + 32 + byteLen);

  return { epoch, miner, parentStateRoot, patchHash, evalReportHash, compactPatchBytes };
}

/**
 * Decode a CortexEpochFinalized log.
 * topics[0] = sig, topics[1] = epoch (indexed)
 * data = abi.encode(parentStateRoot, patchSetRoot, newStateRoot, coreVersionHash, experienceCorpusRoot)
 */
export function decodeEpochFinalizedLog(
  topics: readonly string[],
  data: string,
): EpochFinalizedEvent {
  const epoch = BigInt(topics[1] ?? '0x0');
  const dataBytes = hexToBytes(data.startsWith('0x') ? data : '0x' + data);
  return {
    epoch,
    parentStateRoot: bytesToHex(readSlice32(dataBytes, 0)),
    patchSetRoot: bytesToHex(readSlice32(dataBytes, 32)),
    newStateRoot: bytesToHex(readSlice32(dataBytes, 64)),
    coreVersionHash: bytesToHex(readSlice32(dataBytes, 96)),
    experienceCorpusRoot: bytesToHex(readSlice32(dataBytes, 128)),
  };
}

/**
 * Decode a CortexStateSnapshot log.
 * topics[0] = sig, topics[1] = epoch (indexed)
 * data = abi.encode(stateRoot, fullStateBytes)
 */
export function decodeStateSnapshotLog(
  topics: readonly string[],
  data: string,
): StateSnapshotEvent {
  const epoch = BigInt(topics[1] ?? '0x0');
  const dataBytes = hexToBytes(data.startsWith('0x') ? data : '0x' + data);
  const stateRoot = bytesToHex(readSlice32(dataBytes, 0));
  const dynamicOffset = Number(readBigEndian32From(dataBytes, 32));
  const byteLen = Number(readBigEndian32From(dataBytes, dynamicOffset));
  const fullStateBytes = dataBytes.subarray(dynamicOffset + 32, dynamicOffset + 32 + byteLen);
  return { epoch, stateRoot, fullStateBytes };
}

// ─── Deterministic reducer ────────────────────────────────────────────────────

function runReducer(
  parentState: CortexState,
  patches: readonly PatchAcceptedEvent[],
): { state: CortexState; acceptedHashes: string[] } {
  const parentRoot = bytesToHex(merkleizeState(parentState)); // already '0x...'-prefixed

  // Pre-pass: only patches whose parentStateRoot matches the EPOCH parent
  // are eligible (matches reducer.ts R03_WRONG_PARENT_ROOT semantics).
  const eligible = patches.filter(
    (p) => p.parentStateRoot.toLowerCase() === parentRoot.toLowerCase(),
  );

  // Sort: scoreDelta desc, wordCount asc, patchHash asc
  const decoded = eligible.map((ev) => {
    const patch = decodePatch(ev.compactPatchBytes);
    return { ev, patch };
  });
  decoded.sort((a, b) => {
    if (a.patch.scoreDelta > b.patch.scoreDelta) return -1;
    if (a.patch.scoreDelta < b.patch.scoreDelta) return 1;
    if (a.patch.wordCount !== b.patch.wordCount) return a.patch.wordCount - b.patch.wordCount;
    return a.ev.patchHash < b.ev.patchHash ? -1 : 1;
  });

  // Apply each accepted patch onto `current` via the reducer-only path so we
  // don't reject everything-after-the-first-with-stale-parent.
  const usedIndices = new Set<number>();
  let currentState = parentState;
  const acceptedHashes: string[] = [];

  for (const { ev, patch } of decoded) {
    if (patch.indices.some((i) => usedIndices.has(i))) continue;
    const result = applyPatchOntoCurrent(currentState, patch);
    if (!result.ok) continue;
    for (const i of patch.indices) usedIndices.add(i);
    currentState = result.state;
    acceptedHashes.push(ev.patchHash);
  }

  return { state: currentState, acceptedHashes };
}

// ─── verify-epoch result types ────────────────────────────────────────────────

export interface VerifyEpochSuccess {
  readonly ok: true;
  readonly epoch: bigint;
  readonly reproducedStateRoot: string;
  readonly expectedStateRoot: string;
  readonly match: boolean;
  readonly patchesProcessed: number;
  readonly acceptedPatchHashes: readonly string[];
  readonly source: 'snapshot' | 'genesis';
}

export interface VerifyEpochError {
  readonly ok: false;
  readonly code:
    | 'NO_FINALIZED_EVENT'
    | 'NO_SNAPSHOT_OR_GENESIS'
    | 'SNAPSHOT_DECODE_ERROR';
  readonly message: string;
}

export type VerifyEpochResult = VerifyEpochSuccess | VerifyEpochError;

export interface VerifyEpochInput {
  readonly epoch: bigint;
  readonly finalizedEvent: EpochFinalizedEvent | null;
  readonly patchEvents: readonly PatchAcceptedEvent[];
  readonly snapshotEvent: StateSnapshotEvent | null;
  readonly genesisState?: CortexState;
}

/**
 * Reproduce the newStateRoot for a finalized epoch using only chain data.
 */
export function verifyEpoch(input: VerifyEpochInput): VerifyEpochResult {
  if (!input.finalizedEvent) {
    return {
      ok: false,
      code: 'NO_FINALIZED_EVENT',
      message: `No CortexEpochFinalized event for epoch ${input.epoch}`,
    };
  }

  let startState: CortexState;
  let source: 'snapshot' | 'genesis';

  if (input.snapshotEvent) {
    try {
      startState = unpack(input.snapshotEvent.fullStateBytes);
      source = 'snapshot';
    } catch (err: unknown) {
      return {
        ok: false,
        code: 'SNAPSHOT_DECODE_ERROR',
        message: `Snapshot decode error: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  } else if (input.genesisState) {
    startState = input.genesisState;
    source = 'genesis';
  } else {
    return {
      ok: false,
      code: 'NO_SNAPSHOT_OR_GENESIS',
      message: `No snapshot and no genesis state for epoch ${input.epoch}`,
    };
  }

  const { state: finalState, acceptedHashes } = runReducer(startState, input.patchEvents);
  const reproducedStateRoot = (bytesToHex(merkleizeState(finalState))).toLowerCase();
  const expectedStateRoot = input.finalizedEvent.newStateRoot.toLowerCase();

  return {
    ok: true,
    epoch: input.epoch,
    reproducedStateRoot,
    expectedStateRoot,
    match: reproducedStateRoot === expectedStateRoot,
    patchesProcessed: input.patchEvents.length,
    acceptedPatchHashes: acceptedHashes,
    source,
  };
}
