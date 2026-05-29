/**
 * LEGACY decoder for the pre-canonical events (CoretexPatchBytes + the old two-arg
 * CortexStateAdvanced). SUPERSEDED by ./coretex-registry.ts (canonical CoreTexRegistry events).
 * Retained only for its generic RPC transport helpers (rpcCall/receiptLogs/rangeLogs/RpcLog) and
 * for decoding historical pre-rename logs. Do NOT use the old event topics on the launch path.
 */
import { readFileSync } from 'node:fs';

import { unpack, pack } from '../state/codec.js';
import { applyPatch, decodePatch } from '../state/patch.js';
import { bytesToHex, hexToBytes, merkleizeState } from '../state/merkle.js';
import { keccak256 } from '../state/keccak256.js';
import { computePatchHash } from '../eval/seed-derivation.js';
import type { CortexState } from '../state/types.js';

export interface RpcLog {
  readonly address?: string;
  readonly topics: readonly string[];
  readonly data: string;
  readonly blockNumber?: string;
  readonly transactionHash?: string;
  readonly logIndex?: string;
}

export interface V4PatchBytesEvent {
  readonly epochId: bigint;
  readonly miner: string;
  readonly patchHash: string;
  readonly receiptHash: string;
  readonly compactPatchBytes: Uint8Array;
}

export interface CortexStateAdvancedEvent {
  readonly epochId: bigint;
  readonly transitionIndex: bigint;
  readonly parentStateRoot: string;
  readonly newStateRoot: string;
  readonly patchHash: string;
  readonly artifactHash: string;
  readonly wordCount: number;
}

export interface ReplayTransitionSuccess {
  readonly ok: true;
  readonly epochId: string;
  readonly transitionIndex: string;
  readonly parentStateRoot: string;
  readonly newStateRoot: string;
  readonly reproducedStateRoot: string;
  readonly patchHash: string;
  readonly scoreDeltaPpm: string;
  readonly wordCount: number;
  readonly compactPatchBytesHex: string;
  readonly newStatePackedHex: string;
}

export interface ReplayTransitionError {
  readonly ok: false;
  readonly code:
    | 'NO_PATCH_BYTES'
    | 'NO_STATE_ADVANCED'
    | 'MULTIPLE_ADVANCES'
    | 'NO_MATCHING_PATCH_EVENT_FOR_ADVANCE'
    | 'PATCH_HASH_MISMATCH'
    | 'PATCH_PARENT_MISMATCH'
    | 'STATE_PARENT_MISMATCH'
    | 'APPLY_FAILED'
    | 'NEW_ROOT_MISMATCH';
  readonly message: string;
}

export interface ReplayTransitionErrorMultipleAdvances {
  readonly ok: false;
  readonly code: 'MULTIPLE_ADVANCES';
  readonly message: string;
}

export type ReplayTransitionResult = ReplayTransitionSuccess | ReplayTransitionError | ReplayTransitionErrorMultipleAdvances;

export interface ReplayBatchSuccess {
  readonly ok: true;
  readonly transitionCount: number;
  readonly results: readonly ReplayTransitionSuccess[];
  readonly finalStatePackedHex: string;
}

export interface ReplayBatchError {
  readonly ok: false;
  readonly transitionCount: number;
  readonly results: readonly ReplayTransitionResult[];
  readonly error: ReplayTransitionError | { readonly ok: false; readonly code: 'OUT_OF_ORDER_LOGS'; readonly message: string };
}

export type ReplayBatchResult = ReplayBatchSuccess | ReplayBatchError;

export const V4_EVENT_TOPICS = {
  CoretexPatchBytes: eventTopic('CoretexPatchBytes(uint64,address,bytes32,bytes32,bytes)'),
  CortexStateAdvanced: eventTopic('CortexStateAdvanced(uint64,uint64,bytes32,bytes32,bytes32,bytes32,uint16)'),
} as const;

export function replayV4TransitionFromLogs(
  parentState: CortexState,
  logs: readonly RpcLog[],
): ReplayTransitionResult {
  const patches = logs.map(decodeCoretexPatchBytesLog).filter((v): v is V4PatchBytesEvent => v !== null);
  const advances = logs.map(decodeCortexStateAdvancedLog).filter((v): v is CortexStateAdvancedEvent => v !== null);
  if (patches.length === 0) {
    return { ok: false, code: 'NO_PATCH_BYTES', message: 'No CoretexPatchBytes event found' };
  }
  if (advances.length === 0) {
    return { ok: false, code: 'NO_STATE_ADVANCED', message: 'No CortexStateAdvanced event found' };
  }
  // R2: singular replay must receive exactly one advance event.
  // A log set containing multiple advances belongs to the batch path.
  if (advances.length > 1) {
    return {
      ok: false,
      code: 'MULTIPLE_ADVANCES',
      message: `replayV4TransitionFromLogs received ${advances.length} CortexStateAdvanced events; use replayV4TransitionsFromLogs for multi-transition log sets`,
    };
  }

  const advance = advances[0]!;
  const patchEvent = patches.find((event) => eqHex(event.patchHash, advance.patchHash));
  if (!patchEvent) {
    return {
      ok: false,
      code: 'NO_MATCHING_PATCH_EVENT_FOR_ADVANCE',
      message: `No CoretexPatchBytes event matched state advance patchHash ${advance.patchHash}`,
    };
  }
  // Domain-prefixed patch hash (keccak256("coretex-patch-hash-v1" || compactBytes)) — MUST match
  // the on-chain value the contract validates and the coordinator signs. Raw keccak256 would desync.
  const computedPatchHash = computePatchHash(patchEvent.compactPatchBytes);
  if (!eqHex(computedPatchHash, patchEvent.patchHash) || !eqHex(computedPatchHash, advance.patchHash)) {
    return { ok: false, code: 'PATCH_HASH_MISMATCH', message: 'Patch bytes do not match signed/on-chain patchHash' };
  }

  const patch = decodePatch(patchEvent.compactPatchBytes);
  const patchParent = bytesToHex(patch.parentStateRoot);
  if (!eqHex(patchParent, advance.parentStateRoot)) {
    return { ok: false, code: 'PATCH_PARENT_MISMATCH', message: 'Patch parent root does not match state advance parent' };
  }

  const observedParent = bytesToHex(merkleizeState(parentState));
  if (!eqHex(observedParent, advance.parentStateRoot)) {
    return {
      ok: false,
      code: 'STATE_PARENT_MISMATCH',
      message: `Parent state body hashes to ${observedParent}, expected ${advance.parentStateRoot}`,
    };
  }

  const applied = applyPatch(parentState, patch);
  if (!applied.ok) {
    return { ok: false, code: 'APPLY_FAILED', message: `${applied.code}: ${applied.message}` };
  }
  const reproducedStateRoot = bytesToHex(merkleizeState(applied.state));
  if (!eqHex(reproducedStateRoot, advance.newStateRoot)) {
    return {
      ok: false,
      code: 'NEW_ROOT_MISMATCH',
      message: `Replayed patch hashes to ${reproducedStateRoot}, expected ${advance.newStateRoot}`,
    };
  }

  return {
    ok: true,
    epochId: advance.epochId.toString(),
    transitionIndex: advance.transitionIndex.toString(),
    parentStateRoot: advance.parentStateRoot,
    newStateRoot: advance.newStateRoot,
    reproducedStateRoot,
    patchHash: advance.patchHash,
    scoreDeltaPpm: patch.scoreDelta.toString(),
    wordCount: patch.wordCount,
    compactPatchBytesHex: bytesToHex(patchEvent.compactPatchBytes),
    newStatePackedHex: bytesToHex(pack(applied.state)),
  };
}

export function replayV4TransitionsFromLogs(
  parentState: CortexState,
  logs: readonly RpcLog[],
): ReplayBatchResult {
  let currentState = parentState;
  const results: ReplayTransitionResult[] = [];

  // R1: sort logs by (blockNumber, logIndex) ascending before iterating so
  // that out-of-order delivery (e.g. from RPC batching) is corrected.
  const sortedLogs = [...logs].sort((a, b) => {
    const blockA = a.blockNumber ? BigInt(a.blockNumber) : 0n;
    const blockB = b.blockNumber ? BigInt(b.blockNumber) : 0n;
    if (blockA !== blockB) return blockA < blockB ? -1 : 1;
    const idxA = a.logIndex ? Number(a.logIndex) : 0;
    const idxB = b.logIndex ? Number(b.logIndex) : 0;
    return idxA - idxB;
  });

  const patchLogs = sortedLogs.filter((log) => decodeCoretexPatchBytesLog(log) !== null);
  const advanceLogs = sortedLogs.filter((log) => decodeCortexStateAdvancedLog(log) !== null);

  // R1: assert strictly monotone transitionIndex across advance events.
  let lastTransitionIndex: bigint | null = null;
  for (const advanceLog of advanceLogs) {
    const advance = decodeCortexStateAdvancedLog(advanceLog);
    if (advance !== null) {
      if (lastTransitionIndex !== null && advance.transitionIndex <= lastTransitionIndex) {
        const err = {
          ok: false as const,
          code: 'OUT_OF_ORDER_LOGS' as const,
          message: `CortexStateAdvanced transitionIndex ${advance.transitionIndex} is not strictly greater than previous ${lastTransitionIndex}`,
        };
        return { ok: false, transitionCount: 0, results: [], error: err };
      }
      lastTransitionIndex = advance.transitionIndex;
    }
  }

  for (const advanceLog of advanceLogs) {
    const advance = decodeCortexStateAdvancedLog(advanceLog);
    const patchLog = patchLogs.find((log) => {
      const patch = decodeCoretexPatchBytesLog(log);
      return patch !== null && advance !== null && eqHex(patch.patchHash, advance.patchHash);
    });
    const result = replayV4TransitionFromLogs(currentState, patchLog ? [patchLog, advanceLog] : [advanceLog]);
    results.push(result);
    if (!result.ok) {
      return { ok: false, transitionCount: results.length, results, error: result as ReplayTransitionError };
    }
    currentState = unpack(hexToBytes(result.newStatePackedHex));
  }

  return {
    ok: true,
    transitionCount: results.length,
    results: results as ReplayTransitionSuccess[],
    finalStatePackedHex: bytesToHex(pack(currentState)),
  };
}

export function loadPackedState(path: string): CortexState {
  const bytes = readFileSync(path);
  if (bytes.length !== 32768) throw new Error(`packed state must be 32768 bytes, got ${bytes.length}`);
  return unpack(new Uint8Array(bytes));
}

export function decodeCoretexPatchBytesLog(log: RpcLog): V4PatchBytesEvent | null {
  if (!log.topics[0] || !eqHex(log.topics[0], V4_EVENT_TOPICS.CoretexPatchBytes)) return null;
  const data = hexToBytes(log.data);
  const offset = Number(readWord(data, 32));
  const length = Number(readWord(data, offset));
  return {
    epochId: readTopicBigInt(log.topics[1]),
    miner: topicAddress(log.topics[2]),
    patchHash: normalizeBytes32(log.topics[3]),
    receiptHash: bytesToHex(data.subarray(0, 32)),
    compactPatchBytes: data.subarray(offset + 32, offset + 32 + length),
  };
}

export function decodeCortexStateAdvancedLog(log: RpcLog): CortexStateAdvancedEvent | null {
  if (!log.topics[0] || !eqHex(log.topics[0], V4_EVENT_TOPICS.CortexStateAdvanced)) return null;
  const data = hexToBytes(log.data);
  return {
    epochId: readTopicBigInt(log.topics[1]),
    transitionIndex: readTopicBigInt(log.topics[2]),
    parentStateRoot: bytesToHex(data.subarray(0, 32)),
    newStateRoot: bytesToHex(data.subarray(32, 64)),
    patchHash: bytesToHex(data.subarray(64, 96)),
    artifactHash: bytesToHex(data.subarray(96, 128)),
    wordCount: Number(readWord(data, 128)),
  };
}

export async function rpcCall<T>(rpcUrl: string, method: string, params: unknown[]): Promise<T> {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
  const body = await res.json() as { result?: T; error?: { message?: string } };
  if (body.error) throw new Error(body.error.message ?? 'RPC error');
  return body.result as T;
}

export async function receiptLogs(rpcUrl: string, txHash: string): Promise<RpcLog[]> {
  const receipt = await rpcCall<{ logs?: RpcLog[] }>(rpcUrl, 'eth_getTransactionReceipt', [txHash]);
  return receipt.logs ?? [];
}

export async function rangeLogs(
  rpcUrl: string,
  address: string | readonly string[] | undefined,
  fromBlock: string,
  toBlock: string,
): Promise<RpcLog[]> {
  const params: Record<string, unknown> = {
    fromBlock,
    toBlock,
    topics: [[V4_EVENT_TOPICS.CoretexPatchBytes, V4_EVENT_TOPICS.CortexStateAdvanced]],
  };
  if (address) params.address = address;
  return rpcCall<RpcLog[]>(rpcUrl, 'eth_getLogs', [params]);
}

function eventTopic(signature: string): string {
  return bytesToHex(keccak256(new TextEncoder().encode(signature)));
}

function readWord(data: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let i = 0; i < 32; i++) value = (value << 8n) | BigInt(data[offset + i] ?? 0);
  return value;
}

function readTopicBigInt(topic: string | undefined): bigint {
  return BigInt(topic ?? '0x0');
}

function topicAddress(topic: string | undefined): string {
  const hex = (topic ?? '0x' + '00'.repeat(32)).replace(/^0x/, '');
  return '0x' + hex.slice(-40).toLowerCase();
}

function normalizeBytes32(value: string | undefined): string {
  const hex = (value ?? '0x').replace(/^0x/, '').padStart(64, '0');
  return '0x' + hex.toLowerCase();
}

function eqHex(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}
