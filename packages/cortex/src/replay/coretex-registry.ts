/**
 * Canonical CoreTexRegistry replay decoder.
 *
 * Decodes the canonical on-chain events emitted by contracts/src/CoreTexRegistry.sol —
 * CoreTexEpochStarted / CoreTexStateAdvanced / CoreTexEpochFinalized — and replays the state
 * advances in transition order from a packed parent state, reproducing the final liveStateRoot.
 *
 * Single-event design: CoreTexStateAdvanced carries the full compactPatchBytes (data availability),
 * so replay needs no separate patch event. This supersedes the old v4 (CoretexPatchBytes +
 * CortexStateAdvanced(uint64,uint64,…)) decoder.
 */
import { applyPatch, decodePatch } from '../state/patch.js';
import { bytesToHex, hexToBytes, merkleizeState } from '../state/merkle.js';
import { keccak256 } from '../state/keccak256.js';
import { computePatchHash } from '../eval/seed-derivation.js';
import type { CortexState } from '../state/types.js';
import { rpcCall, type RpcLog } from './v4.js';

// ── canonical event signatures (param TYPES only, indexed kept in the type list) ──
const SIG_EPOCH_STARTED = 'CoreTexEpochStarted(uint64,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32)';
const SIG_STATE_ADVANCED = 'CoreTexStateAdvanced(uint64,uint64,address,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint256,uint16,bytes)';
const SIG_EPOCH_FINALIZED = 'CoreTexEpochFinalized(uint64,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32)';

function eventTopic(sig: string): string { return bytesToHex(keccak256(new TextEncoder().encode(sig))); }

export const CORETEX_EVENT_TOPICS = {
  CoreTexEpochStarted: eventTopic(SIG_EPOCH_STARTED),
  CoreTexStateAdvanced: eventTopic(SIG_STATE_ADVANCED),
  CoreTexEpochFinalized: eventTopic(SIG_EPOCH_FINALIZED),
} as const;

export interface CoreTexEpochStartedEvent {
  readonly epoch: bigint;
  readonly parentStateRoot: string;
  readonly coreVersionHash: string;
  readonly corpusRoot: string;
  readonly activeFrontierRoot: string;
  readonly baselineManifestHash: string;
  readonly hiddenSeedCommit: string;
}

export interface CoreTexStateAdvancedEvent {
  readonly epoch: bigint;
  readonly transitionIndex: bigint;
  readonly miner: string;
  readonly parentStateRoot: string;
  readonly newStateRoot: string;
  readonly patchHash: string;
  readonly evalReportHash: string;
  readonly coreVersionHash: string;
  readonly corpusRoot: string;
  readonly activeFrontierRoot: string;
  readonly improvementCredits: bigint;
  readonly wordCount: number;
  readonly compactPatchBytes: Uint8Array;
}

export interface CoreTexEpochFinalizedEvent {
  readonly epoch: bigint;
  readonly parentStateRoot: string;
  readonly finalStateRoot: string;
  readonly coreVersionHash: string;
  readonly corpusRoot: string;
  readonly activeFrontierRoot: string;
  readonly patchSetRoot: string;
  readonly scoreRoot: string;
  readonly baselineManifestHash: string;
}

// ── decode helpers ──
function eqHex(a: string | undefined, b: string): boolean { return (a ?? '').toLowerCase() === b.toLowerCase(); }
function word(data: Uint8Array, i: number): string { return bytesToHex(data.subarray(i * 32, i * 32 + 32)); }
function wordNum(data: Uint8Array, i: number): bigint { let v = 0n; for (let j = 0; j < 32; j++) v = (v << 8n) | BigInt(data[i * 32 + j] ?? 0); return v; }
function topicBig(t: string | undefined): bigint { return BigInt(t ?? '0x0'); }
function topicAddr(t: string | undefined): string { const h = (t ?? '0x' + '00'.repeat(32)).replace(/^0x/, ''); return '0x' + h.slice(-40).toLowerCase(); }

/** Fetch all canonical CoreTexRegistry logs (started/advanced/finalized) in a block range. */
export async function coretexRangeLogs(
  rpcUrl: string,
  address: string | readonly string[] | undefined,
  fromBlock: string,
  toBlock: string,
): Promise<RpcLog[]> {
  const params: Record<string, unknown> = {
    fromBlock, toBlock,
    topics: [[CORETEX_EVENT_TOPICS.CoreTexEpochStarted, CORETEX_EVENT_TOPICS.CoreTexStateAdvanced, CORETEX_EVENT_TOPICS.CoreTexEpochFinalized]],
  };
  if (address) params.address = address;
  return rpcCall<RpcLog[]>(rpcUrl, 'eth_getLogs', [params]);
}

export function decodeCoreTexEpochStarted(log: RpcLog): CoreTexEpochStartedEvent | null {
  if (!eqHex(log.topics[0], CORETEX_EVENT_TOPICS.CoreTexEpochStarted)) return null;
  const d = hexToBytes(log.data);
  return {
    epoch: topicBig(log.topics[1]),
    parentStateRoot: word(d, 0), coreVersionHash: word(d, 1), corpusRoot: word(d, 2),
    activeFrontierRoot: word(d, 3), baselineManifestHash: word(d, 4), hiddenSeedCommit: word(d, 5),
  };
}

export function decodeCoreTexStateAdvanced(log: RpcLog): CoreTexStateAdvancedEvent | null {
  if (!eqHex(log.topics[0], CORETEX_EVENT_TOPICS.CoreTexStateAdvanced)) return null;
  const d = hexToBytes(log.data);
  // head: 7 bytes32 + improvementCredits(uint256) + wordCount(uint16) + bytes-offset = words 0..9
  const off = Number(wordNum(d, 9));
  const len = Number(wordNum(d, off / 32));
  const start = off + 32;
  return {
    epoch: topicBig(log.topics[1]), transitionIndex: topicBig(log.topics[2]), miner: topicAddr(log.topics[3]),
    parentStateRoot: word(d, 0), newStateRoot: word(d, 1), patchHash: word(d, 2), evalReportHash: word(d, 3),
    coreVersionHash: word(d, 4), corpusRoot: word(d, 5), activeFrontierRoot: word(d, 6),
    improvementCredits: wordNum(d, 7), wordCount: Number(wordNum(d, 8)),
    compactPatchBytes: d.subarray(start, start + len),
  };
}

export function decodeCoreTexEpochFinalized(log: RpcLog): CoreTexEpochFinalizedEvent | null {
  if (!eqHex(log.topics[0], CORETEX_EVENT_TOPICS.CoreTexEpochFinalized)) return null;
  const d = hexToBytes(log.data);
  return {
    epoch: topicBig(log.topics[1]),
    parentStateRoot: word(d, 0), finalStateRoot: word(d, 1), coreVersionHash: word(d, 2),
    corpusRoot: word(d, 3), activeFrontierRoot: word(d, 4), patchSetRoot: word(d, 5),
    scoreRoot: word(d, 6), baselineManifestHash: word(d, 7),
  };
}

export interface CoreTexReplayResult {
  readonly ok: boolean;
  readonly code?: 'NO_EPOCH_STARTED' | 'STATE_PARENT_MISMATCH' | 'PATCH_HASH_MISMATCH'
    | 'APPLY_FAILED' | 'NEW_ROOT_MISMATCH' | 'CORE_VERSION_MISMATCH' | 'OUT_OF_ORDER'
    | 'FINAL_ROOT_MISMATCH' | 'NO_PATCH_BYTES';
  readonly message?: string;
  readonly epochStarted?: CoreTexEpochStartedEvent;
  readonly transitions: number;
  readonly reproducedFinalRoot?: string;
  readonly onChainFinalRoot?: string;
}

/**
 * Replay all CoreTexStateAdvanced logs in transition order from `parentState`, verifying parent
 * continuity, patch-hash binding, applied new root, and (if provided) coreVersionHash == expectedBundleHash.
 * If a CoreTexEpochStarted log is present its parentStateRoot must match the starting state.
 * If a CoreTexEpochFinalized log is present, its finalStateRoot must equal the reproduced final root.
 */
export function replayCoreTexFromLogs(
  parentState: CortexState,
  logs: readonly RpcLog[],
  opts: { expectedBundleHash?: string } = {},
): CoreTexReplayResult {
  const started = logs.map(decodeCoreTexEpochStarted).find((v): v is CoreTexEpochStartedEvent => v !== null);
  const advances = logs.map(decodeCoreTexStateAdvanced).filter((v): v is CoreTexStateAdvancedEvent => v !== null)
    .sort((a, b) => (a.transitionIndex < b.transitionIndex ? -1 : a.transitionIndex > b.transitionIndex ? 1 : 0));
  const finalized = logs.map(decodeCoreTexEpochFinalized).find((v): v is CoreTexEpochFinalizedEvent => v !== null);

  const withStart = <T extends object>(o: T): T & { epochStarted?: CoreTexEpochStartedEvent } =>
    (started ? { ...o, epochStarted: started } : o);

  let state = parentState;
  let root = bytesToHex(merkleizeState(state));
  if (started && !eqHex(started.parentStateRoot, root)) {
    return withStart({ ok: false as const, code: 'STATE_PARENT_MISMATCH' as const, message: `epochStarted.parentStateRoot ${started.parentStateRoot} != provided parent ${root}`, transitions: 0 });
  }

  let expectedIdx = 0n;
  for (const adv of advances) {
    if (adv.transitionIndex !== expectedIdx) {
      return { ok: false, code: 'OUT_OF_ORDER', message: `transitionIndex ${adv.transitionIndex} != expected ${expectedIdx}`, transitions: Number(expectedIdx) };
    }
    expectedIdx++;
    if (opts.expectedBundleHash && !eqHex(adv.coreVersionHash, opts.expectedBundleHash)) {
      return { ok: false, code: 'CORE_VERSION_MISMATCH', message: `advance ${adv.transitionIndex} coreVersionHash ${adv.coreVersionHash} != expected ${opts.expectedBundleHash}`, transitions: Number(adv.transitionIndex) };
    }
    if (!eqHex(adv.parentStateRoot, root)) {
      return { ok: false, code: 'STATE_PARENT_MISMATCH', message: `advance ${adv.transitionIndex} parent ${adv.parentStateRoot} != live ${root}`, transitions: Number(adv.transitionIndex) };
    }
    if (adv.compactPatchBytes.length === 0) {
      return { ok: false, code: 'NO_PATCH_BYTES', message: `advance ${adv.transitionIndex} has empty compactPatchBytes`, transitions: Number(adv.transitionIndex) };
    }
    if (!eqHex(computePatchHash(adv.compactPatchBytes), adv.patchHash)) {
      return { ok: false, code: 'PATCH_HASH_MISMATCH', message: `advance ${adv.transitionIndex} patchHash mismatch`, transitions: Number(adv.transitionIndex) };
    }
    const res = applyPatch(state, decodePatch(adv.compactPatchBytes));
    if (!res.ok) {
      return { ok: false, code: 'APPLY_FAILED', message: `advance ${adv.transitionIndex} applyPatch ${res.code}`, transitions: Number(adv.transitionIndex) };
    }
    const newRoot = bytesToHex(merkleizeState(res.state));
    if (!eqHex(newRoot, adv.newStateRoot)) {
      return { ok: false, code: 'NEW_ROOT_MISMATCH', message: `advance ${adv.transitionIndex} reproduced ${newRoot} != on-chain ${adv.newStateRoot}`, transitions: Number(adv.transitionIndex) };
    }
    state = res.state;
    root = newRoot;
  }

  if (finalized && !eqHex(finalized.finalStateRoot, root)) {
    return withStart({ ok: false as const, code: 'FINAL_ROOT_MISMATCH' as const, message: `epochFinalized.finalStateRoot ${finalized.finalStateRoot} != reproduced ${root}`, transitions: advances.length, reproducedFinalRoot: root, onChainFinalRoot: finalized.finalStateRoot });
  }
  const result: {
    ok: true; transitions: number; reproducedFinalRoot: string;
    epochStarted?: CoreTexEpochStartedEvent; onChainFinalRoot?: string;
  } = { ok: true, transitions: advances.length, reproducedFinalRoot: root };
  if (started) result.epochStarted = started;
  if (finalized) result.onChainFinalRoot = finalized.finalStateRoot;
  return result;
}
