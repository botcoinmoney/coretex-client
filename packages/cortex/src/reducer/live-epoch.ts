/**
 * Live 24-hour epoch state advancement.
 *
 * Unlike the end-of-epoch greedy reducer, this path processes verified
 * improvements in arrival order and advances the public Cortex state during
 * the epoch. The 24-hour epoch remains the accounting/audit window; state does
 * not wait until epoch close to absorb useful, non-conflicting improvements.
 */

import type { CortexState, Patch } from '../state/types.js';
import { applyPatchOntoCurrent, encodePatch } from '../state/patch.js';
import { buildMerkleCache, updateMerkleCache, bytesToHex } from '../state/merkle.js';
import { keccak256 } from '../state/keccak256.js';
import type { MarginalEvaluator, RejectionCode, AcceptedPatch } from './reducer.js';
import { computePatchSetRoot, stubMarginalEvaluator } from './reducer.js';
import {
  OUTCOME_CORETEX_STATE_ADVANCE,
  computeCoreTexWorkUnitsBps,
  type CoreTexWorkPolicy,
} from '../rewards/index.js';

export type LiveRejectionCode = RejectionCode | 'L01_NOT_IMPROVEMENT';

export interface LiveEpochInputPatch {
  readonly miner: string;
  readonly patch: Patch;
  readonly patchBytes: Uint8Array;
  readonly scoreDelta: bigint;
  readonly marginalEvaluator: MarginalEvaluator;
}

export interface StateAdvance {
  readonly miner: string;
  readonly patch: Patch;
  readonly patchBytes: Uint8Array;
  readonly patchHash: string;
  readonly parentStateRoot: string;
  readonly newStateRoot: string;
  readonly marginalGain: bigint;
  /** V4 work units in basis points; 30000 means 3x current tier credits. */
  readonly workUnitsBps: bigint;
  /** Backward-compatible alias for the V4 work-unit amount. */
  readonly creditUnits: bigint;
  readonly advanceIndex: number;
}

export interface LiveRejectedPatch {
  readonly miner: string;
  readonly patch: Patch;
  readonly patchBytes: Uint8Array;
  readonly reason: LiveRejectionCode;
}

export interface LiveEpochOutput {
  readonly newState: CortexState;
  readonly patchSetRoot: Uint8Array;
  readonly patchSetRootHex: string;
  readonly newStateRoot: Uint8Array;
  readonly newStateRootHex: string;
  readonly advances: StateAdvance[];
  readonly rejected: LiveRejectedPatch[];
}

export interface LiveEpochRewardOptions {
  readonly qualifiedScreenerPassesSinceLastStateAdvance?: string | bigint | number;
  readonly workPolicy?: CoreTexWorkPolicy;
  /** r5: when true, applyPatchOntoCurrent hard-fails on reserved-region / malformed-PolicyAtom
   *  writes (validatePolicyRegions). Set from the pinned profile's policyAtomsMode. Default off (r4). */
  readonly policyAtomsMode?: boolean;
}

/**
 * Advance the epoch state as verified improvements arrive.
 *
 * Acceptance rules:
 *   - patch.parentStateRoot must equal the current live state root
 *   - marginalGain must be strictly greater than threshold
 *   - applyPatch must succeed on the current live state
 *
 * This means a patch that merely passes a cheap screener but does not improve
 * the current live state earns no credits and never reaches the on-chain state
 * advance log.
 */
export function advanceEpochState(
  parentState: CortexState,
  patches: readonly LiveEpochInputPatch[],
  threshold: bigint = 0n,
  rewardOptions: LiveEpochRewardOptions = {},
): LiveEpochOutput {
  let current = parentState;
  let currentMerkle = buildMerkleCache(current);
  const advances: StateAdvance[] = [];
  const rejected: LiveRejectedPatch[] = [];

  for (const item of patches) {
    const parentRootBytes = currentMerkle.root;
    const parentRootHex = bytesToHex(parentRootBytes);
    if (!bytesEqual(item.patch.parentStateRoot, parentRootBytes)) {
      rejected.push({
        miner: item.miner,
        patch: item.patch,
        patchBytes: item.patchBytes,
        reason: 'R03_WRONG_PARENT_ROOT',
      });
      continue;
    }

    const marginalGain = item.marginalEvaluator(current, item.patch);
    if (marginalGain <= threshold) {
      rejected.push({
        miner: item.miner,
        patch: item.patch,
        patchBytes: item.patchBytes,
        reason: 'L01_NOT_IMPROVEMENT',
      });
      continue;
    }

    const applyResult = applyPatchOntoCurrent(current, item.patch, rewardOptions.policyAtomsMode === true);
    if (!applyResult.ok) {
      const reason: LiveRejectionCode =
        applyResult.code === 'E01' ? 'R03_WRONG_PARENT_ROOT'
        : applyResult.code === 'E04' ? 'R05_RESERVED_BIT_SET'
        : applyResult.code === 'E05' ? 'L01_NOT_IMPROVEMENT'
        : 'R04_INVALID_TARGET';
      rejected.push({
        miner: item.miner,
        patch: item.patch,
        patchBytes: item.patchBytes,
        reason,
      });
      continue;
    }

    current = applyResult.state;
    currentMerkle = updateMerkleCache(
      currentMerkle,
      item.patch.indices.map((index, i) => ({ index, word: item.patch.newWords[i] ?? 0n })),
    );
    const newStateRootHex = bytesToHex(currentMerkle.root);
    const workUnitInput = {
      outcome: OUTCOME_CORETEX_STATE_ADVANCE,
      qualifiedScreenerPassesSinceLastStateAdvance:
        toBigInt(rewardOptions.qualifiedScreenerPassesSinceLastStateAdvance ?? 0n) + BigInt(advances.length),
      ...(rewardOptions.workPolicy ? { policy: rewardOptions.workPolicy } : {}),
    };
    const workUnitsBps = computeCoreTexWorkUnitsBps(workUnitInput);
    advances.push({
      miner: item.miner.toLowerCase(),
      patch: item.patch,
      patchBytes: item.patchBytes,
      patchHash: bytesToHex(keccak256(item.patchBytes)),
      parentStateRoot: parentRootHex,
      newStateRoot: newStateRootHex,
      marginalGain,
      workUnitsBps,
      creditUnits: workUnitsBps,
      advanceIndex: advances.length,
    });
  }

  const acceptedForRoot: AcceptedPatch[] = advances.map((advance) => ({
    patch: advance.patch,
    patchBytes: advance.patchBytes,
    marginalGain: advance.marginalGain,
    acceptanceIndex: advance.advanceIndex,
  }));
  const patchSetRoot = computePatchSetRoot(acceptedForRoot);
  const newStateRoot = currentMerkle.root;

  return {
    newState: current,
    patchSetRoot,
    patchSetRootHex: bytesToHex(patchSetRoot),
    newStateRoot,
    newStateRootHex: bytesToHex(newStateRoot),
    advances,
    rejected,
  };
}

function toBigInt(value: string | bigint | number): bigint {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new RangeError('reward counter must be a non-negative safe integer');
    return BigInt(value);
  }
  if (!/^(0|[1-9][0-9]*)$/.test(value)) throw new RangeError('reward counter must be a non-negative decimal string');
  return BigInt(value);
}

export function makeLiveEpochInput(
  miner: string,
  patch: Patch,
  patchBytes?: Uint8Array,
  marginalEvaluator: MarginalEvaluator = stubMarginalEvaluator,
): LiveEpochInputPatch {
  const bytes = patchBytes ?? encodePatch(patch);
  return {
    miner: miner.toLowerCase(),
    patch,
    patchBytes: bytes,
    scoreDelta: patch.scoreDelta,
    marginalEvaluator,
  };
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
