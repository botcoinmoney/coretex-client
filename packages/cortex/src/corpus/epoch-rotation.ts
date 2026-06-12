import { createHash, createSign, createVerify } from 'node:crypto';

import type { CorpusDelta } from './delta.js';
import { corpusDeltaSha256 } from './delta.js';
import { canonicalJson } from '../canonical/json.js';

export interface EpochRotationManifestSigner {
  readonly keyId: string;
  readonly algorithm: 'RSA-SHA256' | 'ECDSA-SHA256';
  readonly signature: string;
}

export interface EpochRotationManifest {
  readonly schemaVersion: 'coretex.epoch-rotation.v1';
  readonly epoch: number;
  readonly generatedAt: string;
  readonly previousCorpusRoot: string;
  readonly nextCorpusRoot: string;
  readonly corpusDeltaHash: string;
  readonly challengeBookHash: string;
  readonly bundleHash: string;
  readonly minImprovementPpm: number;
  readonly stateAdvanceThresholdPpm?: number;
  readonly baselineParentScorePpm?: number;
  readonly baselineVariancePpm?: number;
  readonly baselineVarianceSource?: 'rotating_pack' | 'broad_sampling' | 'unavailable';
  readonly fixedPackRepeatabilityPpm?: number;
  readonly screenerThresholdPpm?: number;
  readonly recentNoiseFloorPpm?: number;
  readonly controller?: {
    readonly inputs: Record<string, unknown>;
    readonly output: Record<string, unknown>;
    readonly reason: string;
  };
  readonly activeFrontierRoot?: string;
  readonly hiddenSeedCommit?: string;
  readonly advancesObserved: number;
  readonly qualityAttemptsObserved: number;
  readonly signer?: EpochRotationManifestSigner;
}

export interface BuildEpochRotationManifestOptions {
  readonly epoch: number;
  readonly delta: CorpusDelta;
  readonly challengeBook: unknown;
  readonly bundleHash: string;
  readonly minImprovementPpm: number;
  readonly stateAdvanceThresholdPpm?: number;
  readonly baselineParentScorePpm?: number;
  readonly baselineVariancePpm?: number;
  readonly baselineVarianceSource?: 'rotating_pack' | 'broad_sampling' | 'unavailable';
  readonly fixedPackRepeatabilityPpm?: number;
  readonly screenerThresholdPpm?: number;
  readonly recentNoiseFloorPpm?: number;
  readonly controller?: {
    readonly inputs: Record<string, unknown>;
    readonly output: Record<string, unknown>;
    readonly reason: string;
  };
  readonly activeFrontierRoot?: string;
  readonly hiddenSeedCommit?: string;
  readonly advancesObserved: number;
  readonly qualityAttemptsObserved: number;
  readonly generatedAt?: string;
}

export function buildEpochRotationManifest(opts: BuildEpochRotationManifestOptions): EpochRotationManifest {
  return {
    schemaVersion: 'coretex.epoch-rotation.v1',
    epoch: opts.epoch,
    generatedAt: opts.generatedAt ?? new Date().toISOString(),
    previousCorpusRoot: opts.delta.previousRoot,
    nextCorpusRoot: opts.delta.nextRoot,
    corpusDeltaHash: hashCorpusDelta(opts.delta),
    challengeBookHash: hashJson(opts.challengeBook),
    bundleHash: opts.bundleHash.toLowerCase(),
    minImprovementPpm: opts.minImprovementPpm,
    ...(opts.stateAdvanceThresholdPpm !== undefined ? { stateAdvanceThresholdPpm: opts.stateAdvanceThresholdPpm } : {}),
    ...(opts.baselineParentScorePpm !== undefined ? { baselineParentScorePpm: opts.baselineParentScorePpm } : {}),
    ...(opts.baselineVariancePpm !== undefined ? { baselineVariancePpm: opts.baselineVariancePpm } : {}),
    ...(opts.baselineVarianceSource !== undefined ? { baselineVarianceSource: opts.baselineVarianceSource } : {}),
    ...(opts.fixedPackRepeatabilityPpm !== undefined ? { fixedPackRepeatabilityPpm: opts.fixedPackRepeatabilityPpm } : {}),
    ...(opts.screenerThresholdPpm !== undefined ? { screenerThresholdPpm: opts.screenerThresholdPpm } : {}),
    ...(opts.recentNoiseFloorPpm !== undefined ? { recentNoiseFloorPpm: opts.recentNoiseFloorPpm } : {}),
    ...(opts.controller !== undefined ? { controller: opts.controller } : {}),
    ...(opts.activeFrontierRoot !== undefined ? { activeFrontierRoot: opts.activeFrontierRoot.toLowerCase() } : {}),
    ...(opts.hiddenSeedCommit !== undefined ? { hiddenSeedCommit: opts.hiddenSeedCommit.toLowerCase() } : {}),
    advancesObserved: opts.advancesObserved,
    qualityAttemptsObserved: opts.qualityAttemptsObserved,
  };
}

export function signEpochRotationManifest(
  manifest: EpochRotationManifest,
  privateKeyPem: string,
  keyId: string,
  algorithm: EpochRotationManifestSigner['algorithm'] = 'RSA-SHA256',
): EpochRotationManifest {
  const unsigned = withoutSigner(manifest);
  const signer = createSign(algorithm === 'RSA-SHA256' ? 'RSA-SHA256' : 'SHA256');
  signer.update(canonicalJson(unsigned));
  signer.end();
  return {
    ...unsigned,
    signer: {
      keyId,
      algorithm,
      signature: `0x${signer.sign(privateKeyPem).toString('hex')}`,
    },
  };
}

export function verifyEpochRotationManifestSignature(
  manifest: EpochRotationManifest,
  publicKeyPem: string,
): boolean {
  if (!manifest || typeof manifest !== 'object') return false;
  const signer = (manifest as { signer?: Partial<EpochRotationManifestSigner> }).signer;
  if (!signer || typeof signer !== 'object') return false;
  if (signer.algorithm !== 'RSA-SHA256' && signer.algorithm !== 'ECDSA-SHA256') return false;
  if (typeof signer.signature !== 'string' || !/^0x[0-9a-fA-F]+$/.test(signer.signature) || signer.signature.length % 2 !== 0) {
    return false;
  }
  try {
    const verifier = createVerify(signer.algorithm === 'RSA-SHA256' ? 'RSA-SHA256' : 'SHA256');
    verifier.update(canonicalJson(withoutSigner(manifest)));
    verifier.end();
    return verifier.verify(publicKeyPem, Buffer.from(signer.signature.replace(/^0x/i, ''), 'hex'));
  } catch {
    return false;
  }
}

// ── Frontier-state pruning (hidden-row retirement support) ────────────────────

/**
 * Structural mirror of the coordinator EpochFrontierRuntimeState
 * (`coretex.epoch-frontier-state.v1`) — kept structural so corpus rotation code
 * does not depend on the coordinator module.
 */
export interface EpochFrontierStateLike {
  readonly schemaVersion: string;
  readonly order: readonly string[];
  readonly reservePtr: number;
  readonly active: readonly (readonly [string, number])[];
  readonly retired: readonly string[];
  readonly cumulativeActivated: number;
  readonly cumulativeRetired: number;
  readonly initialized: boolean;
  readonly injectedSinceLastStep: number;
  readonly ewmaAccepts: number | null;
}

export interface PrunedEpochFrontierState<T extends EpochFrontierStateLike> {
  readonly state: T;
  /** Ids dropped from the order/reserve (no longer present in the corpus). */
  readonly prunedOrderIds: readonly string[];
  /** Ids dropped from the ACTIVE set — each is a forced activeFrontierRoot change. */
  readonly prunedActiveIds: readonly string[];
  readonly prunedRetiredIds: readonly string[];
}

/**
 * Drop ids that are no longer present in the corpus (e.g. hidden rows retired via
 * CorpusDelta.removedIds) from a persisted epoch-frontier runtime state, preserving
 * `reservePtr` semantics (decremented for every pruned id ahead of the pointer) and the
 * cumulative counters. `makeEpochFrontier` hard-rejects initialState ids that are not in
 * `evalHiddenIds`, so the rotation pipeline MUST prune before re-hydrating the frontier.
 */
export function pruneEpochFrontierState<T extends EpochFrontierStateLike>(
  state: T,
  isKnownId: (id: string) => boolean,
): PrunedEpochFrontierState<T> {
  if (state.schemaVersion !== 'coretex.epoch-frontier-state.v1') {
    throw new Error(`pruneEpochFrontierState: unsupported schema ${state.schemaVersion}`);
  }
  const prunedOrderIds: string[] = [];
  const order: string[] = [];
  let reservePtr = state.reservePtr;
  state.order.forEach((id, idx) => {
    if (isKnownId(id)) { order.push(id); return; }
    prunedOrderIds.push(id);
    if (idx < state.reservePtr) reservePtr -= 1;
  });
  const prunedActiveIds = state.active.filter(([id]) => !isKnownId(id)).map(([id]) => id);
  const active = state.active.filter(([id]) => isKnownId(id));
  const prunedRetiredIds = state.retired.filter((id) => !isKnownId(id));
  const retired = state.retired.filter((id) => isKnownId(id));
  return {
    state: { ...state, order, reservePtr, active, retired },
    prunedOrderIds,
    prunedActiveIds,
    prunedRetiredIds,
  };
}

export function hashCorpusDelta(delta: CorpusDelta): string {
  // Delta can carry binary embedding bytes; defer to delta.ts canonical-JSON
  // which knows how to hex-encode Uint8Array fields.
  return `0x${corpusDeltaSha256(delta)}`;
}

export function hashJson(value: unknown): string {
  return `0x${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

function withoutSigner(manifest: EpochRotationManifest): Omit<EpochRotationManifest, 'signer'> {
  const { signer: _signer, ...unsigned } = manifest;
  return unsigned;
}
