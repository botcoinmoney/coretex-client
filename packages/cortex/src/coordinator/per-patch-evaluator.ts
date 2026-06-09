/**
 * Per-patch evaluation orchestrator.
 *
 * Composes the per-patch on-chain randomness primitives into a single
 * `runPerPatchEvaluation(request, deps)` function that:
 *
 *   1. Computes patchHash + dedupKey.
 *   2. Short-circuits on dedup-cache hit (anti-probing-via-resubmission).
 *   3. Runs the live-eval admission gate (structural / dedup / per-miner-cap).
 *   4. Fetches `receivedAtBlock` from the Base RPC.
 *   5. Computes `targetBlock = receivedAtBlock + targetBlockOffset`,
 *      waits for it to land, fetches `blockhash`.
 *   6. Derives the two domain-separated eval seeds (gate + confirm).
 *   7. Calls the injected scorer for each pack.
 *   8. A patch is accepted iff BOTH packs clear `thresholdPpm` — dual-
 *      pack confirmation that drops false-acceptance to p². See plan
 *      §"Dual-Pack Confirmation".
 *   9. Returns a receipt carrying every seed input + both scores so any
 *      replay watcher can byte-reproduce the decision from public chain
 *      data after the post-epoch `epochSecret` reveal.
 *
 * What does NOT live here:
 *   - HTTP request decoding (host route wires `evaluate(body)` to this).
 *   - Persistence (host stores receipts, dedup cache, miner counts).
 *   - Model loading (scorer is injectable — production wires
 *     `evaluateRetrievalBenchmarkPatch`; tests pass a deterministic fake).
 *
 * Pure orchestration. Same input + same deps → byte-identical receipt.
 */
import {
  deriveGateEvalSeed,
  deriveConfirmEvalSeed,
  computePatchHash,
  computeDedupKey,
} from '../eval/seed-derivation.js';
import { keccak256 } from '../state/keccak256.js';
import { bytesToHex } from '../state/merkle.js';
import { liveEvalAdmissionDecision, type LiveEvalAdmissionRejectReason } from '../eval/live-eval-admission.js';
import type { BaseRpcClient } from './base-blockhash.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface PerPatchRequest {
  readonly normalizedPatchBytes: Uint8Array;
  readonly parentRoot: string;          // bytes32 hex
  readonly minerAddress: string;        // bytes20 hex (caller normalises case)
  readonly epochId: number;             // current epoch
  /** Caller-asserted structural validity. Host runs full structural
   *  decode + signature check first; this is the result. */
  readonly structurallyValid: boolean;
}

/**
 * Injected scorer signature. Caller binds `corpus`, `bundleHash`,
 * `scoringOpts`, and any per-host model state in closure; the
 * orchestrator only feeds the per-patch parameters that vary.
 *
 * Production wires `evaluateRetrievalBenchmarkPatch` and returns the FLOORS-AWARE verdict
 * `{ scorePpm: result.deltaPpm, accepted: result.accepted, rejectionReason: result.reason }` —
 * NOT just the scalar. `runPerPatchEvaluation` gates each pack on `accepted` (which encodes the
 * structural / protected-regression / family-catastrophic floors + acceptance threshold from
 * `evaluatePatchAcceptance`) AND the dual-pack `thresholdPpm`, so a high-scoring patch that
 * breaks structure or catastrophically regresses a family CANNOT be accepted. Tests pass a
 * deterministic fake returning the same object shape.
 */
export interface PerPatchScoreResult {
  readonly scorePpm: number;
  /** Floors-aware acceptance from the canonical scorer (structural/protected/family + threshold). */
  readonly accepted: boolean;
  readonly rejectionReason?: string;
}
export type PerPatchScorer = (args: {
  readonly normalizedPatchBytes: Uint8Array;
  readonly parentRoot: string;
  readonly evalSeed: string;          // bytes32 hex
  readonly which: 'gate' | 'confirm'; // tag so the scorer can log / inspect
}) => Promise<PerPatchScoreResult>;

export interface PerPatchEvaluatorDeps {
  readonly rpcClient: BaseRpcClient;
  readonly scorer: PerPatchScorer;
  /** Bundle profile pin: where the targetBlockOffset comes from. */
  readonly targetBlockOffset: number;
  /** Bundle profile pin: minimum delta the patch must clear on BOTH packs. */
  readonly thresholdPpm: number;
  /** Live-eval admission cap per miner per epoch. Host owns the value. */
  readonly perMinerCap: number;
  /** Inputs the seed derivation needs that are constant across an epoch. */
  readonly epochSecret: string;       // bytes32 hex
  readonly corpusRoot: string;        // bytes32 hex
  readonly bundleHash: string;        // bytes32 hex
  /** Dedup cache the host maintains across receipts in this epoch.
   *  Key = dedupKey, value = previous receipt. Pass the same Map each
   *  call. The orchestrator does NOT mutate it; the host inserts on
   *  successful eval. */
  readonly dedupCache: ReadonlyMap<string, PerPatchReceipt>;
  /** Per-miner admission counter. Same contract as dedupCache. */
  readonly minerAdmissions: ReadonlyMap<string, number>;
  /** Max wait for the future blockhash. Defaults to 120 s (2× the
   *  60 s budget at targetBlockOffset=30) — generous enough that
   *  Base must be genuinely stalled for this to fire. */
  readonly waitTimeoutMs?: number;
}

export interface PerPatchReceipt {
  readonly patchHash: string;
  readonly dedupKey: string;
  readonly parentRoot: string;
  readonly minerAddress: string;
  readonly epochId: number;
  // Anti-pre-testing witness — everything a watcher needs to
  // reproduce the seeds without coordinator-private state.
  readonly receivedAtBlock: number;
  readonly targetBlock: number;
  readonly blockhash: string;
  readonly gateSeed: string;
  readonly confirmSeed: string;
  // Dual-pack outcome.
  readonly gateScorePpm: number;
  readonly confirmScorePpm: number;
  readonly accepted: boolean;
  /** Populated on rejection — never on acceptance. */
  readonly rejectionReason?:
    | 'cached'                          // dedup-cache hit (caller short-circuits before this is reached)
    | 'structurally-invalid'
    | 'duplicate-key-collapsed'
    | 'per-miner-cap-reached'
    | 'gate-below-threshold'
    | 'confirm-below-threshold'
    | 'gate-acceptance-floor'            // gate pack failed structural/protected/family acceptance floors
    | 'confirm-acceptance-floor'         // confirm pack failed structural/protected/family acceptance floors
    | 'admit-malformed-input';
}

export interface PerPatchDualPackEvaluationProof {
  readonly kind: 'coretex-dual-pack-v1';
  readonly mode: 'future_blockhash_dual_pack';
  readonly epochId: number;
  readonly receivedAtBlock: number;
  readonly targetBlock: number;
  readonly targetBlockOffset: number;
  readonly blockhash: string;
  readonly patchHash: string;
  readonly parentStateRoot: string;
  readonly corpusRoot: string;
  readonly coreVersionHash: string;
  readonly hiddenSeedCommit: string;
  readonly epochSecretCommit: string;
  readonly gate: {
    readonly domain: 'gate';
    readonly seedCommit: string;
    readonly accepted: boolean;
    readonly scorePpm: number;
  };
  readonly confirm: {
    readonly domain: 'confirm';
    readonly seedCommit: string;
    readonly accepted: boolean;
    readonly scorePpm: number;
  };
}

export function dualPackProofFromPerPatchReceipt(
  receipt: PerPatchReceipt,
  context: {
    readonly corpusRoot: string;
    readonly coreVersionHash: string;
    readonly hiddenSeedCommit: string;
    readonly targetBlockOffset: number;
  },
): PerPatchDualPackEvaluationProof {
  if (!receipt.accepted) {
    throw new Error('dualPackProofFromPerPatchReceipt: receipt was not accepted');
  }
  return {
    kind: 'coretex-dual-pack-v1',
    mode: 'future_blockhash_dual_pack',
    epochId: receipt.epochId,
    receivedAtBlock: receipt.receivedAtBlock,
    targetBlock: receipt.targetBlock,
    targetBlockOffset: context.targetBlockOffset,
    blockhash: receipt.blockhash.toLowerCase(),
    patchHash: receipt.patchHash.toLowerCase(),
    parentStateRoot: receipt.parentRoot.toLowerCase(),
    corpusRoot: context.corpusRoot.toLowerCase(),
    coreVersionHash: context.coreVersionHash.toLowerCase(),
    hiddenSeedCommit: context.hiddenSeedCommit.toLowerCase(),
    epochSecretCommit: context.hiddenSeedCommit.toLowerCase(),
    gate: {
      domain: 'gate',
      seedCommit: seedCommit(receipt.gateSeed),
      accepted: true,
      scorePpm: receipt.gateScorePpm,
    },
    confirm: {
      domain: 'confirm',
      seedCommit: seedCommit(receipt.confirmSeed),
      accepted: true,
      scorePpm: receipt.confirmScorePpm,
    },
  };
}

// ─── Orchestrator ─────────────────────────────────────────────────────────────

export async function runPerPatchEvaluation(
  request: PerPatchRequest,
  deps: PerPatchEvaluatorDeps,
): Promise<PerPatchReceipt> {
  // 1 & 2: hashes + dedup cache.
  const patchHash = computePatchHash(request.normalizedPatchBytes);
  const dedupKey = computeDedupKey(request.parentRoot, request.normalizedPatchBytes);
  const cached = deps.dedupCache.get(dedupKey);
  if (cached) {
    // Return the cached receipt with a 'cached' tag instead of running
    // the costly eval. Anti-probing-via-resubmission: a miner cannot
    // re-roll a packbond by submitting the same patch twice.
    return {
      patchHash: cached.patchHash,
      dedupKey: cached.dedupKey,
      parentRoot: cached.parentRoot,
      minerAddress: cached.minerAddress,
      epochId: cached.epochId,
      receivedAtBlock: cached.receivedAtBlock,
      targetBlock: cached.targetBlock,
      blockhash: cached.blockhash,
      gateSeed: cached.gateSeed,
      confirmSeed: cached.confirmSeed,
      gateScorePpm: cached.gateScorePpm,
      confirmScorePpm: cached.confirmScorePpm,
      accepted: cached.accepted,
      rejectionReason: 'cached',
    };
  }

  // 3: admission gate.
  const minerAddress = request.minerAddress.toLowerCase();
  const dedupedKeysThisEpoch = new Set(deps.dedupCache.keys());
  const admission = liveEvalAdmissionDecision({
    minerAddress,
    patchHash,
    dedupKey,
    dedupedKeysThisEpoch,
    minerAdmissionsThisEpoch: deps.minerAdmissions.get(minerAddress) ?? 0,
    perMinerCap: deps.perMinerCap,
    structurallyValid: request.structurallyValid,
  });
  if (!admission.admit) {
    // Build a receipt that documents the rejection but doesn't carry
    // seed/blockhash material since we never derived them.
    return {
      patchHash,
      dedupKey,
      parentRoot: request.parentRoot,
      minerAddress,
      epochId: request.epochId,
      receivedAtBlock: 0,
      targetBlock: 0,
      blockhash: '0x' + '00'.repeat(32),
      gateSeed: '0x' + '00'.repeat(32),
      confirmSeed: '0x' + '00'.repeat(32),
      gateScorePpm: 0,
      confirmScorePpm: 0,
      accepted: false,
      rejectionReason: mapAdmissionReason(admission.reason),
    };
  }

  // 4 & 5: blockhash binding. This is the anti-pre-testing chokepoint —
  // the blockhash literally doesn't exist when the patch arrived, so
  // neither the coordinator nor the miner could have computed the
  // seeds in advance.
  const receivedAtBlock = await deps.rpcClient.getLatestBlockNumber();
  const targetBlock = receivedAtBlock + deps.targetBlockOffset;
  const { blockhash } = await deps.rpcClient.waitForBlock(
    targetBlock,
    deps.waitTimeoutMs ?? 120_000,
  );

  // 6: derive both seeds from the same blockhash via different domain
  // prefixes. Same anti-pre-testing property holds for both. Miner
  // identity is NOT part of the seed — first-submitter wins on the
  // shared (parentRoot, patchBytes) dedup cache, so including
  // minerAddress in the seed would create ambiguity without
  // preventing sybil rerolls.
  const seedInput = {
    epochSecret: deps.epochSecret,
    blockhash,
    epochId: request.epochId,
    patchHash,
    parentRoot: request.parentRoot,
    corpusRoot: deps.corpusRoot,
    bundleHash: deps.bundleHash,
  };
  const gateSeed = deriveGateEvalSeed(seedInput);
  const confirmSeed = deriveConfirmEvalSeed(seedInput);

  // 7 & 8: dual-pack scoring + acceptance. Run sequentially so we can
  // short-circuit on a gate-fail before paying the confirm-pack CPU
  // cost.
  const gate = await deps.scorer({
    normalizedPatchBytes: request.normalizedPatchBytes,
    parentRoot: request.parentRoot,
    evalSeed: gateSeed,
    which: 'gate',
  });
  const gateScorePpm = gate.scorePpm;
  // A pack passes ONLY if it clears the dual-pack threshold AND the canonical acceptance floors
  // (structural/protected/family). `accepted` is the authority — never bypass it with score alone.
  const gatePass = gateScorePpm >= deps.thresholdPpm && gate.accepted;
  if (!gatePass) {
    return {
      patchHash, dedupKey,
      parentRoot: request.parentRoot, minerAddress,
      epochId: request.epochId,
      receivedAtBlock, targetBlock, blockhash,
      gateSeed, confirmSeed,
      gateScorePpm, confirmScorePpm: 0,
      accepted: false,
      rejectionReason: !gate.accepted ? 'gate-acceptance-floor' : 'gate-below-threshold',
    };
  }

  const confirm = await deps.scorer({
    normalizedPatchBytes: request.normalizedPatchBytes,
    parentRoot: request.parentRoot,
    evalSeed: confirmSeed,
    which: 'confirm',
  });
  const confirmScorePpm = confirm.scorePpm;
  const confirmPass = confirmScorePpm >= deps.thresholdPpm && confirm.accepted;
  const confirmReason: 'confirm-acceptance-floor' | 'confirm-below-threshold' =
    !confirm.accepted ? 'confirm-acceptance-floor' : 'confirm-below-threshold';

  return {
    patchHash, dedupKey,
    parentRoot: request.parentRoot, minerAddress,
    epochId: request.epochId,
    receivedAtBlock, targetBlock, blockhash,
    gateSeed, confirmSeed,
    gateScorePpm, confirmScorePpm,
    accepted: confirmPass,
    ...(!confirmPass ? { rejectionReason: confirmReason } : {}),
  };
}

function mapAdmissionReason(
  reason: LiveEvalAdmissionRejectReason,
): Exclude<PerPatchReceipt['rejectionReason'], undefined> {
  switch (reason) {
    case 'structurally-invalid': return 'structurally-invalid';
    case 'duplicate-key-collapsed': return 'duplicate-key-collapsed';
    case 'per-miner-cap-reached': return 'per-miner-cap-reached';
    case 'malformed-input':
    default:
      return 'admit-malformed-input';
  }
}

function seedCommit(seed: string): string {
  return bytesToHex(keccak256(hexToBytes(seed))).toLowerCase();
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error('hexToBytes: malformed hex');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}
