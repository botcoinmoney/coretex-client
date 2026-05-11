/**
 * Sealed-eval orchestration — Phase S3 / S4 of
 * `docs/CORETEX_SEALED_EPOCH_EVAL_HARDENING_PLAN.md`.
 *
 * Pure orchestration over admitted reveals: gate → confirm → batch
 * settlement. The scorer is INJECTED so the orchestration logic can
 * be unit-tested with a deterministic fake; production wires
 * `evaluateRetrievalBenchmarkPatch` into the same shape after the
 * launch corpus completes.
 *
 * What lives here:
 *   - SealedScorer function type
 *   - AdmittedReveal + GateOutcome + ConfirmOutcome types
 *   - runGateEvaluation: scores all admitted reveals on the gate pack
 *   - runConfirmEvaluation: scores finalists on the confirm pack
 *   - selectBatchWinners: deterministic finalist sort + greedy
 *     marginal-gain selection over the epoch parent (S4)
 *
 * What does NOT live here:
 *   - Model loading or model inference (the injected scorer is
 *     production-only — tests pass a deterministic fake)
 *   - Persistence (the host stores admitted reveals + outcomes)
 *   - On-chain anchoring (commitmentRoot is anchored by the
 *     coordinator before seed reveal; settlement winners produce
 *     work receipts on the existing V4 submitWorkReceipt path)
 *   - The per-query report publication delay — that's a host policy
 *     enforced at /coretex/eval-report/:hash read time
 */
import type { CortexState, Patch } from '../state/types.js';

// ─── Types ────────────────────────────────────────────────────────────────────

/**
 * A revealed-and-admitted commitment that may earn finalist status.
 * The orchestrator consumes these in deterministic order; ordering is
 * established by `sortAdmittedReveals` so replay reproduces the same
 * gate/confirm/settlement decisions byte-for-byte.
 */
export interface AdmittedReveal {
  /** commitmentHash from the commit ledger (bytes32 hex). */
  readonly commitmentHash: string;
  /** Miner who submitted the commitment (bytes20 hex, lowercased). */
  readonly minerAddress: string;
  /** Decoded patch the reveal opened. */
  readonly patch: Patch;
  /** Raw compact-patch wire bytes (kept for signed-receipt construction). */
  readonly patchBytes: Uint8Array;
}

/**
 * Per-admitted-reveal gate outcome. Score deltas are uint32 ppm:
 *   deltaPpm = score(candidateSubstrate, gatePack)
 *             - score(parentSubstrate,    gatePack)
 */
export interface GateOutcome {
  readonly commitmentHash: string;
  readonly minerAddress: string;
  /** Composite score delta in ppm, positive iff the patch improves retrieval. */
  readonly gateDeltaPpm: number;
  /** True iff `gateDeltaPpm >= minImprovementPpm + replayTolerancePpm + baselineVariancePpm`. */
  readonly isFinalist: boolean;
}

/**
 * Per-finalist confirm outcome. Independent draw of the confirm pack
 * filters out gate-pack-luck advances.
 */
export interface ConfirmOutcome {
  readonly commitmentHash: string;
  readonly minerAddress: string;
  readonly confirmDeltaPpm: number;
  /** True iff confirm pack also clears threshold. */
  readonly clearsConfirm: boolean;
}

/**
 * Injected scorer signature. Production wires
 * `evaluateRetrievalBenchmarkPatch` (which loads pinned BGE-M3 +
 * Qwen3 reranker and returns the full PatchEvalResult); the
 * orchestrator only needs the score delta in ppm, so the wire here
 * is intentionally narrower than the full PatchEvalResult — the
 * caller projects out `deltaPpm` from `result.deltaPpm`.
 *
 * Pure function from the orchestrator's perspective: same parent +
 * patch + pack must always produce the same deltaPpm (the
 * reranker is byte-deterministic per the bundle's replayTolerancePpm
 * pin). Real-world variance across hosts is bounded by
 * `replayTolerancePpm`.
 */
export type SealedScorer = (
  parentSubstrate: CortexState,
  patch: Patch,
  packSeedHex: string,
) => Promise<number>;

export interface BatchSettlementInput {
  readonly epochParentSubstrate: CortexState;
  readonly finalists: readonly ConfirmOutcome[];
  readonly admittedReveals: readonly AdmittedReveal[];
  /** Maximum number of accepted state advances per epoch. */
  readonly maxAdvancesPerEpoch: number;
  /** Threshold the confirm pack must clear, in ppm. */
  readonly thresholdPpm: number;
  /**
   * Marginal-gain re-evaluator. Given the current substrate (after
   * previously-accepted patches) and a candidate, returns the
   * marginal deltaPpm. In production this is the same scorer wired
   * for gate/confirm but against the live substrate's evolving root.
   */
  readonly marginalScorer: (current: CortexState, patch: Patch) => Promise<number>;
  /**
   * Apply a patch to a substrate; same shape as `applyPatch` in
   * state/patch.ts. Injected so the orchestrator stays free of
   * substrate-codec imports.
   */
  readonly applyPatch: (state: CortexState, patch: Patch) => CortexState;
}

export interface BatchWinner {
  readonly commitmentHash: string;
  readonly minerAddress: string;
  readonly patch: Patch;
  readonly patchBytes: Uint8Array;
  /** Substrate root AFTER this winner is applied (bytes32 hex). */
  readonly newStateRootCandidate: CortexState;
  /** Marginal deltaPpm at the moment of acceptance. */
  readonly marginalDeltaPpm: number;
}

export interface BatchSettlementResult {
  readonly winners: readonly BatchWinner[];
  /** Final substrate root after all winners applied (bytes32 hex). */
  readonly finalStateRoot: CortexState;
  /** Commitments that conflicted with already-selected patches. */
  readonly rejectedConflicts: readonly string[];
  /** Commitments that fell below threshold on marginal re-evaluation. */
  readonly rejectedBelowThreshold: readonly string[];
  /** Commitments dropped because the per-epoch winner cap was reached. */
  readonly rejectedCapReached: readonly string[];
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Deterministic ordering for finalist evaluation. Sorted by:
 *   1. confirmDeltaPpm descending (best first)
 *   2. patch size ascending (cheaper patches first when tied)
 *   3. commitmentHash ascending (stable tie-break)
 *
 * Replay reproduces this exact order on any host given the same
 * inputs, so the batch winners are deterministic.
 */
export function sortFinalists(
  finalists: readonly ConfirmOutcome[],
  patchSizeByHash: ReadonlyMap<string, number>,
): ConfirmOutcome[] {
  return [...finalists].sort((a, b) => {
    if (a.confirmDeltaPpm !== b.confirmDeltaPpm) return b.confirmDeltaPpm - a.confirmDeltaPpm;
    const sa = patchSizeByHash.get(a.commitmentHash) ?? 0;
    const sb = patchSizeByHash.get(b.commitmentHash) ?? 0;
    if (sa !== sb) return sa - sb;
    return a.commitmentHash < b.commitmentHash ? -1 : a.commitmentHash > b.commitmentHash ? 1 : 0;
  });
}

/**
 * Two patches conflict if they touch any common word index. The
 * batch reducer skips conflicting candidates so each settlement
 * round preserves replayable state advances.
 */
export function patchesConflict(a: Patch, b: Patch): boolean {
  const aIdx = new Set(a.indices);
  for (const idx of b.indices) {
    if (aIdx.has(idx)) return true;
  }
  return false;
}

// ─── Gate phase (S3) ──────────────────────────────────────────────────────────

export interface RunGateEvaluationInput {
  readonly admittedReveals: readonly AdmittedReveal[];
  readonly parentSubstrate: CortexState;
  /** gateSeed from deriveGateSeed(coretexEvalSeed), bytes32 hex. */
  readonly gateSeedHex: string;
  readonly thresholdPpm: number;
  readonly scorer: SealedScorer;
}

/**
 * Score every admitted reveal on the gate pack. Patches whose delta
 * meets or exceeds threshold become finalists; the rest are dropped
 * before the expensive confirm pass.
 *
 * Deterministic given an injected scorer that's deterministic
 * (production scorer is, modulo replayTolerancePpm).
 */
export async function runGateEvaluation(input: RunGateEvaluationInput): Promise<readonly GateOutcome[]> {
  const out: GateOutcome[] = [];
  for (const reveal of input.admittedReveals) {
    const deltaPpm = await input.scorer(input.parentSubstrate, reveal.patch, input.gateSeedHex);
    out.push({
      commitmentHash: reveal.commitmentHash,
      minerAddress: reveal.minerAddress,
      gateDeltaPpm: deltaPpm,
      isFinalist: deltaPpm >= input.thresholdPpm,
    });
  }
  return out;
}

// ─── Confirm phase (S3) ───────────────────────────────────────────────────────

export interface RunConfirmEvaluationInput {
  readonly finalists: readonly GateOutcome[];
  /**
   * Map from commitmentHash to the corresponding AdmittedReveal — the
   * confirm scorer needs the decoded patch.
   */
  readonly admittedRevealsByHash: ReadonlyMap<string, AdmittedReveal>;
  readonly parentSubstrate: CortexState;
  /** confirmSeed from deriveConfirmSeed(coretexEvalSeed), bytes32 hex. */
  readonly confirmSeedHex: string;
  readonly thresholdPpm: number;
  readonly scorer: SealedScorer;
}

/**
 * Score finalists on the confirm pack. Only candidates whose
 * deltaPpm clears threshold proceed to batch settlement.
 */
export async function runConfirmEvaluation(input: RunConfirmEvaluationInput): Promise<readonly ConfirmOutcome[]> {
  const out: ConfirmOutcome[] = [];
  for (const finalist of input.finalists) {
    if (!finalist.isFinalist) continue;
    const reveal = input.admittedRevealsByHash.get(finalist.commitmentHash);
    if (!reveal) {
      // Defensive: a finalist with no matching admitted reveal is a
      // host-side bookkeeping bug. Report a zero delta so the host
      // observes the gap and the audit log surfaces the inconsistency.
      out.push({
        commitmentHash: finalist.commitmentHash,
        minerAddress: finalist.minerAddress,
        confirmDeltaPpm: 0,
        clearsConfirm: false,
      });
      continue;
    }
    const deltaPpm = await input.scorer(input.parentSubstrate, reveal.patch, input.confirmSeedHex);
    out.push({
      commitmentHash: finalist.commitmentHash,
      minerAddress: finalist.minerAddress,
      confirmDeltaPpm: deltaPpm,
      clearsConfirm: deltaPpm >= input.thresholdPpm,
    });
  }
  return out;
}

// ─── Batch settlement (S4) ────────────────────────────────────────────────────

/**
 * Deterministic batch settlement. Sorts finalists, walks them in
 * order, skips conflicts and stale candidates whose marginal gain
 * dropped below threshold on the evolving substrate, accepts up to
 * `maxAdvancesPerEpoch`. Same input → same winners on any host.
 */
export async function selectBatchWinners(input: BatchSettlementInput): Promise<BatchSettlementResult> {
  const admittedByHash = new Map<string, AdmittedReveal>();
  for (const r of input.admittedReveals) admittedByHash.set(r.commitmentHash, r);

  const patchSizeByHash = new Map<string, number>();
  for (const r of input.admittedReveals) patchSizeByHash.set(r.commitmentHash, r.patchBytes.length);

  const sorted = sortFinalists(input.finalists, patchSizeByHash);

  let current = input.epochParentSubstrate;
  const winners: BatchWinner[] = [];
  const rejectedConflicts: string[] = [];
  const rejectedBelowThreshold: string[] = [];
  const rejectedCapReached: string[] = [];
  // Per-miner-per-epoch winner cap of 1 — keep the "miner already won
  // this epoch" rule from the hardening plan. Subsequent winners by
  // the same miner are skipped without a conflict reason.
  const winnersByMiner = new Set<string>();

  for (const finalist of sorted) {
    if (winners.length >= input.maxAdvancesPerEpoch) {
      rejectedCapReached.push(finalist.commitmentHash);
      continue;
    }
    if (winnersByMiner.has(finalist.minerAddress)) {
      // Plan §"Batch State Selection": "if miner already won this
      // epoch: continue". Same family as cap-reached at the per-miner
      // level. Track separately in the audit so the difference shows
      // up in reports.
      rejectedCapReached.push(finalist.commitmentHash);
      continue;
    }
    const reveal = admittedByHash.get(finalist.commitmentHash);
    if (!reveal) {
      rejectedBelowThreshold.push(finalist.commitmentHash);
      continue;
    }
    // Conflict check against already-selected patches.
    let conflicts = false;
    for (const w of winners) {
      if (patchesConflict(reveal.patch, w.patch)) { conflicts = true; break; }
    }
    if (conflicts) {
      rejectedConflicts.push(finalist.commitmentHash);
      continue;
    }
    // Marginal re-evaluation on the current substrate (which has
    // accumulated previously-accepted winners). Pack-luck advances
    // that were stale by the time their turn came get filtered here.
    const marginalDeltaPpm = await input.marginalScorer(current, reveal.patch);
    if (marginalDeltaPpm < input.thresholdPpm) {
      rejectedBelowThreshold.push(finalist.commitmentHash);
      continue;
    }
    current = input.applyPatch(current, reveal.patch);
    winners.push({
      commitmentHash: finalist.commitmentHash,
      minerAddress: finalist.minerAddress,
      patch: reveal.patch,
      patchBytes: reveal.patchBytes,
      newStateRootCandidate: current,
      marginalDeltaPpm,
    });
    winnersByMiner.add(finalist.minerAddress);
  }

  return {
    winners,
    finalStateRoot: current,
    rejectedConflicts,
    rejectedBelowThreshold,
    rejectedCapReached,
  };
}
