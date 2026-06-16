/**
 * Baseline re-evaluation for major-corpus-delta grace.
 *
 * Replaces the auditor's proposed `evaluateBaselines` (4 baselines + variance)
 * with a single, simpler signal: the parent substrate's score on the new
 * query pack, sampled N times to expose any reranker-side noise. The
 * three other baselines the auditor named (empty / frequency / visible-split)
 * are diagnostic and useful for transparency reporting, but the only
 * value the difficulty calculator and acceptance rule actually needs is
 *   `parentScorePpm` (the comparison point)
 *   `variancePpm`   (so acceptance is normalized against reranker noise)
 *
 * This module deliberately exports only the type + a thin orchestrator
 * that delegates to the same `evaluateRetrievalBenchmarkState` the
 * production scorer uses. No new scoring path, no new model, no new
 * runtime dependency. Callers run this on the calibration host /
 * epoch-rotation tooling, NOT on the live coordinator hot path.
 *
 * The baseline result is published in the signed epoch rotation
 * manifest. Any independent verifier reproduces it from the bundle +
 * corpus root + eval seed + pinned models.
 *
   * Spec: epoch rotation manifests define the current baseline-reset /
   * rate-matching lane; verifier reproducibility is pinned by bundle, corpus
   * root, eval seed, and model hashes.
   */

import type { CortexState } from '../state/types.js';
import type { CompositeScore, ScoringOptions } from '../eval/retrieval-benchmark.js';
import { evaluateRetrievalBenchmarkState } from '../eval/retrieval-benchmark.js';
import type { ProductionCorpus } from '../eval/retrieval-corpus.js';
import type { QueryPack } from '../eval/hidden-query-pack.js';

export interface BaselineScores {
  /**
   * The parent substrate's composite score on this query pack, in ppm
   * (composite × 1_000_000 rounded to integer). This is the comparison
   * point for the next epoch's acceptance rule: a patch is accepted
   * iff its delta score exceeds `minImprovementPpm + variancePpm + replayTolerancePpm`.
   */
  readonly parentScorePpm: number;
  /**
   * Standard deviation of the parent score across `samples` runs, in
   * ppm. Reranker forward passes are deterministic given the same
   * pinned models + inputs, so on a single calibrated host this is
   * usually exactly 0. On heterogeneous hardware or under runtime
   * upgrades it captures real reranker-side noise so acceptance
   * doesn't oscillate on the boundary.
   */
  readonly variancePpm: number;
  /** Number of times the parent score was sampled. */
  readonly samples: number;
  /** corpusRoot the baseline was computed against. */
  readonly corpusRoot: string;
  /** epochId the query pack was derived for. */
  readonly epochId: number;
  /** The exact CompositeScore object from the first sample (full breakdown). */
  readonly compositeScore: CompositeScore;
}

export interface EvaluateBaselineOptions {
  /**
   * Number of times to re-evaluate the parent score. Default 1 (the
   * pinned reranker is byte-deterministic on a single host, so one
   * sample is enough; calibration on heterogeneous hardware should
   * pass `samples ≥ 3`).
   */
  readonly samples?: number;
}

/**
 * Compute the baseline score of `parentSubstrate` on `pack`, sampled
 * `samples` times. Variance is the population std-dev across samples,
 * scaled to ppm.
 *
 * Pure orchestrator: delegates to `evaluateRetrievalBenchmarkState`
 * (the production scorer) — no new scoring logic. Intended to be
 * invoked from the calibration host or from the per-epoch rotation
 * tooling, never from the live coordinator hot path.
 */
export async function evaluateBaseline(
  parentSubstrate: CortexState,
  corpus: ProductionCorpus,
  pack: QueryPack,
  scoringOpts: ScoringOptions,
  opts: EvaluateBaselineOptions = {},
): Promise<BaselineScores> {
  const samples = Math.max(1, Math.floor(opts.samples ?? 1));
  const compositeScores: CompositeScore[] = [];
  const ppmSamples: number[] = [];
  for (let i = 0; i < samples; i++) {
    const cs = await evaluateRetrievalBenchmarkState(parentSubstrate, corpus, pack, scoringOpts);
    compositeScores.push(cs);
    ppmSamples.push(Math.round(cs.composite * 1_000_000));
  }
  const mean = ppmSamples.reduce((s, v) => s + v, 0) / samples;
  const variance = samples > 1
    ? Math.sqrt(ppmSamples.reduce((s, v) => s + (v - mean) ** 2, 0) / samples)
    : 0;
  return {
    parentScorePpm: Math.round(mean),
    variancePpm: Math.round(variance),
    samples,
    corpusRoot: pack.corpusRoot,
    epochId: pack.epochId,
    compositeScore: compositeScores[0]!,
  };
}

/**
 * Determine whether the just-applied corpus delta crossed the
 * majorDeltaThreshold pinned in the bundle. The threshold is the new
 * `eval_hidden` event count delta over which the next epoch enters
 * grace (see `nextMinImprovementPpm`'s `majorDeltaActive` input).
 *
 * Pure function — no I/O, no model calls. Intended to be called by
 * the calibrator and by per-epoch rotation tooling.
 */
export function isMajorDelta(
  newEvalHiddenCount: number,
  prevEvalHiddenCount: number,
  majorDeltaThreshold: number,
): boolean {
  return newEvalHiddenCount - prevEvalHiddenCount >= majorDeltaThreshold;
}
