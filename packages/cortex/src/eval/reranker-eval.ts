/**
 * Reranker-based state and patch evaluator for CoreTex v4.
 *
 * This is a parallel scoring path to `experiments/harness/local-model-eval.mjs`.
 * The orchestrator can choose between the embedding-similarity path and this
 * cross-encoder reranker path.  The cross-encoder path is the production
 * reward-law evaluator (§8 plan).
 *
 * Family weights follow the bundle profile (§9): 20/20/20/20/10/10.
 */

import { createHash } from 'node:crypto';
import type { CortexState, Patch } from '../state/index.js';
import { applyPatch } from '../state/patch.js';
import type { CrossEncoderReranker } from './reranker.js';
import type { ProductionCorpus, ProductionCorpusEvent, ProductionCorpusFamily } from './corpus.js';
import { eventIdToKey128, eventIdToMem128 } from './corpus.js';

// ─── Constants ────────────────────────────────────────────────────────────────

const MEMORY_INDEX_START = 32;
const MEMORY_INDEX_SLOTS = 44;
const RETRIEVAL_KEYS_START = 384;
const RETRIEVAL_KEY_SLOTS = 36;
const RELATIONS_START = 672;
const RELATIONS_END = 799;

/**
 * Family weights matching the launch bundle 20/20/20/20/10/10 profile (§9).
 * Keys match the component names in RerankerEvalComponents.
 */
export const RERANKER_WEIGHTS = Object.freeze({
  nearCollisionRetrieval:    0.20,
  temporalCurrentStale:      0.20,
  longHorizonCompression:    0.20,
  relationMultiHop:          0.20,
  codebookCompression:       0.10,
  localModelAgreement:       0.10,
});

// ─── Types ────────────────────────────────────────────────────────────────────

export interface RerankerEvalComponents {
  readonly nearCollisionRetrieval: number;
  readonly temporalCurrentStale: number;
  readonly longHorizonCompression: number;
  readonly relationMultiHop: number;
  readonly codebookCompression: number;
  readonly localModelAgreement: number;
}

export interface RerankerEvalResult {
  readonly model: string;
  /** Composite score in [0, 1]. */
  readonly composite: number;
  readonly components: RerankerEvalComponents;
  readonly familyHitRates: Record<string, number>;
  readonly weights: typeof RERANKER_WEIGHTS;
}

export interface EvaluateStateWithRerankerOptions {
  readonly reranker: CrossEncoderReranker;
  /**
   * Maximum number of tasks to build per corpus family.
   * Default: 64 (same default as local-model-eval.mjs).
   */
  readonly maxTasksPerFamily?: number | undefined;
  /**
   * Number of top-ranked candidates to consider a query "hit".
   * Default: 1 (top-1 hit rate).
   */
  readonly topK?: number | undefined;
}

export interface EvaluatePatchWithRerankerOptions {
  /** Apply a patch to the parent state (default: built-in applyPatch). */
  applyPatch?: (state: CortexState, patch: Patch) => { ok: true; state: CortexState } | { ok: false; code: string };
  readonly corpus: ProductionCorpus;
  readonly reranker: CrossEncoderReranker;
  /**
   * Minimum score delta (composite units) required for `pass: true`.
   * Default: 0.0025 (≈ 2500 ppm).
   */
  readonly threshold?: number | undefined;
}

export interface PatchEvalResult {
  readonly pass: boolean;
  readonly scoreDelta: number;
  readonly before: RerankerEvalResult;
  readonly after: RerankerEvalResult;
  readonly noRegression: boolean;
  readonly regressions: string[];
  /** Present only when the patch is structurally invalid. */
  readonly errorCode?: string | undefined;
}

// ─── Substrate region reader ──────────────────────────────────────────────────

interface SubstrateMemoryView {
  readonly activeMemIds: Set<string>;
  readonly revokedMemIds: Set<string>;
  readonly activeKeyIds: Set<string>;
  readonly routingAccuracy: number;
  readonly codebookActive: number;
}

function readSubstrateView(state: CortexState): SubstrateMemoryView {
  const words = state.words;
  const activeMemIds = new Set<string>();
  const revokedMemIds = new Set<string>();
  const activeKeyIds = new Set<string>();

  for (let s = 0; s < MEMORY_INDEX_SLOTS; s++) {
    const w0 = words[MEMORY_INDEX_START + s * 8] ?? 0n;
    if (w0 === 0n) continue;
    const eventId = (w0 >> 128n) & ((1n << 128n) - 1n);
    if (eventId === 0n) continue;
    const flags = Number((w0 >> 64n) & 0xffffn);
    if ((flags & 0x0001) === 0) continue;
    if ((flags & 0x0002) !== 0) revokedMemIds.add(eventId.toString());
    else activeMemIds.add(eventId.toString());
  }

  for (let s = 0; s < RETRIEVAL_KEY_SLOTS; s++) {
    const w0 = words[RETRIEVAL_KEYS_START + s * 8] ?? 0n;
    if (w0 === 0n) continue;
    const keyId = (w0 >> 128n) & ((1n << 128n) - 1n);
    if (keyId === 0n) continue;
    const flags = Number((w0 >> 80n) & 0xffffn);
    if ((flags & 0x0001) !== 0) activeKeyIds.add(keyId.toString());
  }

  let filledRelations = 0;
  for (let i = RELATIONS_START; i <= RELATIONS_END; i++) {
    const w = words[i] ?? 0n;
    const weight = Number((w >> 192n) & 0xffffn);
    if (weight > 0) filledRelations++;
  }

  let codebookActive = 0;
  for (let slot = 0; slot < 48; slot++) {
    const w0 = words[896 + slot * 2] ?? 0n;
    const code = Number((w0 >> 240n) & 0xffffn);
    const codeType = Number((w0 >> 224n) & 0xffffn);
    const flags = Number((w0 >> 208n) & 0xffffn);
    if (code !== 0 && (codeType === 1 || codeType === 2) && (flags & 0x0001) !== 0) codebookActive++;
  }

  const routingAccuracy = filledRelations / (RELATIONS_END - RELATIONS_START + 1);

  return { activeMemIds, revokedMemIds, activeKeyIds, routingAccuracy, codebookActive };
}

// ─── Task builder ─────────────────────────────────────────────────────────────

interface EvalTask {
  readonly family: string;
  readonly kind: string;
  readonly query: string;
  readonly document: string;
  readonly isPositive: boolean;
  /**
   * For stale tasks: the task is a "hit" if the item is structurally revoked
   * AND the reranker score is low (model agrees memory is irrelevant).
   */
  readonly structurallyRevoked?: boolean;
}

function buildRerankerTasks(
  corpus: ProductionCorpus,
  view: SubstrateMemoryView,
  maxTasksPerFamily: number,
): EvalTask[] {
  const tasks: EvalTask[] = [];
  const familyCounts = new Map<string, number>();

  function maybeAdd(task: EvalTask): void {
    const n = familyCounts.get(task.family) ?? 0;
    if (maxTasksPerFamily > 0 && n >= maxTasksPerFamily) return;
    familyCounts.set(task.family, n + 1);
    tasks.push(task);
  }

  // Near-collision retrieval: query vs. candidate corpus items that are
  // currently active in the retrieval-key region.
  for (const event of corpus.events.near_collision) {
    if (event.relevant === false) continue;
    const isActive = view.activeKeyIds.has(eventIdToKey128(event.id).toString());
    const doc = eventText(event);
    maybeAdd({
      family: 'near_collision',
      kind: 'exact_retrieval',
      query: event.queryText ?? '',
      document: doc,
      isPositive: isActive,
    });
  }

  // Temporal: stale entries should be revoked; current entries should be active.
  for (const event of corpus.events.temporal) {
    const memId = eventIdToMem128(event.id).toString();
    const doc = eventText(event);
    if (event.isStaleTruth) {
      const revoked = view.revokedMemIds.has(memId);
      maybeAdd({
        family: 'temporal_stale',
        kind: 'stale_memory_rejection',
        query: event.queryText ?? '',
        document: doc,
        isPositive: false, // stale docs should NOT be retrieved
        structurallyRevoked: revoked,
      });
    } else {
      const active = view.activeMemIds.has(memId);
      maybeAdd({
        family: 'temporal_current',
        kind: 'temporal_update_correctness',
        query: event.queryText ?? '',
        document: doc,
        isPositive: active,
      });
    }
  }

  // Long-horizon: memory should survive compression (active in MemoryIndex).
  for (const event of corpus.events.long_horizon) {
    const memId = eventIdToMem128(event.id).toString();
    const isActive = view.activeMemIds.has(memId);
    const doc = eventText(event);
    maybeAdd({
      family: 'long_horizon',
      kind: 'compression_survival',
      query: event.queryText ?? '',
      document: doc,
      isPositive: isActive,
    });
  }

  return tasks;
}

function eventText(event: ProductionCorpusEvent): string {
  const answer = event.truthText ?? '';
  return `${event.queryText ?? ''}\n${answer}`.trim();
}

// ─── Main evaluation functions ────────────────────────────────────────────────

/**
 * Evaluate a state against the corpus using the cross-encoder reranker.
 *
 * For each task built from the active substrate region, score the
 * (query, candidate-document) pair.  A task is a "hit" when:
 *   - near_collision / temporal_current / long_horizon:
 *       reranker score > 0.5 AND the item is structurally active
 *   - temporal_stale:
 *       item is structurally revoked AND reranker score <= 0.5
 *       (model agrees this memory is no longer relevant)
 */
export async function evaluateStateWithReranker(
  state: CortexState,
  corpus: ProductionCorpus,
  opts: EvaluateStateWithRerankerOptions,
): Promise<RerankerEvalResult> {
  const { reranker, maxTasksPerFamily = 64, topK = 1 } = opts;

  const view = readSubstrateView(state);
  const tasks = buildRerankerTasks(corpus, view, maxTasksPerFamily);

  // Batch-score all (query, document) pairs.
  const pairs = tasks.map((t) => ({ query: t.query, document: t.document }));
  const scores = pairs.length > 0 ? await reranker.score(pairs) : [];

  // Tally hits per family.
  const family: Record<string, { hits: number; total: number }> = {
    near_collision: { hits: 0, total: 0 },
    temporal_stale: { hits: 0, total: 0 },
    temporal_current: { hits: 0, total: 0 },
    long_horizon: { hits: 0, total: 0 },
  };

  for (let i = 0; i < tasks.length; i++) {
    const task = tasks[i]!;
    const score = scores[i] ?? 0;
    const fam = family[task.family];
    if (!fam) continue;
    fam.total++;

    let hit = false;
    if (task.kind === 'stale_memory_rejection') {
      // Hit = item is revoked structurally AND model score is low (≤ 0.5)
      hit = (task.structurallyRevoked === true) && (score <= 0.5);
    } else {
      // Hit = item is active AND model score is high (in top-k band)
      hit = task.isPositive && score > (1 / (topK + 1));
    }
    if (hit) fam.hits++;
  }

  const ratio = (f: { hits: number; total: number }): number =>
    f.total === 0 ? 0 : f.hits / f.total;

  const nearCollisionRetrieval = ratio(family['near_collision']!);
  const staleRejection = ratio(family['temporal_stale']!);
  const temporalCurrent = ratio(family['temporal_current']!);
  const temporalCurrentStale = (staleRejection + temporalCurrent) / 2;
  const longHorizonCompression = ratio(family['long_horizon']!);
  const relationMultiHop = view.routingAccuracy;
  const codebookCompression = view.codebookActive / 48;
  const localModelAgreement =
    (nearCollisionRetrieval + temporalCurrentStale + longHorizonCompression + relationMultiHop + codebookCompression) / 5;

  const components: RerankerEvalComponents = {
    nearCollisionRetrieval,
    temporalCurrentStale,
    longHorizonCompression,
    relationMultiHop,
    codebookCompression,
    localModelAgreement,
  };

  const composite = clamp01(
    RERANKER_WEIGHTS.nearCollisionRetrieval    * nearCollisionRetrieval
    + RERANKER_WEIGHTS.temporalCurrentStale    * temporalCurrentStale
    + RERANKER_WEIGHTS.longHorizonCompression  * longHorizonCompression
    + RERANKER_WEIGHTS.relationMultiHop        * relationMultiHop
    + RERANKER_WEIGHTS.codebookCompression     * codebookCompression
    + RERANKER_WEIGHTS.localModelAgreement     * localModelAgreement,
  );

  return {
    model: reranker.model,
    composite,
    components,
    familyHitRates: {
      near_collision: nearCollisionRetrieval,
      temporal_stale: staleRejection,
      temporal_current: temporalCurrent,
      temporal_current_stale: temporalCurrentStale,
      long_horizon: longHorizonCompression,
      relation_multi_hop: relationMultiHop,
      codebook_compression: codebookCompression,
    },
    weights: RERANKER_WEIGHTS,
  };
}

/**
 * Evaluate a patch by comparing baseline and candidate states.
 *
 * Returns `pass: true` only when:
 *   1. The patch is structurally valid.
 *   2. `scoreDelta >= threshold`.
 *   3. No per-component regression versus the baseline.
 *
 * Mirrors the contract of `evaluatePatchWithLocalModel` from
 * `experiments/harness/local-model-eval.mjs`.
 */
export async function evaluatePatchWithReranker(
  parentState: CortexState,
  patch: Patch,
  opts: EvaluatePatchWithRerankerOptions,
): Promise<PatchEvalResult> {
  const { corpus, reranker, threshold = 0.0025 } = opts;
  const patchFn = opts.applyPatch ?? applyPatch;

  const before = await evaluateStateWithReranker(parentState, corpus, { reranker });

  const applied = patchFn(parentState, patch);
  if (!applied.ok) {
    return {
      pass: false,
      scoreDelta: 0,
      before,
      after: before,
      noRegression: false,
      regressions: [],
      errorCode: (applied as { ok: false; code: string }).code,
    };
  }

  const after = await evaluateStateWithReranker(applied.state, corpus, { reranker });

  const delta = after.composite - before.composite;
  const regressions = componentRegressions(before.components, after.components);
  const noRegression = regressions.length === 0 && after.composite + 1e-12 >= before.composite;

  return {
    pass: noRegression && delta + 1e-12 >= threshold,
    scoreDelta: Math.round(delta * 1_000_000),
    before,
    after,
    noRegression,
    regressions,
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function componentRegressions(
  before: RerankerEvalComponents,
  after: RerankerEvalComponents,
  epsilon = 1e-12,
): string[] {
  const fields: Array<keyof RerankerEvalComponents> = [
    'nearCollisionRetrieval',
    'temporalCurrentStale',
    'longHorizonCompression',
    'relationMultiHop',
    'codebookCompression',
  ];
  return fields.filter((f) => (after[f] ?? 0) + epsilon < (before[f] ?? 0));
}

function clamp01(v: number): number {
  return Math.max(0, Math.min(1, v));
}

// Re-export for callers that need the corpus type
export type { ProductionCorpus, ProductionCorpusFamily };
