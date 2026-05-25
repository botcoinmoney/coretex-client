/**
 * CoreTex production retrieval scorer.
 *
 * Spec: specs/retrieval_benchmark.md.
 *
 * Replaces the previous slot-fill `scoreProductionState` /
 * `evaluateStateWithReranker` path. The reward law is `nDCG@10` over the
 * per-epoch hidden query pack, retrieval-dominant, with sanity, temporal,
 * multi-hop, and abstention sub-metrics.
 */

import type { CortexState, Patch } from '../state/index.js';
import { applyPatch } from '../state/patch.js';
import { keccak256 } from '../state/keccak256.js';
import { decodeSubstrate, type DecodedSubstrate, type RelationCategoryLens, POLICY_SELECTOR } from '../substrate/retrieval-decoder.js';
import { biEncoderModelIdHash } from '../substrate/retrieval-decoder.js';
import { structuralValidity } from '../substrate/structural-validity.js';
import type { CrossEncoderReranker } from './reranker.js';
import type { BiEncoder } from './bi-encoder.js';
import { cosineSimilarity, dequantize } from './bi-encoder.js';
import type {
  ProductionCorpus,
  ProductionCorpusEvent,
  RetrievalKeyLayout,
} from './retrieval-corpus.js';
import {
  buildPublicCorpusIndex,
  firstStageCandidates,
  type PublicCorpusIndex,
  type PublicCorpusDoc,
} from './public-corpus-index.js';
import type { QueryPack } from './hidden-query-pack.js';
import {
  ndcgAtK,
  mrrAtK,
  recallAtK,
  temporalCurrentStaleHit,
  temporalCurrentStaleAccuracy,
  multiHopRelationHit,
  multiHopRelationRecallAtK,
  abstentionAccuracy,
} from './ir-metrics.js';

export interface CompositeWeights {
  readonly w_retrieval: number;
  readonly w_temporal: number;
  readonly w_relation_recall: number;
  readonly w_abstention: number;
  readonly w_structural_sanity: number;
}

export const DEFAULT_COMPOSITE_WEIGHTS: CompositeWeights = {
  w_retrieval: 0.75,
  w_temporal: 0.08,
  w_relation_recall: 0.07,
  w_abstention: 0.05,
  w_structural_sanity: 0.05,
};

/**
 * §6.6 pipeline-version pin enforcement. The bundle profile pins
 * `pipelineVersion` so a replay validator routes to the matching code
 * path. When a binary scores against a bundle that pins a different
 * version (future migration, downgrade attempt), throw fail-closed so
 * scoring doesn't silently produce wrong numbers. No env-var bypass:
 * a mismatch ALWAYS fails closed — operators upgrade the binary or
 * downgrade the bundle, but never silently cross versions.
 */
export function assertPipelineVersionMatches(bundlePin?: string): void {
  if (!bundlePin) return; // older bundles without the pin: caller decides
  if (CORETEX_PIPELINE_VERSIONS_SUPPORTED.has(bundlePin)) return; // r4 + r5 both replayable
  throw new Error(
    `pipelineVersion mismatch: bundle pins '${bundlePin}', this binary implements ` +
    `{${[...CORETEX_PIPELINE_VERSIONS_SUPPORTED].join(', ')}}. Run a binary whose pipeline matches the ` +
    `bundle (or rebuild the bundle against this binary's pipeline) — no override exists.`,
  );
}

export function assertValidWeights(w: CompositeWeights): void {
  const sum = w.w_retrieval + w.w_temporal + w.w_relation_recall + w.w_abstention + w.w_structural_sanity;
  if (Math.abs(sum - 1) > 1e-6) throw new Error(`composite weights must sum to 1.0 (got ${sum})`);
  if (w.w_retrieval < 0.7 - 1e-9) throw new Error(`w_retrieval must be >= 0.70 (got ${w.w_retrieval})`);
  if (w.w_structural_sanity > 0.10 + 1e-9)
    throw new Error(`w_structural_sanity must be <= 0.10 (got ${w.w_structural_sanity})`);
  if (w.w_temporal <= 0 || w.w_relation_recall <= 0 || w.w_abstention <= 0) {
    throw new Error('w_temporal, w_relation_recall, w_abstention must be > 0');
  }
}

/**
 * Canonical acceptance threshold in ppm. Combines the three bundle-
 * pinned terms that callers previously had to fold in manually:
 *
 *   threshold = minImprovementPpm + replayTolerancePpm + baselineVariancePpm
 *
 * Hosts wiring the per-patch evaluator pass the result here as
 * `thresholdPpm`. Centralizing this prevents call sites from forgetting
 * a term (replay tolerance + baseline variance must BOTH be on top of
 * minImprovement so that pack-luck advances within reranker-noise
 * range don't qualify).
 */
export function computeAcceptanceThresholdPpm(profile: {
  readonly patchAcceptanceFloors: { readonly minImprovementPpm: number };
  readonly replayTolerancePpm: number;
  readonly baselineVariancePpm?: number;
}): number {
  return profile.patchAcceptanceFloors.minImprovementPpm
       + profile.replayTolerancePpm
       + (profile.baselineVariancePpm ?? 0);
}

export interface ScoringOptions {
  readonly weights: CompositeWeights;
  readonly biEncoder: BiEncoder;
  readonly reranker: CrossEncoderReranker;
  readonly retrievalKeyLayout: RetrievalKeyLayout;
  readonly biEncoderHash: string;          // bundle-pinned 4-byte hash hex
  readonly relationHopBudget: number;      // calibrated, typ. 2-3
  readonly abstentionThreshold: number;    // calibrated
  readonly rerankerTopK: number;           // calibrated, e.g. 10

  /**
   * Owner-scoped retrieval (Layer-2 validity fix, 2026-05-21). When 'restrict'
   * AND the query event carries `ownerScoped===true` + `ownerEntityId`, stage-1
   * retrieval is restricted to the owner's memory store (the events tagged with
   * that owner entity) instead of the pooled corpus. This is the realistic,
   * well-posed task: real memory retrieval searches a KNOWN user's/project's
   * store, not a pool of strangers. Without it, first-name subjects collide
   * ~80-way at 100k and the relation families are ill-posed. Cross-entity
   * families (entity_disambiguation, abstention) carry `ownerScoped=false` and
   * stay pooled. Default 'off' preserves the legacy full-pool behavior.
   */
  readonly ownerScopeMode?: 'off' | 'restrict';

  /**
   * EvidencePolicy (opt-in, default off). A candidate THIRD miner-facing strategy
   * surface (distinct from temporal records / relation edges / dense lenses): the
   * miner writes compact POLICY atoms to the CODEBOOK region (not data, not answer
   * maps) that drive generalizable, honest scorer effects. Currently implements
   * `high_density_evidence` (CODEBOOK code=5): boost candidates whose event is
   * corroborated by many PUBLIC supports-edges (in-degree >= K). The in-degree is
   * corpus-derived (public, auditable); the miner's degree of freedom is the POLICY
   * (threshold K + weight), not the data. Default off → the default scoring path is
   * byte-identical. See EVIDENCE_POLICY_DESIGN.md.
   */
  readonly evidencePolicyEnabled?: boolean;

  /**
   * Diagnostic-only (opt-in, default off). When true, the per-query breakdown
   * surfaces the FULL final reranked list (`finalRankingFull`: docId + relevance,
   * in final-reorder order) in addition to the top-20 view. Used by offline
   * oracle-upper-bound probes (substrate-r5 oracle ladder) that need to reorder
   * the complete reranked list and recompute nDCG faithfully with the same
   * `ndcgAtK`. Pure diagnostic — does not affect scoring or any reward path; the
   * default scoring path is byte-identical when unset.
   */
  readonly exposeFullRanking?: boolean;

  // ─── v2-lens pipeline params (substrate-hardening Phase A) ───
  readonly firstStageTopK: number;             // calibrated per-stratum (Run 1)
  readonly lensTopK: number;                   // how many lens vectors contribute to stage-2 reweighting
  readonly lensWeight: number;                 // stage-2 lens bonus scale (Run 0)
  readonly anchorWeight: number;               // stage-2 anchor bonus scale (Run 0)
  readonly relationExpansionBudget: number;    // Phase A: anchor-to-anchor BFS doc cap
  /**
   * Phase B (corpus-native category-lens BFS) candidate-pool budget.
   * Optional; when omitted, defaults to `relationExpansionBudget` for
   * backwards compatibility with bundles that predate the budget split.
   *
   * Phase A (anchor-to-anchor BFS through `decoded.relations`) and Phase B
   * (corpus-native event.relations BFS via category-lens entries) used to
   * share a single counter capped by `relationExpansionBudget`. On
   * launch-corpus scale that coupling let Phase B flood the candidate
   * pool with 189 docs across 16 queries and displace 14 of 15
   * anchor-mandatory truths from the reranker's top-10 (commit
   * ce106be artifact). The two phases now have independent budgets:
   * substrate retains anchor-graph relation capacity while operators
   * can guard the broader corpus-native expansion separately.
   *
   * Launch-v3 candidate pin: relationExpansionBudget=12,
   * categoryLensExpansionBudget=0 (Phase B disabled; substrate
   * structure intact for future tightening).
   */
  readonly categoryLensExpansionBudget?: number;
  /**
   * Phase B traversal direction. Substrate-viability knob.
   *   'bidirectional' (default) — follow forward edges (question →
   *      answer-entity) AND inverse edges (entity ← all questions pointing
   *      at it). Closes the semantic cluster around the answer entity; the
   *      lever that lets a stage-1 question reach a SIBLING question's truth
   *      doc that shares the same answer entity. This is the historical
   *      behaviour and the only mode that produces non-anchor "generalized"
   *      routing lift.
   *   'forward' — follow only forward edges. The cluster is one-hop from
   *      each stage-1 doc; sibling-question truths reached only if a direct
   *      forward edge exists. Isolates how much Phase B lift is inverse-edge
   *      (true generalized routing) vs. forward-edge (near-trivial).
   * Optional; defaults to 'bidirectional' for backwards compatibility.
   */
  readonly categoryLensTraversalDirection?: 'forward' | 'bidirectional';
  /**
   * Phase B PRECISE-ADMISSION knob (deep-memory scaling fix). When set to a
   * positive integer, the category-lens BFS is seeded ONLY from the top-K most
   * query-similar stage-1 docs (stage-1 is sorted descending by cosine), instead
   * of from EVERY stage-1 candidate (up to `firstStageTopK`). On a shallow
   * owner-scoped store this is a no-op (stage-1 is already small). On a DEEP
   * universe it is the difference between routing from the query's genuinely
   * relevant seed (the bridge doc that names the subject → high stage-1 rank →
   * follow its single public edge to the specific answer) versus admitting the
   * edge-peers of hundreds of unrelated stage-1 candidates (the whole edge-type
   * CATEGORY blob — e.g. ~1000 `supersedes` docs — which floods the rerank pool).
   * Undefined (default) preserves the legacy all-stage-1-seed behaviour so prior
   * owner-scoped P1/P2/P3 results are unchanged. Recommended deep value: 8–16.
   */
  readonly categoryLensSeedTopK?: number;
  /**
   * Hop budget for the categoryLens BFS specifically (independent of the
   * anchor-relation `relationHopBudget`). At hop budget 1 the lens admits only
   * the DIRECT routed-edge neighbours of the query-similar seed docs — e.g. the
   * bridge_seed's answer target — but NOT the answer's own siblings (2 hops),
   * which is the main source of cluster collateral / induced junk in the
   * evidence-bundle path. Undefined (default) falls back to relationHopBudget so
   * prior results are unchanged. Recommended deep value: 1.
   */
  readonly categoryLensHopBudget?: number;
  /**
   * Phase B scoring-bonus toggle. Substrate-viability knob.
   * When false, docs that entered the pool via Phase B still appear in the
   * candidate pool (inclusion-only) but receive NO categoryLensBonus — the
   * reranker sees them on biCosine + non-Phase-B substrate bonuses alone.
   * Isolates whether Phase B lift comes from EXPANSION (reaching the doc at
   * all) vs. BIASING (the additive lens bonus nudging it up the pre-rank).
   * Optional; defaults to true (bonus applied).
   */
  readonly categoryLensBonusEnabled?: boolean;
  /**
   * Phase B bonus scale override. When set, the categoryLensBonus uses this
   * weight instead of `lensWeight`. Lets viability runs sweep the Phase B
   * bias independently of the Phase A / retrieval-key lens bonus. Optional;
   * when omitted, falls back to `lensWeight` (historical behaviour).
   * Ignored when `categoryLensBonusEnabled === false`.
   *
   * This is the ADMISSION scale: it biases the PRE-RANK score so a category-lens
   * routed doc enters the reranker cap. See `categoryLensFinalBonusWeight`.
   */
  readonly categoryLensBonusWeight?: number;
  /**
   * NON-FLOODING PROMOTION — the FINAL-reorder category-lens bonus scale.
   * Defaults to `categoryLensBonusWeight` (back-compat: legacy single-bonus
   * behavior). Set to ~0 for an INCLUSION-ONLY profile: category-lens routing
   * still admits a doc into the reranker cap (via the admission scale) but adds
   * little/no bias to the FINAL ranking, so the reranker — not a flat additive
   * lens bonus — decides final order. This is the fix for the P2 flood
   * (`lensJunkTop10`≈9), where a large final additive bonus swamped the reranker.
   * Ignored when `categoryLensBonusEnabled === false`.
   */
  readonly categoryLensFinalBonusWeight?: number;
  /**
   * SCORE-INHERITANCE alpha ∈ [0,1]. When > 0, a category-lens-edge target
   * inherits `alpha × its best lens-peer's reranker score` (one hop), floored at
   * its own score, applied in the FINAL reorder only (reported rerankerScore
   * stays raw). Lifts a surface-dissimilar bridge ANSWER the reranker under-ranks
   * via the signal that it links to a high-scoring bridge — targeted along
   * genuine public edges, so junk edges confer no boost. Default 0 (off).
   */
  readonly categoryLensScoreInheritance?: number;
  /**
   * EVIDENCE-BUNDLE reranking (deep-memory final-surfacing fix). When true, a
   * category-lens-routed candidate (admitted via categoryLensBFS that has a lens-peer)
   * is scored by the cross-encoder together with its highest-query-similarity lens-peer
   * (the BRIDGE), as a compact `Bridge evidence:\n<bridge>\nCandidate answer:\n<answer>`
   * bundle, instead of `query + answer` alone. The bridge ANSWER is intentionally
   * lexically distant from the query (routing-required), so the bridge carries the
   * relevance signal; without it the reranker is under-informed and demotes the answer
   * below the subject's dense same-surface docs at depth. The reported rerankerScore is
   * the bundle score (the substrate's evidence-aware judgment). Default false (legacy:
   * query+answer only) — opt-in so owner-scoped P1/P2/P3 are unchanged.
   */
  readonly categoryLensEvidenceBundle?: boolean;
  readonly temporalCurrentBoost: number;       // stage-2 temporal bonus (current truth)
  readonly temporalStaleSuppression: number;   // stage-2 temporal penalty (stale truth)
  /**
   * ORACLE / DIAGNOSTIC ONLY (substrate-vNext Lifecycle oracle upper-bound, 2026-05-24).
   * When true, a substrate temporal record's boost/suppress is applied to a doc ONLY when that
   * doc belongs to the CURRENT query's own truth set — i.e. each chain's routing is SCOPED to its
   * owning query instead of the blunt GLOBAL behaviour (current default) where a boosted current
   * doc lifts ANY pack temporal query whose pool contains it, flooding neighbours (the measured
   * 0.65 pack-interference factor). This models the IDEAL scoped lifecycle surface (scope_differs)
   * using qrels as the oracle scope signal. NOT a substrate-format change; production callers leave
   * it undefined (= blunt global behaviour, byte-identical). Marked oracle: uses query truth labels.
   */
  readonly temporalOracleScopePerQuery?: boolean;
  /**
   * TEMPORAL answer-vs-contrast eval semantics (launch lever, 2026-05-25). When true, on temporal
   * queries a STALE (superseded) doc earns 0 nDCG reward — it is CONTRAST evidence, not a correct
   * answer to "the current value" — so the reward neither credits outdated info nor penalises the
   * substrate's correct demotion of it; stale recall is reported separately (temporalContrastRecall)
   * as a diagnostic. Real-Qwen confirmed to recover in-context temporal yield 0.30→0.56
   * (PROFILE_QREL_YIELD_EXPERIMENT.md). Default off → current behaviour (stale qrel relevance counts).
   * EVAL-SEMANTICS only — NOT a substrate change, NOT a protocol epoch.
   */
  readonly temporalStaleContrast?: boolean;
  /**
   * §6.5 reranker-input cap (MemReranker semantics). Number of pool
   * candidates that get forwarded to the cross-encoder reranker per
   * query — sorted by (biCosine + substrateBonus) descending, tie-break
   * by docId for determinism. Without this cap the reranker scores all
   * ~3,200 first-stage candidates per query, making both calibration and
   * production patch evaluation infeasible on a single GPU. The cap is
   * on COMPUTE per query; substrate expressivity is unchanged — a doc
   * the substrate finds compelling (anchor, lens-aligned, BFS-reached)
   * still enters the reranker pool because substrateBonus contributes to
   * the pre-rank score. Typical: 128.
   */
  readonly rerankerInputTopK: number;

  /**
   * §6.4 lens-diversity floor — wired into `decodeSubstrate` so a substrate
   * whose active lens vectors collapse onto one direction fails structural
   * validity and the scorer composite floors to zero. Mandatory: when
   * omitted, the floor check is skipped and a collapsed substrate scores
   * normally. Hosts pass `profile.lensDiversityFloor` here.
   */
  readonly lensDiversityFloor?: number;

  /**
   * §6.6 pipeline-version pin. When set, the scorer asserts the bundle's
   * pinned pipeline matches what this code implements (currently
   * `'coretex-retrieval-v2-lens'`). Replay validators consume the pin to
   * route to the matching code path; a bundle that pins a future version
   * cannot be replayed by an older binary without an explicit override.
   */
  readonly pipelineVersion?: string;

  // ── r5 PolicyAtom knobs (active only under pipelineVersion policy-r5) ──
  /** Decode the reclaimed words as PolicyAtoms (set from pipelineVersion r5). HARD gate. */
  readonly policyAtomsMode?: boolean;
  /** Per-family enable flags (operator profile). A disabled family is decoded but NOT applied. */
  readonly enableEvidenceBundleAtoms?: boolean;
  readonly enableConflictLifecycleAtoms?: boolean;
  readonly enableAbstentionAtoms?: boolean;
  /** Per-family budget caps (ppm-ish). A miner atom's budget is clamped to these. */
  readonly policyMaxBudgetEvidence?: number;
  readonly policyMaxBudgetConflict?: number;
  /**
   * Abstention is a SPLIT: the miner atom supplies the public no-evidence-path policy;
   * the confidence gate is an OPERATOR PROFILE calibration. Abstain fires only when the
   * atom's selector matches AND the calibrated top1 score < this threshold (Qwen top1 is
   * saturated ~0.999x so this is never a hardcoded universal — it is profile-pinned).
   */
  readonly policyAbstentionTop1Threshold?: number;
  /** Emit per-atom trace receipts (atomId/family/selectorMatched/docsMoved/evidencePath/delta/junk). */
  readonly policyEmitTraces?: boolean;
}

/** The pipeline version this codebase implements. Bundles that pin a
 *  different value cannot be replayed by this binary — there is no
 *  override; operators upgrade the binary or rebuild the bundle.
 *
 *  r4 (2026-05-24) = the Tier-2 substrate epoch: MemoryIndex repacked to
 *  STRIDE-1 (WORDS_PER_SLOT 8→1, SLOT_COUNT 44→352) and the temporal
 *  retrievalSlot<36 coupling removed, lifting the current/stale PAIR cap
 *  18→96 (TEMPORAL_DECOUPLING_DESIGN.md). This changes the scorer's
 *  substrate DECODE semantics, so an r3-signed (stride-8) bundle must NOT
 *  be silently scored by this binary — the version pin fails it closed.
 *
 *  r5 (2026-05-25) = the PolicyAtom epoch: reclaimed RetrievalKeys+Codebook
 *  words read as typed PolicyAtoms (this binary implements BOTH r4 and r5;
 *  r4 stays replayable). The active decode is chosen by the profile's pin. */
export const CORETEX_PIPELINE_VERSION_THIS_BINARY = 'coretex-retrieval-v2-lens-r4';
export const CORETEX_PIPELINE_VERSION_R5 = 'coretex-retrieval-v2-policy-r5';
/** Versions this binary can replay (r4 + r5 coexist; decode mode chosen by the profile pin). */
export const CORETEX_PIPELINE_VERSIONS_SUPPORTED: ReadonlySet<string> = new Set([
  CORETEX_PIPELINE_VERSION_THIS_BINARY,
  CORETEX_PIPELINE_VERSION_R5,
]);

/** r5 PolicyAtom trace receipt (Memory-IR pipeline input; emitted when policyEmitTraces). */
export interface PolicyAtomTrace {
  readonly atomId: string;
  readonly atomFamily: 'evidence_bundle' | 'conflict_lifecycle' | 'abstention';
  readonly selectorMatched: boolean;
  readonly action: string;
  readonly anchorEvent: string | null;
  readonly docsMoved: number;
  readonly evidencePath: readonly string[];
  readonly beta: number;
}

export interface PerQueryBreakdown {
  readonly recordId: string;
  readonly family: string;
  readonly nDCG10: number;
  readonly mrr10: number;
  readonly recall10: number | null;
  readonly temporalHit: boolean | null;
  readonly multiHopHit: boolean | null;
  readonly categoryLensRelationHit: boolean | null;
  readonly abstentionHit: boolean | null;
  readonly top1Score: number;
  /**
   * §6.5 candidate-funnel introspection: docIds that made the
   * `rerankerInputTopK` cap (sorted by preRank desc). Used by gates
   * G1/G2 (candidate-funnel recall) to verify the substrate's routing
   * function — does an engineered substrate push the truth doc into the
   * cap when stage-1 alone misses it? Empty when the cap is the entire
   * pool (cap >= pool size). Doesn't change the composite score.
   */
  readonly cappedDocIds?: readonly string[];
  /**
   * Candidate-source attribution (parallel array to cappedDocIds). Each
   * entry lists which routing mechanisms placed that docId into the
   * candidate pool: 'stage1', 'anchorMandatory', 'anchorBFS', or
   * 'categoryLensBFS'. A doc reached by multiple mechanisms carries all
   * applicable tags. Pure diagnostic — does not affect scoring.
   * Used to answer "which mechanism actually produces relevant top-K
   * docs?" without inferring from indirect signals.
   */
  readonly cappedDocSources?: readonly (readonly string[])[];
  /**
   * Pre-rank score components per capped doc (parallel array to
   * cappedDocIds). Each entry exposes the raw inputs to preRankScore so
   * downstream diagnostics can compute lens-promotion-into-cap, hard-
   * negative injection, etc. without re-running the scorer:
   *
   *   preRankScore = biCosine + lensBonus + anchorBonus + categoryLensBonus + temporalBonus
   *
   * A doc whose preRankScore − lensBonus would be below the K-th-place
   * threshold is "lens-promoted into the cap"; a doc whose biCosine
   * alone would be in the cap but is displaced by a substrate-promoted
   * doc is "substrate-displaced." Both questions are answerable from
   * this field plus cappedDocIds.
   */
  readonly cappedDocComponents?: readonly {
    biCosine: number;
    lensBonus: number;
    anchorBonus: number;
    categoryLensBonus: number;
    temporalBonus: number;
    preRankScore: number;
  }[];
  /**
   * Final ranking (top 20) — what the reranker decided, with relevance
   * labels, source tags, and pre-rank components attached. Used to
   * answer "which mechanism produces relevant docs in the final top-10?"
   * and "are hard negatives in top-20 from anchor BFS or category-lens
   * BFS expansion?"
   *
   * `finalReorderingScore = rerankerScore + substrateBonus` is the sort
   * key actually used by the evaluator. `relevance` is the qrel for
   * this query (0 = irrelevant, ≥1 = graded relevance).
   */
  readonly finalRankingTop20?: readonly {
    docId: string;
    rank: number;
    rerankerScore: number;
    finalReorderingScore: number;
    relevance: number;
    sources: readonly string[];
    biCosine: number;
    lensBonus: number;
    anchorBonus: number;
    categoryLensBonus: number;
    temporalBonus: number;
  }[];
  /**
   * Admission-headroom diagnostic: true iff any qrel doc with relevance>0 is
   * among the `rerankerInputTopK`-capped candidates (sorted by preRankScore =
   * biCosine + substrateBonus). RERANKER-INDEPENDENT — a routing surface can
   * only help by getting an answer INTO this cap, so the answer-in-cap rate
   * (and its complement, residual routing headroom) bounds the value of any
   * new substrate routing region. Null for abstention probes (no answer to
   * admit). Pure diagnostic — does not affect scoring.
   */
  readonly answerInCap?: boolean | null;
  /**
   * Diagnostic-only (opt-in via ScoringOptions.exposeFullRanking): the FULL final
   * reranked candidate list (docId + graded relevance) in final-reorder order, not
   * truncated to 20. Used by offline oracle-upper-bound probes that reorder the
   * complete reranked list and recompute nDCG faithfully. Undefined unless the
   * opt-in is set. Pure diagnostic — does not affect scoring.
   */
  readonly finalRankingFull?: readonly { docId: string; relevance: number; rerankerScore: number }[];
  /**
   * Diagnostic (temporalStaleContrast mode): recall@rerankerTopK of this temporal query's STALE
   * (contrast) docs — observable but NOT in the reward. Null when off / non-temporal / no stale docs.
   */
  readonly temporalContrastRecall?: number | null;
  /** r5: per-atom trace receipts (when policyEmitTraces). */
  readonly policyTraces?: readonly PolicyAtomTrace[];
  /** r5: this query's abstain decision + whether it false-abstained (answerable query). */
  readonly policyAbstain?: boolean;
  readonly policyFalseAbstain?: boolean;
}

export interface CompositeScore {
  readonly composite: number;
  readonly nDCG10: number;
  readonly mrr10: number;
  readonly recall10: number;
  readonly temporal: number;
  readonly multiHopRecall10: number;
  readonly categoryLensRelationHit10: number;
  readonly abstention: number;
  readonly structuralValidity: number;
  readonly perQuery: readonly PerQueryBreakdown[];
}

export interface PatchEvalResult {
  readonly accepted: boolean;
  readonly reason?: string;
  readonly before: CompositeScore;
  readonly after: CompositeScore;
  readonly deltaPpm: number;
  readonly perFamilyDelta: Record<string, number>;
}

// ─── Scoring ─────────────────────────────────────────────────────────────────

/**
 * Score a single query against the substrate using the v2-lens pipeline.
 *
 * Spec: specs/substrate_retrieval_semantics.md plus the active evaluator
 * profile described in release/calibration/CURRENT.md.
 *
 * Two-stage retrieval, substrate is the bias not the gate:
 *   Stage 1: blind BGE-M3 cosine over the full public corpus index →
 *            Top-`firstStageTopK` docs. Substrate-agnostic; same answer
 *            for every miner against a given query, including a miner
 *            with no submitted patch.
 *   Stage 2: substrate-driven bias. Lens vectors (RetrievalKeys), anchor
 *            exemplars (MemoryIndex), relation BFS expansion, temporal
 *            modulation. Adds bonuses to rerank scores; bonuses cannot
 *            manufacture docs from thin air — relation expansion only
 *            adds docs already in the public corpus, reachable via the
 *            decoder's domain-share-validated relation edges.
 *
 * Anti-cheat invariant: empty substrate → score = stage1 baseline. No
 * free oracle credit. The labeled corpus is never read by stage-1 (the
 * `firstStageCandidates` signature accepts only `PublicCorpusIndex`,
 * which contains no qrels or truth-as-answer-set).
 *
 * Pinned formula:
 *   substrateBonus(d)         = lensBonus(d) + anchorBonus(d) + temporalBonus(d)
 *   finalReorderingScore(d)   = rerankerScore(d) + substrateBonus(d)
 *
 * `max` over active lenses/anchors prevents miners from gaming by
 * stacking N colinear vectors. The decoder's lens-diversity floor
 * (substrate-hardening §6.4) closes the residual collapse case.
 */
export async function scoreSubstrateAgainstQuery(
  decoded: DecodedSubstrate,
  query: ProductionCorpusEvent,
  corpus: ProductionCorpus,
  opts: ScoringOptions,
): Promise<{
  ranked: readonly { documentId: string; relevance: number; rerankerScore: number; memorySlot: number | null }[];
  top1Score: number;
  cappedDocIds: readonly string[];
  cappedDocSources: readonly (readonly string[])[];
  cappedDocComponents: readonly {
    biCosine: number;
    lensBonus: number;
    anchorBonus: number;
    categoryLensBonus: number;
    temporalBonus: number;
    preRankScore: number;
  }[];
  finalRankingTop20: readonly {
    docId: string;
    rank: number;
    rerankerScore: number;
    finalReorderingScore: number;
    relevance: number;
    sources: readonly string[];
    biCosine: number;
    lensBonus: number;
    anchorBonus: number;
    categoryLensBonus: number;
    temporalBonus: number;
  }[];
  answerInCap: boolean;
  finalRankingFull: readonly { docId: string; relevance: number; rerankerScore: number }[] | undefined;
  policyTraces: readonly PolicyAtomTrace[];
  policyAbstain: boolean;
}> {
  const queryVec = dequantize(query.embeddings.query, opts.retrievalKeyLayout);
  const publicIndex = getOrBuildPublicIndex(corpus);

  // ─── Stage 1: substrate-agnostic BGE-M3 first-stage retrieval ────────────
  // Stage-1 output is substrate-agnostic — depends only on (queryVec,
  // publicIndex, K). The same query scored twice in a dual-pack flow
  // (parent vs candidate substrate) shares its Top-K. Cache per
  // (corpus, query.id, K) to amortize the ~600ms cosine sweep across all
  // patch evaluations within a pack. See substrate-hardening §6.7.
  // Owner-scoped stage-1 (Layer-2 validity fix): when enabled and the query
  // carries a public owner scope, rank ONLY the owner's store. Owner scopes are
  // small (~tens to low-hundreds of docs ≪ firstStageTopK), so we rank the full
  // scope exactly — no buried-but-excluded risk inside scope. The owner set is
  // PUBLIC retrieval context (query.ownerEntityId), never derived from qrels.
  const useOwnerScope =
    (opts.ownerScopeMode ?? 'off') === 'restrict' && query.ownerScoped === true && !!query.ownerEntityId;
  const stage1ScopeTag = useOwnerScope ? `s:${query.ownerEntityId}` : 'p';
  const stage1Docs = getOrComputeStage1(corpus, query.id, opts.firstStageTopK, stage1ScopeTag, () =>
    useOwnerScope
      ? scopedFirstStageCandidates(
          queryVec,
          getOrBuildEntityScopeIndex(corpus).get(query.ownerEntityId!) ?? [],
          opts.firstStageTopK,
          opts.retrievalKeyLayout,
        )
      : firstStageCandidates(queryVec, publicIndex, opts.firstStageTopK),
  );

  // Resolve doc text for the reranker pairs (text lives in the labeled corpus).
  const docTextById = getOrBuildDocTextIndex(corpus);

  // Map: docId → { embedding, text, eventId, memorySlot, provenance, sources }
  // `sources` records which routing mechanism(s) added this doc to the
  // candidate pool. A doc may be reached by multiple paths (e.g., stage1
  // AND anchorMandatory); store all that applied. Pure diagnostic — does
  // not affect scoring. Surfaced in PerQueryBreakdown.cappedDocSources so
  // calibration can answer "which mechanism delivered the top-10 docs?"
  type SourceTag = 'stage1' | 'anchorMandatory' | 'anchorBFS' | 'categoryLensBFS';
  type CandidateRecord = {
    docId: string;
    embedding: Uint8Array;
    text: string;
    eventId: string;
    memorySlot: number | null; // anchor slot that brought it via stage-2 (if any)
    isCurrentTruth: boolean;
    isStaleTruth: boolean;
    sources: Set<SourceTag>;
  };
  const pool = new Map<string, CandidateRecord>();
  function addSource(record: CandidateRecord, src: SourceTag) {
    record.sources.add(src);
  }

  for (const d of stage1Docs) {
    const text = docTextById.get(d.id);
    if (!text) continue; // skip if text is missing (shouldn't happen with a built index)
    pool.set(d.id, {
      docId: d.id,
      embedding: d.embedding,
      text,
      eventId: d.eventId,
      memorySlot: null,
      // Corpus current/stale labels are NOT used for scoring (that would leak an
      // oracle the miner doesn't control). Temporal modulation is driven solely
      // by the miner's decoded.temporal records (see temporalBySlot below).
      isCurrentTruth: false,
      isStaleTruth: false,
      sources: new Set(['stage1']),
    });
  }

  // ─── Stage 2: substrate-driven candidate expansion via relations BFS ─────
  // Build an anchor-slot → corpus-event map once per scoring call.
  const corpusByRecordId = getOrBuildRecordIdIndex(corpus);
  const anchorSlotToEvent = new Map<number, ProductionCorpusEvent>();
  for (let m = 0; m < decoded.memoryIndex.length; m++) {
    const slot = decoded.memoryIndex[m];
    if (!slot || slot.revoked) continue;
    const ev = corpusByRecordId.get(slot.recordId);
    if (ev) anchorSlotToEvent.set(m, ev);
  }

  // §6.5+ Anchor-as-routing-primitive: each active anchor's truth docs are
  // added to the candidate pool directly. Without this, anchors are purely
  // decorative — the substrate has no way to inject docs into the pool past
  // stage-1 misses, which makes Phase B's BFS the only routing surface and
  // reduces the substrate to "additive bias over what bi-encoder found
  // anyway." The G2 funnel-recall gate showed multi_hop_relation /
  // long_horizon recall stuck at 0% because of this gap. Anchor budget is
  // already capped at 44 MemoryIndex slots — this contributes at most 44
  // additional truth docs per query, dwarfed by stage-1's firstStageTopK.
  // Anti-cheat invariant intact: anchors are public; reranker still judges.
  for (const [slot, ev] of anchorSlotToEvent) {
    for (const td of ev.truthDocuments) {
      const existing = pool.get(td.id);
      if (existing) {
        // Stage-1 already had this doc, but anchor-mandatory ALSO routes it.
        addSource(existing, 'anchorMandatory');
        continue;
      }
      const emb = ev.embeddings.perTruth.get(td.id);
      if (!emb) continue;
      pool.set(td.id, {
        docId: td.id,
        embedding: emb,
        text: td.text,
        eventId: ev.id,
        memorySlot: slot,
        isCurrentTruth: td.isCurrent,
        isStaleTruth: !td.isCurrent,
        sources: new Set(['anchorMandatory']),
      });
    }
  }

  // Relation adjacency (sourceSlot → [targetSlot]). Decoder has already
  // dropped domain-share-failing edges (substrate-hardening §6.4).
  const relAdj = new Map<number, number[]>();
  for (const e of decoded.relations) {
    const arr = relAdj.get(e.sourceSlot) ?? [];
    arr.push(e.targetSlot);
    relAdj.set(e.sourceSlot, arr);
  }

  // Phase A: BFS from active anchors up to `relationHopBudget` hops; add
  // truth docs of visited anchors to the pool until
  // `relationExpansionBudget` is reached. Has its OWN counter — Phase B
  // (corpus-native category-lens BFS, below) carries an independent
  // budget so the two channels don't share a flood-prone pool budget.
  let anchorBfsExpansionAdded = 0;
  const visited = new Set<number>(anchorSlotToEvent.keys());
  let frontier: number[] = Array.from(visited);
  for (let hop = 0; hop < opts.relationHopBudget && anchorBfsExpansionAdded < opts.relationExpansionBudget; hop++) {
    const next: number[] = [];
    for (const slot of frontier) {
      const neighbors = relAdj.get(slot) ?? [];
      for (const nbr of neighbors) {
        if (visited.has(nbr)) continue;
        visited.add(nbr);
        const ev = anchorSlotToEvent.get(nbr);
        if (!ev) continue;
        // Add this neighbor's truth docs to the pool.
        for (const td of ev.truthDocuments) {
          const existing = pool.get(td.id);
          if (existing) { addSource(existing, 'anchorBFS'); continue; }
          const emb = ev.embeddings.perTruth.get(td.id);
          if (!emb) continue;
          pool.set(td.id, {
            docId: td.id,
            embedding: emb,
            text: td.text,
            eventId: ev.id,
            memorySlot: nbr,
            isCurrentTruth: td.isCurrent,
            isStaleTruth: !td.isCurrent,
            sources: new Set(['anchorBFS']),
          });
          anchorBfsExpansionAdded++;
          if (anchorBfsExpansionAdded >= opts.relationExpansionBudget) break;
        }
        next.push(nbr);
        if (anchorBfsExpansionAdded >= opts.relationExpansionBudget) break;
      }
      if (anchorBfsExpansionAdded >= opts.relationExpansionBudget) break;
    }
    frontier = next;
  }

  // Anchor-seeded corpus-relation expansion (substrate-controlled relation routing).
  // A decoded relation edge from anchored slot S carries an edgeType T; it instructs
  // the scorer to follow event(S)'s CORPUS relations of edgeType T to related events
  // and add their truths via anchorBFS — reaching NON-anchored relation targets that
  // the pure anchor-to-anchor BFS above cannot (that BFS pre-marks every anchored
  // slot visited, so it never adds a node; this is the fix). Bounded by
  // relationExpansionBudget; the reranker still judges. Substrate chooses WHICH
  // anchored event + edgeType to follow; it cannot fabricate corpus edges.
  const eventByCorpusIdForPhaseA = corpusByCorpusId(corpus);
  const relEdgeTypesBySlot = new Map<number, Set<string>>();
  for (const e of decoded.relations) {
    let s = relEdgeTypesBySlot.get(e.sourceSlot);
    if (!s) { s = new Set<string>(); relEdgeTypesBySlot.set(e.sourceSlot, s); }
    s.add(e.edgeType);
  }
  for (const [slot, ev] of anchorSlotToEvent) {
    if (anchorBfsExpansionAdded >= opts.relationExpansionBudget) break;
    const edgeTypes = relEdgeTypesBySlot.get(slot);
    if (!edgeTypes || !ev.relations) continue;
    for (const rel of ev.relations) {
      if (anchorBfsExpansionAdded >= opts.relationExpansionBudget) break;
      if (!edgeTypes.has(rel.edgeType)) continue;
      const tgt = eventByCorpusIdForPhaseA.get(rel.other_id);
      if (!tgt) continue;
      for (const td of tgt.truthDocuments) {
        const existing = pool.get(td.id);
        if (existing) { addSource(existing, 'anchorBFS'); continue; }
        const emb = tgt.embeddings.perTruth.get(td.id);
        if (!emb) continue;
        pool.set(td.id, {
          docId: td.id, embedding: emb, text: td.text, eventId: tgt.id,
          memorySlot: null, isCurrentTruth: false, isStaleTruth: false,
          sources: new Set(['anchorBFS']),
        });
        anchorBfsExpansionAdded++;
        if (anchorBfsExpansionAdded >= opts.relationExpansionBudget) break;
      }
    }
  }

  // Tag pool entries that match an active anchor directly with the anchor's slot.
  for (const [slot, ev] of anchorSlotToEvent) {
    for (const td of ev.truthDocuments) {
      const entry = pool.get(td.id);
      if (entry && entry.memorySlot === null) {
        entry.memorySlot = slot;
        entry.isCurrentTruth = td.isCurrent;
        entry.isStaleTruth = !td.isCurrent;
      }
    }
  }

  // ─── Phase B: stage-1 BFS expansion via corpus-native event.relations ─────
  // For each stage-1 candidate doc, find its source event; follow the event's
  // corpus-native relations whose edgeType matches one of the substrate's
  // category-lens entries; add the related event's truth docs to the pool.
  //
  // Phase B carries its OWN budget — `categoryLensExpansionBudget` —
  // separate from Phase A's `relationExpansionBudget`. On launch-corpus
  // scale (~296k corpus relation edges), sharing one budget let Phase B
  // flood the candidate pool with hundreds of plausible-but-irrelevant
  // docs and displace anchor-mandatory truths from the reranker's
  // top-10 (commit ce106be artifact). Splitting the budgets lets the
  // operator disable Phase B (categoryLensExpansionBudget=0) while
  // retaining Phase A's anchor-graph routing. Default value falls back
  // to `relationExpansionBudget` for backwards compatibility with
  // bundles that predate the split.
  //
  // This remains the substrate's corpus-scale retrieval lever that scales
  // past the 44-anchor cap. Stage-1 surfacing ANY question with the same
  // answer-entity reaches that entity's truth doc via category-lens; the
  // reranker scores it. Anti-cheat invariant intact: the substrate only
  // chooses WHICH edgeTypes to follow; it cannot manufacture new edges.
  const categoryLensExpansionBudget = opts.categoryLensExpansionBudget ?? opts.relationExpansionBudget;
  const lensesByEdgeType = new Map<string, RelationCategoryLens>();
  for (const lens of decoded.categoryLenses) {
    // If multiple lenses share an edgeType, keep the highest-weight one.
    const existing = lensesByEdgeType.get(lens.edgeType);
    if (!existing || lens.weight > existing.weight) lensesByEdgeType.set(lens.edgeType, lens);
  }
  const eventByCorpusId = corpusByCorpusId(corpus);
  /** Per-doc category-lens weight (max across applicable lenses), normalised to [0,1). */
  const categoryLensWeightByDocId = new Map<string, number>();
  /**
   * Lens-edge adjacency (event ↔ event), recorded as the BFS traverses each
   * matching category-lens edge. Used by SCORE-INHERITANCE: a surface-dissimilar
   * answer that the reranker under-ranks can inherit a bounded fraction of its
   * lens-linked bridge's reranker score, but ONLY along a genuine public edge —
   * so a junk edge (whose peer scores low) confers no boost. Targeted, one-hop,
   * flood-resistant. Empty / unused unless `categoryLensScoreInheritance > 0`.
   */
  const lensPeerEvents = new Map<string, Set<string>>();
  const addLensPeer = (a: string, b: string) => {
    let s = lensPeerEvents.get(a); if (!s) { s = new Set(); lensPeerEvents.set(a, s); } s.add(b);
    let t = lensPeerEvents.get(b); if (!t) { t = new Set(); lensPeerEvents.set(b, t); } t.add(a);
  };
  if (lensesByEdgeType.size > 0 && categoryLensExpansionBudget > 0) {
    // Per-event semantic cluster: BFS follows category-lens-matching edges
    // BIDIRECTIONALLY. Stage-1 finds similar question events; forward edges
    // (question → answer-entity) plus inverse edges (entity ← all questions
    // pointing at it) close the cluster around the query's answer entity.
    // This is the lever that lets multi-hop / long-horizon families reach
    // their own truth docs via stage-1 docs that share the same answer
    // entity. Without bidirectional, the cluster is one-hop only and recall
    // remains at the stage-1 ceiling.
    const traversalDirection = opts.categoryLensTraversalDirection ?? 'bidirectional';
    const inverseIndex = traversalDirection === 'bidirectional'
      ? getOrBuildInverseRelationIndex(corpus)
      : null;
    const visitedEventIds = new Set<string>();
    // Seed BFS with the stage-1 candidate events. PRECISE-ADMISSION: when
    // `categoryLensSeedTopK` is set, seed ONLY from the top-K most query-similar
    // stage-1 docs (stage1Docs is sorted descending by cosine), so relation routing
    // expands from the query's genuinely relevant seed (e.g. the bridge doc) rather
    // than from every stage-1 candidate — the latter admits the whole edge-type
    // CATEGORY into the pool and floods deep universes. Default (undefined): legacy
    // all-stage-1-seed behaviour (no-op on shallow owner-scoped stores).
    const seedTopK = opts.categoryLensSeedTopK !== undefined && opts.categoryLensSeedTopK > 0
      ? opts.categoryLensSeedTopK : stage1Docs.length;
    for (let i = 0; i < stage1Docs.length && i < seedTopK; i++) visitedEventIds.add(stage1Docs[i]!.eventId);
    let frontierEventIds: string[] = Array.from(visitedEventIds);

    let categoryLensExpansionAdded = 0;
    const lensHopBudget = opts.categoryLensHopBudget !== undefined && opts.categoryLensHopBudget > 0
      ? opts.categoryLensHopBudget : opts.relationHopBudget;
    for (let hop = 0; hop < lensHopBudget && categoryLensExpansionAdded < categoryLensExpansionBudget; hop++) {
      const next: string[] = [];
      for (const eventId of frontierEventIds) {
        if (categoryLensExpansionAdded >= categoryLensExpansionBudget) break;
        const sourceEvent = eventByCorpusId.get(eventId);
        if (!sourceEvent) continue;

        // Forward edges: event.relations[*]
        if (sourceEvent.relations) {
          for (const rel of sourceEvent.relations) {
            const lens = lensesByEdgeType.get(rel.edgeType);
            if (!lens) continue;
            const tgtId = rel.other_id;
            const targetEvent = eventByCorpusId.get(tgtId);
            if (!targetEvent) continue;
            // Apply routing signal to the target's docs whether or not the
            // target is already in the pool (tagging existing consumes no
            // budget). Only ENQUEUE for further expansion if newly visited.
            categoryLensExpansionAdded += addEventTruthsToPool(
              targetEvent, pool, categoryLensWeightByDocId, lens.weight / 0xFFFF,
              categoryLensExpansionBudget - categoryLensExpansionAdded,
            );
            addLensPeer(eventId, tgtId);
            if (!visitedEventIds.has(tgtId)) { visitedEventIds.add(tgtId); next.push(tgtId); }
            if (categoryLensExpansionAdded >= categoryLensExpansionBudget) break;
          }
        }

        // Inverse edges: events that have a relation pointing AT this event.
        // For category-lens semantics, the edgeType filter still applies —
        // we only traverse inverse edges whose forward edgeType matches a
        // substrate lens. Cross-reference via the precomputed inverse index.
        const inverseRels = inverseIndex?.get(eventId);
        if (inverseRels) {
          for (const inv of inverseRels) {
            const lens = lensesByEdgeType.get(inv.edgeType);
            if (!lens) continue;
            const srcId = inv.fromEventId;
            const sourceFromInverse = eventByCorpusId.get(srcId);
            if (!sourceFromInverse) continue;
            categoryLensExpansionAdded += addEventTruthsToPool(
              sourceFromInverse, pool, categoryLensWeightByDocId, lens.weight / 0xFFFF,
              categoryLensExpansionBudget - categoryLensExpansionAdded,
            );
            addLensPeer(eventId, srcId);
            if (!visitedEventIds.has(srcId)) { visitedEventIds.add(srcId); next.push(srcId); }
            if (categoryLensExpansionAdded >= categoryLensExpansionBudget) break;
          }
        }
      }
      frontierEventIds = next;
    }
  }

  // ─── Stage 2 bonuses: lens, anchor, temporal ─────────────────────────────
  const activeLensVecs: Float32Array[] = [];
  for (let s = 0; s < decoded.retrievalKeys.length; s++) {
    const key = decoded.retrievalKeys[s];
    if (!key) continue;
    if (key.modelIdHash.toLowerCase() !== opts.biEncoderHash.toLowerCase()) continue;
    activeLensVecs.push(dequantize(key.quantizedBytes, opts.retrievalKeyLayout));
    if (activeLensVecs.length >= opts.lensTopK) break;
  }

  // Anchor truth embeddings (one per active anchor that has a current/sole truth).
  const anchorTruthVecs: Float32Array[] = [];
  for (const [, ev] of anchorSlotToEvent) {
    // Pick the current truth if any, else the first truth.
    const truth = ev.truthDocuments.find((t) => t.isCurrent) ?? ev.truthDocuments[0];
    if (!truth) continue;
    const emb = ev.embeddings.perTruth.get(truth.id);
    if (!emb) continue;
    anchorTruthVecs.push(dequantize(emb, opts.retrievalKeyLayout));
  }

  const isTemporalQuery = query.family === 'temporal';
  // ORACLE scoped-lifecycle (temporalOracleScopePerQuery): the set of doc ids that belong to THIS
  // query's own temporal truth (current + stale). Used to scope temporal modulation to the owning
  // query so one chain's boost can't flood neighbour temporal queries. null = blunt global default.
  const ownTemporalTruthIds = (opts.temporalOracleScopePerQuery === true && isTemporalQuery)
    ? new Set((query.truthDocuments ?? []).map((t) => t.id))
    : null;

  // §temporal — SUBSTRATE-CONTROLLED temporal modulation, driven by the miner's
  // decoded Temporal records (decoded.temporal), NOT corpus isCurrentTruth labels
  // (which the miner doesn't control and would leak an oracle).
  // Semantics (spec substrate_retrieval_semantics.md): currentStaleFlag=true marks
  // a STALE memory (its MemoryIndex slot must be revoked); supersededBy points to
  // the current replacement slot. We map each record's slot -> event via recordId
  // (decoded.memoryIndex includes revoked slots) so suppression/boost reaches the
  // event's docs ANYWHERE in the pool (stage1-retrieved OR anchored) — temporal is
  // event-scoped, not anchor-gated.
  const temporalSuppressEventIds = new Set<string>();
  const temporalBoostEventIds = new Set<string>();
  for (const tr of decoded.temporal) {
    const slot = decoded.memoryIndex[tr.memorySlot];
    if (!slot) continue;
    const ev = corpusByRecordId.get(slot.recordId);
    if (!ev) continue;
    if (tr.currentStaleFlag) {
      temporalSuppressEventIds.add(ev.id); // stale (revoked slot)
      if (tr.supersededBy !== 0xff) {
        const curSlot = decoded.memoryIndex[tr.supersededBy];
        const curEv = curSlot ? corpusByRecordId.get(curSlot.recordId) : undefined;
        if (curEv) temporalBoostEventIds.add(curEv.id); // the current replacement
      }
    } else {
      temporalBoostEventIds.add(ev.id); // explicitly-current memory
    }
  }

  // Phase B bonus knobs (hoisted; constant across the pool). bonusEnabled=false
  // zeroes the bias (inclusion-only test); bonusWeight overrides the scale.
  //
  // NON-FLOODING PROMOTION (split admission from final reorder): the category-lens
  // bonus has TWO scales. The ADMISSION scale (`categoryLensBonusWeight`) adds to
  // the PRE-RANK score so a routed doc enters the reranker cap. The FINAL scale
  // (`categoryLensFinalBonusWeight`) adds to the FINAL reorder. P2 flooded because
  // a large additive bonus in the FINAL reorder swamped the reranker and force-
  // floated the whole lens blob into top-10. Inclusion-only sets the final scale
  // to ~0 so category-lens routing earns a candidate the chance to be judged but
  // the RERANKER determines final order. Back-compat: when unset, the final scale
  // defaults to the admission scale → identical to the legacy single-bonus path.
  const categoryLensBonusEnabled = opts.categoryLensBonusEnabled ?? true;
  const categoryLensAdmissionScale = opts.categoryLensBonusWeight ?? opts.lensWeight;
  const categoryLensFinalScale = opts.categoryLensFinalBonusWeight ?? categoryLensAdmissionScale;

  // ─── EvidencePolicy (opt-in, default off): miner-written CODEBOOK policy atoms ──
  // high_density_evidence (code=5): a generalizable contribution rule — boost
  // candidates whose event has PUBLIC supports-edge in-degree >= K (corroboration),
  // with the atom's bounded weight. In-degree is corpus-derived (public, auditable);
  // the miner writes only the POLICY (threshold + weight), never a doc/query/answer
  // map. Family-agnostic for v1. Default off → contributionBoostByEventId stays empty
  // and the per-candidate bonus below is 0 (default path unchanged).
  const POLICY_HIGH_DENSITY = 5;
  const contributionBoostByEventId = new Map<string, number>();
  if (opts.evidencePolicyEnabled === true) {
    const atoms = decoded.codebook.filter(
      (e): e is NonNullable<typeof e> => e !== null && e.valid && e.code === POLICY_HIGH_DENSITY,
    );
    if (atoms.length > 0) {
      const inDeg = getOrBuildSupportsInDegree(corpus);
      for (const a of atoms) {
        const k = Number(a.payload & 0xffffn);                       // bits[15:0]  = in-degree threshold
        const weightPpm = Number((a.payload >> 16n) & 0xffffffffn);  // bits[47:16] = weight (ppm)
        const w = Math.max(0, Math.min(1, weightPpm / 1_000_000));
        if (k <= 0 || w <= 0) continue;
        for (const [evId, deg] of inDeg) {
          if (deg >= k) {
            const prev = contributionBoostByEventId.get(evId) ?? 0;
            if (w > prev) contributionBoostByEventId.set(evId, w);
          }
        }
      }
    }
  }
  const evidencePolicyActive = contributionBoostByEventId.size > 0;

  // Compute substrateBonus + pre-rank score per pool entry.
  //
  // §6.5 reranker-input cap (MemReranker semantics). The reranker is a
  // cross-encoder; running it over the full stage-1 pool (firstStageTopK,
  // typ. 3200) at 0.6B params × 2048 seq len is O(firstStageTopK) per query.
  // The canonical MemReranker shape is: bi-encoder candidates → small
  // top-N pre-ranked pool → cross-encoder refinement on top-N only.
  //
  // We restore that shape with a TWO-key pre-rank: (biCosine + substrateBonus).
  // - The biCosine half preserves recall on docs the bi-encoder ranked highly
  //   even when the substrate is empty (early-epoch miners with no substrate
  //   still get correct rankings).
  // - The substrateBonus half keeps the substrate's full expressive power:
  //   a doc the substrate finds compelling (anchor, lens-aligned, BFS-reached)
  //   gets promoted into the reranker pool even if biCosine alone would have
  //   ranked it far down. Substrate-promoted docs from stage-1 rank-3000 still
  //   make it to the reranker. The cap is on COMPUTE per query, not on what
  //   the substrate can express.
  const candidates: {
    record: CandidateRecord;
    admissionBonus: number;  // pre-rank cap inclusion bias
    finalBonus: number;      // final-reorder bias (reranker-dominated under inclusion-only)
    biCosine: number;
    preRankScore: number;
    docVec: Float32Array;
    lensBonus: number;
    anchorBonus: number;
    categoryLensBonus: number;       // admission-scale (drives cap inclusion)
    categoryLensFinalBonus: number;  // final-scale (drives final reorder)
    temporalBonus: number;
    evidencePolicyBonus: number;     // CODEBOOK high_density_evidence contribution boost
  }[] = [];
  for (const record of pool.values()) {
    const docVec = dequantize(record.embedding, opts.retrievalKeyLayout);

    let lensMaxCos = 0;
    for (const lens of activeLensVecs) {
      const c = cosineSimilarity(docVec, lens);
      if (c > lensMaxCos) lensMaxCos = c;
    }
    const lensBonus = activeLensVecs.length > 0 ? opts.lensWeight * lensMaxCos : 0;

    let anchorMaxCos = 0;
    for (const av of anchorTruthVecs) {
      const c = cosineSimilarity(docVec, av);
      if (c > anchorMaxCos) anchorMaxCos = c;
    }
    const anchorBonus = anchorTruthVecs.length > 0 ? opts.anchorWeight * anchorMaxCos : 0;

    // Temporal bonus driven by the miner's decoded Temporal records, event-scoped
    // (reaches stage1-retrieved docs of marked events), NOT corpus labels.
    let temporalBonus = 0;
    if (isTemporalQuery && (ownTemporalTruthIds === null || ownTemporalTruthIds.has(record.docId))) {
      if (temporalSuppressEventIds.has(record.eventId)) temporalBonus = -opts.temporalStaleSuppression;
      else if (temporalBoostEventIds.has(record.eventId)) temporalBonus = opts.temporalCurrentBoost;
    }

    // Phase B: docs that entered the pool via a category-lens carry the
    // (max-over-applicable) lens weight as an additive bonus. The substrate
    // expresses preference for the edge-types whose expansion brought
    // useful answers; the reranker still has final say.
    const categoryLensNormWeight = categoryLensWeightByDocId.get(record.docId) ?? 0;
    const categoryLensBonus = categoryLensBonusEnabled
      ? categoryLensAdmissionScale * categoryLensNormWeight
      : 0;
    const categoryLensFinalBonus = categoryLensBonusEnabled
      ? categoryLensFinalScale * categoryLensNormWeight
      : 0;

    // Admission (pre-rank cap inclusion) vs final (reorder) bonuses. lens/anchor/
    // temporal contribute to BOTH; only the category-lens routing bonus is split,
    // so an inclusion-only profile (categoryLensFinalBonusWeight≈0) lets the
    // reranker — not a flat lens bias — decide final order among routed docs.
    // EvidencePolicy contribution boost (opt-in; 0 unless a high_density atom matched).
    // ADMISSION-ONLY (non-flooding promotion, mirrors the relation inclusion-only fix): the
    // policy lifts a low-cosine but corroborated answer INTO the reranker cap; the RERANKER
    // decides final order among the admitted corroborated class. Adding it to the FINAL reorder
    // force-floats the whole boosted class into top-10 (flood), so it is excluded from finalBonus.
    const evidencePolicyBonus = evidencePolicyActive ? (contributionBoostByEventId.get(record.eventId) ?? 0) : 0;

    const admissionBonus = lensBonus + anchorBonus + temporalBonus + categoryLensBonus + evidencePolicyBonus;
    const finalBonus = lensBonus + anchorBonus + temporalBonus + categoryLensFinalBonus;
    const biCosine = cosineSimilarity(docVec, queryVec);
    candidates.push({
      record,
      admissionBonus,
      finalBonus,
      biCosine,
      preRankScore: biCosine + admissionBonus,
      docVec,
      lensBonus,
      anchorBonus,
      categoryLensBonus,
      categoryLensFinalBonus,
      temporalBonus,
      evidencePolicyBonus,
    });
  }

  if (candidates.length === 0) {
    return { ranked: [], top1Score: 0, cappedDocIds: [], cappedDocSources: [], cappedDocComponents: [], finalRankingTop20: [], answerInCap: false, finalRankingFull: opts.exposeFullRanking === true ? [] : undefined, policyTraces: [], policyAbstain: false };
  }

  // ─── §6.5 reranker-input cap: take top-N by pre-rank ─────────────────────
  // Sort all candidates by (biCosine + substrateBonus) DESCENDING, then take
  // top `rerankerInputTopK`. Tie-break by docId (lexicographic) so the cap is
  // byte-deterministic across hosts — two candidates with identical pre-rank
  // scores would otherwise be order-dependent on Map iteration, and that's a
  // determinism foot-gun. Docs that don't make the cap get a sentinel
  // rerankerScore of 0 and finalReorderingScore = substrateBonus only; they
  // can still appear in the final ranking but at the bottom.
  //
  // §6.5+ ANCHOR-MANDATORY: docs nominated by an active substrate anchor
  // (memorySlot !== null) are MANDATORY pool inclusions. Without this,
  // anchor's own truth gets dropped by preRank for queries where biCosine
  // is low (multi_hop / long_horizon — exactly the families the substrate
  // most needs to route). Anchors are the substrate's strongest "this
  // matters" signal; the reranker MUST see them. Bounded above by the
  // 44 MemoryIndex slot count, so this contributes at most 44 + truth-doc
  // multiplicity per query — well under any reasonable cap.
  candidates.sort((a, b) => {
    if (b.preRankScore !== a.preRankScore) return b.preRankScore - a.preRankScore;
    return a.record.docId < b.record.docId ? -1 : a.record.docId > b.record.docId ? 1 : 0;
  });
  const rerankerInputCap = Math.max(1, opts.rerankerInputTopK);

  // §6.5+ Anchor-mandatory sub-cap. With 44 MemoryIndex slots and events
  // possibly carrying multiple truth docs, an unbounded mandatory pool could
  // exceed `rerankerInputTopK` and cause unbounded reranker work per query —
  // a worst-case DoS for the open-source replay validator. We cap mandatory
  // inclusions at the cap itself, taking docs in (slot, docId) lexicographic
  // order so the truncation is byte-deterministic across replay hosts.
  const anchorMandatoryAll = candidates
    // Force-include direct anchors (memorySlot set) AND relation-routed docs
    // (anchorBFS) so a substrate-routed answer the bi-encoder ranked far down
    // still reaches the reranker. Both are bounded by relationExpansionBudget +
    // the 44-slot anchor cap, so this cannot blow up the reranker workload.
    .filter((c) => c.record.memorySlot !== null || c.record.sources.has('anchorBFS'))
    .sort((a, b) => {
      const sa = a.record.memorySlot ?? 0;
      const sb = b.record.memorySlot ?? 0;
      if (sa !== sb) return sa - sb;
      return a.record.docId < b.record.docId ? -1 : 1;
    });
  const anchorMandatory = anchorMandatoryAll.slice(0, rerankerInputCap);
  const anchorMandatoryIds = new Set(anchorMandatory.map((c) => c.record.docId));
  const preRankFill = candidates.filter((c) => !anchorMandatoryIds.has(c.record.docId));
  const fillCount = Math.max(0, rerankerInputCap - anchorMandatory.length);
  const rerankerCandidates = anchorMandatory.concat(preRankFill.slice(0, fillCount));

  // ─── Reranker: cross-encoder over (query, candidate-text) pairs ──────────
  // EVIDENCE-BUNDLE: for a category-lens-routed candidate, bundle its highest-query-
  // similarity lens-peer (the bridge) into the document so the reranker sees the
  // relevance-carrying bridge alongside the lexically-distant answer.
  const evidenceBundle = opts.categoryLensEvidenceBundle === true && lensPeerEvents.size > 0;
  let bestPeerTextByEvent: Map<string, string> | null = null;
  if (evidenceBundle) {
    // per-event: the highest-biCosine candidate text (the most query-similar doc of that event).
    const bestByEvent = new Map<string, { text: string; biCosine: number }>();
    for (const c of candidates) {
      const cur = bestByEvent.get(c.record.eventId);
      if (!cur || c.biCosine > cur.biCosine) bestByEvent.set(c.record.eventId, { text: c.record.text, biCosine: c.biCosine });
    }
    bestPeerTextByEvent = new Map();
    for (const [ev] of bestByEvent) bestPeerTextByEvent.set(ev, bestByEvent.get(ev)!.text);
  }
  const bundleDoc = (c: typeof rerankerCandidates[number]): string => {
    if (!evidenceBundle || !c.record.sources.has('categoryLensBFS')) return c.record.text;
    const peers = lensPeerEvents.get(c.record.eventId);
    if (!peers || peers.size === 0) return c.record.text;
    // pick the peer event with the highest query-biCosine (the bridge seed).
    let bridgeText: string | null = null, bridgeCos = -Infinity;
    for (const pe of peers) {
      const t = bestPeerTextByEvent?.get(pe);
      if (t === undefined) continue;
      const bc = candidates.find((x) => x.record.eventId === pe)?.biCosine ?? -Infinity;
      if (bc > bridgeCos) { bridgeCos = bc; bridgeText = t; }
    }
    return bridgeText ? `Bridge evidence:\n${bridgeText}\nCandidate answer:\n${c.record.text}` : c.record.text;
  };
  const pairs = rerankerCandidates.map((c) => ({ query: query.queryText, document: bundleDoc(c) }));
  const rerankerScoresTopN = pairs.length > 0 ? await opts.reranker.score(pairs) : [];
  if (rerankerScoresTopN.length !== pairs.length) {
    throw new Error(
      `retrieval-benchmark: reranker returned ${rerankerScoresTopN.length} scores for ${pairs.length} pairs`,
    );
  }
  for (let i = 0; i < rerankerScoresTopN.length; i++) {
    if (!Number.isFinite(rerankerScoresTopN[i])) {
      throw new Error(`retrieval-benchmark: reranker score[${i}] is non-finite (${rerankerScoresTopN[i]})`);
    }
  }
  // Map rerank scores back to candidates by docId. Indexing by array
  // position is unsafe because `rerankerCandidates = anchorMandatory ++
  // preRankFill` reorders relative to `candidates` (anchor-mandatory docs
  // are pulled to the front of the rerank pool regardless of preRank
  // position). A positional copy attaches scores to the wrong docs
  // whenever any anchor-mandatory candidate is not already the top-
  // preRank doc. Non-reranked docs (those that didn't make the cap) get 0.
  const rerankerScoreByDocId = new Map<string, number>();
  for (let i = 0; i < rerankerCandidates.length; i++) {
    rerankerScoreByDocId.set(rerankerCandidates[i]!.record.docId, rerankerScoresTopN[i]!);
  }

  // ─── Score-inheritance (optional, default off) ───────────────────────────
  // A lens-edge target inherits `alpha × its best lens-peer's reranker score`
  // (one hop), floored at its own score. This lifts a surface-dissimilar bridge
  // ANSWER that the reranker under-ranks, using the signal that it is linked to
  // a high-scoring BRIDGE — but ONLY along a genuine public edge. A junk edge's
  // peer scores low, so it confers no boost (flood-resistant). The reported
  // `rerankerScore` stays RAW (honest attribution); only the final reorder uses
  // the inherited score. alpha=0 ⇒ exact legacy behavior.
  const inheritAlpha = opts.categoryLensScoreInheritance ?? 0;
  const effectiveRerankByDocId = new Map<string, number>();
  if (inheritAlpha > 0 && lensPeerEvents.size > 0) {
    const docsByEvent = new Map<string, string[]>();
    for (const c of candidates) {
      const arr = docsByEvent.get(c.record.eventId);
      if (arr) arr.push(c.record.docId); else docsByEvent.set(c.record.eventId, [c.record.docId]);
    }
    const _dbg = process.env.CORETEX_INHERIT_DEBUG === '1';
    let _dbgLensDocs = 0, _dbgWithPeers = 0, _dbgPeerMaxPos = 0, _dbgLifted = 0;
    for (const c of candidates) {
      const own = rerankerScoreByDocId.get(c.record.docId) ?? 0;
      let peerMax = 0;
      const peers = lensPeerEvents.get(c.record.eventId);
      if (peers) {
        for (const pe of peers) {
          for (const pd of docsByEvent.get(pe) ?? []) {
            const ps = rerankerScoreByDocId.get(pd) ?? 0;
            if (ps > peerMax) peerMax = ps;
          }
        }
      }
      const inherited = inheritAlpha * peerMax;
      effectiveRerankByDocId.set(c.record.docId, inherited > own ? inherited : own);
      if (_dbg && c.record.sources.has('categoryLensBFS')) { _dbgLensDocs++; if (peers && peers.size) _dbgWithPeers++; if (peerMax > 0) _dbgPeerMaxPos++; if (inherited > own) _dbgLifted++; }
    }
    if (_dbg) console.error(`[inherit-dbg] q=${query.id} lensPeerEvents=${lensPeerEvents.size} catLensDocs=${_dbgLensDocs} withPeers=${_dbgWithPeers} peerMax>0=${_dbgPeerMaxPos} lifted=${_dbgLifted}`);
  }
  const effRerank = (docId: string, raw: number): number =>
    inheritAlpha > 0 ? (effectiveRerankByDocId.get(docId) ?? raw) : raw;

  // ─── r5 PolicyAtoms: BOUNDED QUERY-LOCAL final-reorder nudges ─────────────
  // Reproduces the A100 oracle's per-query bounded intervention from PUBLIC structure
  // only: per query, UNIT = (max−min rerankerScore over this query's OWN reranked list);
  // an atom adds ±(budget/1000)·UNIT to the docs it targets, where the target set is
  // reconstructed from PUBLIC edges out of the atom's MemoryIndex anchor (NO qrel/answer id).
  // An atom fires ONLY if its anchor event is present in THIS query's candidate pool
  // (query-local gate). Disabled families are skipped. No atoms ⇒ zero bonus ⇒ byte-identical
  // to the r4 final reorder (the no-op safety invariant).
  const policyBonusByDocId = new Map<string, number>();
  const policyTraces: PolicyAtomTrace[] = [];
  let policyAbstain = false;
  if (opts.policyAtomsMode === true) {
    const rsVals = rerankerCandidates.map((c) => rerankerScoreByDocId.get(c.record.docId) ?? 0);
    const UNIT = rsVals.length ? Math.max(...rsVals) - Math.min(...rsVals) : 0;
    const docsByEventLocal = new Map<string, string[]>();
    const eventsInPool = new Set<string>();
    for (const c of candidates) {
      eventsInPool.add(c.record.eventId);
      const a = docsByEventLocal.get(c.record.eventId);
      if (a) a.push(c.record.docId); else docsByEventLocal.set(c.record.eventId, [c.record.docId]);
    }
    const sign = (action: string): number => (action === 'suppress' ? -1 : 1);
    const addBonus = (docId: string, delta: number) => policyBonusByDocId.set(docId, (policyBonusByDocId.get(docId) ?? 0) + delta);
    const PUBLIC_EDGES = new Set(['supports', 'supersedes', 'coreference_of', 'causes', 'derived_from', 'co_occurs_with']);

    // Evidence-bundle / answer-density: target = anchor's PUBLIC-edge reach (+ anchor's own docs for bundle/include).
    if (opts.enableEvidenceBundleAtoms !== false) {
      for (const atom of decoded.evidenceBundleAtoms) {
        const anchorEv = anchorSlotToEvent.get(atom.targetSlot);
        if (!anchorEv || !eventsInPool.has(anchorEv.id)) continue; // query-local gate
        const beta = Math.min(atom.budget, opts.policyMaxBudgetEvidence ?? atom.budget) / 1000;
        const target = new Set<string>();
        const evidencePath: string[] = [];
        for (const rel of anchorEv.relations ?? []) {
          if (!PUBLIC_EDGES.has(rel.edgeType)) continue;
          const tgt = eventByCorpusIdForPhaseA.get(rel.other_id);
          if (!tgt || !docsByEventLocal.has(tgt.id)) continue;
          for (const d of docsByEventLocal.get(tgt.id)!) target.add(d);
          evidencePath.push(`${rel.edgeType}->${tgt.id}`);
        }
        if (atom.action === 'bundle' || atom.action === 'include') for (const d of docsByEventLocal.get(anchorEv.id) ?? []) target.add(d);
        if (target.size === 0) continue;
        for (const d of target) addBonus(d, sign(atom.action) * beta * UNIT);
        if (opts.policyEmitTraces) policyTraces.push({ atomId: `eb#${atom.atomIndex}`, atomFamily: 'evidence_bundle', selectorMatched: true, action: atom.action, anchorEvent: anchorEv.id, docsMoved: target.size, evidencePath, beta });
      }
    }
    // Conflict_lifecycle: target = anchor event's OWN docs (miner anchors boost@resolved, suppress@candidate;
    // resolved-vs-candidate is the miner's PUBLIC supersedes-structure judgment, encoded as the action choice).
    if (opts.enableConflictLifecycleAtoms !== false) {
      for (const atom of decoded.conflictLifecycleAtoms) {
        const anchorEv = anchorSlotToEvent.get(atom.targetSlot);
        if (!anchorEv || !eventsInPool.has(anchorEv.id)) continue; // query-local: same conflict set in pool
        const beta = Math.min(atom.budget, opts.policyMaxBudgetConflict ?? atom.budget) / 1000;
        const ownDocs = docsByEventLocal.get(anchorEv.id) ?? [];
        if (ownDocs.length === 0) continue;
        for (const d of ownDocs) addBonus(d, sign(atom.action) * beta * UNIT);
        if (opts.policyEmitTraces) policyTraces.push({ atomId: `cl#${atom.atomIndex}`, atomFamily: 'conflict_lifecycle', selectorMatched: true, action: atom.action, anchorEvent: anchorEv.id, docsMoved: ownDocs.length, evidencePath: [], beta });
      }
    }
    // Abstention: SPLIT — miner atom supplies the public no-evidence-path policy; the confidence
    // gate (top1 < threshold) is the OPERATOR PROFILE calibration. Abstain only when BOTH hold.
    if (opts.enableAbstentionAtoms !== false && decoded.abstentionAtoms.length > 0) {
      const hasPublicEvidencePath = candidates.some((c) => c.record.memorySlot !== null || c.record.sources.has('anchorBFS') || c.record.sources.has('categoryLensBFS'));
      const maxRerank = rsVals.length ? Math.max(...rsVals) : 0;
      const thr = opts.policyAbstentionTop1Threshold;
      for (const atom of decoded.abstentionAtoms) {
        const requireNoEvidence = (atom.flags & 0x01) !== 0;
        const noEvidenceOk = !requireNoEvidence || !hasPublicEvidencePath;
        const confidenceOk = thr === undefined || maxRerank < thr;
        if (atom.selector === POLICY_SELECTOR.MISSING_EVIDENCE && noEvidenceOk && confidenceOk) {
          policyAbstain = true;
          if (opts.policyEmitTraces) policyTraces.push({ atomId: `ab#${atom.atomIndex}`, atomFamily: 'abstention', selectorMatched: true, action: 'abstain', anchorEvent: null, docsMoved: 0, evidencePath: [], beta: 0 });
          break;
        }
      }
    }
  }

  // ─── Pinned final ranking formula ────────────────────────────────────────
  const qrelById = new Map(query.qrels.map((q) => [q.documentId, q.relevance]));
  const ranked = candidates
    .map((c) => {
      const r = rerankerScoreByDocId.get(c.record.docId) ?? 0;
      return {
        documentId: c.record.docId,
        memorySlot: c.record.memorySlot,
        rerankerScore: r,
        finalReorderingScore: effRerank(c.record.docId, r) + c.finalBonus + (policyBonusByDocId.get(c.record.docId) ?? 0),
        relevance: qrelById.get(c.record.docId) ?? 0,
      };
    })
    .sort((a, b) => {
      if (b.finalReorderingScore !== a.finalReorderingScore) {
        return b.finalReorderingScore - a.finalReorderingScore;
      }
      if (b.rerankerScore !== a.rerankerScore) return b.rerankerScore - a.rerankerScore;
      return a.documentId < b.documentId ? -1 : a.documentId > b.documentId ? 1 : 0;
    })
    .map((r) => ({
      documentId: r.documentId,
      memorySlot: r.memorySlot,
      rerankerScore: r.rerankerScore,
      relevance: r.relevance,
    }));

  const top1Score = ranked.length > 0 ? ranked[0]!.rerankerScore : 0;
  // Expose the cap pool's docIds so gates G1/G2 can verify substrate
  // routing without inferring from rerankerScore==0 sentinels.
  const cappedDocIds = rerankerCandidates.map((c) => c.record.docId);
  const cappedDocSources = rerankerCandidates.map((c) => Array.from(c.record.sources));
  const cappedDocComponents = rerankerCandidates.map((c) => ({
    biCosine: c.biCosine,
    lensBonus: c.lensBonus,
    anchorBonus: c.anchorBonus,
    categoryLensBonus: c.categoryLensBonus,
    temporalBonus: c.temporalBonus,
    preRankScore: c.preRankScore,
  }));
  // Final ranking top-20 with full attribution + components. Joining
  // candidate components into the final-rank ordering lets
  // downstream answer "which mechanism produced relevant docs in
  // top-10" and "which surface injected hard negatives at top-20."
  const componentsByDocId = new Map(candidates.map((c) => [c.record.docId, c]));
  const finalRankingTop20 = ranked.slice(0, 20).map((r, idx) => {
    const c = componentsByDocId.get(r.documentId);
    const cs = c?.record.sources;
    const finalReorderingScore = effRerank(r.documentId, r.rerankerScore ?? 0) + (c?.finalBonus ?? 0);
    return {
      docId: r.documentId,
      rank: idx + 1,
      rerankerScore: r.rerankerScore,
      finalReorderingScore,
      relevance: r.relevance,
      sources: cs ? Array.from(cs) : [],
      biCosine: c?.biCosine ?? 0,
      lensBonus: c?.lensBonus ?? 0,
      anchorBonus: c?.anchorBonus ?? 0,
      categoryLensBonus: c?.categoryLensBonus ?? 0,
      temporalBonus: c?.temporalBonus ?? 0,
    };
  });
  // ─── env-guarded relation trace (P1.5/P2 Phase-B diagnosis) ──────────────
  // CORETEX_RELTRACE_QID=<query id> CORETEX_RELTRACE_DOCS=<csv doc ids>. Emits one stderr JSON line
  // exposing, per target doc, the lowest-layer status: seed (stage-1) → enqueued (pool) → tagged
  // (categoryLensBFS) → normWeight → preRank → reranker-cap → Qwen rank → final rank, plus lensJunkTop10.
  // No behavior change when unset. Lets the trace harness classify each query at its lowest failing layer.
  if (process.env['CORETEX_RELTRACE_QID'] === query.id && process.env['CORETEX_RELTRACE_DOCS']) {
    const targets = process.env['CORETEX_RELTRACE_DOCS']!.split(',').filter(Boolean);
    const stage1Set = new Set(stage1Docs.map((d) => d.id));
    const capSet = new Set(rerankerCandidates.map((c) => c.record.docId));
    const candByDoc = new Map(candidates.map((c) => [c.record.docId, c]));
    const rerankOrder = [...rerankerCandidates].sort((a, b) => (rerankerScoreByDocId.get(b.record.docId) ?? 0) - (rerankerScoreByDocId.get(a.record.docId) ?? 0));
    const rerankRankByDoc = new Map(rerankOrder.map((c, i) => [c.record.docId, i + 1]));
    const finalRankByDoc = new Map(ranked.map((r, i) => [r.documentId, i + 1]));
    const lensJunkTop10 = finalRankingTop20.filter((r) => r.rank <= 10 && (r.relevance ?? 0) === 0 && (r.sources ?? []).includes('categoryLensBFS')).length;
    const tr = targets.map((t) => {
      const poolE = pool.get(t); const cand = candByDoc.get(t);
      return { doc: t, inStage1: stage1Set.has(t), inPool: !!poolE, sources: poolE ? Array.from(poolE.sources) : [],
        categoryLensNormWeight: categoryLensWeightByDocId.get(t) ?? 0, preRankScore: cand?.preRankScore ?? null,
        categoryLensBonus: cand?.categoryLensBonus ?? null, inCap: capSet.has(t), qwenScore: rerankerScoreByDocId.get(t) ?? null,
        rerankRank: rerankRankByDoc.get(t) ?? null, finalRank: finalRankByDoc.get(t) ?? null };
    });
    process.stderr.write('RELTRACE ' + JSON.stringify({ queryId: query.id, family: query.family, stage1Count: stage1Docs.length, poolSize: pool.size, lensJunkTop10, targets: tr }) + '\n');
  }
  // answerInCap: true iff any qrel doc with relevance>0 is among the
  // rerankerInputTopK-capped candidates. RERANKER-INDEPENDENT (cap membership
  // is determined by preRankScore = biCosine + substrateBonus only). This is
  // the admission-headroom signal: a routing surface can only help by getting
  // an answer INTO this cap; if answers are already in-cap, no routing surface
  // helps. Pure diagnostic — does not affect scoring. For abstention probes
  // (no relevance>0 qrels) there is no answer to admit, so this is false.
  const capSetForAnswer = new Set(cappedDocIds);
  const answerInCap = query.qrels.some((q) => q.relevance > 0 && capSetForAnswer.has(q.documentId));
  // Opt-in: the FULL reranked list (diagnostic only, for offline oracle probes).
  const finalRankingFull = opts.exposeFullRanking === true
    ? ranked.map((r) => ({ docId: r.documentId, relevance: r.relevance, rerankerScore: r.rerankerScore }))
    : undefined;
  return { ranked, top1Score, cappedDocIds, cappedDocSources, cappedDocComponents, finalRankingTop20, answerInCap, finalRankingFull, policyTraces, policyAbstain };
}

// ─── Owner-scoped retrieval (Layer-2 validity fix) ──────────────────────────

/**
 * eventId → count of INCOMING public `supports`-edges (corroboration in-degree).
 * Corpus-derived (public, auditable), memoized per corpus instance. Used by
 * EvidencePolicy `high_density_evidence`: the miner's POLICY asserts "answers
 * corroborated by >= K supports edges are more relevant"; the in-degree itself is
 * public corpus structure, not miner-written data or an answer map.
 */
const supportsInDegreeCache = new WeakMap<ProductionCorpus, Map<string, number>>();
function getOrBuildSupportsInDegree(corpus: ProductionCorpus): Map<string, number> {
  const cached = supportsInDegreeCache.get(corpus);
  if (cached) return cached;
  const inDeg = new Map<string, number>();
  for (const ev of corpus.events) {
    if (!ev.relations) continue;
    for (const rel of ev.relations) {
      if (rel.edgeType !== 'supports') continue;
      inDeg.set(rel.other_id, (inDeg.get(rel.other_id) ?? 0) + 1);
    }
  }
  supportsInDegreeCache.set(corpus, inDeg);
  return inDeg;
}

/**
 * Exact cosine ranking over a small owner-scope doc set (the owner's memory
 * store). Owner scopes are tens-to-low-hundreds of docs ≪ firstStageTopK, so
 * we score the whole scope (no heap/approximation) and take top-k. Tie-break
 * by docId for cross-host determinism, matching `firstStageCandidates`.
 */
function scopedFirstStageCandidates(
  queryVec: Float32Array,
  scopeDocs: readonly PublicCorpusDoc[],
  k: number,
  layout: RetrievalKeyLayout,
): readonly PublicCorpusDoc[] {
  if (k <= 0 || scopeDocs.length === 0) return [];
  const scored = scopeDocs.map((d) => ({ d, cos: cosineSimilarity(queryVec, dequantize(d.embedding, layout)) }));
  scored.sort((a, b) => {
    if (b.cos !== a.cos) return b.cos - a.cos;
    return a.d.id < b.d.id ? -1 : a.d.id > b.d.id ? 1 : 0;
  });
  return scored.slice(0, k).map((s) => s.d);
}

/**
 * entityId → that owner's truth docs ({id, eventId, embedding}). Built from the
 * PUBLIC per-event entityIds + embeddings. The owner store for scope restriction
 * and (later) within-scope entity-text seeding. Cached per corpus instance.
 */
const entityScopeIndexCache = new WeakMap<ProductionCorpus, Map<string, PublicCorpusDoc[]>>();
function getOrBuildEntityScopeIndex(corpus: ProductionCorpus): Map<string, PublicCorpusDoc[]> {
  const cached = entityScopeIndexCache.get(corpus);
  if (cached) return cached;
  const index = new Map<string, PublicCorpusDoc[]>();
  const seenPerEntity = new Map<string, Set<string>>();
  for (const event of corpus.events) {
    if (!event.entityIds || event.entityIds.length === 0) continue;
    for (const td of event.truthDocuments) {
      const emb = event.embeddings.perTruth.get(td.id);
      if (!emb) continue;
      for (const entId of event.entityIds) {
        let seen = seenPerEntity.get(entId);
        if (!seen) { seen = new Set(); seenPerEntity.set(entId, seen); }
        if (seen.has(td.id)) continue;
        seen.add(td.id);
        let arr = index.get(entId);
        if (!arr) { arr = []; index.set(entId, arr); }
        arr.push({ id: td.id, eventId: event.id, embedding: emb });
      }
    }
  }
  // Stable order per entity (docId asc) for deterministic seeding/budgeting.
  for (const arr of index.values()) arr.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  entityScopeIndexCache.set(corpus, index);
  return index;
}

// ─── Per-call corpus-side index caches ──────────────────────────────────────

const publicIndexCache = new WeakMap<ProductionCorpus, PublicCorpusIndex>();
function getOrBuildPublicIndex(corpus: ProductionCorpus): PublicCorpusIndex {
  const cached = publicIndexCache.get(corpus);
  if (cached) return cached;
  const idx = buildPublicCorpusIndex(corpus);
  publicIndexCache.set(corpus, idx);
  return idx;
}

const docTextCache = new WeakMap<ProductionCorpus, Map<string, string>>();
function getOrBuildDocTextIndex(corpus: ProductionCorpus): Map<string, string> {
  const cached = docTextCache.get(corpus);
  if (cached) return cached;
  const map = new Map<string, string>();
  for (const event of corpus.events) {
    for (const t of event.truthDocuments) if (!map.has(t.id)) map.set(t.id, t.text);
    for (const n of event.hardNegatives) if (!map.has(n.id)) map.set(n.id, n.text);
  }
  docTextCache.set(corpus, map);
  return map;
}

const recordIdIndexCacheV2 = new WeakMap<ProductionCorpus, Map<bigint, ProductionCorpusEvent>>();
function getOrBuildRecordIdIndex(corpus: ProductionCorpus): Map<bigint, ProductionCorpusEvent> {
  const cached = recordIdIndexCacheV2.get(corpus);
  if (cached) return cached;
  const built = new Map<bigint, ProductionCorpusEvent>();
  for (const e of corpus.events) built.set(stableRecordIdFor(e.id), e);
  recordIdIndexCacheV2.set(corpus, built);
  return built;
}

/** Phase B: lookup by corpus event id (string) for follow-the-relation BFS
 *  from stage-1 candidates. Mirrors `corpus.byId` (already on the loaded
 *  ProductionCorpus object) but exposed as a typed accessor for clarity. */
function corpusByCorpusId(corpus: ProductionCorpus): ReadonlyMap<string, ProductionCorpusEvent> {
  return corpus.byId;
}

/** Phase B inverse-relation index. For each target event id, list of
 *  (fromEventId, edgeType) pairs. Lets BFS traverse edges backward —
 *  "this entity is referenced by these N questions." Cached on corpus. */
interface InverseRelationEntry { readonly fromEventId: string; readonly edgeType: string; }
const inverseRelCacheV2 = new WeakMap<ProductionCorpus, Map<string, InverseRelationEntry[]>>();
function getOrBuildInverseRelationIndex(corpus: ProductionCorpus): Map<string, InverseRelationEntry[]> {
  const cached = inverseRelCacheV2.get(corpus);
  if (cached) return cached;
  const inverse = new Map<string, InverseRelationEntry[]>();
  for (const ev of corpus.events) {
    if (!ev.relations) continue;
    for (const rel of ev.relations) {
      const list = inverse.get(rel.other_id) ?? [];
      list.push({ fromEventId: ev.id, edgeType: rel.edgeType });
      inverse.set(rel.other_id, list);
    }
  }
  inverseRelCacheV2.set(corpus, inverse);
  return inverse;
}

/** Phase B: add `event`'s truth docs to the candidate pool with a given
 *  category-lens weight. Returns the number of docs actually added (new
 *  to the pool). Skips docs already present but updates their lens
 *  weight to the max of the previous and new value. */
function addEventTruthsToPool(
  event: ProductionCorpusEvent,
  pool: Map<string, {
    docId: string;
    embedding: Uint8Array;
    text: string;
    eventId: string;
    memorySlot: number | null;
    isCurrentTruth: boolean;
    isStaleTruth: boolean;
    sources: Set<'stage1' | 'anchorMandatory' | 'anchorBFS' | 'categoryLensBFS'>;
  }>,
  categoryLensWeightByDocId: Map<string, number>,
  normWeight: number,
  cap: number,
): number {
  let added = 0;
  for (const td of event.truthDocuments) {
    const existing = pool.get(td.id);
    if (existing) {
      // Apply the relation-routing signal (source tag + lens weight) to docs
      // ALREADY in the pool. Crucial under owner-scope, where every owner doc
      // is a stage-1 seed: the lens-edge target is already present, so the
      // routing value is the EDGE SIGNAL (ranking), not novel pool inclusion.
      // Tagging existing docs expands nothing → does NOT consume the budget.
      existing.sources.add('categoryLensBFS');
      const prev = categoryLensWeightByDocId.get(td.id) ?? 0;
      if (normWeight > prev) categoryLensWeightByDocId.set(td.id, normWeight);
      continue;
    }
    if (added >= cap) continue; // budget gates only NEW pool additions
    const emb = event.embeddings.perTruth.get(td.id);
    if (!emb) continue;
    pool.set(td.id, {
      docId: td.id,
      embedding: emb,
      text: td.text,
      eventId: event.id,
      memorySlot: null,
      isCurrentTruth: td.isCurrent,
      isStaleTruth: !td.isCurrent,
      sources: new Set(['categoryLensBFS']),
    });
    categoryLensWeightByDocId.set(td.id, normWeight);
    added++;
  }
  return added;
}

/**
 * Substrate-hardening §6.7 — per-(query, K) stage-1 cache. Keyed by corpus
 * (WeakMap) and by `${query.id}#${K}` (Map) so a long-running coordinator
 * process reuses the Top-K across all patch evaluations against the same
 * parent state in a pack.
 *
 * Memory: bounded by the live query set. For pack_size=128 queries × 2 packs
 * × Top-K=3200 docs × ~16 bytes per PublicCorpusDoc reference ≈ 13 MB per
 * corpus. Negligible; the dense embedding bytes live in the index, not in
 * the cache.
 *
 * `invalidateStage1CacheForCorpus(corpus)` clears the per-corpus cache. The
 * coordinator calls this on epoch transitions to drop stale Top-Ks if the
 * cache survives across epochs in the same process.
 */
const stage1Cache = new WeakMap<ProductionCorpus, Map<string, readonly { id: string; eventId: string; embedding: Uint8Array }[]>>();
function getOrComputeStage1(
  corpus: ProductionCorpus,
  queryId: string,
  k: number,
  scopeTag: string,
  compute: () => readonly { id: string; eventId: string; embedding: Uint8Array }[],
): readonly { id: string; eventId: string; embedding: Uint8Array }[] {
  let perCorpus = stage1Cache.get(corpus);
  if (!perCorpus) {
    perCorpus = new Map();
    stage1Cache.set(corpus, perCorpus);
  }
  // The stage-1 result depends on the retrieval SCOPE (owner-scoped vs pooled,
  // and WHICH owner). Without `scopeTag` in the key, the same queryId scored
  // under different scopes would cross-contaminate (a scoped Top-K served to a
  // pooled call or vice-versa). scopeTag = 'p' (pooled) | 's:<ownerEntityId>'.
  const key = `${queryId}#${k}#${scopeTag}`;
  const cached = perCorpus.get(key);
  if (cached) return cached;
  const fresh = compute();
  perCorpus.set(key, fresh);
  return fresh;
}

/** Drop the stage-1 Top-K cache for a corpus. Coordinator calls this on
 *  epoch transitions if the cache outlives a single epoch in-process. */
export function invalidateStage1CacheForCorpus(corpus: ProductionCorpus): void {
  stage1Cache.delete(corpus);
}

function resolveCorpusDocsForRecordId(
  recordId: bigint,
  corpus: ProductionCorpus,
): { id: string; text: string }[] {
  // Production corpus indexes records by stable string id. The substrate's
  // 128-bit recordId is the truncation of keccak256(id). For scoring, we
  // build the map lazily and cache it on the corpus by side-channel.
  const cache = recordIdIndexCache.get(corpus);
  if (cache) {
    const event = cache.get(recordId);
    if (!event) return [];
    return [...event.truthDocuments.map((d) => ({ id: d.id, text: d.text })),
            ...event.hardNegatives.map((n) => ({ id: n.id, text: n.text }))];
  }
  const built = new Map<bigint, ProductionCorpusEvent>();
  for (const e of corpus.events) {
    built.set(stableRecordIdFor(e.id), e);
  }
  recordIdIndexCache.set(corpus, built);
  const event = built.get(recordId);
  if (!event) return [];
  return [...event.truthDocuments.map((d) => ({ id: d.id, text: d.text })),
          ...event.hardNegatives.map((n) => ({ id: n.id, text: n.text }))];
}

const recordIdIndexCache = new WeakMap<ProductionCorpus, Map<bigint, ProductionCorpusEvent>>();

/**
 * Stable 128-bit substrate record id for a corpus event. Public so corpus
 * builders use the same mapping when constructing memory-index slots.
 */
export function stableRecordIdFor(id: string): bigint {
  // Lazy-loaded keccak from state.
  // We use the same keccak256 the substrate uses to keep the mapping aligned.
  const enc = new TextEncoder();
  const bytes = keccak256(enc.encode(`coretex:record:${id}`));
  let v = 0n;
  for (let i = 0; i < 16; i++) v = (v << 8n) | BigInt(bytes[i]!);
  return v;
}

/**
 * Score the substrate against the entire query pack. Returns the composite
 * score and per-query breakdown.
 */
export async function evaluateRetrievalBenchmarkState(
  state: CortexState,
  corpus: ProductionCorpus,
  pack: QueryPack,
  opts: ScoringOptions,
): Promise<CompositeScore> {
  assertValidWeights(opts.weights);
  assertPipelineVersionMatches(opts.pipelineVersion);
  // §6.4 lens-diversity floor — only effective when the bundle pins the
  // floor AND we pass the full retrievalKeyLayout (decoder needs `dim`
  // and quantization to dequantize lens vectors). Without these, the
  // floor check is skipped and a collapsed substrate scores normally.
  const decoded = decodeSubstrate(state, {
    biEncoderModelIdHash: opts.biEncoderHash,
    retrievalKeyHeaderBytes: opts.retrievalKeyLayout.headerBytes,
    ...(opts.policyAtomsMode ? { policyAtomsMode: true } : {}),
    ...(typeof opts.lensDiversityFloor === 'number'
      ? { lensDiversityFloor: opts.lensDiversityFloor, retrievalKeyLayout: opts.retrievalKeyLayout }
      : {}),
  });
  const sv = structuralValidity(decoded);

  const perQuery: PerQueryBreakdown[] = [];
  const ndcgs: number[] = [];
  const mrrs: number[] = [];
  const recalls: number[] = [];
  const tempHits: (boolean | null)[] = [];
  const multiHits: (boolean | null)[] = [];
  const categoryLensRelationHits: (boolean | null)[] = [];
  const abstHits: (boolean | null)[] = [];

  // Build the relation graph once.
  const relGraph = new Map<number, number[]>();
  for (const e of decoded.relations) {
    const arr = relGraph.get(e.sourceSlot) ?? [];
    arr.push(e.targetSlot);
    relGraph.set(e.sourceSlot, arr);
  }

  for (const query of pack.events) {
    const isAbstentionProbe = query.truthDocuments.length === 0;
    const { ranked, top1Score, cappedDocIds, cappedDocSources, cappedDocComponents, finalRankingTop20, answerInCap, finalRankingFull, policyTraces, policyAbstain } = await scoreSubstrateAgainstQuery(decoded, query, corpus, opts);

    // nDCG / MRR / Recall over reranked list.
    const idealRels = query.qrels.map((q) => q.relevance);
    const totalRel = query.qrels.filter((q) => q.relevance > 0).length;
    // TEMPORAL answer-vs-contrast (opt-in `temporalStaleContrast`): on temporal queries a STALE
    // (superseded) doc is CONTRAST evidence, not a correct answer to "the CURRENT value" — so give it
    // 0 nDCG reward (the reward must not be defeated by, nor penalise the substrate's correct demotion
    // of, stale docs) while tracking its recall SEPARATELY as a diagnostic (observable, not rewarded).
    // Default off → current behaviour. Real-Qwen confirmed to recover in-context temporal yield
    // 0.30→0.56 (PROFILE_QREL_YIELD_EXPERIMENT.md). Not a substrate change; eval-semantics only.
    let ndcg: number;
    let temporalContrastRecall: number | null = null;
    if (opts.temporalStaleContrast === true && query.family === 'temporal') {
      const staleIds = new Set(query.truthDocuments.filter((d) => !d.isCurrent).map((d) => d.id));
      const rankedC = ranked.map((r) => (staleIds.has(r.documentId) ? { ...r, relevance: 0 } : r));
      const idealC = query.qrels.map((q) => (staleIds.has(q.documentId) ? 0 : q.relevance));
      ndcg = ndcgAtK(rankedC, idealC, opts.rerankerTopK);
      if (staleIds.size > 0) {
        const inTopK = ranked.slice(0, opts.rerankerTopK).filter((r) => staleIds.has(r.documentId)).length;
        temporalContrastRecall = inTopK / staleIds.size;
      }
    } else {
      ndcg = ndcgAtK(ranked, idealRels, opts.rerankerTopK);
    }
    const mrr = mrrAtK(ranked, opts.rerankerTopK);
    const rec = recallAtK(ranked, totalRel, opts.rerankerTopK);

    let tempHit: boolean | null = null;
    if (query.family === 'temporal' && query.temporal) {
      const currentDoc = query.truthDocuments.find((d) => d.isCurrent);
      const staleDocs = query.truthDocuments.filter((d) => !d.isCurrent).map((d) => d.id);
      tempHit = temporalCurrentStaleHit(ranked, currentDoc?.id ?? null, staleDocs);
    }

    let multiHit: boolean | null = null;
    if (query.family === 'multi_hop_relation') {
      // Resolve candidate memory slots from the top-k retrieval candidates.
      const candidateSlots = ranked
        .slice(0, opts.rerankerTopK)
        .map((r) => r.memorySlot)
        .filter((s): s is number => s !== null);
      // Resolve answer memory slots: find memory-index slots whose recordId
      // matches any of the query's truth docs' record ids (proxied by the
      // corpus event's id).
      const truthEventIds = new Set<string>();
      if (query.relations && query.relations.length > 0) {
        for (const rel of query.relations) truthEventIds.add(rel.other_id);
      } else {
        truthEventIds.add(query.id);
      }
      const answerSlots = new Set<number>();
      for (let m = 0; m < decoded.memoryIndex.length; m++) {
        const slot = decoded.memoryIndex[m];
        if (!slot) continue;
        for (const eid of truthEventIds) {
          if (slot.recordId === stableRecordIdFor(eid)) answerSlots.add(m);
        }
      }
      multiHit = multiHopRelationHit(candidateSlots, answerSlots, relGraph, opts.relationHopBudget);
    }

    const categoryLensRelationHit = query.family === 'multi_hop_relation'
      ? finalRankingTop20.some((r) =>
          r.rank <= opts.rerankerTopK &&
          r.relevance > 0 &&
          r.sources.includes('categoryLensBFS'),
        )
      : null;

    // Abstention decision: under r5 (policyAtomsMode + abstention enabled) the abstain decision is
    // the PolicyAtom decision (public no-evidence-path selector AND operator-calibrated top1 gate);
    // otherwise the legacy raw top1<abstentionThreshold. `policyFalseAbstain` flags an abstain on an
    // ANSWERABLE query (the false-abstention risk the operator gated on).
    const r5Abstention = opts.policyAtomsMode === true && opts.enableAbstentionAtoms !== false && decoded.abstentionAtoms.length > 0;
    let abstHit: boolean | null = null;
    if (isAbstentionProbe) {
      abstHit = r5Abstention ? policyAbstain : top1Score < opts.abstentionThreshold;
    }
    const policyFalseAbstain = r5Abstention && !isAbstentionProbe && policyAbstain;

    ndcgs.push(ndcg);
    mrrs.push(mrr);
    if (rec !== null) recalls.push(rec);
    tempHits.push(tempHit);
    multiHits.push(multiHit);
    categoryLensRelationHits.push(categoryLensRelationHit);
    abstHits.push(abstHit);

    perQuery.push({
      recordId: query.id,
      family: query.family,
      nDCG10: ndcg,
      mrr10: mrr,
      recall10: rec,
      temporalHit: tempHit,
      multiHopHit: multiHit,
      categoryLensRelationHit,
      abstentionHit: abstHit,
      top1Score,
      cappedDocIds,
      cappedDocSources,
      cappedDocComponents,
      finalRankingTop20,
      answerInCap: isAbstentionProbe ? null : answerInCap,
      ...(finalRankingFull !== undefined ? { finalRankingFull } : {}),
      temporalContrastRecall,
      ...(opts.policyEmitTraces && policyTraces.length > 0 ? { policyTraces } : {}),
      ...(opts.policyAtomsMode === true ? { policyAbstain, policyFalseAbstain } : {}),
    });
  }

  const meanNdcg = ndcgs.length === 0 ? 0 : ndcgs.reduce((a, b) => a + b, 0) / ndcgs.length;
  const meanMrr = mrrs.length === 0 ? 0 : mrrs.reduce((a, b) => a + b, 0) / mrrs.length;
  const meanRec = recalls.length === 0 ? 0 : recalls.reduce((a, b) => a + b, 0) / recalls.length;
  const tempAcc = temporalCurrentStaleAccuracy(tempHits);
  const multiAcc = multiHopRelationRecallAtK(multiHits);
  const categoryLensRelationHitAcc = multiHopRelationRecallAtK(categoryLensRelationHits);
  const abstAcc = abstentionAccuracy(abstHits);

  const composite =
    opts.weights.w_retrieval * meanNdcg +
    opts.weights.w_temporal * tempAcc +
    opts.weights.w_relation_recall * multiAcc +
    opts.weights.w_abstention * abstAcc +
    opts.weights.w_structural_sanity * sv;

  return {
    composite: clamp01(composite),
    nDCG10: meanNdcg,
    mrr10: meanMrr,
    recall10: meanRec,
    temporal: tempAcc,
    multiHopRecall10: multiAcc,
    categoryLensRelationHit10: categoryLensRelationHitAcc,
    abstention: abstAcc,
    structuralValidity: sv,
    perQuery,
  };
}

export interface PatchAcceptanceFloors {
  readonly minImprovementPpm: number;
  readonly structuralFloor: number;
  readonly protectedRegressionFloor: number;
  readonly familyCatastrophicFloor: number;
  /**
   * Production acceptance threshold in ppm — the minimum `deltaPpm` a
   * patch must clear for `result.accepted === true`. Production wires
   * `computeAcceptanceThresholdPpm(profile)` = minImprovementPpm +
   * replayTolerancePpm + baselineVariancePpm. Keeping this explicit
   * (rather than re-deriving from `minImprovementPpm` alone) closes the
   * footgun where a caller reads `result.accepted` thinking it captures
   * the full production gate. When omitted, the evaluator falls back to
   * `minImprovementPpm` — only acceptable for self-eval / scoring
   * primitives that are NOT making advancement decisions; production
   * hosts must always pass it.
   */
  readonly acceptanceThresholdPpm?: number;
}

export async function evaluateRetrievalBenchmarkPatch(
  parentState: CortexState,
  patch: Patch,
  corpus: ProductionCorpus,
  pack: QueryPack,
  opts: ScoringOptions,
  floors: PatchAcceptanceFloors,
): Promise<PatchEvalResult> {
  const acceptanceThresholdPpm = floors.acceptanceThresholdPpm ?? floors.minImprovementPpm;
  const before = await evaluateRetrievalBenchmarkState(parentState, corpus, pack, opts);
  const applied = applyPatch(parentState, patch);
  if (!applied.ok) {
    return {
      accepted: false,
      reason: `apply_failed:${applied.code}`,
      before,
      after: before,
      deltaPpm: 0,
      perFamilyDelta: {},
    };
  }
  const after = await evaluateRetrievalBenchmarkState(applied.state, corpus, pack, opts);

  if (after.structuralValidity < floors.structuralFloor) {
    return {
      accepted: false,
      reason: 'structural_validity_below_floor',
      before,
      after,
      deltaPpm: Math.round((after.composite - before.composite) * 1_000_000),
      perFamilyDelta: perFamilyDelta(before, after),
    };
  }

  // Per-record protected regression check.
  const beforeById = new Map(before.perQuery.map((q) => [q.recordId, q]));
  for (const q of after.perQuery) {
    const ev = corpus.byId.get(q.recordId);
    if (!ev || !ev.protected) continue;
    const prev = beforeById.get(q.recordId);
    if (!prev) continue;
    const drop = prev.nDCG10 - q.nDCG10;
    if (drop > floors.protectedRegressionFloor) {
      return {
        accepted: false,
        reason: `protected_regression:${q.recordId}`,
        before,
        after,
        deltaPpm: Math.round((after.composite - before.composite) * 1_000_000),
        perFamilyDelta: perFamilyDelta(before, after),
      };
    }
  }

  // Per-family catastrophic regression.
  const familyDelta = perFamilyDelta(before, after);
  const familyBefore = perFamilyMean(before);
  const familyAfter = perFamilyMean(after);
  for (const fam of Object.keys(familyBefore)) {
    const beforeVal = familyBefore[fam] ?? 0;
    const afterVal = familyAfter[fam] ?? 0;
    if (beforeVal > 0 && afterVal < floors.familyCatastrophicFloor * beforeVal) {
      return {
        accepted: false,
        reason: `family_catastrophic:${fam}`,
        before,
        after,
        deltaPpm: Math.round((after.composite - before.composite) * 1_000_000),
        perFamilyDelta: familyDelta,
      };
    }
  }

  const deltaPpm = Math.round((after.composite - before.composite) * 1_000_000);
  if (deltaPpm < acceptanceThresholdPpm) {
    return {
      accepted: false,
      reason: 'no_retrieval_improvement',
      before,
      after,
      deltaPpm,
      perFamilyDelta: familyDelta,
    };
  }
  return { accepted: true, before, after, deltaPpm, perFamilyDelta: familyDelta };
}

function perFamilyMean(score: CompositeScore): Record<string, number> {
  const buckets = new Map<string, number[]>();
  for (const q of score.perQuery) {
    const arr = buckets.get(q.family) ?? [];
    arr.push(q.nDCG10);
    buckets.set(q.family, arr);
  }
  const out: Record<string, number> = {};
  for (const [k, vs] of buckets) {
    out[k] = vs.length === 0 ? 0 : vs.reduce((a, b) => a + b, 0) / vs.length;
  }
  return out;
}

function perFamilyDelta(before: CompositeScore, after: CompositeScore): Record<string, number> {
  const b = perFamilyMean(before);
  const a = perFamilyMean(after);
  const out: Record<string, number> = {};
  for (const k of new Set([...Object.keys(b), ...Object.keys(a)])) {
    out[k] = (a[k] ?? 0) - (b[k] ?? 0);
  }
  return out;
}

function clamp01(v: number): number {
  return Math.max(0, Math.min(1, v));
}

export { biEncoderModelIdHash };
