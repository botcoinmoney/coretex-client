/**
 * CoreTex bundle manifest — production retrieval-benchmark form.
 *
 * Specs:
 *   - specs/retrieval_benchmark.md
 *   - specs/substrate_retrieval_semantics.md
 *   - specs/corpus_retrieval.md
 *   - specs/hidden_query_pack.md
 *   - specs/determinism.md
 *
 * The bundle pins:
 *   - bi-encoder + revision + per-file SHA-256 + retrieval-key layout
 *   - production cross-encoder reranker + revision + per-file SHA-256
 *   - labeling cross-encoder reranker (separate, stronger; for qrel labeling)
 *   - runtime versions (CPU-only)
 *   - composite weights (retrieval-dominant)
 *   - hidden-pack profile (size + quotas)
 *   - calibration outputs (`replayTolerancePpm`, floors, hop budget)
 *
 * `bundleHash = keccak256(canonicalJson(manifest \ bundleHash))`. The
 * coordinator startup assertion refuses to run if the on-chain
 * `coreVersionHash` does not equal `bundleHash`.
 */

import { existsSync, readFileSync, statSync, openSync, readSync, closeSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { basename, relative, resolve } from 'node:path';

import { bytesToHex } from '../state/merkle.js';
import { keccak256 } from '../state/keccak256.js';
import type { RetrievalKeyLayout } from '../eval/retrieval-corpus.js';
import type { ScoringOptions } from '../eval/retrieval-benchmark.js';
import type { BiEncoder } from '../eval/bi-encoder.js';
import type { CrossEncoderReranker } from '../eval/reranker.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface BundleFile {
  readonly role: string;
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
}

export interface ModelFileFetch {
  readonly path: string;
  readonly sha256: string;
  readonly bytes?: number;
}

export type RuntimeFlavor = 'torch-transformers' | 'onnxruntime-cpu';

export interface RuntimePin {
  readonly flavor: RuntimeFlavor;
  readonly versions: Record<string, string>;
  readonly buildFlags: readonly string[];
}

export interface ClientVersionPolicy {
  /**
   * Minimum CoreTex client version required for canonical replay.
   * Clients below this version are considered outdated.
   */
  readonly minimumVersion: string;
  /**
   * Optional operator-visible target version for upgrades.
   */
  readonly recommendedVersion?: string;
  /**
   * When true, outdated clients must fail closed unless an explicit
   * override is provided by the caller.
   */
  readonly hardFailOutdated: boolean;
}

export type Quantization =
  | { readonly weights: 'int8'; readonly activations: 'fp32'; readonly accumulation: 'fp32'; readonly scheme: 'symmetric_per_channel' | 'asymmetric_per_tensor' }
  | { readonly weights: 'bf16'; readonly activations: 'bf16'; readonly accumulation: 'fp32'; readonly flushDenormals: true };

export interface BiEncoderManifest {
  readonly provider: 'huggingface';
  readonly modelId: string;
  readonly revision: string;
  readonly mode: 'dense';
  readonly outputDim: number;
  readonly tokenizerRevision: string;
  readonly quantization: Quantization;
  readonly retrievalKeyLayout: RetrievalKeyLayout;
  readonly files: readonly ModelFileFetch[];
}

export interface RerankerManifest {
  readonly provider: 'huggingface';
  readonly modelId: string;
  readonly revision: string;
  readonly files: readonly ModelFileFetch[];
}

export interface PackQuotaPin {
  readonly stratum: string;
  readonly minCount: number;
}

export interface HiddenPackProfilePin {
  readonly packSize: number;
  readonly quotas: readonly PackQuotaPin[];
}

export interface CompositeWeightPin {
  readonly w_retrieval: number;
  readonly w_temporal: number;
  readonly w_relation_recall: number;
  readonly w_abstention: number;
  readonly w_structural_sanity: number;
}

export interface PatchAcceptanceFloorsPin {
  readonly minImprovementPpm: number;
  readonly structuralFloor: number;
  readonly protectedRegressionFloor: number;
  readonly familyCatastrophicFloor: number;
}

export interface SplitRatiosPin {
  readonly trainVisiblePct: number;
  readonly calibrationPct: number;
  readonly evalHiddenPct: number;
  readonly canaryPct: number;
}

/**
 * Hard-negative categories the corpus generator emits by construction.
 *
 * Each category corresponds to a specific synthesis site in the active
 * V2/DGEN-1 corpus generators:
 *
 *   near_collision_entity   — different entity, same domain (nearestEntityDocs)
 *   near_collision_attribute — same entity, wrong attribute value (previous synth path)
 *   temporal_stale          — explicitly stale prior value (modifier/trap-temporal staleText)
 *   trap                    — designed adversarial trap (challenge.silentTraps / trapTextsForQuestion)
 *   lexical_distractor      — surface overlap, weak semantic relevance
 *   relation_neighbor       — multi-hop neighbor (relation-target text)
 *   unrelated               — true negative / padding filler
 *
 * The mapping from category to qrel relevance is pinned by the bundle
 * via `negCategoryRelevanceMap` and validated against the production
 * reranker's score distribution before launch.
 */
export type NegCategory =
  | 'near_collision_entity'
  | 'near_collision_attribute'
  | 'temporal_stale'
  | 'trap'
  | 'lexical_distractor'
  | 'relation_neighbor'
  | 'unrelated';

export type NegCategoryRelevanceMap = Readonly<Record<NegCategory, number>>;

export interface EvaluatorProfile {
  readonly name: string;
  readonly version: string;
  readonly scoreScale: 'ppm';
  readonly scorePpmEncoding: 'uint32-0-to-1000000';
  readonly patchScoreDeltaEncoding: 'int64-ppm';
  readonly primaryMetric: 'ndcg@10';
  readonly acceleratorPolicy: 'cpu_only';
  readonly runtimePin: RuntimePin;
  readonly clientVersionPolicy?: ClientVersionPolicy;
  readonly replayTolerancePpm: number;
  readonly compositeWeights: CompositeWeightPin;
  readonly patchAcceptanceFloors: PatchAcceptanceFloorsPin;
  readonly splitRatios: SplitRatiosPin;
  readonly hiddenPack: HiddenPackProfilePin;
  readonly relationHopBudget: number;
  readonly abstentionThreshold: number;
  readonly rerankerTopK: number;
  readonly retrievalKeyTopK: number;
  readonly relationEdgeTypes: readonly string[];

  // ─── v2-lens pipeline pins (substrate-hardening §6.3) ─────────────────────
  /** Pinned scorer pipeline. v2-lens is the two-stage corpus-retrieval + substrate-bias pipeline.
   *  `coretex-retrieval-v2-policy-r5` = the PolicyAtom epoch (reclaimed RetrievalKeys+Codebook
   *  words read as typed PolicyAtoms; r4 stays replayable). */
  readonly pipelineVersion?: 'coretex-retrieval-v2-lens' | 'coretex-retrieval-v2-lens-r2' | 'coretex-retrieval-v2-lens-r3' | 'coretex-retrieval-v2-lens-r4' | 'coretex-retrieval-v2-policy-r5';
  // ─── r5 PolicyAtom knobs (active only when pipelineVersion = …-policy-r5) ───
  /** Per-family enables. A disabled family is decoded but its atoms are NOT applied. */
  readonly enableEvidenceBundleAtoms?: boolean;
  readonly enableConflictLifecycleAtoms?: boolean;
  readonly enableAbstentionAtoms?: boolean;
  readonly enableValidityAtoms?: boolean;
  readonly enableEntityResolutionAtoms?: boolean;
  readonly enableScopeAtoms?: boolean;
  /** Per-family budget caps; a miner atom's budget is clamped to these (anti-flood). */
  readonly policyMaxBudgetEvidence?: number;
  readonly policyMaxBudgetConflict?: number;
  readonly policyMaxBudgetEntity?: number;
  readonly policyMaxBudgetScope?: number;
  readonly policyEntityMaxDocs?: number;
  readonly policyScopeMaxDocs?: number;
  readonly policyScopeMaxSuppress?: number;
  /** Operator-calibrated abstention confidence gate (NOT hardcoded; Qwen top1 is saturated).
   *  Abstain fires only when the atom's no-evidence-path selector matches AND top1 < this. */
  readonly policyAbstentionTop1Threshold?: number;
  /** Category-A: abstain only if ALSO top1-top2 margin < this (combined with top1; never top1 alone). */
  readonly policyAbstentionMarginThreshold?: number;
  /** Emit per-atom trace receipts for the Memory-IR pipeline (default off). */
  readonly policyEmitTraces?: boolean;
  /** Query-local gate: atom fires only if its anchor is in the query's top-K stage-1 docs by biCosine (default 24). */
  readonly policyQueryLocalTopK?: number;
  /** r5.1: enable query-conditioned admission (generic public entity selector injects matched anchors). */
  readonly policyQueryConditionedAdmission?: boolean;
  /** Category-B: relation-TYPED admission — restrict admission + evidence boost to the query's
   *  PUBLIC parsed relation-intent edge types (finer than r5.1's entity-only all-edge admission). */
  readonly policyRelationTypedAdmission?: boolean;
  /** Launch-reduced: raw MemoryIndex anchors are disabled; r5 policy anchors remain usable. */
  readonly enableRawRoutingAnchors?: boolean;
  /** Launch-reduced: Phase-A anchor-to-anchor relation edges are disabled; category lenses remain usable. */
  readonly enableRelationAnchorEdges?: boolean;
  /** Launch-reduced: evidence_bundle is bundle-only; reach-only boost/include/suppress actions are inert. */
  readonly policyEvidenceAllowedActions?: readonly ('include' | 'boost' | 'suppress' | 'bundle')[];
  /** conflict_lifecycle: gate conflict-atom admission on a PUBLIC parsed conflict/scope intent
   *  (parseQueryConflictIntent) instead of the coarse CONFLICT_SET_MEMBER entity selector — eliminates
   *  the off-family damage. MUST be true whenever enableConflictLifecycleAtoms is true at launch. */
  readonly policyConflictIntentAdmission?: boolean;
  /** aspect_constraint (A100 CANDIDATE — default-off scaffold; NOT a launch surface yet): gate aspect-atom
   *  admission on a PUBLIC parsed aspect intent (parseQueryAspectIntent). The boost HOOK is not yet wired
   *  (r5.1, pending the A100 boost-only verdict) — this flag is no-op-safe scaffolding; validated strictly
   *  so it cannot be silently half-enabled. */
  readonly enableAspectConstraintAtoms?: boolean;
  readonly policyAspectIntentAdmission?: boolean;
  /** Bounded experimental aspect boost weight, (0, 0.5]. Required when enableAspectConstraintAtoms. */
  readonly policyAspectBoost?: number;
  /** Memory-IR sidecar doc rendering for the reranker ('F2' prefixes the derived lifecycle header).
   *  Pin only with a Memory-IR-tuned reranker (E1); default off → raw doc text. */
  readonly rerankerMemoryIRFormat?: 'off' | 'F2';
  /** Full protocol Memory-IR document rendering for a Memory-IR-tuned reranker. Default off. */
  readonly rerankerMemoryIRMode?: 'off' | 'full';
  /** Memory-IR lifecycle SOURCE: 'resolved' (substrate's decoded temporal state — launch form, lifecycle
   *  earned by the miner patch) vs 'corpus' (raw corpus labels — convenience). Default 'corpus'. */
  readonly rerankerMemoryIRSource?: 'corpus' | 'resolved';
  /** Stage-1 BGE-M3 first-stage retrieval cap (Run 1; per-stratum worst-case ≥0.90). */
  readonly firstStageTopK?: number;
  /**
   * Stage-1 retrieval mode. Default 'dense' preserves historical bundles.
   * 'hybrid' combines public lexical BM25 over doc text with BGE-M3 dense cosine.
   * Public text is miner-visible corpus content; no qrels/truth labels are exposed.
   */
  readonly firstStageMode?: 'dense' | 'lexical' | 'hybrid';
  readonly firstStageDenseWeight?: number;
  readonly firstStageLexicalWeight?: number;
  /**
   * §6.5 reranker-input cap. Number of pool candidates the cross-encoder
   * scores per query, taken from the top of (biCosine + substrateBonus).
   * Without this cap the reranker scores all `firstStageTopK` (~3,200)
   * candidates, making single-GPU calibration and per-patch production
   * scoring infeasible. Substrate expressivity unchanged: substrateBonus
   * can promote a stage-1 rank-3000 doc into the reranker pool. Typical
   * launch value: 128 (32× speedup over full-pool reranking).
   */
  readonly rerankerInputTopK?: number;
  /** Stage-2 lens-bonus contributing vectors per query. Capped by RetrievalKey slot count. */
  readonly lensTopK?: number;
  /** Stage-2 lens bonus scale (Run 0). */
  readonly lensWeight?: number;
  /** Stage-2 anchor bonus scale (Run 0). */
  readonly anchorWeight?: number;
  /**
   * Phase A budget: substrate-internal anchor-to-anchor BFS doc cap per
   * query (Run 0). Independent from Phase B (corpus-native category-lens
   * BFS) — see `categoryLensExpansionBudget`. On launch corpus the
   * shared-budget coupling let Phase B flood the candidate pool with
   * 189 docs and displace anchor-mandatory truths from top-10. Splitting
   * the budgets keeps Phase A capacity while letting operators guard
   * Phase B independently.
   */
  readonly relationExpansionBudget?: number;
  /**
   * Phase B budget: corpus-native category-lens BFS doc cap per query.
   * Optional; when omitted, scorers fall back to `relationExpansionBudget`
   * for backwards compatibility with bundles that predate the budget
   * split. Launch-v3 pin: 0 (Phase B suppressed — substrate retains
   * category-lens entries for future per-family / selectivity work).
   * See `RELATION_CATLENS_DECISION.md` in `release/calibration/cpu-2026-05-19-repaired-qrels/`.
   */
  readonly categoryLensExpansionBudget?: number;
  /** Stage-2 temporal modulation: bonus for current truth docs on temporal queries. */
  readonly temporalCurrentBoost?: number;
  /** Stage-2 temporal modulation: penalty for stale truth docs on temporal queries. */
  readonly temporalStaleSuppression?: number;
  /**
   * Owner-scoped retrieval (Layer-2 validity fix, 2026-05-22). When 'restrict',
   * stage-1 + relation seeding for an owner-scoped query (event.ownerScoped) are
   * restricted to the query's PUBLIC owner store — the realistic, well-posed task.
   * Default 'off' = legacy full-pool. The V2 launch lane pins 'restrict'.
   */
  readonly ownerScopeMode?: 'off' | 'restrict';
  /**
   * Non-flooding promotion: FINAL-reorder category-lens bonus scale. Defaults to
   * `categoryLensBonusWeight`/`lensWeight` (legacy single-bonus). The V2 lane pins
   * 0 (INCLUSION-ONLY): category-lens admits to the rerank cap but the reranker —
   * not a flat additive bonus — sets final order (fixes the P2 flood).
   */
  readonly categoryLensFinalBonusWeight?: number;
  /**
   * Score-inheritance alpha ∈ [0,1]. When > 0, a category-lens-edge target inherits
   * `alpha × its best lens-peer's reranker score` (one hop, final reorder only,
   * edge-gated) — the public bridge→answer routing signal. V2 candidate: 0.3
   * (NOT launch-pinned until 3-seed adversarial + larger sample sign-off).
   */
  readonly categoryLensScoreInheritance?: number;
  /**
   * Precise-admission knob (deep-memory scaling): seed the category-lens BFS only
   * from the top-K most query-similar stage-1 docs, instead of every stage-1
   * candidate. Prevents whole-edge-type-CATEGORY admission flooding the rerank pool
   * on deep universes. Undefined = legacy all-stage-1-seed behaviour. Deep value 8–16.
   */
  readonly categoryLensSeedTopK?: number;
  readonly categoryLensHopBudget?: number;
  /** Evidence-bundle reranking: score a routed answer together with its bridge (deep-memory surfacing). */
  readonly categoryLensEvidenceBundle?: boolean;
  /**
   * TEMPORAL answer-vs-contrast eval semantics (2026-05-25). When true, temporal-query STALE docs earn
   * 0 nDCG reward (contrast role; recall tracked separately as `temporalContrastRecall`) so the reward
   * aligns with "current beats stale" instead of penalising the substrate's correct demotion of
   * superseded values. Real-Qwen confirmed to recover in-context temporal yield 0.30→0.56
   * (PROFILE_QREL_YIELD_EXPERIMENT.md). Eval-semantics only; NOT a substrate change / protocol epoch.
   */
  readonly temporalStaleContrast?: boolean;
  /** §6.4 lens-diversity floor — mean pairwise cosine among active lenses must be ≤ this. */
  readonly lensDiversityFloor?: number;
  /** §6.1 pinned dedupe algorithm for PublicCorpusIndex. */
  readonly corpusDocDedupe?: 'canonical-doc-id';
  /**
   * §5 Run 1 selection-policy attestation. When `firstStageTopK` is pinned via
   * the per-stratum recall@K rule WITHOUT meeting the target on all strata,
   * this field records the operator-override decision in the signed bundle so
   * replay validators see that the override is explicit (not a silent threshold
   * violation). Hashed into `bundleHash` — any change requires a new bundle.
   */
  readonly firstStageTopKSelection?: FirstStageTopKSelection;
  readonly revealGracePeriodSeconds: number;
  /**
   * Maps each hard-negative category emitted by the corpus generator to
   * its graded qrel relevance. Replaces the per-event 4B-reranker labeling
   * call: the synthesizer already knows the structural category at
   * construction time, and this map turns that into a relevance bucket
   * deterministically.
   *
   * Pinned by the bundle so replay is deterministic and the map is
   * part of the signed bundle hash — any change requires a new
   * `bundleHash` and re-validation.
   */
  readonly negCategoryRelevanceMap: NegCategoryRelevanceMap;
  /**
   * Phase H1/H2 hardening. The new `eval_hidden` event count above
   * which the next epoch enters one-cycle major-delta grace
   * (`nextMinImprovementPpm({ majorDeltaActive: true })`). Pinned by
   * the calibrator from the launch corpus's eval_hidden population
   * (default ~5%). Optional for backward compatibility with bundles
   * that predate the hardening; coordinators reading a bundle without
   * this field MUST fall back to the pre-grace difficulty rule.
   */
  readonly majorDeltaThreshold?: number;
  /**
   * Phase H1/H2 hardening. The parent substrate's composite score on
   * the genesis hidden query pack, in ppm (composite × 1_000_000).
   * Pinned by `scripts/pin-baseline-into-bundle.mjs` running on the
   * calibration host after bundle build. Optional because pre-baseline
   * bundles (the initial output of `build-coretex-bundle.mjs`) don't
   * have it yet; the orchestrator chain populates it as step 7/9.
   *
   * The acceptance rule should normalize against this score plus
   * `replayTolerancePpm`. Production `baselineVariancePpm` is only added
   * when `baselineVarianceSource` is `rotating_pack` or `broad_sampling`.
   */
  readonly baselineParentScorePpm?: number;
  /**
   * Production-relevant baseline variance, in ppm. Must be omitted unless
   * computed from rotating-pack or broad sampling.
   */
  readonly baselineVariancePpm?: number;
  readonly baselineVarianceSource?: 'rotating_pack' | 'broad_sampling' | 'unavailable';
  /** Fixed-pack repeated-run variance. Calibration/debug only; not a production threshold term. */
  readonly fixedPackRepeatabilityPpm?: number;
  /** Number of samples used to compute the baseline/repeatability fields. */
  readonly baselineSamples?: number;
  /**
   * The eval seed used to derive the genesis hidden query pack that
   * the baseline was computed against. Any independent verifier can
   * reproduce the same pack + baseline score from
   * (bundle, corpus, baselineEvalSeedHex) — no coordinator-private
   * state involved.
   */
  readonly baselineEvalSeedHex?: string;
  /**
   * Per-patch on-chain randomness binding
   * (docs/CORETEX_V4_ONCHAIN_RANDOMNESS_PLAN.md).
   *
   * `chainId` + `blockTimeSeconds` pin the chain a verifier queries
   * for blockhashes; `targetBlockOffset` is the number of blocks past
   * `receivedAtBlock` that a patch's eval seed binds to (default 30 ≈
   * 60 s on Base — aligned with the per-miner challenge rate limit).
   *
   * `replayBlockhashLookbackBlocks` is the minimum blockhash-history
   * depth the configured Base RPC must retain; verifiers fail closed
   * if the RPC can't reach back to the targetBlock of an in-grace
   * receipt.
   */
  readonly baseRpcConfig: BaseRpcConfigPin;
  /**
   * Staged-active-root corpus policy (per
   * `docs/CORETEX_V4_ONCHAIN_RANDOMNESS_PLAN.md` §"Staged Active Root").
   *
   * The full launch corpus is generated up-front as a deterministic
   * RESERVE (seeds [0..seedsPerDomain) per domain). At launch the
   * active root is a deterministic prefix `seeds[0..S)` where S =
   * `initialActiveSeedsPerDomain`; subsequent daily corpus deltas
   * advance the active root forward by ≤ `routineDeltaMaxMajorFraction`
   * of the major-delta-grace threshold so growth stays in the normal
   * difficulty-ramp regime.
   *
   * Optional for backward compat with pre-staging bundles. When
   * omitted, the entire corpus is the active root (previous
   * single-source-of-truth behavior).
   */
  readonly corpusStagingPolicy?: CorpusStagingPolicyPin;
  /**
   * Difficulty-controller knobs pinned into the signed profile so the launch
   * controller shape is auditable and replayable, instead of living only in
   * `difficulty.ts` defaults + ad-hoc harness CLI flags. Maps onto the optional
   * `DifficultyInputs` fields via `controllerParamsFromProfile()` (the single
   * profile → controller-override path, analogous to `scoringOptionsFromProfile`).
   *
   * Optional for backward compatibility: when omitted, `controllerParamsFromProfile`
   * falls back to the pinned `difficulty.ts` protocol defaults (rampUp 1.5 / decay
   * 0.85 / under-target recovery 0.95 / drift 1.05 / qualityHighThresholdMult
   * 4) — the pre-pin behaviour plus the production anti-plateau recovery pin.
   *
   * 2026-05-24 launch calibration (`V2_DGEN1_ENDURANCE_FINDINGS.md` §Controller-
   * calibration A/B): `qualityHighThresholdMult=1` so the `decay` branch can engage
   * (`qualityHighThreshold = mult × targetAdvances ≤ honestAttempts`), and a gentler
   * `rampUpMaxRatio≈1.1`, recover +25% temporal runway (51→64) with anti-cheat 0.
   */
  readonly controllerParams?: ControllerParamsPin;
  /** LAUNCH-REQUIRED active-frontier / churn controller pin (EpochFrontier). When present, the
   *  validator rotates the active eval_hidden frontier deterministically and recomputes the
   *  baseline on activeRootChanged. Hashed into bundleHash so churn behavior is attested. */
  readonly epochFrontier?: EpochFrontierPin;
}

/**
 * §5 attestation of how `firstStageTopK` was chosen. Embedded in
 * `EvaluatorProfile` and therefore in the canonical bundle JSON that
 * `bundleHash` is computed over — every override claim is signed.
 *
 * - `worst-stratum-target` — K met the per-stratum recall@K floor on
 *   every family; `calibrationReport` MUST reference the Run 1 artifact.
 * - `operator-override` — at least one family failed the floor and the
 *   operator deliberately accepted that, expecting substrate-level BFS
 *   to bridge those families; `substrateBridgedFamilies` MUST list
 *   them, and `reason` MUST explain why (free-form, ≥ 16 chars).
 */
export interface FirstStageTopKSelection {
  readonly method: 'worst-stratum-target' | 'operator-override';
  readonly reason: string;
  readonly servedFamilyRecallAtPinnedK?: Readonly<Record<string, number>>;
  readonly substrateBridgedFamilies?: readonly string[];
  readonly calibrationReport?: string;
}

export interface BaseRpcConfigPin {
  readonly chainId: number;
  readonly blockTimeSeconds: number;
  readonly targetBlockOffset: number;
  readonly replayBlockhashLookbackBlocks: number;
}

export const DEFAULT_BASE_RPC_CONFIG: BaseRpcConfigPin = {
  chainId: 8453,                          // Base mainnet
  blockTimeSeconds: 2,
  targetBlockOffset: 30,                  // ≈ 60 s on Base
  replayBlockhashLookbackBlocks: 50_000,  // ≈ 28 h coverage
};

/**
 * Pinned difficulty-controller shape (see `EvaluatorProfile.controllerParams`).
 * Every field is optional so a profile can pin a subset; unset fields fall back
 * to the `difficulty.ts` protocol defaults inside `controllerParamsFromProfile`.
 *
 * `qualityHighThresholdMult` is a MULTIPLIER on the runtime `targetAdvances`
 * (the absolute `qualityHighThreshold = mult × targetAdvances`), because the
 * per-epoch target is a runtime/emission parameter, not a signed profile pin.
 */
export interface ControllerParamsPin {
  /** Max multiplier when ramping difficulty up. difficulty.ts default 1.5. */
  readonly rampUpMaxRatio?: number;
  /** Multiplier when decaying (0 advances AND many quality attempts). difficulty.ts default 0.85. */
  readonly decayRatio?: number;
  /** Deprecated legacy field for slow upward drift; retained for old signed profiles. */
  readonly smallDriftRatio?: number;
  /** Multiplier for under-target recovery when real quality attempts are present. difficulty.ts default 0.95. */
  readonly underTargetRecoveryRatio?: number;
  /** Multiplier on runtime targetAdvances setting the "high quality attempts" threshold. difficulty.ts default 4. */
  readonly qualityHighThresholdMult?: number;
}

/** EpochFrontier (churn) launch pin. Mirrors scripts/lib/epoch-frontier.mjs
 *  DEFAULT_EPOCH_FRONTIER_PROFILE; pinned into the signed profile so the active-frontier rotation
 *  is deterministic + attested. baselineRecompute MUST be 'activeRootChanged', majorDeltaPolicy
 *  'corpusRootChanged' (the two are distinct triggers). */
export interface EpochFrontierPin {
  readonly mode: 'off' | 'C0' | 'C1' | 'C2' | 'C3' | 'C4';
  readonly activeWindow: number;
  readonly minChurn?: number;
  readonly maxChurn?: number;
  readonly headroomLowWatermark?: number;
  readonly headroomHighWatermark?: number;
  readonly ewmaHalfLife?: number;
  readonly targetAccepts?: number;
  readonly expectedYieldPerUnit?: number;
  readonly maxRootDeltaPerEpoch?: number;
  readonly maxAge?: number | null;
  readonly seed: string;
  readonly baselineRecompute: 'activeRootChanged';
  readonly majorDeltaPolicy: 'corpusRootChanged';
}

/** difficulty.ts protocol defaults, expressed as a controller pin (the legacy pre-pin shape). */
export const DEFAULT_CONTROLLER_PARAMS: Required<ControllerParamsPin> = {
  rampUpMaxRatio: 1.5,
  decayRatio: 0.85,
  smallDriftRatio: 1.05,
  underTargetRecoveryRatio: 0.95,
  qualityHighThresholdMult: 4,
};

export interface CorpusStagingPolicyPin {
  /** Number of seeds per domain in the active root at launch. Must
   *  be ≤ the reserve's `seedsPerDomain`. */
  readonly initialActiveSeedsPerDomain: number;
  /** Fraction of `majorDeltaThreshold` a routine daily delta may
   *  consume. Cap so routine growth stays in the normal-delta regime
   *  (no grace-period trigger). Recommend 0.50. */
  readonly routineDeltaMaxMajorFraction: number;
  /** Minimum hidden-pack runway in days the active root must cover
   *  against the calibrated `epochsPerDay`. Used as the capacity
   *  gate during initial-active-size selection. Recommend 45–60. */
  readonly initialActiveRunwayDays: number;
}

export const DEFAULT_CORPUS_STAGING_POLICY: CorpusStagingPolicyPin = {
  initialActiveSeedsPerDomain: 128,       // ≈ 25% of a 512-seed reserve
  routineDeltaMaxMajorFraction: 0.50,
  initialActiveRunwayDays: 60,
};

export interface CoreTexBundleManifest {
  readonly schemaVersion: 'coretex.client-bundle.v2';
  readonly generatedAt: string;
  readonly bundleName: string;
  readonly substrate: {
    readonly wordCount: 1024;
    readonly packedBytes: 32768;
    readonly specs: readonly BundleFile[];
    readonly implementation: readonly BundleFile[];
  };
  readonly corpus: {
    readonly root: string;
    readonly files: readonly BundleFile[];
  };
  readonly evaluator: {
    readonly profile: EvaluatorProfile;
    readonly files: readonly BundleFile[];
  };
  readonly model: {
    readonly biEncoder: BiEncoderManifest;
    readonly reranker: RerankerManifest;
    readonly labelingReranker: RerankerManifest;
  };
  readonly replay: {
    readonly commands: readonly string[];
    readonly coordinatorCacheOptional: true;
    readonly snapshots: readonly BundleFile[];
  };
  readonly bundleHash: string;
}

export interface ClientVersionPolicyResult {
  readonly ok: boolean;
  readonly code: 'ok' | 'client-version-missing' | 'client-version-invalid' | 'client-version-outdated';
  readonly message: string;
}

// ─── BGE-M3 bi-encoder manifest factory ──────────────────────────────────────

/**
 * Default retrieval-key layout for BGE-M3 dense mode at 256-byte slot budget.
 * Calibration may pin a smaller dim; defaults are conservative.
 */
export const BGE_M3_DEFAULT_LAYOUT: RetrievalKeyLayout = {
  dim: 243,           // 256 - 9 header - 4-byte int8 scale = 243 payload scalars
  quantization: 'int8',
  headerBytes: 9,
};

export const BGE_M3_DEFAULT_REVISION = '5617a9f61b028005a4858fdac845db406aefb181';

export const BGE_M3_DENSE_FILES: readonly ModelFileFetch[] = [
  { path: '1_Pooling/config.json', sha256: 'e54c164a07274f2eb45bb724f54a79d1efcc90c41573887cd9a29aeee0597352', bytes: 191 },
  { path: 'colbert_linear.pt', sha256: '19bfbae397c2b7524158c919d0e9b19393c5639d098f0a66932c91ed8f5f9abb', bytes: 2100674 },
  { path: 'config.json', sha256: '26159e7ad065073448460117eb24b7a4572f6f4e78eadff65dc0a11c052449fa', bytes: 687 },
  { path: 'config_sentence_transformers.json', sha256: '1eef72430e7194a1e59680e635aed81ffa083f05668dbc5bb1c56c04c0999c38', bytes: 123 },
  { path: 'modules.json', sha256: '84e40c8e006c9b1d6c122e02cba9b02458120b5fb0c87b746c41e0207cf642cf', bytes: 349 },
  { path: 'pytorch_model.bin', sha256: 'b5e0ce3470abf5ef3831aa1bd5553b486803e83251590ab7ff35a117cf6aad38', bytes: 2271145830 },
  { path: 'sentence_bert_config.json', sha256: 'eb9b44b13c0f52a3b3685c3b1cbdea1ba8b04bea123b98f61610048940776eb1', bytes: 54 },
  { path: 'sentencepiece.bpe.model', sha256: 'cfc8146abe2a0488e9e2a0c56de7952f7c11ab059eca145a0a727afce0db2865', bytes: 5069051 },
  { path: 'sparse_linear.pt', sha256: '45c93804d2142b8f6d7ec6914ae23a1eee9c6a1d27d83d908a20d2afb3595ad9', bytes: 3516 },
  { path: 'special_tokens_map.json', sha256: '8c785abebea9ae3257b61681b4e6fd8365ceafde980c21970d001e834cf10835', bytes: 964 },
  { path: 'tokenizer.json', sha256: '21106b6d7dab2952c1d496fb21d5dc9db75c28ed361a05f5020bbba27810dd08', bytes: 17098108 },
  { path: 'tokenizer_config.json', sha256: 'a62b2b6784f990259fddef5f16388693a8043be4f69179e6a5257eeb3f9abac4', bytes: 444 },
];

export interface BgeM3ManifestOptions {
  readonly revision?: string;
  readonly tokenizerRevision?: string;
  readonly outputDim?: number;
  readonly quantization?: Quantization;
  readonly retrievalKeyLayout?: RetrievalKeyLayout;
  readonly files?: readonly ModelFileFetch[];
}

export function bgeM3DenseManifest(opts: BgeM3ManifestOptions = {}): BiEncoderManifest {
  return {
    provider: 'huggingface',
    modelId: 'BAAI/bge-m3',
    revision: opts.revision ?? BGE_M3_DEFAULT_REVISION,
    mode: 'dense',
    outputDim: opts.outputDim ?? 1024,
    tokenizerRevision: opts.tokenizerRevision ?? opts.revision ?? BGE_M3_DEFAULT_REVISION,
    quantization: opts.quantization ?? {
      weights: 'int8',
      activations: 'fp32',
      accumulation: 'fp32',
      scheme: 'symmetric_per_channel',
    },
    retrievalKeyLayout: opts.retrievalKeyLayout ?? BGE_M3_DEFAULT_LAYOUT,
    files: opts.files ?? BGE_M3_DENSE_FILES,
  };
}

// ─── Reranker factories ──────────────────────────────────────────────────────

export const QWEN3_RERANKER_DEFAULT_REVISION = 'e61197ed45024b0ed8a2d74b80b4d909f1255473';

export const QWEN3_RERANKER_06B_FILES: readonly ModelFileFetch[] = [
  { path: 'config.json', sha256: 'd479c427a9ca5295218063d4f9aca4f297ab4ac27487cca7af42c84643d51ef0', bytes: 727 },
  { path: 'config_sentence_transformers.json', sha256: '6a153d6696f78fd588c1c728967f0b773ea869d3c6028f151ce71ebe49140762', bytes: 325 },
  { path: 'generation_config.json', sha256: '81051cd3f6e77013827148d0b8a6ead93f8ac390d5ab805f849199f0af6a08db', bytes: 214 },
  { path: 'modules.json', sha256: '6f13b6b4a89e577b591b2077bca40c67c26541a6740a8809267cb474f90806a9', bytes: 280 },
  { path: 'sentence_bert_config.json', sha256: '3234ebd224d492cbe8d55d5ec80a3f408451c4db3005bafb64fe1c51c763e01e', bytes: 362 },
  { path: 'tokenizer_config.json', sha256: '253153d0738ceb4c668d2eff957714dd2bea0b56de772a9fdccd96cbf517e6a0', bytes: 9706 },
  { path: 'vocab.json', sha256: 'ca10d7e9fb3ed18575dd1e277a2579c16d108e32f27439684afa0e10b1440910', bytes: 2776833 },
  { path: 'merges.txt', sha256: '8831e4f1a044471340f7c0a83d7bd71306a5b867e95fd870f74d0c5308a904d5', bytes: 1671853 },
  { path: 'tokenizer.json', sha256: 'aeb13307a71acd8fe81861d94ad54ab689df773318809eed3cbe794b4492dae4', bytes: 11422654 },
  { path: 'model.safetensors', sha256: '27cd75a405b9c1b46b59abfd88aaa209e6fed2a1972cde9b70e7659537c5e65b', bytes: 1191588280 },
  { path: '1_LogitScore/config.json', sha256: '73e3156450564d8a98b7e47bcf5aace0f29600828b51937da545571e84db3ff3', bytes: 57 },
  { path: 'chat_template.jinja', sha256: '6f682162495ec5b39fd9005c01b6aa2a74669379fe967039f1e2cbbe8752369d', bytes: 741 },
];

export interface RerankerManifestOptions {
  readonly revision?: string;
  readonly files?: readonly ModelFileFetch[];
}

export function qwen3Reranker06BManifest(opts: RerankerManifestOptions = {}): RerankerManifest {
  return {
    provider: 'huggingface',
    modelId: 'Qwen/Qwen3-Reranker-0.6B',
    revision: opts.revision ?? QWEN3_RERANKER_DEFAULT_REVISION,
    files: opts.files ?? QWEN3_RERANKER_06B_FILES,
  };
}

export interface MemRerankerManifestOptions {
  readonly modelId: 'memreranker/0.6B' | 'memreranker/4B' | string;
  readonly revision: string;
  readonly files: readonly ModelFileFetch[];
}

export function memRerankerManifest(opts: MemRerankerManifestOptions): RerankerManifest {
  return {
    provider: 'huggingface',
    modelId: opts.modelId,
    revision: opts.revision,
    files: opts.files,
  };
}

export const MEMRERANKER_4B_DEFAULT_REVISION = '7fe33c1385f652f52d370b8822d6b620b32b6ec4';

export const MEMRERANKER_4B_FILES: readonly ModelFileFetch[] = [
  { path: '1_LogitScore/config.json', sha256: '73e3156450564d8a98b7e47bcf5aace0f29600828b51937da545571e84db3ff3', bytes: 57 },
  { path: 'chat_template.jinja', sha256: '6f682162495ec5b39fd9005c01b6aa2a74669379fe967039f1e2cbbe8752369d', bytes: 741 },
  { path: 'config.json', sha256: '82d53bdb18bfab8cd5ec620710f1561903dfdbdf8f5cf81d2237f7fa62766502', bytes: 1593 },
  { path: 'config_sentence_transformers.json', sha256: '6a153d6696f78fd588c1c728967f0b773ea869d3c6028f151ce71ebe49140762', bytes: 325 },
  { path: 'generation_config.json', sha256: 'ba8396a48fbb26b33af6cdf4463ec064e5f3b692bf5eb0ca1c9d964df377cf2d', bytes: 213 },
  { path: 'model.safetensors', sha256: '48aef1a3c826aabaf8a3852d3d5122ebd456d166ae3e1e401279fc82c15e0ec2', bytes: 8820160440 },
  { path: 'modules.json', sha256: '6f13b6b4a89e577b591b2077bca40c67c26541a6740a8809267cb474f90806a9', bytes: 280 },
  { path: 'sentence_bert_config.json', sha256: '3234ebd224d492cbe8d55d5ec80a3f408451c4db3005bafb64fe1c51c763e01e', bytes: 362 },
  { path: 'special_tokens_map.json', sha256: '76862e765266b85aa9459767e33cbaf13970f327a0e88d1c65846c2ddd3a1ecd', bytes: 613 },
  { path: 'tokenizer.json', sha256: 'be75606093db2094d7cd20f3c2f385c212750648bd6ea4fb2bf507a6a4c55506', bytes: 11422650 },
  { path: 'tokenizer_config.json', sha256: '579073f506a3f85caed232bb91617cfb93028408d1f43ffaf66f3fc1aee9a9af', bytes: 348 },
];

export function memReranker4BManifest(opts: RerankerManifestOptions = {}): RerankerManifest {
  return {
    provider: 'huggingface',
    modelId: 'IAAR-Shanghai/MemReranker-4B',
    revision: opts.revision ?? MEMRERANKER_4B_DEFAULT_REVISION,
    files: opts.files ?? MEMRERANKER_4B_FILES,
  };
}

// ─── Default profile ─────────────────────────────────────────────────────────

const DEFAULT_SPEC_FILES = [
  'specs/cortex_state.md',
  'specs/cortex_schema.json',
  'specs/packing_spec.md',
  'specs/merkleization_spec.md',
  'specs/patch_format.md',
  'specs/retrieval_benchmark.md',
  'specs/substrate_retrieval_semantics.md',
  'specs/corpus_retrieval.md',
  'specs/hidden_query_pack.md',
  'specs/determinism.md',
] as const;

// Launch reference implementation = the TypeScript path ONLY. The TS impl is what the coordinator,
// scorer, replay watcher, and contract-adjacent code all execute at launch. cortex_py was REMOVED
// from the attested set (2026-05-29): it does not enforce the current r5 PolicyAtom grammar
// (no policy_atoms_mode; validate.py leaves 896-991 / PolicyAtom regions unconstrained), so
// attesting it as a launch reference impl would falsely claim a second r5-correct implementation.
// Per the "current launch grammar only, no r4-compat surface" rule, Python is quarantined to
// dev-only tooling and is NOT part of launch attestation/reference claims. (Re-add ONLY if/when
// cortex_py is brought to full r5 parity with cross-impl byte-exact tests.)
const DEFAULT_IMPL_FILES = [
  'packages/cortex/src/state/codec.ts',
  'packages/cortex/src/state/merkle.ts',
  'packages/cortex/src/state/patch.ts',
  'packages/cortex/src/state/types.ts',
  'packages/cortex/src/state/validate.ts',
] as const;

const DEFAULT_EVALUATOR_FILES = [
  'packages/cortex/src/eval/retrieval-corpus.ts',
  'packages/cortex/src/eval/retrieval-benchmark.ts',
  'packages/cortex/src/eval/ir-metrics.ts',
  'packages/cortex/src/eval/hidden-query-pack.ts',
  'packages/cortex/src/eval/bi-encoder.ts',
  'packages/cortex/src/eval/reranker.ts',
  // Per-patch on-chain randomness stack — pinned so the bundleHash
  // catches any drift in the acceptance/replay logic. See
  // docs/CORETEX_V4_ONCHAIN_RANDOMNESS_PLAN.md.
  'packages/cortex/src/eval/seed-derivation.ts',
  'packages/cortex/src/eval/live-eval-admission.ts',
  'packages/cortex/src/coordinator/base-blockhash.ts',
  'packages/cortex/src/coordinator/patch-received-notice.ts',
  'packages/cortex/src/coordinator/per-patch-evaluator.ts',
  'packages/cortex/src/coordinator/retrieval-data-source.ts',
  'packages/cortex/src/coordinator/epoch-frontier.ts',
  'packages/cortex/src/replay/per-patch.ts',
  'packages/cortex/src/substrate/retrieval-decoder.ts',
  'packages/cortex/src/substrate/structural-validity.ts',
  'packages/cortex/src/substrate/slot-policy.ts',
  'packages/cortex/src/corpus/admission.ts',
  'packages/cortex/src/corpus/delta.ts',
  'packages/cortex/src/corpus/logical-delta-bridge.ts',
  'packages/cortex/src/corpus/epoch-rotation.ts',
  'packages/cortex/src/rewards/difficulty.ts',
  'packages/cortex/src/rewards/work-units.ts',
  'packages/cortex/src/coordinator/endpoints.ts',
  'packages/cortex/src/replay/v4.ts',
  'packages/cortex/src/replay-cli.ts',
] as const;

// runtimePin is the floor of installed Python runtime versions a coordinator
// host must satisfy to run the canonical scoring path. Bumped from
// torch 2.4 / transformers 4.46 to 2.6 / 4.55 because:
//   - transformers ≥ 4.51 is required to load Qwen3 architectures
//     (`model_type='qwen3'` was added in that release; 4.46 raised
//     ValueError on AutoConfig.from_pretrained for Qwen/Qwen3-Reranker-0.6B
//     and IAAR-Shanghai/MemReranker-4B);
//   - transformers ≥ 4.55 raises a torch-version guard requiring torch ≥ 2.6
//     when loading any pickle-encoded checkpoint (CVE-2025-32434 in
//     `torch.load`); BGE-M3 still ships pytorch_model.bin (pickle), so
//     torch 2.6 is the minimum that loads the bundle's pinned bi-encoder.
// Major.minor pin allows patch upgrades but still refuses unrelated majors.
export const DEFAULT_RUNTIME_PIN: RuntimePin = {
  flavor: 'torch-transformers',
  versions: {
    torch: '2.6.*',
    transformers: '4.55.*',
    'huggingface_hub': '0.36.*',
    tokenizers: '0.21.*',
  },
  buildFlags: ['cpu-only'],
};

export const DEFAULT_COMPOSITE_WEIGHTS_PIN: CompositeWeightPin = {
  w_retrieval: 0.75,
  w_temporal: 0.08,
  w_relation_recall: 0.07,
  w_abstention: 0.05,
  w_structural_sanity: 0.05,
};

export const DEFAULT_PATCH_FLOORS: PatchAcceptanceFloorsPin = {
  minImprovementPpm: 2500,
  structuralFloor: 0.95,
  protectedRegressionFloor: 0.05,
  familyCatastrophicFloor: 0.85,
};

export const DEFAULT_SPLIT_RATIOS_PIN: SplitRatiosPin = {
  trainVisiblePct: 70,
  calibrationPct: 10,
  evalHiddenPct: 15,
  canaryPct: 5,
};

export const DEFAULT_HIDDEN_PACK_PROFILE: HiddenPackProfilePin = {
  packSize: 64,
  quotas: [
    { stratum: 'family=near_collision,bucket=hard', minCount: 4 },
    { stratum: 'family=temporal,bucket=hard', minCount: 4 },
    { stratum: 'family=long_horizon,bucket=hard', minCount: 4 },
    { stratum: 'family=multi_hop_relation,bucket=hard', minCount: 4 },
  ],
};

export const DEFAULT_RELATION_EDGE_TYPES = [
  'supports',
  'supersedes',
  'coreference_of',
  'causes',
  'derived_from',
  'co_occurs_with',
] as const;

/**
 * Default category→relevance mapping. Validated against the production
 * reranker (Qwen3-Reranker-0.6B) before launch — the launch checklist
 * requires the median Qwen3 score per category to be monotonic in this
 * map's relevance bucket and to lie within an envelope around the
 * assigned value (no inverted buckets, no "unrelated" with high score).
 *
 * The map is part of the signed bundle so replay is deterministic and
 * verifiable by anyone who can rerun the corpus generator + the pinned
 * reranker against the same challenge-library inputs.
 */
export const DEFAULT_NEG_CATEGORY_RELEVANCE_MAP: NegCategoryRelevanceMap = {
  // Same entity, wrong attribute value — high lexical+semantic overlap,
  // strong partial-credit signal because the substrate "knows about the
  // right entity" even if it picks the wrong attribute.
  near_collision_attribute: 0.4,
  // Different entity, same domain — moderate overlap, weaker partial credit.
  near_collision_entity:    0.2,
  // Explicitly stale prior value — was correct, no longer is. Partial credit
  // because the temporal substrate must distinguish "was" from "is".
  temporal_stale:           0.4,
  // Designed adversarial trap — must reject; no credit.
  trap:                     0.0,
  // High lexical overlap, low semantic relevance — small credit for
  // surface match but punishes substrates that rely on lexical alone.
  lexical_distractor:       0.2,
  // Multi-hop neighbor (relation target) — partial credit because the
  // substrate reaching it via relations is the v4 design intent.
  relation_neighbor:        0.4,
  // True negative / synthetic padding — no credit.
  unrelated:                0.0,
};

export const DEFAULT_PROFILE: EvaluatorProfile = {
  name: 'coretex-v4-launch',
  version: 'v2',
  scoreScale: 'ppm',
  scorePpmEncoding: 'uint32-0-to-1000000',
  patchScoreDeltaEncoding: 'int64-ppm',
  primaryMetric: 'ndcg@10',
  acceleratorPolicy: 'cpu_only',
  runtimePin: DEFAULT_RUNTIME_PIN,
  replayTolerancePpm: 250,            // canonical replay disagreement ceiling
  compositeWeights: DEFAULT_COMPOSITE_WEIGHTS_PIN,
  patchAcceptanceFloors: DEFAULT_PATCH_FLOORS,
  splitRatios: DEFAULT_SPLIT_RATIOS_PIN,
  hiddenPack: DEFAULT_HIDDEN_PACK_PROFILE,
  relationHopBudget: 3,
  abstentionThreshold: 0.001,
  rerankerTopK: 10,
  retrievalKeyTopK: 50,
  relationEdgeTypes: DEFAULT_RELATION_EDGE_TYPES,
  revealGracePeriodSeconds: 60 * 60 * 6,  // 6h pre-calibration; calibrate replaces
  negCategoryRelevanceMap: DEFAULT_NEG_CATEGORY_RELEVANCE_MAP,
  baseRpcConfig: DEFAULT_BASE_RPC_CONFIG,

  // ─── v2-lens pipeline defaults (substrate-hardening §6.3). Calibration
  //     Runs 0+1 produce the real pinned values; these are pre-calibration
  //     placeholders. The hardening doc pins these via Run 0 (sensitivity
  //     sweep) and Run 1 (firstStageTopK per-stratum). ───────────────────
  // NOTE: this DEFAULT_PROFILE is the CONSERVATIVE r4 baseline (PolicyAtoms OFF — the r5-no-atoms==r4 safety
  // baseline). It is NOT the launch config. The SIGNED LAUNCH profile is r5 with the 3 PolicyAtom families active:
  // release/bundle/evaluator-profile-v2-dgen1-policy-r5-{100k,300k}.json. Do not read these defaults as "what ships".
  // Canonical r4/r5 explainer: release/calibration/CURRENT.md (top) + specs/cortex_state.md §Range C-r5/F-r5.
  pipelineVersion: 'coretex-retrieval-v2-lens-r4',  // Tier-2 substrate epoch (stride-1 MemoryIndex, 96-pair temporal)
  firstStageTopK: 200,             // calibration Run 1 will tune per-stratum
  rerankerInputTopK: 128,          // §6.5 MemReranker-style cross-encoder pool cap
  lensTopK: 36,                    // == retrievalKeys slot count
  lensWeight: 0.10,                // calibration Run 0 will tune
  anchorWeight: 0.15,              // calibration Run 0 will tune
  relationExpansionBudget: 50,     // calibration Run 0 will tune (Phase A: anchor-to-anchor BFS)
  categoryLensExpansionBudget: 50, // calibration Run 0 will tune (Phase B: corpus-native catLens BFS)
  temporalCurrentBoost: 0.10,      // calibration Run 0 will tune
  temporalStaleSuppression: 0.10,  // calibration Run 0 will tune
  lensDiversityFloor: 0.70,        // §6.4; calibration Run 0 confirms
  corpusDocDedupe: 'canonical-doc-id',
  // §5 selection-policy attestation. The DEFAULT_PROFILE's K=200 is a
  // pre-calibration placeholder; calibration Run 1 replaces this with
  // the production-pinned value AND its method (worst-stratum-target
  // when the floor is met, operator-override otherwise).
  firstStageTopKSelection: {
    method: 'worst-stratum-target',
    reason: 'DEFAULT_PROFILE placeholder; calibration Run 1 replaces this with the production-pinned method and evidence.',
    calibrationReport: 'release/calibration/first-stage-topk-sweep.json',
  },
};

/**
 * Canonical profile → `ScoringOptions` mapping. The SINGLE place that turns a
 * signed `EvaluatorProfile` into scorer options, so production, calibration, and
 * replay all express the SAME config — including the V2 knobs (`ownerScopeMode`,
 * `categoryLensFinalBonusWeight`, `categoryLensScoreInheritance`). Previously
 * each caller assembled options ad hoc, so the signed profile could not fully
 * express the winning V2 config (owner-scope + non-flooding promotion + score-
 * inheritance). Runtime deps (models) are injected; the profile supplies scalars.
 */
export function scoringOptionsFromProfile(
  profile: EvaluatorProfile,
  runtime: {
    readonly biEncoder: BiEncoder;
    readonly reranker: CrossEncoderReranker;
    readonly biEncoderHash: string;
    readonly retrievalKeyLayout: RetrievalKeyLayout;
  },
): ScoringOptions {
  return {
    weights: profile.compositeWeights,
    biEncoder: runtime.biEncoder,
    reranker: runtime.reranker,
    biEncoderHash: runtime.biEncoderHash,
    retrievalKeyLayout: runtime.retrievalKeyLayout,
    relationHopBudget: profile.relationHopBudget,
    abstentionThreshold: profile.abstentionThreshold,
    rerankerTopK: profile.rerankerTopK,
    retrievalKeyTopK: profile.retrievalKeyTopK,
    firstStageTopK: profile.firstStageTopK ?? 3200,
    ...(profile.firstStageMode !== undefined ? { firstStageMode: profile.firstStageMode } : {}),
    ...(profile.firstStageDenseWeight !== undefined ? { firstStageDenseWeight: profile.firstStageDenseWeight } : {}),
    ...(profile.firstStageLexicalWeight !== undefined ? { firstStageLexicalWeight: profile.firstStageLexicalWeight } : {}),
    rerankerInputTopK: profile.rerankerInputTopK ?? 128,
    lensTopK: profile.lensTopK ?? 36,
    lensWeight: profile.lensWeight ?? 0.1,
    anchorWeight: profile.anchorWeight ?? 0.15,
    relationExpansionBudget: profile.relationExpansionBudget ?? 50,
    ...(profile.categoryLensExpansionBudget !== undefined ? { categoryLensExpansionBudget: profile.categoryLensExpansionBudget } : {}),
    ...(profile.lensDiversityFloor !== undefined ? { lensDiversityFloor: profile.lensDiversityFloor } : {}),
    temporalCurrentBoost: profile.temporalCurrentBoost ?? 0.1,
    temporalStaleSuppression: profile.temporalStaleSuppression ?? 0.1,
    // ─── V2 launch-lane knobs (the winning config the profile must express) ───
    ...(profile.ownerScopeMode !== undefined ? { ownerScopeMode: profile.ownerScopeMode } : {}),
    ...(profile.categoryLensFinalBonusWeight !== undefined ? { categoryLensFinalBonusWeight: profile.categoryLensFinalBonusWeight } : {}),
    ...(profile.categoryLensScoreInheritance !== undefined ? { categoryLensScoreInheritance: profile.categoryLensScoreInheritance } : {}),
    ...(profile.categoryLensSeedTopK !== undefined ? { categoryLensSeedTopK: profile.categoryLensSeedTopK } : {}),
    ...(profile.categoryLensHopBudget !== undefined ? { categoryLensHopBudget: profile.categoryLensHopBudget } : {}),
    ...(profile.categoryLensEvidenceBundle !== undefined ? { categoryLensEvidenceBundle: profile.categoryLensEvidenceBundle } : {}),
    ...(profile.temporalStaleContrast !== undefined ? { temporalStaleContrast: profile.temporalStaleContrast } : {}),
    pipelineVersion: profile.pipelineVersion,
    // ─── r5 PolicyAtoms: policyAtomsMode is driven HARD by the pinned pipelineVersion ───
    ...(profile.pipelineVersion === 'coretex-retrieval-v2-policy-r5' ? { policyAtomsMode: true } : {}),
    ...(profile.enableEvidenceBundleAtoms !== undefined ? { enableEvidenceBundleAtoms: profile.enableEvidenceBundleAtoms } : {}),
    ...(profile.enableConflictLifecycleAtoms !== undefined ? { enableConflictLifecycleAtoms: profile.enableConflictLifecycleAtoms } : {}),
    ...(profile.enableAbstentionAtoms !== undefined ? { enableAbstentionAtoms: profile.enableAbstentionAtoms } : {}),
    ...(profile.enableValidityAtoms !== undefined ? { enableValidityAtoms: profile.enableValidityAtoms } : {}),
    ...(profile.enableEntityResolutionAtoms !== undefined ? { enableEntityResolutionAtoms: profile.enableEntityResolutionAtoms } : {}),
    ...(profile.enableScopeAtoms !== undefined ? { enableScopeAtoms: profile.enableScopeAtoms } : {}),
    ...(profile.policyMaxBudgetEvidence !== undefined ? { policyMaxBudgetEvidence: profile.policyMaxBudgetEvidence } : {}),
    ...(profile.policyMaxBudgetConflict !== undefined ? { policyMaxBudgetConflict: profile.policyMaxBudgetConflict } : {}),
    ...(profile.policyMaxBudgetEntity !== undefined ? { policyMaxBudgetEntity: profile.policyMaxBudgetEntity } : {}),
    ...(profile.policyMaxBudgetScope !== undefined ? { policyMaxBudgetScope: profile.policyMaxBudgetScope } : {}),
    ...(profile.policyEntityMaxDocs !== undefined ? { policyEntityMaxDocs: profile.policyEntityMaxDocs } : {}),
    ...(profile.policyScopeMaxDocs !== undefined ? { policyScopeMaxDocs: profile.policyScopeMaxDocs } : {}),
    ...(profile.policyScopeMaxSuppress !== undefined ? { policyScopeMaxSuppress: profile.policyScopeMaxSuppress } : {}),
    ...(profile.policyAbstentionTop1Threshold !== undefined ? { policyAbstentionTop1Threshold: profile.policyAbstentionTop1Threshold } : {}),
    ...(profile.policyAbstentionMarginThreshold !== undefined ? { policyAbstentionMarginThreshold: profile.policyAbstentionMarginThreshold } : {}),
    ...(profile.policyEmitTraces !== undefined ? { policyEmitTraces: profile.policyEmitTraces } : {}),
    ...(profile.policyQueryLocalTopK !== undefined ? { policyQueryLocalTopK: profile.policyQueryLocalTopK } : {}),
    ...(profile.policyQueryConditionedAdmission !== undefined ? { policyQueryConditionedAdmission: profile.policyQueryConditionedAdmission } : {}),
    ...(profile.policyRelationTypedAdmission !== undefined ? { policyRelationTypedAdmission: profile.policyRelationTypedAdmission } : {}),
    ...(profile.enableRawRoutingAnchors !== undefined ? { enableRawRoutingAnchors: profile.enableRawRoutingAnchors } : {}),
    ...(profile.enableRelationAnchorEdges !== undefined ? { enableRelationAnchorEdges: profile.enableRelationAnchorEdges } : {}),
    ...(profile.policyEvidenceAllowedActions !== undefined ? { policyEvidenceAllowedActions: profile.policyEvidenceAllowedActions } : {}),
    ...(profile.policyConflictIntentAdmission !== undefined ? { policyConflictIntentAdmission: profile.policyConflictIntentAdmission } : {}),
    ...(profile.enableAspectConstraintAtoms !== undefined ? { enableAspectConstraintAtoms: profile.enableAspectConstraintAtoms } : {}),
    ...(profile.policyAspectIntentAdmission !== undefined ? { policyAspectIntentAdmission: profile.policyAspectIntentAdmission } : {}),
    ...(profile.policyAspectBoost !== undefined ? { policyAspectBoost: profile.policyAspectBoost } : {}),
    ...(profile.rerankerMemoryIRFormat !== undefined ? { rerankerMemoryIRFormat: profile.rerankerMemoryIRFormat } : {}),
    ...(profile.rerankerMemoryIRMode !== undefined ? { rerankerMemoryIRMode: profile.rerankerMemoryIRMode } : {}),
    ...(profile.rerankerMemoryIRSource !== undefined ? { rerankerMemoryIRSource: profile.rerankerMemoryIRSource } : {}),
  } as ScoringOptions;
}

/**
 * Canonical profile → difficulty-controller overrides mapping. The SINGLE place
 * that turns a signed `EvaluatorProfile`'s `controllerParams` into the optional
 * `DifficultyInputs` fields, so the launch controller shape is sourced from the
 * signed profile (auditable, replayable) rather than ad-hoc harness CLI flags.
 *
 * `targetAdvances` is a runtime/emission parameter, so it is supplied by the
 * caller and used to resolve the absolute `qualityHighThreshold` from the pinned
 * `qualityHighThresholdMult`. When `controllerParams` (or a field) is absent the
 * `difficulty.ts` protocol defaults apply — identical to the pre-pin behaviour.
 *
 * The returned object is spread directly into `nextMinImprovementPpm(...)`.
 */
export function controllerParamsFromProfile(
  profile: EvaluatorProfile,
  targetAdvances: number,
): {
  readonly rampUpMaxRatio: number;
  readonly decayRatio: number;
  readonly smallDriftRatio: number;
  readonly underTargetRecoveryRatio: number;
  readonly qualityHighThreshold: number;
} {
  const cp = profile.controllerParams ?? {};
  const mult = cp.qualityHighThresholdMult ?? DEFAULT_CONTROLLER_PARAMS.qualityHighThresholdMult;
  return {
    rampUpMaxRatio: cp.rampUpMaxRatio ?? DEFAULT_CONTROLLER_PARAMS.rampUpMaxRatio,
    decayRatio: cp.decayRatio ?? DEFAULT_CONTROLLER_PARAMS.decayRatio,
    smallDriftRatio: cp.smallDriftRatio ?? DEFAULT_CONTROLLER_PARAMS.smallDriftRatio,
    underTargetRecoveryRatio: cp.underTargetRecoveryRatio ?? DEFAULT_CONTROLLER_PARAMS.underTargetRecoveryRatio,
    qualityHighThreshold: mult * targetAdvances,
  };
}

// ─── Build / verify ──────────────────────────────────────────────────────────

export interface BuildBundleManifestOptions {
  readonly repoRoot: string;
  readonly bundleName?: string;
  readonly generatedAt?: string;
  readonly corpusRoot: string;
  readonly corpusFiles: readonly string[];
  readonly biEncoder: BiEncoderManifest;
  readonly reranker: RerankerManifest;
  readonly labelingReranker: RerankerManifest;
  readonly evaluatorProfile?: Partial<EvaluatorProfile>;
  readonly extraEvaluatorFiles?: readonly string[];
  readonly snapshotFiles?: readonly string[];
}

export function buildBundleManifest(opts: BuildBundleManifestOptions): CoreTexBundleManifest {
  assertBytes32(opts.corpusRoot, 'corpusRoot');
  validateBiEncoderManifest(opts.biEncoder);
  validateRerankerManifest(opts.reranker, 'reranker');
  validateRerankerManifest(opts.labelingReranker, 'labelingReranker');
  assertSeparateLabelingModel(opts.reranker, opts.labelingReranker);

  const generatedAt = opts.generatedAt ?? new Date(0).toISOString();
  const profile: EvaluatorProfile = { ...DEFAULT_PROFILE, ...opts.evaluatorProfile };
  validateProfile(profile);

  const evaluatorFiles = [...DEFAULT_EVALUATOR_FILES, ...(opts.extraEvaluatorFiles ?? [])];

  const withoutHash = {
    schemaVersion: 'coretex.client-bundle.v2' as const,
    generatedAt,
    bundleName: opts.bundleName ?? 'botcoin-coretex-v4',
    substrate: {
      wordCount: 1024 as const,
      packedBytes: 32768 as const,
      specs: DEFAULT_SPEC_FILES.map((path) => hashFile(opts.repoRoot, path, 'substrate-spec')),
      implementation: DEFAULT_IMPL_FILES.map((path) => hashFile(opts.repoRoot, path, 'substrate-impl')),
    },
    corpus: {
      root: opts.corpusRoot,
      files: opts.corpusFiles.map((path) => hashFile(opts.repoRoot, path, 'corpus')),
    },
    evaluator: {
      profile,
      files: evaluatorFiles.map((path) => hashFile(opts.repoRoot, path, 'evaluator')),
    },
    model: {
      biEncoder: opts.biEncoder,
      reranker: opts.reranker,
      labelingReranker: opts.labelingReranker,
    },
    replay: {
      commands: [
        'coretex-replay tx --tx <hash> --rpc <url> --parent-state <state.bin> --bundle-manifest <manifest.json> --core-version-hash <bundleHash>',
        'coretex-replay current --events <events.json> --parent-state <state.bin> --bundle-manifest <manifest.json> --core-version-hash <bundleHash>',
        'coretex-replay watch --rpc <url> --v4 <address> --cortex-state <address> --from-block <n> --parent-state <state.bin> --bundle-manifest <manifest.json> --core-version-hash <bundleHash>',
      ],
      coordinatorCacheOptional: true as const,
      snapshots: (opts.snapshotFiles ?? []).map((path) => hashFile(opts.repoRoot, path, 'substrate-snapshot')),
    },
  };

  const bundleHash = hashJson(withoutHash);
  return { ...withoutHash, bundleHash };
}

export function verifyBundleManifest(manifest: CoreTexBundleManifest, repoRoot: string): string[] {
  const errors: string[] = [];
  if (manifest.schemaVersion !== 'coretex.client-bundle.v2') errors.push('bad schemaVersion');
  if (manifest.substrate.wordCount !== 1024) errors.push('substrate.wordCount must be 1024');
  if (manifest.substrate.packedBytes !== 32768) errors.push('substrate.packedBytes must be 32768');
  validateBytes32(manifest.corpus.root, 'corpus.root', errors);
  validateBiEncoderManifest(manifest.model.biEncoder, errors);
  validateRerankerManifest(manifest.model.reranker, 'reranker', errors);
  validateRerankerManifest(manifest.model.labelingReranker, 'labelingReranker', errors);
  if (manifest.model.reranker.modelId === manifest.model.labelingReranker.modelId
   && manifest.model.reranker.revision === manifest.model.labelingReranker.revision) {
    errors.push('labelingReranker must differ from production reranker');
  }
  validateProfile(manifest.evaluator.profile, errors);

  for (const file of [
    ...manifest.substrate.specs,
    ...manifest.substrate.implementation,
    ...manifest.corpus.files,
    ...manifest.evaluator.files,
    ...manifest.replay.snapshots,
  ]) {
    const abs = resolve(repoRoot, file.path);
    if (!existsSync(abs)) {
      errors.push(`${file.path}: missing`);
      continue;
    }
    const got = sha256HexStreaming(abs);
    if (got !== file.sha256.toLowerCase()) errors.push(`${file.path}: sha256 mismatch`);
  }

  const { bundleHash: _bundleHash, ...withoutHash } = manifest;
  const expected = hashJson(withoutHash);
  if (expected !== manifest.bundleHash.toLowerCase()) {
    errors.push(`bundleHash mismatch: expected ${expected} got ${manifest.bundleHash}`);
  }
  return errors;
}

export function computeBundleHashFromManifest(manifestWithoutHash: Omit<CoreTexBundleManifest, 'bundleHash'>): string {
  return hashJson(manifestWithoutHash);
}

export function withRecomputedBundleHash(manifest: CoreTexBundleManifest): CoreTexBundleManifest {
  const { bundleHash: _bundleHash, ...withoutHash } = manifest;
  return {
    ...withoutHash,
    bundleHash: computeBundleHashFromManifest(withoutHash),
  };
}

export function evaluateClientVersionPolicy(
  policy: ClientVersionPolicy | undefined,
  clientVersion: string | undefined,
): ClientVersionPolicyResult {
  if (!policy) {
    return { ok: true, code: 'ok', message: 'no client version policy pinned in bundle' };
  }
  if (!clientVersion) {
    return {
      ok: false,
      code: 'client-version-missing',
      message: `bundle requires client >= ${policy.minimumVersion}, but no client version was provided`,
    };
  }
  if (!isSemver(clientVersion)) {
    return {
      ok: false,
      code: 'client-version-invalid',
      message: `client version must be semver x.y.z (got ${clientVersion})`,
    };
  }
  if (compareSemver(clientVersion, policy.minimumVersion) < 0) {
    const recommended = policy.recommendedVersion ? ` recommended=${policy.recommendedVersion}` : '';
    return {
      ok: false,
      code: 'client-version-outdated',
      message: `client ${clientVersion} is below bundle minimum ${policy.minimumVersion}.${recommended}`,
    };
  }
  return { ok: true, code: 'ok', message: `client ${clientVersion} satisfies bundle minimum ${policy.minimumVersion}` };
}

export function compareSemverVersions(a: string, b: string): number {
  return compareSemver(a, b);
}

function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'undefined') return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return JSON.stringify(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'bigint') return JSON.stringify(value.toString());
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(obj[key])}`).join(',')}}`;
  }
  throw new TypeError(`canonicalJson: unsupported ${typeof value}`);
}

function hashFile(repoRoot: string, filePath: string, role: string): BundleFile {
  const abs = resolve(repoRoot, filePath);
  const size = statSync(abs).size;
  return {
    role,
    path: slash(relative(repoRoot, abs)) || basename(abs),
    sha256: sha256HexStreaming(abs),
    bytes: size,
  };
}

function sha256HexStreaming(path: string): string {
  // readFileSync has a 2 GiB cap; launch corpus is ~6 GB. Stream via sync
  // chunked reads to keep the hash sync (callers are sync).
  const hash = createHash('sha256');
  const fd = openSync(path, 'r');
  try {
    const buf = Buffer.alloc(64 * 1024 * 1024);
    while (true) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n <= 0) break;
      hash.update(buf.subarray(0, n));
    }
  } finally {
    closeSync(fd);
  }
  return hash.digest('hex');
}

function hashJson(value: unknown): string {
  return bytesToHex(keccak256(new TextEncoder().encode(canonicalJson(value))));
}

function sha256Hex(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

function validateBiEncoderManifest(manifest: BiEncoderManifest, errors?: string[]): void {
  const out = errors ?? [];
  if (manifest.provider !== 'huggingface') out.push('biEncoder.provider must be huggingface');
  if (!manifest.modelId) out.push('biEncoder.modelId is required');
  validateRevision(manifest.revision, 'biEncoder.revision', out);
  validateRevision(manifest.tokenizerRevision, 'biEncoder.tokenizerRevision', out);
  if (manifest.mode !== 'dense') out.push('biEncoder.mode must be dense');
  if (manifest.outputDim <= 0) out.push('biEncoder.outputDim must be positive');
  if (manifest.retrievalKeyLayout.headerBytes < 9) out.push('retrievalKeyLayout.headerBytes must be >= 9');
  validateModelFiles(manifest.files, 'biEncoder', out);
  if (!errors && out.length) throw new Error(out.join('; '));
}

function validateRerankerManifest(manifest: RerankerManifest, role: string, errors?: string[]): void {
  const out = errors ?? [];
  if (manifest.provider !== 'huggingface') out.push(`${role}.provider must be huggingface`);
  if (!manifest.modelId) out.push(`${role}.modelId is required`);
  validateRevision(manifest.revision, `${role}.revision`, out);
  validateModelFiles(manifest.files, role, out);
  if (!errors && out.length) throw new Error(out.join('; '));
}

function assertSeparateLabelingModel(prod: RerankerManifest, lab: RerankerManifest): void {
  if (prod.modelId === lab.modelId && prod.revision === lab.revision) {
    throw new Error('labelingReranker must differ from production reranker (modelId or revision)');
  }
}

function validateRevision(revision: string, field: string, errors: string[]): void {
  const value = revision?.trim() ?? '';
  if (!value || isMutableOrPlaceholderRevision(value)) {
    errors.push(`${field} must be a pinned immutable commit sha, not a mutable ref or placeholder`);
    return;
  }
  if (!/^[0-9a-f]{40}$/i.test(value)) {
    errors.push(`${field} must be a 40-hex Hugging Face commit sha`);
  }
}

function validateModelFiles(files: readonly ModelFileFetch[], role: string, errors: string[]): void {
  if (files.length === 0) errors.push(`${role}.files must not be empty`);
  for (const file of files) {
    if (!file.path) errors.push(`${role} file path is required`);
    if (!/^[0-9a-f]{64}$/i.test(file.sha256)) errors.push(`${role} ${file.path}: sha256 must be 64 hex chars`);
    if (file.bytes !== undefined && (!Number.isSafeInteger(file.bytes) || file.bytes <= 0)) {
      errors.push(`${role} ${file.path}: bytes must be a positive safe integer`);
    }
  }
}

function validateProfile(profile: EvaluatorProfile, errors?: string[]): void {
  const out = errors ?? [];
  if (profile.acceleratorPolicy !== 'cpu_only') out.push("acceleratorPolicy must be 'cpu_only'");
  if (profile.primaryMetric !== 'ndcg@10') out.push("primaryMetric must be 'ndcg@10'");
  if (profile.clientVersionPolicy !== undefined) {
    const policy = profile.clientVersionPolicy;
    if (!isSemver(policy.minimumVersion)) {
      out.push(`clientVersionPolicy.minimumVersion must be semver x.y.z (got ${policy.minimumVersion})`);
    }
    if (policy.recommendedVersion !== undefined && !isSemver(policy.recommendedVersion)) {
      out.push(`clientVersionPolicy.recommendedVersion must be semver x.y.z (got ${policy.recommendedVersion})`);
    }
    if (typeof policy.hardFailOutdated !== 'boolean') {
      out.push('clientVersionPolicy.hardFailOutdated must be a boolean');
    }
  }
  const w = profile.compositeWeights;
  const sum = w.w_retrieval + w.w_temporal + w.w_relation_recall + w.w_abstention + w.w_structural_sanity;
  if (Math.abs(sum - 1) > 1e-6) out.push(`compositeWeights must sum to 1.0 (got ${sum})`);
  if (w.w_retrieval < 0.7 - 1e-9) out.push(`w_retrieval must be >= 0.70 (got ${w.w_retrieval})`);
  if (w.w_structural_sanity > 0.10 + 1e-9) out.push(`w_structural_sanity must be <= 0.10 (got ${w.w_structural_sanity})`);
  if (w.w_temporal <= 0 || w.w_relation_recall <= 0 || w.w_abstention <= 0)
    out.push('w_temporal, w_relation_recall, w_abstention must all be > 0');
  const sr = profile.splitRatios;
  if (sr.trainVisiblePct + sr.calibrationPct + sr.evalHiddenPct + sr.canaryPct !== 100)
    out.push('splitRatios must sum to 100');
  if (profile.relationHopBudget < 1 || profile.relationHopBudget > 6)
    out.push('relationHopBudget must be in [1,6]');
  if (profile.relationExpansionBudget !== undefined) {
    if (!Number.isInteger(profile.relationExpansionBudget) || profile.relationExpansionBudget < 0) {
      out.push('relationExpansionBudget must be a non-negative integer when present');
    }
  }
  if (profile.categoryLensExpansionBudget !== undefined) {
    if (!Number.isInteger(profile.categoryLensExpansionBudget) || profile.categoryLensExpansionBudget < 0) {
      out.push('categoryLensExpansionBudget must be a non-negative integer when present');
    }
  }
  // ─── r5 PolicyAtom knob validation ───
  for (const k of ['policyMaxBudgetEvidence', 'policyMaxBudgetConflict', 'policyMaxBudgetEntity', 'policyMaxBudgetScope'] as const) {
    const v = profile[k];
    if (v !== undefined && (!Number.isInteger(v) || v < 0 || v > 0xffff)) out.push(`${k} must be an integer in [0, 65535] when present`);
  }
  for (const k of ['policyEntityMaxDocs', 'policyScopeMaxDocs', 'policyScopeMaxSuppress'] as const) {
    const v = profile[k];
    if (v !== undefined && (!Number.isInteger(v) || v < 0 || v > 256)) out.push(`${k} must be an integer in [0, 256] when present`);
  }
  if (profile.enableRawRoutingAnchors !== undefined && typeof profile.enableRawRoutingAnchors !== 'boolean') {
    out.push('enableRawRoutingAnchors must be boolean when present');
  }
  if (profile.enableRelationAnchorEdges !== undefined && typeof profile.enableRelationAnchorEdges !== 'boolean') {
    out.push('enableRelationAnchorEdges must be boolean when present');
  }
  if (profile.policyEvidenceAllowedActions !== undefined) {
    const valid = new Set(['include', 'boost', 'suppress', 'bundle']);
    const seen = new Set<string>();
    if (!Array.isArray(profile.policyEvidenceAllowedActions) || profile.policyEvidenceAllowedActions.length === 0) {
      out.push('policyEvidenceAllowedActions must be a non-empty action array when present');
    } else {
      for (const action of profile.policyEvidenceAllowedActions) {
        if (!valid.has(action)) out.push(`policyEvidenceAllowedActions contains invalid action ${action}`);
        if (seen.has(action)) out.push(`policyEvidenceAllowedActions contains duplicate action ${action}`);
        seen.add(action);
      }
    }
  }
  if (profile.policyAbstentionTop1Threshold !== undefined) {
    const t = profile.policyAbstentionTop1Threshold;
    if (typeof t !== 'number' || t < 0 || t > 1) out.push('policyAbstentionTop1Threshold must be in [0,1] when present');
  }
  if (profile.rerankerMemoryIRFormat !== undefined && !['off', 'F2'].includes(profile.rerankerMemoryIRFormat)) {
    out.push("rerankerMemoryIRFormat must be 'off' or 'F2' when present");
  }
  if (profile.rerankerMemoryIRMode !== undefined && !['off', 'full'].includes(profile.rerankerMemoryIRMode)) {
    out.push("rerankerMemoryIRMode must be 'off' or 'full' when present");
  }
  if (profile.rerankerMemoryIRSource !== undefined && !['corpus', 'resolved'].includes(profile.rerankerMemoryIRSource)) {
    out.push("rerankerMemoryIRSource must be 'corpus' or 'resolved' when present");
  }
  // r5 enables only meaningful under the policy-r5 pipeline pin (warn-as-error: prevents
  // accidentally shipping r5 atoms under an r4 profile, where they would be ignored).
  const r5Enabled = profile.enableEvidenceBundleAtoms || profile.enableConflictLifecycleAtoms || profile.enableAbstentionAtoms || profile.enableAspectConstraintAtoms || profile.enableValidityAtoms || profile.enableEntityResolutionAtoms || profile.enableScopeAtoms;
  if (r5Enabled && profile.pipelineVersion !== 'coretex-retrieval-v2-policy-r5') {
    out.push('r5 PolicyAtom enables require pipelineVersion = coretex-retrieval-v2-policy-r5');
  }
  // aspect_constraint is an A100 CANDIDATE, not a launch surface: its boost hook is not wired (r5.1).
  // Fail closed so it cannot be silently shipped or half-enabled. Admission requires the enable; the
  // enable itself is rejected until the r5.1 hook lands (keeps the signed profile honest).
  if (profile.policyAspectIntentAdmission === true && profile.enableAspectConstraintAtoms !== true) {
    out.push('policyAspectIntentAdmission=true requires enableAspectConstraintAtoms=true');
  }
  // aspect_constraint is a WIRED but EXPERIMENTAL surface (default-off; A100 candidate). Enabling it
  // requires a bounded positive boost so it cannot be silently on-with-zero-effect or flood. It is NOT in
  // the launch profile; the A100 boost-only arm decides promotion (then allocate the r5.1 region).
  if (profile.enableAspectConstraintAtoms === true) {
    const b = profile.policyAspectBoost;
    if (typeof b !== 'number' || !(b > 0) || b > 0.5) {
      out.push('enableAspectConstraintAtoms=true requires policyAspectBoost in (0, 0.5] (bounded experimental boost)');
    }
  }
  // Launch-safety: conflict_lifecycle atoms MUST use the conflict-INTENT selector, never the
  // coarse CONFLICT_SET_MEMBER entity selector (which causes off-family damage). Fail closed.
  if (profile.enableConflictLifecycleAtoms === true && profile.policyConflictIntentAdmission !== true) {
    out.push('enableConflictLifecycleAtoms=true requires policyConflictIntentAdmission=true (no coarse entity-selector fallback)');
  }
  // EpochFrontier (churn) pin validation — launch-required churn must be deterministic + attested.
  if (profile.epochFrontier !== undefined) {
    const f = profile.epochFrontier;
    const modes = ['off', 'C0', 'C1', 'C2', 'C3', 'C4'];
    if (!modes.includes(f.mode)) out.push(`epochFrontier.mode must be one of ${modes.join('|')}`);
    if (!Number.isInteger(f.activeWindow) || f.activeWindow < 1) out.push('epochFrontier.activeWindow must be a positive integer');
    if (typeof f.seed !== 'string' || f.seed.length === 0) out.push('epochFrontier.seed must be a non-empty precommit string');
    if (f.baselineRecompute !== 'activeRootChanged') out.push("epochFrontier.baselineRecompute must be 'activeRootChanged'");
    if (f.majorDeltaPolicy !== 'corpusRootChanged') out.push("epochFrontier.majorDeltaPolicy must be 'corpusRootChanged'");
    if (f.maxRootDeltaPerEpoch !== undefined && (!Number.isInteger(f.maxRootDeltaPerEpoch) || f.maxRootDeltaPerEpoch < 1)) out.push('epochFrontier.maxRootDeltaPerEpoch must be a positive integer when present');
  }
  if (profile.replayTolerancePpm > profile.patchAcceptanceFloors.minImprovementPpm)
    out.push('replayTolerancePpm must be <= patchAcceptanceFloors.minImprovementPpm');

  // negCategoryRelevanceMap: every NegCategory must have a relevance in
  // [0, 1] and the mapping must be present for every category the corpus
  // generator can emit. Empty / partial maps would silently degrade qrels
  // to zero (default-on-miss) and ship a broken benchmark.
  const requiredNegCategories: readonly NegCategory[] = [
    'near_collision_entity',
    'near_collision_attribute',
    'temporal_stale',
    'trap',
    'lexical_distractor',
    'relation_neighbor',
    'unrelated',
  ];
  const m = profile.negCategoryRelevanceMap;
  if (!m || typeof m !== 'object') {
    out.push('negCategoryRelevanceMap is required');
  } else {
    for (const cat of requiredNegCategories) {
      const v = (m as Record<string, number>)[cat];
      if (typeof v !== 'number' || Number.isNaN(v) || v < 0 || v > 1) {
        out.push(`negCategoryRelevanceMap.${cat} must be a number in [0, 1] (got ${String(v)})`);
      }
    }
  }

  // Phase H1/H2 fields are optional, but if any baseline-* field is
  // present the full set must be present and internally consistent —
  // a half-populated baseline would silently invalidate the grace rule.
  const anyBaseline =
    profile.baselineParentScorePpm !== undefined ||
    profile.baselineVariancePpm !== undefined ||
    profile.baselineVarianceSource !== undefined ||
    profile.fixedPackRepeatabilityPpm !== undefined ||
    profile.baselineSamples !== undefined ||
    profile.baselineEvalSeedHex !== undefined;
  if (anyBaseline) {
    if (typeof profile.baselineParentScorePpm !== 'number' || profile.baselineParentScorePpm < 0)
      out.push('baselineParentScorePpm must be a non-negative number when baseline is pinned');
    const source = profile.baselineVarianceSource ?? 'unavailable';
    if (!['rotating_pack', 'broad_sampling', 'unavailable'].includes(source)) {
      out.push('baselineVarianceSource must be rotating_pack, broad_sampling, or unavailable when baseline is pinned');
    }
    if (source === 'rotating_pack' || source === 'broad_sampling') {
      if (typeof profile.baselineVariancePpm !== 'number' || profile.baselineVariancePpm < 0) {
        out.push('baselineVariancePpm must be a non-negative number when production baseline variance is pinned');
      }
    }
    if (source === 'unavailable' && profile.baselineVariancePpm !== undefined && profile.baselineVariancePpm !== 0) {
      out.push('baselineVariancePpm must be omitted or 0 when baselineVarianceSource is unavailable');
    }
    if (profile.fixedPackRepeatabilityPpm !== undefined &&
        (typeof profile.fixedPackRepeatabilityPpm !== 'number' || profile.fixedPackRepeatabilityPpm < 0)) {
      out.push('fixedPackRepeatabilityPpm must be a non-negative number when present');
    }
    if (!Number.isInteger(profile.baselineSamples) || (profile.baselineSamples ?? 0) < 1)
      out.push('baselineSamples must be a positive integer when baseline is pinned');
    if (typeof profile.baselineEvalSeedHex !== 'string' || !/^0x[0-9a-f]{64}$/i.test(profile.baselineEvalSeedHex))
      out.push('baselineEvalSeedHex must be 0x + 64 hex chars when baseline is pinned');
  }
  if (profile.majorDeltaThreshold !== undefined) {
    if (!Number.isInteger(profile.majorDeltaThreshold) || profile.majorDeltaThreshold < 0)
      out.push('majorDeltaThreshold must be a non-negative integer when present');
  }

  // controllerParams is optional (pre-pin bundles ship without it → difficulty.ts
  // defaults apply), but any pinned field must be in a sane controller range so a
  // signed profile can't encode a degenerate controller (e.g. rampUp<1 that would
  // shrink the threshold on a ramp, or decay>=1 that never eases difficulty).
  if (profile.controllerParams !== undefined) {
    const cp = profile.controllerParams;
    if (cp.rampUpMaxRatio !== undefined && (!Number.isFinite(cp.rampUpMaxRatio) || cp.rampUpMaxRatio < 1))
      out.push('controllerParams.rampUpMaxRatio must be a finite number >= 1 when present');
    if (cp.decayRatio !== undefined && (!Number.isFinite(cp.decayRatio) || cp.decayRatio <= 0 || cp.decayRatio >= 1))
      out.push('controllerParams.decayRatio must be a finite number in (0, 1) when present');
    if (cp.smallDriftRatio !== undefined && (!Number.isFinite(cp.smallDriftRatio) || cp.smallDriftRatio < 1))
      out.push('controllerParams.smallDriftRatio must be a finite number >= 1 when present');
    if (cp.underTargetRecoveryRatio !== undefined && (!Number.isFinite(cp.underTargetRecoveryRatio) || cp.underTargetRecoveryRatio <= 0 || cp.underTargetRecoveryRatio > 1))
      out.push('controllerParams.underTargetRecoveryRatio must be a finite number in (0, 1] when present');
    if (cp.qualityHighThresholdMult !== undefined && (!Number.isFinite(cp.qualityHighThresholdMult) || cp.qualityHighThresholdMult <= 0))
      out.push('controllerParams.qualityHighThresholdMult must be a finite number > 0 when present');
  }

  // baseRpcConfig is required at launch — per-patch eval seeds bind to
  // a future Base blockhash, so the chain config has to be pinned and
  // signed alongside the bundle.
  const rpc = profile.baseRpcConfig;
  if (!rpc || typeof rpc !== 'object') {
    out.push('baseRpcConfig is required');
  } else {
    if (!Number.isInteger(rpc.chainId) || rpc.chainId < 1) out.push('baseRpcConfig.chainId must be a positive integer');
    if (!Number.isFinite(rpc.blockTimeSeconds) || rpc.blockTimeSeconds <= 0) out.push('baseRpcConfig.blockTimeSeconds must be > 0');
    if (!Number.isInteger(rpc.targetBlockOffset) || rpc.targetBlockOffset < 1) out.push('baseRpcConfig.targetBlockOffset must be a positive integer');
    if (!Number.isInteger(rpc.replayBlockhashLookbackBlocks) || rpc.replayBlockhashLookbackBlocks < 1)
      out.push('baseRpcConfig.replayBlockhashLookbackBlocks must be a positive integer');
    // Sanity floor: lookback must cover at least one full epoch (24 h)
    // plus the targetBlockOffset, otherwise replay watchers can't
    // reach back to verify the receipt's blockhash.
    const epochSeconds = 24 * 3600;
    const minLookback = Math.ceil(epochSeconds / rpc.blockTimeSeconds) + rpc.targetBlockOffset;
    if (rpc.replayBlockhashLookbackBlocks < minLookback) {
      out.push(`baseRpcConfig.replayBlockhashLookbackBlocks (${rpc.replayBlockhashLookbackBlocks}) must cover one full epoch + targetBlockOffset (>= ${minLookback})`);
    }
  }

  // corpusStagingPolicy is optional (previous bundles ship without it),
  // but if pinned every field must be present and well-formed.
  if (profile.corpusStagingPolicy !== undefined) {
    const sp = profile.corpusStagingPolicy;
    if (!Number.isInteger(sp.initialActiveSeedsPerDomain) || sp.initialActiveSeedsPerDomain < 1)
      out.push('corpusStagingPolicy.initialActiveSeedsPerDomain must be a positive integer');
    if (!Number.isFinite(sp.routineDeltaMaxMajorFraction)
        || sp.routineDeltaMaxMajorFraction <= 0
        || sp.routineDeltaMaxMajorFraction > 1)
      out.push('corpusStagingPolicy.routineDeltaMaxMajorFraction must be in (0, 1]');
    if (!Number.isInteger(sp.initialActiveRunwayDays) || sp.initialActiveRunwayDays < 1)
      out.push('corpusStagingPolicy.initialActiveRunwayDays must be a positive integer');
  }

  // §5 Run 1 selection-policy attestation. Required whenever firstStageTopK
  // is pinned — otherwise a bundle can claim a K that didn't meet the
  // per-stratum recall@K target without leaving any signed evidence.
  if (profile.firstStageTopK && profile.firstStageTopK > 0) {
    const sel = profile.firstStageTopKSelection;
    if (!sel || typeof sel !== 'object') {
      out.push('firstStageTopKSelection is required when firstStageTopK > 0');
    } else {
      if (sel.method !== 'worst-stratum-target' && sel.method !== 'operator-override') {
        out.push("firstStageTopKSelection.method must be 'worst-stratum-target' or 'operator-override'");
      }
      if (typeof sel.reason !== 'string' || sel.reason.trim().length < 16) {
        out.push('firstStageTopKSelection.reason must be a descriptive string (>= 16 chars)');
      }
      if (sel.method === 'worst-stratum-target') {
        if (typeof sel.calibrationReport !== 'string' || sel.calibrationReport.trim().length === 0) {
          out.push("firstStageTopKSelection.calibrationReport is required when method='worst-stratum-target'");
        }
      } else if (sel.method === 'operator-override') {
        if (!Array.isArray(sel.substrateBridgedFamilies) || sel.substrateBridgedFamilies.length === 0) {
          out.push("firstStageTopKSelection.substrateBridgedFamilies must be a non-empty array when method='operator-override'");
        } else {
          for (const fam of sel.substrateBridgedFamilies) {
            if (typeof fam !== 'string' || fam.length === 0) {
              out.push('firstStageTopKSelection.substrateBridgedFamilies entries must be non-empty strings');
              break;
            }
          }
        }
        if (sel.servedFamilyRecallAtPinnedK !== undefined) {
          const r = sel.servedFamilyRecallAtPinnedK;
          if (typeof r !== 'object' || r === null) {
            out.push('firstStageTopKSelection.servedFamilyRecallAtPinnedK must be an object when present');
          } else {
            for (const [fam, val] of Object.entries(r)) {
              if (typeof val !== 'number' || Number.isNaN(val) || val < 0 || val > 1) {
                out.push(`firstStageTopKSelection.servedFamilyRecallAtPinnedK.${fam} must be a number in [0, 1] (got ${String(val)})`);
              }
            }
          }
        }
      }
    }
  }

  if (profile.firstStageMode !== undefined && !['dense', 'lexical', 'hybrid'].includes(profile.firstStageMode)) {
    out.push("firstStageMode must be 'dense', 'lexical', or 'hybrid'");
  }
  for (const [name, val] of [
    ['firstStageDenseWeight', profile.firstStageDenseWeight],
    ['firstStageLexicalWeight', profile.firstStageLexicalWeight],
  ] as const) {
    if (val !== undefined && (!Number.isFinite(val) || val < 0)) {
      out.push(`${name} must be a finite number >= 0`);
    }
  }
  if (profile.firstStageMode === 'hybrid') {
    const dw = profile.firstStageDenseWeight ?? 1;
    const lw = profile.firstStageLexicalWeight ?? 1;
    if (dw === 0 && lw === 0) out.push('hybrid firstStageMode requires firstStageDenseWeight or firstStageLexicalWeight > 0');
  }

  // §6.5 reranker-input cap. When firstStageTopK is pinned, rerankerInputTopK
  // must also be pinned (otherwise a bundle would score all ~3,200 first-stage
  // candidates per query via the cross-encoder, which is infeasible at scale).
  // Required: 1 <= rerankerInputTopK <= firstStageTopK.
  if (profile.firstStageTopK && profile.firstStageTopK > 0) {
    const cap = profile.rerankerInputTopK;
    if (cap === undefined || cap === null) {
      out.push('rerankerInputTopK is required when firstStageTopK > 0 (§6.5 MemReranker-style cross-encoder pool cap)');
    } else if (!Number.isInteger(cap) || cap < 1) {
      out.push(`rerankerInputTopK must be a positive integer (got ${String(cap)})`);
    } else if (cap > profile.firstStageTopK) {
      out.push(`rerankerInputTopK (${cap}) must be <= firstStageTopK (${profile.firstStageTopK})`);
    }
  }

  if (!errors && out.length) throw new Error(out.join('; '));
}

function isMutableOrPlaceholderRevision(revision: string): boolean {
  const lower = revision.toLowerCase();
  return ['main', 'master', 'latest', 'head', 'placeholder', 'todo', 'placeholder-version'].includes(lower);
}

function validateBytes32(value: string, name: string, errors: string[]) {
  if (!isBytes32(value)) errors.push(`${name} must be bytes32 hex`);
}

function assertBytes32(value: string, name: string) {
  if (!isBytes32(value)) throw new Error(`${name} must be bytes32 hex`);
}

function isBytes32(value: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function slash(path: string): string {
  return path.replaceAll('\\', '/');
}

// ─── Coordinator startup assertion ───────────────────────────────────────────

/**
 * Refuses to return when GPU acceleration is hinted at by environment, when
 * the runtime versions don't match the bundle's runtimePin, or when the
 * on-chain coreVersionHash differs from the bundle hash.
 *
 * Spec: specs/determinism.md §Refusal.
 */
export function assertBundleBindingAtStartup(opts: {
  readonly manifest: CoreTexBundleManifest;
  readonly onChainCoreVersionHash: string;
  readonly installedRuntimeVersions: Readonly<Record<string, string>>;
  readonly clientVersion?: string;
  readonly allowOutdatedClient?: boolean;
  /** Coordinator boot attestation (production evaluator §2 score-honesty).
   *  When provided, it must hash-bind and match the bundle's reranker pin. */
  readonly bootAttestation?: AttestedCoordinatorBootAttestation;
}): void {
  if (opts.manifest.bundleHash.toLowerCase() !== opts.onChainCoreVersionHash.toLowerCase()) {
    throw new Error(
      `coreVersionHash mismatch: on-chain ${opts.onChainCoreVersionHash} vs bundle ${opts.manifest.bundleHash}`,
    );
  }
  if (opts.manifest.evaluator.profile.acceleratorPolicy !== 'cpu_only') {
    throw new Error("acceleratorPolicy must be 'cpu_only'");
  }
  for (const envVar of ['CORETEX_USE_GPU', 'PYTORCH_USE_MPS']) {
    const v = process.env[envVar];
    if (v && v !== '0') throw new Error(`refuse to start with ${envVar}=${v}`);
  }
  if (process.env['CUDA_VISIBLE_DEVICES']) {
    throw new Error('refuse to start with CUDA_VISIBLE_DEVICES set');
  }
  const ortProviders = process.env['ONNXRUNTIME_PROVIDERS'] ?? '';
  if (ortProviders.includes('CUDA') || ortProviders.includes('MPS')) {
    throw new Error(`refuse to start with ONNXRUNTIME_PROVIDERS=${ortProviders}`);
  }
  // Validate runtime pin: every required version must match.
  const expected = opts.manifest.evaluator.profile.runtimePin.versions;
  for (const [pkg, range] of Object.entries(expected)) {
    const installed = opts.installedRuntimeVersions[pkg];
    if (!installed) throw new Error(`runtime mismatch: ${pkg} not installed (expected ${range})`);
    if (!matchSemverRange(installed, range)) {
      throw new Error(`runtime mismatch: ${pkg} ${installed} does not match ${range}`);
    }
  }
  const clientCheck = evaluateClientVersionPolicy(
    opts.manifest.evaluator.profile.clientVersionPolicy,
    opts.clientVersion,
  );
  // Do not hard-fail solely because version was not supplied by the host:
  // that would brick validators during rollout. We fail closed only when
  // the supplied version is explicitly invalid or below the minimum.
  const shouldRefuseForClientVersion = clientCheck.code === 'client-version-outdated'
    || clientCheck.code === 'client-version-invalid';
  if (clientCheck.code === 'client-version-missing' && opts.manifest.evaluator.profile.clientVersionPolicy) {
    process.stderr.write(
      `warning: client version policy is pinned but no client version was provided; soft-pass applied (${clientCheck.message})\n`,
    );
  }
  if (
    shouldRefuseForClientVersion
    && opts.manifest.evaluator.profile.clientVersionPolicy?.hardFailOutdated
    && opts.allowOutdatedClient !== true
  ) {
    throw new Error(`outdated client refused: ${clientCheck.message}`);
  }
  if (opts.bootAttestation) {
    assertCoordinatorBootAttestationBinding(opts.bootAttestation, opts.manifest);
  }
}

// ─── Coordinator boot attestation ────────────────────────────────────────────

/**
 * Boot attestation the production evaluator exposes at construction: the
 * resolved reranker identity + canonical prompt-template commitment +
 * Memory-IR mode, hash-bound so the coordinator/replay side can record one
 * bytes32 alongside the bundle binding (§2 score-honesty).
 */
export interface CoordinatorBootAttestation {
  readonly bundleHash: string;
  readonly rerankerModelId: string;
  readonly rerankerRevision: string;
  readonly rerankerMode: 'qwen3-streaming' | 'qwen3-per-batch';
  /** Resolved CORETEX_RERANKER_INSTRUCTION (default = canonical constant). */
  readonly rerankerInstruction: string;
  /** sha256 commitment over the canonical prompt template + instruction
   *  (eval/reranker.ts qwenRerankerPromptTemplateHash). */
  readonly promptTemplateHash: string;
  /** Memory-IR rendering mode pinned by the signed profile (NOT env). */
  readonly memoryIRMode: 'off' | 'full';
}

export type AttestedCoordinatorBootAttestation = CoordinatorBootAttestation & {
  readonly attestationHash: string;
};

const COORDINATOR_BOOT_ATTESTATION_DOMAIN = 'coretex-coordinator-boot-attestation-v1';

export function computeCoordinatorBootAttestationHash(att: CoordinatorBootAttestation): string {
  const canonical = JSON.stringify([
    COORDINATOR_BOOT_ATTESTATION_DOMAIN,
    att.bundleHash.toLowerCase(),
    att.rerankerModelId,
    att.rerankerRevision,
    att.rerankerMode,
    att.rerankerInstruction,
    att.promptTemplateHash.toLowerCase(),
    att.memoryIRMode,
  ]);
  return bytesToHex(keccak256(new TextEncoder().encode(canonical))).toLowerCase();
}

export function buildCoordinatorBootAttestation(
  att: CoordinatorBootAttestation,
): AttestedCoordinatorBootAttestation {
  assertBytes32(att.bundleHash, 'bootAttestation.bundleHash');
  assertBytes32(att.promptTemplateHash, 'bootAttestation.promptTemplateHash');
  if (!att.rerankerModelId || !att.rerankerRevision) {
    throw new Error('bootAttestation requires rerankerModelId and rerankerRevision');
  }
  if (att.rerankerMode !== 'qwen3-streaming' && att.rerankerMode !== 'qwen3-per-batch') {
    throw new Error(`bootAttestation.rerankerMode invalid: ${String(att.rerankerMode)}`);
  }
  if (att.memoryIRMode !== 'off' && att.memoryIRMode !== 'full') {
    throw new Error(`bootAttestation.memoryIRMode invalid: ${String(att.memoryIRMode)}`);
  }
  return { ...att, attestationHash: computeCoordinatorBootAttestationHash(att) };
}

function assertCoordinatorBootAttestationBinding(
  att: AttestedCoordinatorBootAttestation,
  manifest: CoreTexBundleManifest,
): void {
  if (computeCoordinatorBootAttestationHash(att) !== att.attestationHash.toLowerCase()) {
    throw new Error('boot attestation hash does not bind its fields');
  }
  if (att.bundleHash.toLowerCase() !== manifest.bundleHash.toLowerCase()) {
    throw new Error(
      `boot attestation bundleHash ${att.bundleHash} != bundle manifest ${manifest.bundleHash}`,
    );
  }
  const pin = manifest.model?.reranker;
  if (!pin) throw new Error('bundle manifest has no model.reranker pin to attest against');
  if (att.rerankerModelId !== pin.modelId || att.rerankerRevision !== pin.revision) {
    throw new Error(
      `boot attestation reranker ${att.rerankerModelId}@${att.rerankerRevision} != bundle pin ${pin.modelId}@${pin.revision}`,
    );
  }
}

function matchSemverRange(installed: string, range: string): boolean {
  if (range === installed) return true;
  // PEP-440 / pip wheels frequently append build metadata after the patch
  // version (e.g. torch reports "2.6.0+cpu" for the CPU wheel). The pin's
  // major.minor[.patch] semantics should accept these so a "2.6.*" pin
  // matches the "+cpu" build that the bundle authors actually mean to ship.
  // Strip any trailing "+<build>" / "-<pre>" suffix before matching.
  const core = installed.split(/[+\-]/, 1)[0]!;
  // Match X.Y.* against installed X.Y.Z (and X.Y.Z+build)
  const m = range.match(/^(\d+)\.(\d+)\.\*$/);
  if (m) {
    const [, maj, min] = m;
    const re = new RegExp(`^${maj}\\.${min}\\.\\d+$`);
    return re.test(core);
  }
  // Match X.* against installed X.Y.Z
  const major = range.match(/^(\d+)\.\*$/);
  if (major) {
    const [, maj] = major;
    const re = new RegExp(`^${maj}\\.\\d+\\.\\d+$`);
    return re.test(core);
  }
  return false;
}

function isSemver(value: string): boolean {
  return /^\d+\.\d+\.\d+$/.test(value.trim());
}

function compareSemver(a: string, b: string): number {
  const ap = a.split('.').map((part) => Number(part));
  const bp = b.split('.').map((part) => Number(part));
  for (let i = 0; i < 3; i += 1) {
    const av = ap[i] ?? 0;
    const bv = bp[i] ?? 0;
    if (av > bv) return 1;
    if (av < bv) return -1;
  }
  return 0;
}
