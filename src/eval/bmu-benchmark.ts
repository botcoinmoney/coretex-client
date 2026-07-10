/**
 * BMU v1 — Budgeted Memory Utility: the scoring-law module behind
 * `pipelineVersion = 'coretex-bmu-v1-r5state'` (BMU_SPEC.md; spec §9 site 1).
 *
 * What this module IS:
 *   - the deterministic per-task judge (§2.2/§13.2): utility is earned iff the
 *     answer is recoverable from the top-B of the QUANTIZED-composite-ranked
 *     final ordering with ZERO forbidden items admitted;
 *   - the composition-weighted uniform-quantum aggregation (§2.3):
 *     BMU_ppm = round(1e6 · Σ u(t) / packSize) — family weights are realized
 *     by pack COMPOSITION (quotas + overlay slots), never by arithmetic
 *     multipliers;
 *   - the quantization-aware floors (§2.5): absolute per-family/total
 *     regression budgets + protected-row zero-tolerance veto + the unchanged
 *     structural hard floor (r5's ratio floors are NOT applied under BMU);
 *   - the §7 external rejection taxonomy mapping (exactly six reasons);
 *   - the §6.7b ARM-GATE census (per-family eligible-active minima, fresh
 *     cohort, GLOBAL m=1 multiplicity) and the pinned variance-certification
 *     seed schedule / criterion (rev3.1).
 *
 * What this module is NOT:
 *   - a new retrieval pipeline. Stage-1/stage-2 (BGE + Qwen reranker, bonuses,
 *     policy atoms) run UNCHANGED via `evaluateRetrievalBenchmarkState` — the
 *     reranker survives as retrieval plumbing (§13.1); only the reward law on
 *     top of the final ordering changes. The r5 metrics computed alongside are
 *     retained as INTERNAL telemetry only (never the reward, never published
 *     per-row — §8.3/§B2 redaction).
 *   - a state-layout change: the r5 decode law is untouched (I2).
 */

import type { CortexState, Patch } from '../state/index.js';
import { applyPatch } from '../state/patch.js';
import { keccak256 } from '../state/keccak256.js';
import { bytesToHex } from '../state/merkle.js';
import { isBmuScoringLaw, isBmuV2ScoringLaw } from '../pipeline-versions.js';
import {
  evaluateRetrievalBenchmarkState,
  type CompositeScore,
  type PatchAcceptanceFloors,
  type ScoringOptions,
} from './retrieval-benchmark.js';
import { codePointCompare, type ProductionCorpus, type ProductionCorpusEvent } from './retrieval-corpus.js';
import type { QueryPack } from './hidden-query-pack.js';
import {
  BMU_FAMILIES,
  BMU_COMPOSITION_TARGETS,
  BMU_FRESH_WINDOW_DEFAULT,
  BMU_MULTI_HOP_FORCED_INHERIT_ALPHA,
  type BmuFamily,
  type BmuTask,
  bmuFamilyForLogicalFamily,
} from './bmu-task.js';

// ─── Pinned law constants ─────────────────────────────────────────────────────

/** §6.2: packSize is 64 so the per-row quantum is uniform and exact. */
export const BMU_PACK_SIZE = 64;

/** §2.3: the uniform per-row quantum q = 1e6 / 64 = 15,625 ppm. */
export const BMU_ROW_QUANTUM_PPM = 1_000_000 / BMU_PACK_SIZE;

/** §2.4: BMU bundle pin — one flip (15,625) can NEVER advance state; two can.
 *  P4 MAY re-pin within [q+1, 2q] preserving the one-flip-rejecting property. */
export const BMU_MIN_IMPROVEMENT_PPM = 20_000;

/** §2.4: replay tolerance term (unchanged from r5). */
export const BMU_REPLAY_TOLERANCE_PPM = 250;

/** §13.2: default judge quantization grid g in composite-score space. */
export const BMU_JUDGE_SCORE_GRID_DEFAULT = 1e-3;

/** §13.2: bundle validation asserts Rmax = 1 + B + 2P ≤ this. */
export const BMU_JUDGE_RMAX_LIMIT = 4;

/** §2.5: absolute regression budgets (rows where u drops 1→0, protected rows
 *  excluded — those are a zero-tolerance hard veto). */
export const BMU_REGRESSION_BUDGET_PER_FAMILY = 1;
export const BMU_REGRESSION_BUDGET_TOTAL = 2;

/** §6.7b (rev3.1): per-family eligible-active minima E_f_min = k·ceil(N_f·(k+1)/k). */
export const BMU_ARM_GATE_FAMILY_MINIMA: Readonly<Record<BmuFamily, number>> = {
  temporal: 80,
  conflict_lifecycle: 110,
  multi_hop_relation: 110,
  near_collision_abstention: 80,
};

/** §6.7b (rev3.1): N_min = Σ E_f_min = 380 eligible-active rows (76 clusters). */
export const BMU_ARM_GATE_N_MIN = 380;

/** §6.7b: fresh overlay cohort of ≥ 2 clusters per family within freshWindow. */
export const BMU_ARM_GATE_FRESH_CLUSTERS_MIN = 2;

// §6.4 default fresh-cohort window lives in bmu-task.ts (leaf) so the pack
// law can consume it without a module cycle; re-exported here for law users.
export { BMU_FRESH_WINDOW_DEFAULT } from './bmu-task.js';

/** §6.7b variance certification (rev3.1): K runs per state, spread < q/2. */
export const BMU_ARM_VARIANCE_RUNS = 5;
export const BMU_ARM_VARIANCE_DOMAIN = 'bmu-arm-variance';
/** Strict upper bound (spec: "max pairwise spread < q/2 = 7,812 ppm"). */
export const BMU_ARM_VARIANCE_MAX_SPREAD_PPM = 7_812;

// ─── §13.2 deterministic judge ranking rule ───────────────────────────────────

export interface BmuJudgeRankingEntry {
  readonly docId: string;
  readonly rerankerScore: number;
  readonly finalReorderingScore: number;
}

/** Quantize a composite score to the bundle-pinned grid (integer cells). */
export function bmuQuantize(score: number, grid: number): number {
  if (!(grid > 0) || !Number.isFinite(grid)) throw new Error(`bmuQuantize: grid must be a positive finite number (got ${grid})`);
  return Math.round(score / grid);
}

/**
 * The §13.2 judge ordering: (quantized composite desc, quantized rerankerScore
 * desc, docId asc). The FIRST TWO keys are quantized — the r5 secondary
 * tiebreak compares RAW rerankerScore, which would reintroduce float
 * sensitivity exactly when composites tie on the grid.
 */
export function bmuJudgeOrder(
  entries: readonly BmuJudgeRankingEntry[],
  grid: number,
): readonly BmuJudgeRankingEntry[] {
  if (!(grid > 0) || !Number.isFinite(grid)) throw new Error(`bmuJudgeOrder: grid must be a positive finite number (got ${grid})`);
  return [...entries].sort((a, b) => {
    const qa = bmuQuantize(a.finalReorderingScore, grid);
    const qb = bmuQuantize(b.finalReorderingScore, grid);
    if (qb !== qa) return qb - qa;
    const ra = bmuQuantize(a.rerankerScore, grid);
    const rb = bmuQuantize(b.rerankerScore, grid);
    if (rb !== ra) return rb - ra;
    return codePointCompare(a.docId, b.docId);
  });
}

/** Top-B doc ids of the judge ordering (`B ≤ 8 < rerankerTopK` always, §2.2). */
export function bmuJudgeTopB(
  entries: readonly BmuJudgeRankingEntry[],
  budgetB: number,
  grid: number,
): readonly string[] {
  if (!(grid > 0) || !Number.isFinite(grid)) throw new Error(`bmuJudgeTopB: grid must be a positive finite number (got ${grid})`);
  return bmuJudgeOrder(entries, grid).slice(0, budgetB).map((e) => e.docId);
}

// ─── §2.2 per-task utility (binary; no partial credit) ───────────────────────

export interface BmuTaskJudgeInput {
  readonly task: BmuTask;
  /** Top-B doc ids of the judge ordering for this row. */
  readonly topB: readonly string[];
  /** The §5.5 abstention signal: the r5 POLICY-ATOM abstain decision for this
   *  row (`perQuery.policyAbstain`). The r5 atom-less fallback threshold rule
   *  is NOT part of BMU u(t) — do not feed it here. */
  readonly abstainSignal: boolean;
}

export interface BmuTaskUtility {
  readonly utility: 0 | 1;
  /** Internal diagnostic (private audit lane only): why u = 0. */
  readonly failure?:
    | 'missing_required'
    | 'forbidden_admitted'
    | 'answer_not_in_topB'
    | 'false_abstain'
    | 'abstain_signal_missing';
}

/** The §2.2 utility law. Binary per row; the forbidden-trap veto is what makes
 *  label knowledge alone worthless (the miner must perform the operation). */
export function computeBmuTaskUtility(input: BmuTaskJudgeInput): BmuTaskUtility {
  const { task, topB, abstainSignal } = input;
  const inTopB = new Set(topB);
  for (const f of task.forbiddenEvidence) {
    if (inTopB.has(f)) return { utility: 0, failure: 'forbidden_admitted' };
  }
  if (task.abstain === true) {
    return abstainSignal ? { utility: 1 } : { utility: 0, failure: 'abstain_signal_missing' };
  }
  // ANSWERABLE: the false-abstain counterweight (§2.2) — an abstain on an
  // answerable task earns nothing, so always-abstain zeroes ~80% of the pack.
  if (abstainSignal) return { utility: 0, failure: 'false_abstain' };
  for (const r of task.requiredEvidence) {
    if (!inTopB.has(r)) return { utility: 0, failure: 'missing_required' };
  }
  if (!task.answer || !inTopB.has(task.answer.id)) return { utility: 0, failure: 'answer_not_in_topB' };
  return { utility: 1 };
}

// ─── BMU score shape ─────────────────────────────────────────────────────────

export interface BmuPerTaskResult {
  readonly recordId: string;
  readonly family: BmuFamily;
  readonly utility: 0 | 1;
  readonly protected: boolean;
  readonly abstainSignal: boolean;
  readonly failure?: BmuTaskUtility['failure'];
  readonly topB: readonly string[];
}

export interface BmuScoreBreakdown {
  /** THE scalar (I1): round(1e6 · Σ u / packSize), integer ppm ∈ [0, 1e6]. */
  readonly scalarPpm: number;
  readonly packSize: number;
  readonly utilitySum: number;
  /** Per-family U_f in ppm (drives floors telemetry, G-B8 alarm, /score-state
   *  decomposition — §2.3; NOT multiplied into the scalar). */
  readonly familyUtilitiesPpm: Readonly<Record<BmuFamily, number>>;
  readonly familyRowCounts: Readonly<Record<BmuFamily, number>>;
  /** INTERNAL-ONLY per-task detail (private audit lane). NEVER publish per-row
   *  u(t) in artifacts (§8.3 / §6.5 part 3 redaction). */
  readonly perTask: readonly BmuPerTaskResult[];
  readonly judgeScoreGrid: number;
}

/**
 * A BMU evaluation result. Structurally a `CompositeScore` so the existing
 * evaluator plumbing (ppm(before.composite), variance sampling, artifacts)
 * consumes it unchanged: `composite` IS the BMU scalar as a fraction
 * (scalarPpm/1e6 — exact in binary since packSize is a power of two), and the
 * r5 metric fields carry the side-computed r5 telemetry (internal-only).
 */
export interface BmuScore extends CompositeScore {
  readonly bmu: BmuScoreBreakdown;
}

export interface BmuScoringContext {
  /** §13.2 judge grid; bundle-pinned (`judgeScoreGrid`), default 1e-3. */
  readonly judgeScoreGrid?: number;
}

/**
 * BMU v2's law-owned routing primitive. No family, task, role, or intent
 * value participates in routing. Its maximum 64 branch admissions fit the
 * normal reranker cap and therefore receive uniform Qwen admission.
 */
export const BMU_V2_PUBLIC_PATH_BUNDLE = Object.freeze({
  stage1SeedLimit: 4,
  branchLimit: 4,
  steps: Object.freeze([
    Object.freeze({ direction: 'outgoing' as const, edgeTypes: Object.freeze(['supports', 'supersedes', 'coreference_of', 'causes', 'derived_from', 'co_occurs_with']) }),
    Object.freeze({ direction: 'incoming' as const, edgeTypes: Object.freeze(['supports', 'supersedes', 'coreference_of', 'causes', 'derived_from', 'co_occurs_with']) }),
  ]),
});

// ─── State evaluation (the LAW entrypoint) ────────────────────────────────────

/**
 * Score a substrate on a BMU pack. FAIL-CLOSED preconditions:
 *   - `opts.pipelineVersion` must pin the BMU law;
 *   - `opts.policyAtomsMode` must be true (BMU is r5-state policy law);
 *   - EVERY pack row must carry a (load-validated) `bmuTask` — a BMU pack row
 *     without a task is a pack-law violation, never a silent zero.
 *
 * The underlying retrieval pipeline runs verbatim via
 * `evaluateRetrievalBenchmarkState` with `exposeFullRanking` forced on so the
 * judge can re-rank the composite (`finalReorderingScore`) on the quantized
 * chain (§13.2). Determinism is claimed for DECISIONS, not raw scores (I5).
 */
export async function evaluateBmuBenchmarkState(
  state: CortexState,
  corpus: ProductionCorpus,
  pack: QueryPack,
  opts: ScoringOptions,
  bmu: BmuScoringContext = {},
): Promise<BmuScore> {
  if (!isBmuScoringLaw(opts.pipelineVersion)) {
    throw new Error(`evaluateBmuBenchmarkState: pipelineVersion '${String(opts.pipelineVersion)}' does not pin the BMU law`);
  }
  if (opts.policyAtomsMode !== true) {
    throw new Error('evaluateBmuBenchmarkState: policyAtomsMode must be true (BMU rides the r5 policy state law)');
  }
  const grid = bmu.judgeScoreGrid ?? BMU_JUDGE_SCORE_GRID_DEFAULT;
  if (!(grid > 0) || !Number.isFinite(grid)) {
    throw new Error(`evaluateBmuBenchmarkState: judgeScoreGrid must be a positive finite number (got ${String(grid)})`);
  }
  // exposeFullRanking feeds the judge; bmuPolicyBonusClamp arms the §13.2
  // rev3.3 per-doc atom-contribution cap (P_cap = 1) — part of the BMU LAW,
  // never a bundle knob. v2 removes all v1 family/intent helpers and instead
  // admits a bounded, family-agnostic public path to the normal reranker.
  const v2 = isBmuV2ScoringLaw(opts.pipelineVersion);
  const scorePack = v2
    ? { ...pack, events: pack.events.map((event) => {
      const { publicIntent: _publicIntent, ...withoutPublicIntent } = event;
      return withoutPublicIntent;
    }) }
    : pack;
  const r5 = await evaluateRetrievalBenchmarkState(state, corpus, scorePack, {
    ...opts,
    exposeFullRanking: true,
    bmuPolicyBonusClamp: true,
    ...(v2 ? {
      temporalMotifAdmission: false,
      conflictMotifAdmission: false,
      evidenceMotifAdmission: false,
      policyConflictIntentAdmission: false,
      policyQueryConditionedAdmission: false,
      policyRelationTypedAdmission: false,
      enableEntityResolutionAtoms: false,
      enableScopeAtoms: false,
      enableConflictLifecycleAtoms: false,
      enableEvidenceBundleAtoms: false,
      bmuPublicPathBundle: BMU_V2_PUBLIC_PATH_BUNDLE,
    } : {}),
  });

  const perTask: BmuPerTaskResult[] = [];
  const famSum: Record<BmuFamily, number> = { temporal: 0, conflict_lifecycle: 0, multi_hop_relation: 0, near_collision_abstention: 0 };
  const famCount: Record<BmuFamily, number> = { temporal: 0, conflict_lifecycle: 0, multi_hop_relation: 0, near_collision_abstention: 0 };
  let utilitySum = 0;

  for (let i = 0; i < pack.events.length; i++) {
    const event = pack.events[i]!;
    const q = r5.perQuery[i];
    if (!q || q.recordId !== event.id) {
      throw new Error(`evaluateBmuBenchmarkState: perQuery[${i}] misaligned with pack row ${event.id}`);
    }
    const task = event.bmuTask;
    if (!task) {
      throw new Error(`evaluateBmuBenchmarkState: pack row ${event.id} carries no bmuTask — BMU pack eligibility violated (fail-closed)`);
    }
    const full = q.finalRankingFull;
    if (!full) throw new Error(`evaluateBmuBenchmarkState: full ranking missing for row ${event.id}`);
    const entries: BmuJudgeRankingEntry[] = full.map((r) => {
      if (typeof r.finalReorderingScore !== 'number' || !Number.isFinite(r.finalReorderingScore)) {
        throw new Error(`evaluateBmuBenchmarkState: finalReorderingScore missing/non-finite for doc ${r.docId} on row ${event.id}`);
      }
      return { docId: r.docId, rerankerScore: r.rerankerScore, finalReorderingScore: r.finalReorderingScore };
    });
    const topB = bmuJudgeTopB(entries, task.budgetB, grid);
    // §5.5: the abstention signal is EXACTLY the policy-atom decision; the
    // atom-less fallback rule is excluded from u(t) by construction here
    // (policyAbstain is only ever set by the policy-atom path).
    const abstainSignal = q.policyAbstain === true;
    const u = computeBmuTaskUtility({ task, topB, abstainSignal });
    utilitySum += u.utility;
    famSum[task.family] += u.utility;
    famCount[task.family] += 1;
    perTask.push({
      recordId: event.id,
      family: task.family,
      utility: u.utility,
      protected: event.protected === true,
      abstainSignal,
      ...(u.failure !== undefined ? { failure: u.failure } : {}),
      topB,
    });
  }

  const packSize = pack.events.length;
  const scalarPpm = Math.round((1_000_000 * utilitySum) / packSize);
  const familyUtilitiesPpm = Object.fromEntries(
    BMU_FAMILIES.map((f) => [f, famCount[f] === 0 ? 0 : Math.round((1_000_000 * famSum[f]) / famCount[f])]),
  ) as Record<BmuFamily, number>;

  return {
    ...r5,
    // The scalar (I1) rides `composite` so every ppm(composite) consumer sees
    // the BMU number. packSize 64 ⇒ scalarPpm/1e6 is binary-exact and
    // round-trips through Math.round(composite * 1e6) without drift.
    composite: scalarPpm / 1_000_000,
    bmu: {
      scalarPpm,
      packSize,
      utilitySum,
      familyUtilitiesPpm,
      familyRowCounts: { ...famCount },
      perTask,
      judgeScoreGrid: grid,
    },
  };
}

// ─── Patch evaluation (acceptance floors §2.5 + threshold §2.4) ──────────────

export interface BmuPatchEvalResult {
  readonly accepted: boolean;
  readonly reason?: string;
  readonly before: BmuScore;
  readonly after: BmuScore;
  readonly deltaPpm: number;
  readonly perFamilyDelta: Record<string, number>;
}

function bmuPerFamilyDelta(before: BmuScore, after: BmuScore): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of BMU_FAMILIES) {
    out[f] = (after.bmu.familyUtilitiesPpm[f] - before.bmu.familyUtilitiesPpm[f]) / 1_000_000;
  }
  return out;
}

/**
 * The BMU analogue of `evaluateRetrievalBenchmarkPatch`, byte-compatible with
 * the `PatchEvalResult` consumers (per-patch orchestrator / production
 * evaluator). Checks in order (§2.5):
 *   1. patch applies under the r5 grammar (apply_failed:* otherwise);
 *   2. structural validity hard floor (unchanged from r5);
 *   3. protected-row zero-tolerance veto (any protected u 1→0);
 *   4. absolute regression budgets (≤1/family, ≤2 total; protected excluded);
 *   5. Δppm ≥ acceptanceThresholdPpm (§2.4: 20,000 + 250 + 0 = 20,250 —
 *      variance ≡ 0 under the pinned `baselineVarianceSource='unavailable'`).
 * r5's RATIO floors (protectedRegressionFloor as an nDCG drop,
 * familyCatastrophicFloor) are NOT applied — replaced by 3+4 (§2.5).
 */
export async function evaluateBmuBenchmarkPatch(
  parentState: CortexState,
  patch: Patch,
  corpus: ProductionCorpus,
  pack: QueryPack,
  opts: ScoringOptions,
  floors: PatchAcceptanceFloors,
  bmu: BmuScoringContext = {},
  precomputedBefore?: BmuScore,
): Promise<BmuPatchEvalResult> {
  const acceptanceThresholdPpm = floors.acceptanceThresholdPpm ?? floors.minImprovementPpm;
  const before = precomputedBefore ?? await evaluateBmuBenchmarkState(parentState, corpus, pack, opts, bmu);
  const applied = applyPatch(parentState, patch, opts.policyAtomsMode === true);
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
  const after = await evaluateBmuBenchmarkState(applied.state, corpus, pack, opts, bmu);
  const deltaPpm = after.bmu.scalarPpm - before.bmu.scalarPpm;
  const reject = (reason: string): BmuPatchEvalResult => ({
    accepted: false,
    reason,
    before,
    after,
    deltaPpm,
    perFamilyDelta: bmuPerFamilyDelta(before, after),
  });

  if (after.structuralValidity < floors.structuralFloor) {
    return reject('structural_validity_below_floor');
  }

  // Regressed rows: u dropped 1 → 0 (row-aligned; both scores are over the
  // SAME pack so perTask order matches).
  const beforeByRow = new Map(before.bmu.perTask.map((t) => [t.recordId, t]));
  const regressionsByFamily: Record<BmuFamily, number> = { temporal: 0, conflict_lifecycle: 0, multi_hop_relation: 0, near_collision_abstention: 0 };
  let totalRegressions = 0;
  for (const t of after.bmu.perTask) {
    const prev = beforeByRow.get(t.recordId);
    if (!prev || !(prev.utility === 1 && t.utility === 0)) continue;
    // §2.5 protected rows: ANY u 1→0 on a protected row is a hard veto —
    // zero tolerance, excluded from the ≤1/≤2 budgets.
    if (t.protected) return reject(`protected_regression:${t.recordId}`);
    regressionsByFamily[t.family] += 1;
    totalRegressions += 1;
  }
  for (const f of BMU_FAMILIES) {
    if (regressionsByFamily[f] > BMU_REGRESSION_BUDGET_PER_FAMILY) {
      return reject(`regression_budget_family:${f}`);
    }
  }
  if (totalRegressions > BMU_REGRESSION_BUDGET_TOTAL) {
    return reject('regression_budget_total');
  }

  if (deltaPpm < acceptanceThresholdPpm) {
    return reject('no_retrieval_improvement');
  }
  return { accepted: true, before, after, deltaPpm, perFamilyDelta: bmuPerFamilyDelta(before, after) };
}

// ─── §2.3 composition validator ───────────────────────────────────────────────

/** Map a quota stratum string (`family=<bucketed>`) to its BMU family. */
export function bmuFamilyForQuotaStratum(stratum: string): BmuFamily | null {
  const m = /^family=([a-z_]+)$/.exec(stratum);
  if (!m) return null;
  const bucketed = m[1]!;
  if (bucketed === 'temporal') return 'temporal';
  if (bucketed === 'conflict_lifecycle') return 'conflict_lifecycle';
  if (bucketed === 'multi_hop_relation' || bucketed === 'coreference') return 'multi_hop_relation';
  if (bucketed === 'near_collision') return 'near_collision_abstention';
  return null;
}

/**
 * §2.3 `assertValidBmuWeights` — a COMPOSITION validator: with pinned quotas
 * Q_f and pinned per-BMU-family overlay slots O_f, asserts
 * `|(Q_f + O_f)/packSize − w_f| ≤ 0.03` for every family, exactly the four v1
 * families present, and every quota stratum mappable to a BMU family. The 2
 * free-fill rows are EXCLUDED (they bound realized per-pack deviation, not the
 * pinned expectation). r5's `assertValidWeights` is untouched for r5 replay.
 */
export function assertValidBmuWeights(input: {
  readonly packSize: number;
  readonly quotas: readonly { readonly stratum: string; readonly minCount: number }[];
  readonly familySlots: Readonly<Partial<Record<BmuFamily, number>>>;
}): void {
  const { packSize, quotas, familySlots } = input;
  if (!Number.isInteger(packSize) || packSize < 1) throw new Error(`assertValidBmuWeights: packSize must be a positive integer (got ${packSize})`);
  const q: Record<BmuFamily, number> = { temporal: 0, conflict_lifecycle: 0, multi_hop_relation: 0, near_collision_abstention: 0 };
  for (const quota of quotas) {
    const fam = bmuFamilyForQuotaStratum(quota.stratum);
    if (fam === null) {
      throw new Error(`assertValidBmuWeights: quota stratum '${quota.stratum}' does not map to a BMU family (§5.6)`);
    }
    if (!Number.isInteger(quota.minCount) || quota.minCount < 0) {
      throw new Error(`assertValidBmuWeights: quota ${quota.stratum} minCount must be a non-negative integer`);
    }
    q[fam] += quota.minCount;
  }
  for (const key of Object.keys(familySlots)) {
    if (!(BMU_FAMILIES as readonly string[]).includes(key)) {
      throw new Error(`assertValidBmuWeights: familySlots key '${key}' is not a BMU family enum name`);
    }
  }
  for (const fam of BMU_FAMILIES) {
    const slots = familySlots[fam];
    if (slots === undefined || !Number.isInteger(slots) || slots < 0) {
      throw new Error(`assertValidBmuWeights: familySlots.${fam} must be a non-negative integer (all four families required)`);
    }
    if (q[fam] === 0) {
      throw new Error(`assertValidBmuWeights: family ${fam} has zero quota reservation — all four v1 families must be present`);
    }
    const share = (q[fam] + slots) / packSize;
    const target = BMU_COMPOSITION_TARGETS[fam];
    const deviation = Math.abs(share - target);
    if (deviation > 0.03 + 1e-9) {
      throw new Error(
        `assertValidBmuWeights: family ${fam} composition share ${share.toFixed(4)} deviates ${deviation.toFixed(4)} > 0.03 from target ${target} (Q=${q[fam]}, O=${slots}, packSize=${packSize})`,
      );
    }
  }
}

// ─── §13.2 Rmax bundle validation ─────────────────────────────────────────────

export interface BmuRmaxProfileShape {
  readonly lensWeight?: number;
  readonly anchorWeight?: number;
  readonly temporalCurrentBoost?: number;
  readonly temporalStaleSuppression?: number;
  readonly categoryLensFinalBonusWeight?: number;
  readonly categoryLensScoreInheritance?: number;
  readonly enableAspectConstraintAtoms?: boolean;
  readonly policyAspectBoost?: number;
}

/** §13.2 rev3.3: the per-doc atom-contribution cap P_cap — the BMU judge
 *  clamps the summed per-doc policyBonus to ±P_cap·UNIT before quantization
 *  (`bmuPolicyBonusClamp`, armed unconditionally by the BMU law module). */
export const BMU_JUDGE_POLICY_CAP = 1;

/** Runtime multi-hop inheritance is included in the range proof. */
export const BMU_JUDGE_FORCED_INHERIT_ALPHA = BMU_MULTI_HOP_FORCED_INHERIT_ALPHA;

/**
 * §13.2 range analysis (rev3.3 pinned arithmetic): with the per-doc
 * atom-contribution cap (P_cap = 1 — the summed policyBonus per doc is
 * clamped to ±1·UNIT before quantization, `bmuPolicyBonusClamp`), the
 * composite lies in [−P_cap, 1 + B + P_cap] and
 *   Rmax = 1 + B + 2·P_cap
 * where B = Σ enabled final-bonus betas (lens + anchor + temporal +
 * categoryLens final + aspect). The rev3-era per-mechanism "P" arithmetic
 * (and its pinned-budget-cap requirement) is superseded: multi-atom same-doc
 * stacking is bounded by the CLAMP in the law itself, not by budget-cap
 * bookkeeping (uncapped worst case was ≈ 77 composite units at 128
 * atoms/region — the clamp is what makes Rmax ≤ 4 honest).
 */
export function computeBmuJudgeRmax(profile: BmuRmaxProfileShape): number {
  const lensW = profile.lensWeight ?? 0.1;
  const anchorW = profile.anchorWeight ?? 0.15;
  const temporalCurrentW = profile.temporalCurrentBoost ?? 0.1;
  const temporalStaleW = profile.temporalStaleSuppression ?? 0.1;
  const catLensFinalW = profile.categoryLensFinalBonusWeight ?? lensW;
  const aspectW = profile.enableAspectConstraintAtoms === true ? (profile.policyAspectBoost ?? 0) : 0;
  const inheritAlpha = profile.categoryLensScoreInheritance ?? 0;
  const named = { lensWeight: lensW, anchorWeight: anchorW, temporalCurrentBoost: temporalCurrentW,
    temporalStaleSuppression: temporalStaleW, categoryLensFinalBonusWeight: catLensFinalW,
    policyAspectBoost: aspectW, categoryLensScoreInheritance: inheritAlpha };
  for (const [name, value] of Object.entries(named)) {
    if (!Number.isFinite(value) || value < 0) {
      throw new Error(`BMU judge Rmax: ${name} must be a finite non-negative number (got ${String(value)})`);
    }
  }
  if (inheritAlpha > 1) {
    throw new Error(`BMU judge Rmax: categoryLensScoreInheritance must be in [0,1] (got ${inheritAlpha})`);
  }
  const rerankerMax = Math.max(1, inheritAlpha, BMU_JUDGE_FORCED_INHERIT_ALPHA);
  return rerankerMax + lensW + anchorW + temporalCurrentW + temporalStaleW
    + catLensFinalW + aspectW + 2 * BMU_JUDGE_POLICY_CAP;
}

export function assertBmuJudgeRmax(profile: BmuRmaxProfileShape): void {
  const rmax = computeBmuJudgeRmax(profile);
  if (rmax > BMU_JUDGE_RMAX_LIMIT + 1e-9) {
    throw new Error(`BMU judge Rmax ${rmax.toFixed(3)} exceeds the pinned limit ${BMU_JUDGE_RMAX_LIMIT} (§13.2) — re-pin the bonus betas / policy budget caps`);
  }
}

// ─── §7 external rejection taxonomy (closed set, exactly six) ─────────────────

export type BmuExternalRejectionReason =
  | 'malformed_patch'
  | 'duplicate_or_capped'
  | 'below_gate'
  | 'failed_holdout_transfer'
  | 'safety_regression'
  | 'stale_context';

export const BMU_EXTERNAL_REJECTION_REASONS: readonly BmuExternalRejectionReason[] = [
  'malformed_patch',
  'duplicate_or_capped',
  'below_gate',
  'failed_holdout_transfer',
  'safety_regression',
  'stale_context',
];

const SCORER_INTEGRITY_CODES = new Set([
  'SCORER_JOB_ID_MISMATCH',
  'SCORER_JOB_NOT_OUTSTANDING',
  'SCORER_HEALTH_MISMATCH',
  'SCORER_CODE_HASH_MISMATCH',
  'SCORER_PIN_MISMATCH',
  'SCORER_SEED_COMMIT_MISMATCH',
  'SCORER_SCORE_PROOF_MISMATCH',
  'SCORER_THRESHOLD_ECHO_MISMATCH',
  'SCORER_POLICY_ECHO_MISMATCH',
  'SCORER_ARTIFACT_MISSING',
  'SCORER_ARTIFACT_HASH_MISMATCH',
  'SCORER_ARTIFACT_CONTEXT_MISMATCH',
]);

function innerReasonNamesSafetyFloor(inner: string): boolean {
  return inner === 'structural_validity_below_floor'
    || inner.startsWith('protected_regression:')
    || inner.startsWith('regression_budget')
    || inner.startsWith('family_catastrophic:');
}

/**
 * §7.3: map (outer rejection code, inner rejection reason) → exactly ONE
 * external reason, or null for coordinator-internal outcomes that must NEVER
 * surface to a miner as a reject (scorer-integrity refusals — retry/alarm; the
 * miner sees pending or `stale_context`). Unknown internal codes also map to
 * null (fail-closed toward non-disclosure).
 */
export function mapBmuExternalRejectionReason(input: {
  readonly outerCode: string;
  readonly innerReason?: string;
}): BmuExternalRejectionReason | null {
  const outer = input.outerCode;
  const inner = input.innerReason ?? '';

  if (SCORER_INTEGRITY_CODES.has(outer)) return null;

  switch (outer) {
    case 'structurally-invalid':
    case 'admit-malformed-input':
    case 'SCORER_RESULT_MALFORMED':
    case 'SCORER_ARTIFACT_MALFORMED':
      return 'malformed_patch';
    case 'cached':
    case 'duplicate-key-collapsed':
    case 'per-miner-cap-reached':
    case 'duplicate_submission':
    case 'duplicate_in_flight':
    case 'CoreTexScreenerCapExceeded':
      return 'duplicate_or_capped';
    case 'gate-below-threshold':
    case 'no_retrieval_improvement':
    case 'SCORER_BELOW_THRESHOLD':
      return 'below_gate';
    case 'confirm-below-threshold':
      return 'failed_holdout_transfer';
    case 'W02_STALE_PARENT':
    case 'SCORER_STALE_CONTEXT':
      return 'stale_context';
    case 'gate-acceptance-floor':
    case 'confirm-acceptance-floor': {
      if (inner.startsWith('apply_failed')) return 'malformed_patch';
      if (innerReasonNamesSafetyFloor(inner)) return 'safety_regression';
      // Threshold miss surfaced through the floors-aware accept (the scorer's
      // accepted=false with reason no_retrieval_improvement): §7.2 semantics —
      // gate side = inert, confirm side = the anti-indexing signal.
      if (inner === 'no_retrieval_improvement') {
        return outer === 'gate-acceptance-floor' ? 'below_gate' : 'failed_holdout_transfer';
      }
      // Unnamed floor: conservatively a safety floor (the outer code exists
      // only when the canonical scorer's floors-aware accept refused).
      return 'safety_regression';
    }
    default:
      if (outer.startsWith('apply_failed')) return 'malformed_patch';
      return null;
  }
}

// ─── §6.7b ARM-GATE census ────────────────────────────────────────────────────

function liveMintEpochFromEventId(id: string): number {
  const m = /^zz_e(\d+)_/.exec(id);
  return m ? Number(m[1]) : -1;
}

export interface BmuArmGateFamilyReport {
  /** Stamped rows of this family in the census pool (reserve ∪ active). */
  readonly stampedRows: number;
  readonly required: number;
  readonly freshClusters: number;
  readonly freshClustersRequired: number;
}

export interface BmuArmGateReport {
  readonly ok: boolean;
  readonly posture: 'arm' | 'boot';
  readonly epochId: number;
  readonly freshWindow: number;
  readonly stampedPoolTotal: number;
  readonly nMinRequired: number;
  readonly perFamily: Readonly<Record<BmuFamily, BmuArmGateFamilyReport>>;
  /** GLOBAL m=1 census violations (rev3.2): a subjectEntityId or templateId in
   *  more than one ACTIVE cluster across ALL families. */
  readonly multiplicityViolations: readonly string[];
  /** Missing or inconsistent canonical identity/alias holdout keys. */
  readonly identityHoldoutViolations: readonly string[];
  readonly reasons: readonly string[];
}

/**
 * §6.7b ARM-GATE precondition (fail-closed arm/boot check; rev3.2 pool
 * semantics): the pool of stamped rows AVAILABLE FOR BULK-ACTIVATION
 * (bmuTask rows in RESERVE ∪ ACTIVE — pre-arm they sit in the reserve; the
 * §6.7a prerequisite-2 bulk-activation is what makes them eligible-active at
 * arm) must satisfy the per-family minima {80, 110, 110, 80} (N_min 380), a
 * fresh overlay cohort of ≥ 2 clusters per family within `freshWindow`, and
 * the GLOBAL m = 1 multiplicity census (across ALL families — §4.1 rev3.2).
 *
 * ORDERING (§6.7b): these count + census checks run BEFORE the one-time
 * bulk-activation (`scripts/coretex-stagger-frontier-activation.mjs
 * --mode bulk-activate`); the §2.4/§6.7b variance certification runs AFTER
 * bulk-activation as part of the rebaseline — it needs live scoreState runs
 * over the post-activation active set (`buildBmuArmVarianceCertification`),
 * which a boot census cannot perform.
 *
 * The frontier's own activation pipe is REPLACEMENT-ONLY (never grows the
 * active set), so minting alone can never open this gate — the bulk-activation
 * prerequisite exists precisely because of that structural fact (§6.7 intro).
 */
export function evaluateBmuArmGate(input: {
  readonly corpus: { readonly events: readonly ProductionCorpusEvent[] };
  /** The stamped-pool membership: RESERVE ∪ ACTIVE frontier ids at the ARM
   *  posture (rev3.2); the ACTIVE set alone at the BOOT posture. */
  readonly poolIds: ReadonlySet<string>;
  readonly epochId: number;
  readonly freshWindow?: number;
  /**
   * Census POSTURE (P3-R1 BLOCKER-1 orchestrator ruling; rev3.3 pins it):
   *  - 'arm'  — the one-time transition arm / bulk-activate moment: the FULL
   *    census (per-family minima + global m=1 + fresh-cohort ≥2 clusters per
   *    family within freshWindow, freshness read from MINT epochs — the arm
   *    gate requires the mint ramp to be RECENT).
   *  - 'boot' — evaluator/scorer construction re-checks: STRUCTURAL only
   *    (per-family minima + global m=1). NEVER freshness: post-arm steady
   *    state legitimately has its newest mint older than freshWindow, and a
   *    reboot must not fail-close on it (liveness).
   */
  readonly posture: 'arm' | 'boot';
}): BmuArmGateReport {
  // P3-R2 hardening: an untyped caller omitting `posture` must never get
  // boot (structural-only) semantics silently — fail closed on anything
  // other than the two pinned postures.
  if (input.posture !== 'arm' && input.posture !== 'boot') {
    throw new Error(`evaluateBmuArmGate: posture must be 'arm' or 'boot' (got ${String((input as { posture?: unknown }).posture)})`);
  }
  const freshWindow = input.freshWindow ?? BMU_FRESH_WINDOW_DEFAULT;
  const perFamilyCount: Record<BmuFamily, number> = { temporal: 0, conflict_lifecycle: 0, multi_hop_relation: 0, near_collision_abstention: 0 };
  const freshClusters: Record<BmuFamily, Set<string>> = {
    temporal: new Set(), conflict_lifecycle: new Set(), multi_hop_relation: new Set(), near_collision_abstention: new Set(),
  };
  // GLOBAL m=1 census: key → set of distinct active motifGroupIds.
  const clustersBySubject = new Map<string, Set<string>>();
  const clustersByTemplate = new Map<string, Set<string>>();
  const clustersByEntityHoldout = new Map<string, Set<string>>();
  const holdoutSignatureByMotif = new Map<string, string>();
  const identityHoldoutViolationSet = new Set<string>();

  let total = 0;
  for (const e of input.corpus.events) {
    const task = e.bmuTask;
    if (!task || e.split !== 'eval_hidden' || !input.poolIds.has(e.id)) continue;
    total += 1;
    perFamilyCount[task.family] += 1;
    const mintEpoch = liveMintEpochFromEventId(e.id);
    if (mintEpoch >= 0 && input.epochId - mintEpoch <= freshWindow) {
      freshClusters[task.family].add(task.motifGroupId);
    }
    if (e.subjectEntityId) {
      const s = clustersBySubject.get(e.subjectEntityId) ?? new Set<string>();
      s.add(task.motifGroupId);
      clustersBySubject.set(e.subjectEntityId, s);
    }
    const t = clustersByTemplate.get(task.templateId) ?? new Set<string>();
    t.add(task.motifGroupId);
    clustersByTemplate.set(task.templateId, t);
    const holdoutKeys = task.entityHoldoutKeys;
    if (!Array.isArray(holdoutKeys) || holdoutKeys.length === 0) {
      identityHoldoutViolationSet.add(`motifGroupId ${task.motifGroupId} has no entityHoldoutKeys (historical rows are not arm-eligible)`);
    } else {
      const sorted = [...new Set(holdoutKeys)].sort(codePointCompare);
      const canonicalSubjectKey = e.subjectEntityId ? `id:${e.subjectEntityId}` : null;
      if (canonicalSubjectKey !== null && !sorted.includes(canonicalSubjectKey)) {
        identityHoldoutViolationSet.add(`motifGroupId ${task.motifGroupId} omits canonical subject holdout key ${canonicalSubjectKey}`);
      }
      if (e.ownerEntityId && e.ownerEntityId !== e.subjectEntityId && sorted.includes(`id:${e.ownerEntityId}`)) {
        identityHoldoutViolationSet.add(`motifGroupId ${task.motifGroupId} includes shared owner id ${e.ownerEntityId} in entityHoldoutKeys`);
      }
      const signature = sorted.join('\n');
      const priorSignature = holdoutSignatureByMotif.get(task.motifGroupId);
      if (priorSignature !== undefined && priorSignature !== signature) {
        identityHoldoutViolationSet.add(`motifGroupId ${task.motifGroupId} has inconsistent entityHoldoutKeys across rows`);
      } else {
        holdoutSignatureByMotif.set(task.motifGroupId, signature);
      }
      for (const key of sorted) {
        const clusters = clustersByEntityHoldout.get(key) ?? new Set<string>();
        clusters.add(task.motifGroupId);
        clustersByEntityHoldout.set(key, clusters);
      }
    }
  }

  const reasons: string[] = [];
  const perFamily = {} as Record<BmuFamily, BmuArmGateFamilyReport>;
  for (const f of BMU_FAMILIES) {
    const required = BMU_ARM_GATE_FAMILY_MINIMA[f];
    perFamily[f] = {
      stampedRows: perFamilyCount[f],
      required,
      freshClusters: freshClusters[f].size,
      freshClustersRequired: BMU_ARM_GATE_FRESH_CLUSTERS_MIN,
    };
    if (perFamilyCount[f] < required) {
      reasons.push(`family ${f}: stamped pool rows ${perFamilyCount[f]} < required ${required}`);
    }
    // Fresh-cohort liveness check binds at the ARM posture ONLY (BLOCKER-1
    // ruling): boot re-checks are structural, never freshness.
    if (input.posture === 'arm' && freshClusters[f].size < BMU_ARM_GATE_FRESH_CLUSTERS_MIN) {
      reasons.push(`family ${f}: fresh clusters ${freshClusters[f].size} < required ${BMU_ARM_GATE_FRESH_CLUSTERS_MIN} within freshWindow ${freshWindow} (arm posture)`);
    }
  }
  if (total < BMU_ARM_GATE_N_MIN) {
    reasons.push(`stamped pool total ${total} < N_min ${BMU_ARM_GATE_N_MIN}`);
  }
  const multiplicityViolations: string[] = [];
  for (const [subject, clusters] of clustersBySubject) {
    if (clusters.size > 1) multiplicityViolations.push(`subjectEntityId ${subject} in ${clusters.size} active clusters (${[...clusters].sort().join(', ')})`);
  }
  for (const [template, clusters] of clustersByTemplate) {
    if (clusters.size > 1) multiplicityViolations.push(`templateId ${template} in ${clusters.size} active clusters (${[...clusters].sort().join(', ')})`);
  }
  for (const [identity, clusters] of clustersByEntityHoldout) {
    if (clusters.size > 1) multiplicityViolations.push(`entityHoldoutKey ${identity} in ${clusters.size} active clusters (${[...clusters].sort().join(', ')})`);
  }
  if (multiplicityViolations.length > 0) {
    reasons.push(`m=1 multiplicity census failed: ${multiplicityViolations.length} violation(s)`);
  }
  const identityHoldoutViolations = [...identityHoldoutViolationSet].sort(codePointCompare);
  if (identityHoldoutViolations.length > 0) {
    reasons.push(`entity/alias holdout census failed: ${identityHoldoutViolations.length} violation(s)`);
  }

  return {
    ok: reasons.length === 0,
    posture: input.posture,
    epochId: input.epochId,
    freshWindow,
    stampedPoolTotal: total,
    nMinRequired: BMU_ARM_GATE_N_MIN,
    perFamily,
    multiplicityViolations,
    identityHoldoutViolations,
    reasons,
  };
}

// ─── §6.7b variance certification (rev3.1: pinned executable procedure) ──────

const utf8 = new TextEncoder();

function u64BE(n: number): Uint8Array {
  const out = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 7; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

export type BmuArmVarianceStateLabel = 'parent' | 'blank';

/** Pinned seed schedule: keccak256('bmu-arm-variance' ‖ u64BE(epochId) ‖
 *  stateLabel ‖ u64BE(i)) — a deterministic pack rotation, never a future
 *  blockhash (the scoreState contract). */
export function bmuArmVarianceSeedHex(epochId: number, stateLabel: BmuArmVarianceStateLabel, runIndex: number): string {
  if (!Number.isInteger(epochId) || epochId < 0) throw new Error(`bmuArmVarianceSeedHex: epochId must be a non-negative integer (got ${String(epochId)})`);
  if (stateLabel !== 'parent' && stateLabel !== 'blank') throw new Error(`bmuArmVarianceSeedHex: stateLabel must be 'parent'|'blank' (got ${String(stateLabel)})`);
  if (!Number.isInteger(runIndex) || runIndex < 0 || runIndex >= BMU_ARM_VARIANCE_RUNS) {
    throw new Error(`bmuArmVarianceSeedHex: runIndex must be an integer in [0, ${BMU_ARM_VARIANCE_RUNS - 1}] (got ${String(runIndex)})`);
  }
  const domain = utf8.encode(BMU_ARM_VARIANCE_DOMAIN);
  const label = utf8.encode(stateLabel);
  const epoch = u64BE(epochId);
  const idx = u64BE(runIndex);
  const buf = new Uint8Array(domain.length + epoch.length + label.length + idx.length);
  buf.set(domain, 0);
  buf.set(epoch, domain.length);
  buf.set(label, domain.length + epoch.length);
  buf.set(idx, domain.length + epoch.length + label.length);
  return bytesToHex(keccak256(buf)).toLowerCase();
}

export interface BmuArmVarianceCertification {
  readonly states: readonly BmuArmVarianceStateLabel[];
  readonly K: number;
  readonly seeds: Readonly<Record<BmuArmVarianceStateLabel, readonly string[]>>;
  readonly scoresPpm: Readonly<Record<BmuArmVarianceStateLabel, readonly number[]>>;
  readonly spreadPpm: Readonly<Record<BmuArmVarianceStateLabel, number>>;
}

/**
 * Build the `armVarianceCertification` record for the signed rotation manifest
 * + arm log (rev3.1 §6.7b). FAIL-CLOSED: throws unless BOTH states carry
 * exactly K = 5 integer scores whose max pairwise spread is
 * < q/2 (= 7,812 ppm) — i.e. zero row flips across the certified rotation.
 * The caller performs the K scoreState runs (samples: 1 each) with the pinned
 * `bmuArmVarianceSeedHex` schedule and feeds the parentScorePpm values here.
 */
export function buildBmuArmVarianceCertification(input: {
  readonly epochId: number;
  readonly scoresPpm: Readonly<Record<BmuArmVarianceStateLabel, readonly number[]>>;
}): BmuArmVarianceCertification {
  const states: readonly BmuArmVarianceStateLabel[] = ['parent', 'blank'];
  const seeds = {} as Record<BmuArmVarianceStateLabel, readonly string[]>;
  const spreadPpm = {} as Record<BmuArmVarianceStateLabel, number>;
  for (const state of states) {
    const scores = input.scoresPpm[state];
    if (!Array.isArray(scores) || scores.length !== BMU_ARM_VARIANCE_RUNS) {
      throw new Error(`buildBmuArmVarianceCertification: ${state} requires exactly K=${BMU_ARM_VARIANCE_RUNS} scores (got ${scores ? scores.length : 'none'})`);
    }
    for (const s of scores) {
      if (!Number.isSafeInteger(s) || s < 0 || s > 1_000_000) {
        throw new Error(`buildBmuArmVarianceCertification: ${state} score ${String(s)} is not an integer ppm in [0, 1e6]`);
      }
    }
    const spread = Math.max(...scores) - Math.min(...scores);
    if (spread >= BMU_ARM_VARIANCE_MAX_SPREAD_PPM) {
      throw new Error(
        `buildBmuArmVarianceCertification: ${state} max pairwise spread ${spread} ppm >= ${BMU_ARM_VARIANCE_MAX_SPREAD_PPM} (q/2) — certification FAILED, the bundle MUST NOT arm`,
      );
    }
    spreadPpm[state] = spread;
    seeds[state] = Array.from({ length: BMU_ARM_VARIANCE_RUNS }, (_, i) => bmuArmVarianceSeedHex(input.epochId, state, i));
  }
  return { states, K: BMU_ARM_VARIANCE_RUNS, seeds, scoresPpm: { parent: [...input.scoresPpm.parent], blank: [...input.scoresPpm.blank] }, spreadPpm };
}

// ─── §10/§8.4 baseline lanes (blank-state AND parent-baseline) ───────────────

/**
 * BMU baseline scoring — the `scoreState` lane under the BMU law (§8.4/§10).
 * Same contract as `evaluateBaseline` (rewards/baseline.ts): score the given
 * substrate `samples` times on ONE caller-derived deterministic pack and
 * report mean/std-dev ppm — but the scalar is the BMU utility and the result
 * additionally carries the per-family U_f decomposition the two-pass
 * rebaseline and the coverage-collapse alarm need (`familyUtilitiesPpm`).
 *
 * Drives BOTH lanes: the blank-state lane (anti-cheat floor; blank ≠ parent
 * trap) and the parent-baseline lane (the number acceptance thresholds are
 * derived from) — the caller supplies the substrate. The measured variance
 * does NOT feed the acceptance threshold (§2.4 pins the variance term to 0);
 * it is the §6.7b ARM-GATE flip-stability certification input.
 */
export async function evaluateBmuBaseline(
  parentSubstrate: CortexState,
  corpus: ProductionCorpus,
  pack: QueryPack,
  scoringOpts: ScoringOptions,
  bmu: BmuScoringContext = {},
  opts: { readonly samples?: number } = {},
): Promise<import('../rewards/baseline.js').BaselineScores> {
  const samples = Math.max(1, Math.floor(opts.samples ?? 1));
  const scores: BmuScore[] = [];
  const ppmSamples: number[] = [];
  for (let i = 0; i < samples; i++) {
    const s = await evaluateBmuBenchmarkState(parentSubstrate, corpus, pack, scoringOpts, bmu);
    scores.push(s);
    ppmSamples.push(s.bmu.scalarPpm);
  }
  const mean = ppmSamples.reduce((a, v) => a + v, 0) / samples;
  const variance = samples > 1
    ? Math.sqrt(ppmSamples.reduce((a, v) => a + (v - mean) ** 2, 0) / samples)
    : 0;
  const familyUtilitiesPpm = scores[0]!.bmu.familyUtilitiesPpm;
  const parentScorePpm = Math.round(mean);
  return {
    parentScorePpm,
    variancePpm: Math.round(variance),
    samples,
    corpusRoot: pack.corpusRoot,
    epochId: pack.epochId,
    compositeScore: scores[0]!,
    familyUtilitiesPpm,
    familyUtilitiesDigest: computeBmuFamilyUtilitiesDigest({
      scoringPipelineVersion: scoringOpts.pipelineVersion!,
      epochId: pack.epochId,
      corpusRoot: pack.corpusRoot,
      baselineSeedHex: pack.evalSeedHex,
      parentScorePpm,
      familyUtilitiesPpm,
    }),
  };
}

/**
 * Integrity binding for the §8.4 per-family baseline decomposition (P3-R1
 * MINOR): keccak256 over the canonical JSON of the decomposition TOGETHER
 * with the identifiers that make it re-derivable (epochId, corpusRoot, the
 * deterministic baseline seed, and the scalar it decomposes). The rebaseline
 * consumer MUST recompute this digest from the fields it received and refuse
 * a mismatch, and — the actual integrity backstop — MAY re-derive the whole
 * decomposition independently, since the baseline seed is deterministic and
 * caller-derived (never a future blockhash). This binds the decomposition to
 * its scoring context; it is NOT a signature (the scorer host is untrusted
 * for authority, trusted for compute, same as the scalar itself).
 */
export function computeBmuFamilyUtilitiesDigest(input: {
  readonly scoringPipelineVersion: string;
  readonly epochId: number;
  readonly corpusRoot: string;
  readonly baselineSeedHex: string;
  readonly parentScorePpm: number;
  readonly familyUtilitiesPpm: Readonly<Record<string, number>>;
}): string {
  if (!isBmuScoringLaw(input.scoringPipelineVersion)) {
    throw new Error(`computeBmuFamilyUtilitiesDigest: '${input.scoringPipelineVersion}' is not a BMU scoring law`);
  }
  const canonical = JSON.stringify({
    baselineSeedHex: input.baselineSeedHex.toLowerCase(),
    corpusRoot: input.corpusRoot.toLowerCase(),
    epochId: input.epochId,
    familyUtilitiesPpm: Object.fromEntries(Object.entries(input.familyUtilitiesPpm).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))),
    parentScorePpm: input.parentScorePpm,
    scoringPipelineVersion: input.scoringPipelineVersion,
  });
  return bytesToHex(keccak256(utf8.encode(canonical))).toLowerCase();
}

// ─── §6.3/§8.3 exclusion-set digest (published-artifact telemetry) ────────────

/**
 * Digest of the confirm-side exclusion key set X (§6.3) for the published
 * artifact's per-family aggregate section (§8.3). Convention (implementation-
 * defined, deterministic): keccak256 over the UTF-8 of the SORTED composite
 * keys joined by '\n'. Empty set digests the empty string.
 */
export function bmuExclusionSetDigest(keys: ReadonlySet<string> | readonly string[]): string {
  const sorted = [...keys].sort(codePointCompare);
  return bytesToHex(keccak256(utf8.encode(sorted.join('\n')))).toLowerCase();
}

// ─── §8.3 published per-family aggregates (artifact body) ─────────────────────

export interface BmuFamilyAggregates {
  /** U_f (ppm) for parent/candidate per pack side. */
  readonly gate: {
    readonly parentFamilyUtilitiesPpm: Readonly<Record<BmuFamily, number>>;
    readonly candidateFamilyUtilitiesPpm: Readonly<Record<BmuFamily, number>>;
    readonly regressedRowsByFamily: Readonly<Record<BmuFamily, number>>;
  };
  readonly confirm: {
    readonly parentFamilyUtilitiesPpm: Readonly<Record<BmuFamily, number>>;
    readonly candidateFamilyUtilitiesPpm: Readonly<Record<BmuFamily, number>>;
    readonly regressedRowsByFamily: Readonly<Record<BmuFamily, number>>;
  };
  /** §6.3 exclusion-set digest (bmuExclusionSetDigest of X). */
  readonly exclusionSetDigest: string;
}

/** Per-family regressed-row counts (u 1→0, protected included — this is audit
 *  telemetry, not the budget arithmetic). */
export function bmuRegressedRowsByFamily(before: BmuScore, after: BmuScore): Record<BmuFamily, number> {
  const beforeByRow = new Map(before.bmu.perTask.map((t) => [t.recordId, t]));
  const out: Record<BmuFamily, number> = { temporal: 0, conflict_lifecycle: 0, multi_hop_relation: 0, near_collision_abstention: 0 };
  for (const t of after.bmu.perTask) {
    const prev = beforeByRow.get(t.recordId);
    if (prev && prev.utility === 1 && t.utility === 0) out[t.family] += 1;
  }
  return out;
}

// Re-exported for convenience of pack-law consumers (bmuFamilyForLogicalFamily
// is the §5.6 reverse mapping used by the overlay slot law).
export { bmuFamilyForLogicalFamily };
