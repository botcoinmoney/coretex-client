/**
 * BMU v1 task schema + family-namespace law (BMU_SPEC.md §4, §5.6).
 *
 * LEAF MODULE (imports nothing) so the corpus loader, the pack law, the
 * BMU benchmark, and the logical-delta bridge can all consume ONE pinned
 * definition of the task shape and the four-namespace family mapping.
 *
 * `bmuTask` is the ONE optional field BMU adds to `ProductionCorpusEvent`
 * (§4.1). Optional-and-absent on every pre-BMU row — absent keys do not
 * change canonical event hashes (the same back-compat convention as
 * `entityIds`), so pre-flip inert minting (§6.7a) is replay-safe.
 */

// ─── Families (invariant I3: exactly these four) ─────────────────────────────

export type BmuFamily =
  | 'temporal'
  | 'conflict_lifecycle'
  | 'multi_hop_relation'
  | 'near_collision_abstention';

/** Fixed family order (also the §6.4 redistribution round-robin order). */
export const BMU_FAMILIES: readonly BmuFamily[] = [
  'temporal',
  'conflict_lifecycle',
  'multi_hop_relation',
  'near_collision_abstention',
];

/**
 * §5.6 mapping: BMU family → corpus `logicalFamily` values (the overlay
 * `familyPriority` namespace; matched logicalFamily-FIRST). Measured on the
 * live epoch-136 corpus. Thin atom families pool into near_collision.
 */
export const BMU_FAMILY_LOGICAL_FAMILIES: Readonly<Record<BmuFamily, readonly string[]>> = {
  temporal: ['temporal_update'],
  conflict_lifecycle: ['conflict_lifecycle'],
  multi_hop_relation: ['multi_session_bridge', 'causal_memory_chain', 'decision_provenance', 'coreference_resolution'],
  near_collision_abstention: ['abstention_missing', 'entity_resolution_atom', 'scope_atom', 'validity_atom'],
};

/**
 * §5.6 mapping: BMU family → bucketed `event.family` values (the quota-stratum
 * namespace, matched via `strataOf`). `coreference` is the legacy bucket the
 * `coreference_resolution` logicalFamily lands in.
 */
export const BMU_FAMILY_BUCKETED: Readonly<Record<BmuFamily, readonly string[]>> = {
  temporal: ['temporal'],
  conflict_lifecycle: ['conflict_lifecycle'],
  multi_hop_relation: ['multi_hop_relation', 'coreference'],
  near_collision_abstention: ['near_collision'],
};

/** Reverse §5.6 mapping: corpus logicalFamily → BMU family (null = not a BMU
 *  family, e.g. the disabled `aspect_constraint`). */
export function bmuFamilyForLogicalFamily(logicalFamily: string | undefined): BmuFamily | null {
  if (!logicalFamily) return null;
  for (const fam of BMU_FAMILIES) {
    if (BMU_FAMILY_LOGICAL_FAMILIES[fam].includes(logicalFamily)) return fam;
  }
  return null;
}

/** §2.3 composition targets w_f (realized STRUCTURALLY via quotas + overlay
 *  slots, never as arithmetic multipliers). */
export const BMU_COMPOSITION_TARGETS: Readonly<Record<BmuFamily, number>> = {
  temporal: 0.20,
  conflict_lifecycle: 0.30,
  multi_hop_relation: 0.30,
  near_collision_abstention: 0.20,
};

/** §4.2 per-family default budgetB (generator MAY override within [1,8]). */
export const BMU_DEFAULT_BUDGET_B: Readonly<Record<BmuFamily, number>> = {
  temporal: 3,
  conflict_lifecycle: 4,
  multi_hop_relation: 4,
  near_collision_abstention: 3,
};

/** §4.2 hard cap: `budgetB > 8` fails corpus load. Always < rerankerTopK (10),
 *  so the budget is a strict tightening of the existing scored-rank cap. */
export const BMU_TASK_MAX_BUDGET = 8;

/** §6.4: default fresh-cohort window (epochs) when the bundle does not pin
 *  `liveEvalPack.freshWindow`. Lives in this leaf module because both the
 *  pack law (overlay slot draw) and the arm-gate census consume it. */
export const BMU_FRESH_WINDOW_DEFAULT = 2;

/** Multi-hop retrieval's forced score-inheritance floor. */
export const BMU_MULTI_HOP_FORCED_INHERIT_ALPHA = 1;

// ─── Task shape (§4.1) ────────────────────────────────────────────────────────

export interface BmuTaskAnswer {
  /** Accepted answer doc id — MUST be a member of `requiredEvidence`. */
  readonly id: string;
  /** Audit-only value; never consulted by the judge. */
  readonly value?: string;
}

export interface BmuTask {
  readonly family: BmuFamily;
  /** Budget B: top-B evidence items (I4). Integer in [1, 8]. */
  readonly budgetB: number;
  /** Doc ids that must ALL be inside top-B for utility ([] only when abstain). */
  readonly requiredEvidence: readonly string[];
  /** Trap doc ids — ANY of these inside top-B zeroes the task. */
  readonly forbiddenEvidence: readonly string[];
  /** REQUIRED unless abstain=true. */
  readonly answer?: BmuTaskAnswer;
  /** Abstention variant (default false). */
  readonly abstain?: boolean;
  /** Cluster identity — held-out partition key (§6.3). Generator-pinned. */
  readonly motifGroupId: string;
  /** Surface-form template id — held-out partition key (§6.3). Generator-pinned. */
  readonly templateId: string;
  /** Narrow canonical subject/name/alias partition keys for confirm exclusion.
   * Optional only for historical pre-hardening rows. */
  readonly entityHoldoutKeys?: readonly string[];
}

/** Structural duck-type of the event fields the BMU task law reads (kept a
 *  structural type so this module stays a leaf — `ProductionCorpusEvent`
 *  satisfies it). */
export interface BmuTaskEventShape {
  readonly id: string;
  readonly family?: string;
  readonly split?: string;
  readonly logicalFamily?: string;
  readonly subjectEntityId?: string;
  readonly bmuTask?: BmuTask;
}

/** True iff the event carries a bmuTask (presence, not validity). */
export function hasBmuTask(event: BmuTaskEventShape): boolean {
  return event.bmuTask !== undefined && event.bmuTask !== null;
}

// ─── §6.3 exclusion keys ─────────────────────────────────────────────────────

/**
 * Composite exclusion keys for a gate-pack row (§6.3): namespaced so a
 * motifGroupId can never collide with a subjectEntityId/templateId string.
 * A candidate row is EXCLUDED from the confirm pool iff ANY of its own keys
 * is in the gate pack's key set X.
 */
export function bmuExclusionKeysForEvent(event: BmuTaskEventShape): readonly string[] {
  const keys: string[] = [];
  const t = event.bmuTask;
  if (t?.motifGroupId) keys.push(`motif:${t.motifGroupId}`);
  if (event.subjectEntityId) keys.push(`subject:${event.subjectEntityId}`);
  if (t?.templateId) keys.push(`template:${t.templateId}`);
  for (const key of t?.entityHoldoutKeys ?? []) keys.push(`entity:${key}`);
  return keys;
}

// ─── Load-time validation (§4.1 — fail-closed, corpus refuses to load) ──────

/**
 * Validate ONE event's `bmuTask` (call only when present). Returns a list of
 * error strings (empty = valid). `docIdExists` answers "does this doc id
 * exist anywhere in the corpus" (truthDocuments/hardNegatives across events).
 *
 * Cross-row checks (motifGroup family consistency) are the caller's job —
 * see `validateBmuCorpusConsistency`.
 */
export function validateBmuTaskOnEvent(
  event: BmuTaskEventShape,
  docIdExists: (docId: string) => boolean,
): string[] {
  const errors: string[] = [];
  const t = event.bmuTask;
  if (!t || typeof t !== 'object') return [`${event.id}: bmuTask must be an object`];
  const err = (msg: string) => errors.push(`${event.id}: ${msg}`);

  if (!BMU_FAMILIES.includes(t.family)) {
    err(`bmuTask.family '${String(t.family)}' is not a BMU family`);
    return errors; // family anchors the remaining checks
  }
  // §4.3 pack-eligibility premise: bmuTask lives on eval_hidden query rows.
  if (event.split !== undefined && event.split !== 'eval_hidden') {
    err(`bmuTask present on split '${event.split}' (must be eval_hidden)`);
  }
  // §5.6 namespace consistency: bmuTask.family must equal the bucketed mapping
  // and the row's logicalFamily must map into the same BMU family.
  if (event.family !== undefined && !BMU_FAMILY_BUCKETED[t.family].includes(event.family)) {
    err(`bucketed family '${event.family}' does not map to bmuTask.family '${t.family}' (§5.6)`);
  }
  if (event.logicalFamily !== undefined && bmuFamilyForLogicalFamily(event.logicalFamily) !== t.family) {
    err(`logicalFamily '${event.logicalFamily}' does not map to bmuTask.family '${t.family}' (§5.6)`);
  }

  if (!Number.isInteger(t.budgetB) || t.budgetB < 1 || t.budgetB > BMU_TASK_MAX_BUDGET) {
    err(`bmuTask.budgetB must be an integer in [1, ${BMU_TASK_MAX_BUDGET}] (got ${String(t.budgetB)})`);
  }
  const strArray = (v: unknown): v is readonly string[] =>
    Array.isArray(v) && v.every((x) => typeof x === 'string' && x.length > 0);
  if (!strArray(t.requiredEvidence)) err('bmuTask.requiredEvidence must be an array of non-empty doc-id strings');
  if (!strArray(t.forbiddenEvidence)) err('bmuTask.forbiddenEvidence must be an array of non-empty doc-id strings');
  if (typeof t.motifGroupId !== 'string' || t.motifGroupId.length === 0) err('bmuTask.motifGroupId must be non-empty');
  if (typeof t.templateId !== 'string' || t.templateId.length === 0) err('bmuTask.templateId must be non-empty');
  if (t.entityHoldoutKeys !== undefined
      && (!strArray(t.entityHoldoutKeys) || t.entityHoldoutKeys.length === 0 || t.entityHoldoutKeys.length > 32)) {
    err('bmuTask.entityHoldoutKeys must be an array of 1..32 non-empty strings when present');
  }
  // Control characters (incl. '\n') in the §6.3 exclusion-key fields would let
  // a crafted id smuggle bytes into the sorted-join exclusion-set DIGEST
  // (§8.3 uses '\n' as the join separator) — refuse them at load, all three
  // key fields (motifGroupId / templateId / event subjectEntityId).
  const CONTROL = /[\u0000-\u001f\u007f]/;
  if (typeof t.motifGroupId === 'string' && CONTROL.test(t.motifGroupId)) err('bmuTask.motifGroupId must not contain control characters');
  if (typeof t.templateId === 'string' && CONTROL.test(t.templateId)) err('bmuTask.templateId must not contain control characters');
  if (event.subjectEntityId !== undefined && CONTROL.test(event.subjectEntityId)) err('subjectEntityId must not contain control characters on a bmuTask row');
  if (Array.isArray(t.entityHoldoutKeys)) {
    const seen = new Set<string>();
    for (const key of t.entityHoldoutKeys) {
      if (typeof key !== 'string') continue;
      if (key.length > 256) err('bmuTask.entityHoldoutKeys entries must be at most 256 characters');
      if (CONTROL.test(key)) err('bmuTask.entityHoldoutKeys entries must not contain control characters');
      if (seen.has(key)) err(`duplicate bmuTask.entityHoldoutKeys entry '${key}'`);
      seen.add(key);
    }
    if (event.subjectEntityId !== undefined && !seen.has(`id:${event.subjectEntityId}`)) {
      err(`bmuTask.entityHoldoutKeys must include canonical subject key 'id:${event.subjectEntityId}'`);
    }
  }
  if (t.abstain !== undefined && typeof t.abstain !== 'boolean') err('bmuTask.abstain must be boolean when present');
  if (errors.length > 0) return errors;

  const required = new Set(t.requiredEvidence);
  const abstain = t.abstain === true;
  if (abstain) {
    if (t.requiredEvidence.length !== 0) err('abstain=true requires requiredEvidence = []');
    if (t.answer !== undefined) err('abstain=true requires answer absent');
  } else {
    if (t.requiredEvidence.length === 0) err('requiredEvidence may be [] only when abstain=true');
    if (!t.answer || typeof t.answer.id !== 'string' || t.answer.id.length === 0) {
      err('bmuTask.answer.id is required unless abstain=true');
    } else if (!required.has(t.answer.id)) {
      err(`answer.id '${t.answer.id}' must be a member of requiredEvidence`);
    }
    if (Number.isInteger(t.budgetB) && t.requiredEvidence.length > t.budgetB) {
      err(`|requiredEvidence| (${t.requiredEvidence.length}) must be <= budgetB (${t.budgetB})`);
    }
  }
  for (const f of t.forbiddenEvidence) {
    if (required.has(f)) err(`doc '${f}' appears in BOTH requiredEvidence and forbiddenEvidence`);
  }
  const seenReq = new Set<string>();
  for (const r of t.requiredEvidence) {
    if (seenReq.has(r)) err(`duplicate requiredEvidence doc '${r}'`);
    seenReq.add(r);
  }
  for (const docId of [...t.requiredEvidence, ...t.forbiddenEvidence, ...(t.answer ? [t.answer.id] : [])]) {
    if (!docIdExists(docId)) err(`referenced doc id '${docId}' does not exist in the corpus`);
  }
  return errors;
}

/**
 * MINT-TIME lint for a stamped row (§6.7a). Validation is LIVE FROM THE FIRST
 * STAMPED MINT: the corpus loader fail-closes on an invalid bmuTask, so an
 * invalid stamped mint that reaches the corpus would brick the NEXT LOAD of
 * the live r5 corpus. Generators and the logical-delta bridge MUST run this
 * lint at mint time and refuse the delta instead. `docIdExists` should answer
 * over the post-delta doc universe (added docs + previous corpus).
 */
export function lintBmuTaskForMint(
  event: BmuTaskEventShape,
  docIdExists: (docId: string) => boolean,
): string[] {
  if (!hasBmuTask(event)) return [];
  return validateBmuTaskOnEvent(event, docIdExists);
}

/**
 * Cross-row corpus consistency for bmuTask rows: every row of a motifGroup
 * carries the same family (a motifGroup is minted from ONE memory structure,
 * §4.1). Returns error strings (empty = consistent).
 *
 * NOTE: the §4.1 multiplicity mint law (m = 1: a subjectEntityId/templateId in
 * at most one ACTIVE cluster, GLOBAL across families) is a property of the
 * ACTIVE WINDOW, not the whole corpus — it is checked by the arm-gate census
 * (`evaluateBmuArmGate`), not here.
 */
export function validateBmuCorpusConsistency(events: readonly BmuTaskEventShape[]): string[] {
  const errors: string[] = [];
  const familyByMotif = new Map<string, { family: BmuFamily; firstRow: string; holdoutSignature: string | null }>();
  for (const e of events) {
    const t = e.bmuTask;
    if (!t || typeof t.motifGroupId !== 'string' || t.motifGroupId.length === 0) continue;
    const prior = familyByMotif.get(t.motifGroupId);
    const holdoutSignature = t.entityHoldoutKeys === undefined
      ? null
      : [...t.entityHoldoutKeys].sort(codePointStringCompare).join('\n');
    if (!prior) {
      familyByMotif.set(t.motifGroupId, { family: t.family, firstRow: e.id, holdoutSignature });
    } else if (prior.family !== t.family) {
      errors.push(
        `motifGroupId '${t.motifGroupId}' spans families '${prior.family}' (${prior.firstRow}) and '${t.family}' (${e.id})`,
      );
    } else if (prior.holdoutSignature !== holdoutSignature) {
      errors.push(`motifGroupId '${t.motifGroupId}' has inconsistent entityHoldoutKeys (${prior.firstRow} vs ${e.id})`);
    }
  }
  return errors;
}

function codePointStringCompare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
