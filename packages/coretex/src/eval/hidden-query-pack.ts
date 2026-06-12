/**
 * Hidden query pack derivation.
 *
 * Spec: specs/hidden_query_pack.md.
 *
 * The query pack is deterministic from (epochId, evalSeed, corpus). Anyone
 * with the seed and the bundle reproduces the same pack and verifies it
 * satisfies the per-stratum quotas pinned in the bundle profile.
 */

import { keccak256 } from '../state/keccak256.js';
import { codePointCompare } from './retrieval-corpus.js';
import type { ProductionCorpus, ProductionCorpusEvent, ProductionCorpusFamily } from './retrieval-corpus.js';

export type HardnessBucket = 'easy' | 'medium' | 'hard';

export interface PackQuota {
  readonly stratum: string;        // e.g. "family=temporal"
  readonly minCount: number;
}

export interface HiddenPackProfile {
  readonly packSize: number;
  readonly quotas: readonly PackQuota[];
  readonly disabledFamilies?: readonly string[];
  readonly disabledSubstrateSurfaces?: readonly string[];
}

export interface QueryPack {
  readonly epochId: number;
  readonly evalSeedHex: string;
  readonly corpusRoot: string;
  readonly events: readonly ProductionCorpusEvent[];
}

export interface ActiveLiveEvalPackOptions {
  readonly activeIds: ReadonlySet<string>;
  readonly limit: number;
  readonly familyPriority?: readonly string[];
  readonly dedupePublicIntent?: boolean;
  /** Optional quota contract to preserve when live rows replace base hidden-pack rows. */
  readonly profile?: HiddenPackProfile;
  readonly quotas?: readonly PackQuota[];
  readonly disabledFamilies?: readonly string[];
}

export function disabledHiddenEvalFamiliesFromProfile(profile: {
  readonly enableAspectConstraintAtoms?: boolean;
  readonly policyAspectIntentAdmission?: boolean;
  readonly disabledSubstrateSurfaces?: readonly string[];
}): readonly string[] {
  const disabled = new Set<string>();
  if (profile.disabledSubstrateSurfaces?.includes('aspect_constraint') ||
      profile.enableAspectConstraintAtoms === false ||
      profile.policyAspectIntentAdmission === false) {
    disabled.add('aspect_constraint');
  }
  return [...disabled].sort();
}

export function hiddenPackProfileFromEvaluatorProfile(profile: {
  readonly hiddenPack: HiddenPackProfile;
  readonly enableAspectConstraintAtoms?: boolean;
  readonly policyAspectIntentAdmission?: boolean;
  readonly disabledSubstrateSurfaces?: readonly string[];
}): HiddenPackProfile {
  const disabledFamilies = new Set([
    ...(profile.hiddenPack.disabledFamilies ?? []),
    ...disabledHiddenEvalFamiliesFromProfile(profile),
  ]);
  return { ...profile.hiddenPack, disabledFamilies: [...disabledFamilies].sort() };
}

/**
 * Compute the hardness bucket for a corpus event.
 *
 * Hardness is derived from the labeling-model score gap between the
 * hardest negative pair and the highest-graded truth. We approximate this
 * as the max negative qrel score: more plausible wrong answers → harder
 * query. Hard negatives are capped at 0.4 because they are deliberately
 * non-answer-bearing.
 *
 * Qrels with `relevance >= 0.5` are treated as POSITIVE (true answer or
 * relation-answer alias) and excluded from the hard-negative
 * calculation. Pre-relation-alias-repair corpora wouldn't have any such
 * qrels outside `event.truthDocuments`; post-repair, relation-target
 * truths are aliased into qrels at relevance=1 and would otherwise
 * collapse every relation-bearing event's bucket to 'hard'.
 */
export function hardnessBucketFor(event: ProductionCorpusEvent): HardnessBucket {
  let maxNeg: number = 0;
  const truthIds = new Set(event.truthDocuments.map((d) => d.id));
  for (const q of event.qrels) {
    if (truthIds.has(q.documentId)) continue;
    if (q.relevance >= 0.5) continue; // positive qrel (true answer / relation alias) — not a hard negative
    if (q.relevance > maxNeg) maxNeg = q.relevance;
  }
  if (maxNeg >= 0.4) return 'hard';
  if (maxNeg >= 0.2) return 'medium';
  return 'easy';
}

export function stratumOf(event: ProductionCorpusEvent): string {
  return `family=${event.family},bucket=${hardnessBucketFor(event)}`;
}

/**
 * Multi-strata membership for an event. Replaces the single-string
 * `stratumOf` for predicate-style quotas — an event can satisfy the
 * "family=temporal" stratum AND the "depth>=3" stratum AND the combined
 * "family=multi_hop_relation,depth>=3" stratum simultaneously, so deep
 * causal/temporal events count toward all relevant quotas.
 *
 * Returns at minimum the family/bucket strata (`stratumOf` base).
 * When the event carries synthesis-time `causalDepth` or
 * `relationHopDepth`, additional `depth>=N` and combined predicates are
 * emitted. Old corpora that predate these fields default to depth 1
 * and emit only the base strata.
 *
 * The predicate-quota matcher in `eventSatisfiesStratum` accepts both
 * exact strings (previous) and predicates (`depth>=N`,
 * `family=X,depth>=N`).
 */
export function strataOf(event: ProductionCorpusEvent): string[] {
  const bucket = hardnessBucketFor(event);
  const family = event.family;
  const causalDepth = event.causalDepth ?? 1;
  const relationHopDepth = event.relationHopDepth ?? 1;
  const out: string[] = [
    `family=${family}`,
    `bucket=${bucket}`,
    `family=${family},bucket=${bucket}`,
  ];
  // Explicit generator difficulty band (DGEN-1+): make hidden-pack selection
  // difficulty-aware (band quotas + epoch band-progression). Independent of the
  // qrel-derived `bucket` (which is only easy/medium/hard); the band carries the
  // generator's structural difficulty incl. very_hard/exhaustion. Old corpora
  // without `event.band` emit no band stratum (back-compat).
  if (event.band) {
    out.push(`band=${event.band}`);
    out.push(`family=${family},band=${event.band}`);
  }
  // Emit depth strata only when the synthesizer set a non-trivial
  // depth — keeps previous corpora's strata list short and avoids
  // misleading "depth>=1" quota matches that always pass.
  if (causalDepth > 1) {
    for (let d = 2; d <= causalDepth; d++) out.push(`depth>=${d}`);
    for (let d = 2; d <= causalDepth; d++) out.push(`family=${family},depth>=${d}`);
  }
  if (relationHopDepth > 1) {
    for (let d = 2; d <= relationHopDepth; d++) out.push(`relationHop>=${d}`);
    for (let d = 2; d <= relationHopDepth; d++) out.push(`family=${family},relationHop>=${d}`);
  }
  return out;
}

/**
 * Predicate quota matcher.
 *
 * Accepts:
 *   - exact strings: matches a literal stratum name from `strataOf(event)`
 *   - predicates: `depth>=N`, `relationHop>=N`, `family=X,depth>=N`, ...
 *
 * Returns true iff the event satisfies the quota's stratum string.
 */
export function eventSatisfiesStratum(event: ProductionCorpusEvent, stratum: string): boolean {
  const strata = strataOf(event);
  if (strata.includes(stratum)) return true;
  // Exact-match miss: treat as predicate. Currently the only predicates
  // we accept are `depth>=N`, `relationHop>=N`, and combined-with-family
  // forms — all of which are emitted by strataOf, so the includes() above
  // already matched if the predicate holds. Fall through to false for
  // unknown predicates, which is the conservative choice (an unsatisfied
  // quota will fail closed in `deriveQueryPack`).
  return false;
}

function evalSeedBytes(evalSeedHex: string): Uint8Array {
  const clean = evalSeedHex.startsWith('0x') ? evalSeedHex.slice(2) : evalSeedHex;
  if (clean.length !== 64) throw new Error(`evalSeed must be 32 bytes (got ${clean.length / 2})`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function u64BE(n: number | bigint): Uint8Array {
  const out = new Uint8Array(8);
  let v = typeof n === 'bigint' ? n : BigInt(n);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function digestU256(parts: Uint8Array[]): bigint {
  let total = 0;
  for (const p of parts) total += p.length;
  const buf = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    buf.set(p, offset);
    offset += p.length;
  }
  const d = keccak256(buf);
  let v = 0n;
  for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(d[i]!);
  return v;
}

/**
 * Derive a deterministic per-epoch query pack from `(epochId, evalSeed, corpus, profile)`.
 * Throws if the post-stratification pack cannot satisfy the quotas.
 */
export function deriveQueryPack(
  epochId: number,
  evalSeedHex: string,
  corpus: ProductionCorpus,
  profile: HiddenPackProfile,
): QueryPack {
  const seed = evalSeedBytes(evalSeedHex);
  const epochBE = u64BE(epochId);

  const sorted = corpus.events
    .filter((e) => hiddenPackEventEligible(e, profile))
    .sort((a, b) => codePointCompare(a.id, b.id));
  if (sorted.length === 0) throw new Error('deriveQueryPack: corpus has no eval_hidden records');

  // QUOTA-FIRST derivation (deterministic, replay-reproducible). Quotas are HARD guarantees, not
  // best-effort fill: reserve each stratum's minCount BEFORE any free sampling. `present` is
  // RE-DERIVED from the pack every iteration via the predicate matcher (never blindly incremented),
  // so an event satisfying multiple strata is counted correctly for each — fixing the prior bug where
  // a blind present++ after eviction over-counted and let the pack fall below quota without throwing.
  // Then fill the remaining slots to EXACTLY packSize (no off-by-one short pack).
  const pack: ProductionCorpusEvent[] = [];
  const ids = new Set<string>();
  const enc = new TextEncoder();
  const satisfies = (e: ProductionCorpusEvent, stratum: string) => eventSatisfiesStratum(e, stratum);

  // 1. quota-first reservation
  for (const quota of profile.quotas) {
    let j = 0;
    while (pack.filter((e) => satisfies(e, quota.stratum)).length < quota.minCount && j < sorted.length * 8) {
      const idx = digestU256([seed, epochBE, enc.encode(`quota:${quota.stratum}`), u64BE(j)]) % BigInt(sorted.length);
      const cand = sorted[Number(idx)]!;
      j++;
      if (ids.has(cand.id)) continue;
      if (!satisfies(cand, quota.stratum)) continue;
      if (pack.length >= profile.packSize) break; // never exceed packSize
      pack.push(cand);
      ids.add(cand.id);
    }
    const got = pack.filter((e) => satisfies(e, quota.stratum)).length;
    if (got < quota.minCount) {
      throw new Error(`deriveQueryPack: stratum ${quota.stratum} cannot meet quota ${quota.minCount} (got ${got}; eval_hidden too small or quotas sum > packSize)`);
    }
  }

  // 2. fill remaining slots to EXACTLY packSize with deterministic free sampling (dedup).
  for (let i = 0; pack.length < profile.packSize && i < sorted.length * 8; i++) {
    const idx = digestU256([seed, epochBE, u64BE(i)]) % BigInt(sorted.length);
    const cand = sorted[Number(idx)]!;
    if (ids.has(cand.id)) continue;
    pack.push(cand);
    ids.add(cand.id);
  }
  if (pack.length !== profile.packSize) {
    throw new Error(`deriveQueryPack: cannot fill exact packSize ${profile.packSize} (got ${pack.length}; eval_hidden unique records exhausted)`);
  }

  return {
    epochId,
    evalSeedHex: evalSeedHex.toLowerCase().startsWith('0x') ? evalSeedHex.toLowerCase() : `0x${evalSeedHex.toLowerCase()}`,
    corpusRoot: corpus.corpusRoot,
    events: pack,
  };
}

function liveEpochFromEventId(id: string): number {
  const m = /^zz_e(\d+)_/.exec(id);
  return m ? Number(m[1]) : -1;
}

function stablePublicIntentKey(event: ProductionCorpusEvent): string | null {
  const e = event as ProductionCorpusEvent & {
    logicalFamily?: string;
    subjectEntityId?: string;
    publicIntent?: Record<string, unknown>;
    scope?: Record<string, unknown>;
  };
  const pi = e.publicIntent ?? {};
  const scope = e.scope ?? {};
  const subjectEntityId = e.subjectEntityId ?? pi.subjectEntityId;
  const keys: Record<string, unknown> = {
    family: e.logicalFamily ?? e.family ?? 'unknown',
    epoch: liveEpochFromEventId(e.id),
    ownerEntityId: e.ownerEntityId,
    subjectEntityId,
    atom: pi.atom,
    attribute: pi.attribute,
    queryTime: pi.queryTime,
    roleAlias: pi.roleAlias,
    name: pi.name,
    selector: pi.selector,
    action: pi.action,
    projectId: pi.projectId ?? scope.projectId,
    sessionId: pi.sessionId ?? scope.sessionId,
    topicId: pi.topicId ?? scope.topicId,
    taskId: pi.taskId ?? scope.taskId,
    userScopeId: pi.userScopeId ?? scope.userScopeId,
  };
  const present = Object.entries(keys).filter(([, value]) => value !== undefined && value !== null && value !== '');
  if (!present.some(([key]) => key !== 'family' && key !== 'epoch')) return null;
  return JSON.stringify(Object.fromEntries(present));
}

/**
 * Canonical active-live overlay for measured packs.
 *
 * `deriveQueryPack` remains the deterministic base hidden pack. This helper is the
 * replayable frontier-aware overlay: given the public/reconstructable active frontier
 * set, it prepends newest active live eval queries before scoring. This replaces
 * harness-only active live injection while keeping qrels/doc ids out of selection.
 */
export function admitActiveLiveEvalEvents(
  pack: QueryPack,
  corpus: ProductionCorpus,
  opts: ActiveLiveEvalPackOptions,
): { pack: QueryPack; added: number; liveEvalInPack: number; familyCounts: Record<string, number> } {
  if (!opts.limit || opts.limit <= 0) return { pack, added: 0, liveEvalInPack: 0, familyCounts: {} };
  const existing = new Set(pack.events.map((e) => e.id));
  const activeIds = opts.activeIds;
  const disabledFamilies = new Set([
    ...(opts.profile?.disabledFamilies ?? []),
    ...(opts.profile?.disabledSubstrateSurfaces ?? []),
    ...(opts.disabledFamilies ?? []),
  ]);
  const isActiveLiveEval = (e: ProductionCorpusEvent): boolean => activeIds.has(e.id)
    && e.split === 'eval_hidden'
    && e.id.startsWith('zz_e')
    && !e.id.includes('_mem_')
    && !disabledFamilies.has(((e as ProductionCorpusEvent & { logicalFamily?: string }).logicalFamily ?? e.family ?? 'unknown'));
  const priority = new Map((opts.familyPriority ?? []).map((f, i) => [f, i] as const));
  const familyOf = (e: ProductionCorpusEvent): string => (e as ProductionCorpusEvent & { logicalFamily?: string }).logicalFamily ?? e.family ?? 'unknown';
  const byFamily = new Map<string, ProductionCorpusEvent[]>();
  for (const e of corpus.events) {
    if (!isActiveLiveEval(e) || existing.has(e.id)) continue;
    const fam = familyOf(e);
    const rows = byFamily.get(fam) ?? [];
    rows.push(e);
    byFamily.set(fam, rows);
  }
  for (const rows of byFamily.values()) {
    rows.sort((a, b) => {
      const ea = liveEpochFromEventId(a.id);
      const eb = liveEpochFromEventId(b.id);
      if (ea !== eb) return eb - ea;
      return codePointCompare(a.id, b.id);
    });
  }
  const familyOrder = [...byFamily.keys()].sort((a, b) => {
    const pa = priority.get(a) ?? 999;
    const pb = priority.get(b) ?? 999;
    if (pa !== pb) return pa - pb;
    return codePointCompare(a, b);
  });
  const live: ProductionCorpusEvent[] = [];
  const dedupePublicIntent = opts.dedupePublicIntent !== false;
  const usedPublicIntentKeys = new Set<string>();
  const deferredByFamily = new Map<string, ProductionCorpusEvent[]>();
  const takeUnique = (fam: string): ProductionCorpusEvent | undefined => {
    const rows = byFamily.get(fam);
    while (rows?.length) {
      const next = rows.shift();
      if (!next) return undefined;
      const key = dedupePublicIntent ? stablePublicIntentKey(next) : null;
      if (!key || !usedPublicIntentKeys.has(key)) {
        if (key) usedPublicIntentKeys.add(key);
        return next;
      }
      const deferred = deferredByFamily.get(fam) ?? [];
      deferred.push(next);
      deferredByFamily.set(fam, deferred);
    }
    return undefined;
  };
  const takeDeferred = (fam: string): ProductionCorpusEvent | undefined => {
    const rows = deferredByFamily.get(fam);
    if (rows?.length) return rows.shift();
    return byFamily.get(fam)?.shift();
  };
  for (let advanced = true; live.length < opts.limit && advanced;) {
    advanced = false;
    for (const fam of familyOrder) {
      if (live.length >= opts.limit) break;
      const next = takeUnique(fam);
      if (!next) continue;
      live.push(next);
      advanced = true;
    }
  }
  for (let advanced = true; live.length < opts.limit && advanced;) {
    advanced = false;
    for (const fam of familyOrder) {
      if (live.length >= opts.limit) break;
      const next = takeDeferred(fam);
      if (!next) continue;
      live.push(next);
      advanced = true;
    }
  }
  const maxEvents = pack.events.length > 0 ? pack.events.length : opts.limit;
  const quotas = opts.quotas ?? opts.profile?.quotas ?? [];
  let finalEvents: readonly ProductionCorpusEvent[];
  if (quotas.length === 0) {
    finalEvents = live.length ? [...live, ...pack.events].slice(0, maxEvents) : pack.events;
  } else {
    finalEvents = quotaSafeLiveOverlay({
      baseEvents: pack.events,
      liveEvents: live,
      maxEvents,
      quotas,
      isActiveLiveEval,
    });
  }
  const added = finalEvents.filter((e) => isActiveLiveEval(e) && !existing.has(e.id)).length;
  const liveEvalInPack = finalEvents.filter(isActiveLiveEval).length;
  const familyCounts: Record<string, number> = {};
  for (const e of finalEvents) {
    if (!isActiveLiveEval(e)) continue;
    const fam = familyOf(e);
    familyCounts[fam] = (familyCounts[fam] ?? 0) + 1;
  }
  return {
    pack: { ...pack, events: finalEvents },
    added,
    liveEvalInPack,
    familyCounts,
  };
}

function quotasSatisfied(events: readonly ProductionCorpusEvent[], quotas: readonly PackQuota[]): boolean {
  return quotas.every((q) => events.filter((e) => eventSatisfiesStratum(e, q.stratum)).length >= q.minCount);
}

function quotaSafeLiveOverlay({
  baseEvents,
  liveEvents,
  maxEvents,
  quotas,
  isActiveLiveEval,
}: {
  readonly baseEvents: readonly ProductionCorpusEvent[];
  readonly liveEvents: readonly ProductionCorpusEvent[];
  readonly maxEvents: number;
  readonly quotas: readonly PackQuota[];
  readonly isActiveLiveEval: (event: ProductionCorpusEvent) => boolean;
}): readonly ProductionCorpusEvent[] {
  if (!quotasSatisfied(baseEvents, quotas)) {
    throw new Error('admitActiveLiveEvalEvents: base hidden pack does not satisfy quotas');
  }
  const finalEvents = [...baseEvents];
  const ids = new Set(finalEvents.map((e) => e.id));
  for (const candidate of liveEvents) {
    if (ids.has(candidate.id)) continue;
    if (finalEvents.length < maxEvents) {
      const trial = [candidate, ...finalEvents];
      if (!quotasSatisfied(trial, quotas)) continue;
      finalEvents.splice(0, 0, candidate);
      ids.add(candidate.id);
      continue;
    }
    let accepted = false;
    for (let i = finalEvents.length - 1; i >= 0; i--) {
      if (isActiveLiveEval(finalEvents[i]!)) continue;
      const trial = [candidate, ...finalEvents.slice(0, i), ...finalEvents.slice(i + 1)].slice(0, maxEvents);
      if (!quotasSatisfied(trial, quotas)) continue;
      ids.delete(finalEvents[i]!.id);
      finalEvents.splice(i, 1);
      finalEvents.splice(0, 0, candidate);
      ids.add(candidate.id);
      accepted = true;
      break;
    }
    if (accepted) continue;
  }
  return finalEvents;
}

function uint8ToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

/**
 * Verify a published pack against the deterministic recomputation.
 */
export function verifyQueryPack(
  pack: QueryPack,
  corpus: ProductionCorpus,
  profile: HiddenPackProfile,
  activeLiveEval?: ActiveLiveEvalPackOptions,
): { ok: true } | { ok: false; reason: string } {
  if (pack.corpusRoot.toLowerCase() !== corpus.corpusRoot.toLowerCase()) {
    return { ok: false, reason: 'corpusRoot mismatch' };
  }
  let recomputed: QueryPack;
  try {
    recomputed = deriveQueryPack(pack.epochId, pack.evalSeedHex, corpus, profile);
    if (activeLiveEval) {
      recomputed = admitActiveLiveEvalEvents(recomputed, corpus, { ...activeLiveEval, profile }).pack;
    }
  } catch (err) {
    return { ok: false, reason: `deriveQueryPack failed: ${(err as Error).message}` };
  }
  if (recomputed.events.length !== pack.events.length) {
    return { ok: false, reason: `pack length mismatch: ${pack.events.length} vs ${recomputed.events.length}` };
  }
  for (let i = 0; i < pack.events.length; i++) {
    if (recomputed.events[i]!.id !== pack.events[i]!.id) {
      return { ok: false, reason: `pack[${i}] id mismatch` };
    }
  }
  return { ok: true };
}

export function packQuotaCoverage(
  pack: QueryPack,
  profile: HiddenPackProfile,
): readonly { readonly stratum: string; readonly count: number; readonly minCount: number; readonly satisfied: boolean }[] {
  return profile.quotas.map((q) => {
    const count = pack.events.filter((e) => eventSatisfiesStratum(e, q.stratum)).length;
    return { stratum: q.stratum, count, minCount: q.minCount, satisfied: count >= q.minCount };
  });
}

export type PerFamilyCount = Partial<Record<ProductionCorpusFamily, number>>;

export function packFamilyCounts(pack: QueryPack): PerFamilyCount {
  const counts: PerFamilyCount = {};
  for (const e of pack.events) {
    counts[e.family] = (counts[e.family] ?? 0) + 1;
  }
  return counts;
}

export function hiddenPackEventEligible(event: ProductionCorpusEvent, profile: HiddenPackProfile): boolean {
  if (event.split !== 'eval_hidden') return false;
  const family = (event as ProductionCorpusEvent & { logicalFamily?: string }).logicalFamily ?? event.family ?? 'unknown';
  const disabled = new Set([...(profile.disabledFamilies ?? []), ...(profile.disabledSubstrateSurfaces ?? [])]);
  return !disabled.has(family);
}
