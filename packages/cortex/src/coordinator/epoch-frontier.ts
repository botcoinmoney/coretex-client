// EpochFrontier — deterministic rotating active-eval_hidden frontier (launch C3 churn controller).
//
// CANONICAL launch implementation. The launch coordinator derives the on-chain `activeFrontierRoot`
// from `profile.epochFrontier` + the production corpus via `makeLaunchFrontier(...).stepEpoch(...)`.
// (CoreTexRegistry/V4 reject bytes32(0), so the challenge/receipt/registry context MUST carry a real
// non-zero root.) This used to live only in scripts/lib/epoch-frontier.mjs — a non-shipped script lib;
// it is now part of packages/cortex so the production path (not just calibration harnesses) derives it.
//
// HONESTY INVARIANTS (by construction): AGGREGATE-ONLY churn (reads epoch-aggregate prevHonestAccepts,
// never per-query solved/failed); retirement by AGE (oldest activation cohort) + deterministic tie-break;
// precommitted seeded stratum-balanced reserve order; mode 'off' is a strict no-op. Every per-epoch root
// is deterministically reproducible from (seed, evalHiddenIds, familyOf, mode, params, prevHonestAccepts).

import { createHash } from 'node:crypto';

const h12 = (s: string): number => parseInt(createHash('sha256').update(s).digest('hex').slice(0, 12), 16);
// bytes32 root: full 32-byte sha256 (0x + 64 hex) — a short prefix would mis-encode on-chain and desync replay.
const rootHash = (ids: Iterable<string>): string => '0x' + createHash('sha256').update([...ids].sort().join('|')).digest('hex');

export type EpochFrontierMode = 'off' | 'C0' | 'C1' | 'C2' | 'C3' | 'C4';

// Optional fields are `T | undefined` (not just `T?`) so callers under exactOptionalPropertyTypes
// may pass an absent/undefined profile field through; the destructuring defaults below apply at runtime.
export interface EpochFrontierParams {
  evalHiddenIds: string[];
  familyOf: (id: string) => string;
  mode?: EpochFrontierMode | undefined;
  activeWindow?: number | undefined;
  churnRate?: number | undefined;
  maxAge?: number | undefined;
  lowAdvancesThreshold?: number | undefined;
  lowAdvancesBumpRate?: number | undefined;
  seed?: string | undefined;
  minChurn?: number | undefined;
  maxChurn?: number | undefined;
  targetAccepts?: number | undefined;
  headroomLowWatermark?: number | undefined;
  headroomHighWatermark?: number | undefined;
  ewmaHalfLife?: number | undefined;
  expectedYieldPerUnit?: number | undefined;
  maxRootDeltaPerEpoch?: number | undefined;
}

export interface EpochFrontierSnapshot {
  epochId: number;
  activationSeed: string;
  activeEvalHiddenCount: number;
  activated: number;
  retired: number;
  churnRate: number;
  reserveRemaining: number;
  cumulativeActivated: number;
  cumulativeRetired: number;
  activeIds: Set<string>;
  activeRoot: string;
  reserveRoot: string;
  retiredRoot: string;
}

export function makeEpochFrontier({
  evalHiddenIds, familyOf, mode = 'off', activeWindow, churnRate = 4,
  maxAge = Infinity, lowAdvancesThreshold = 1, lowAdvancesBumpRate, seed = 'frontier',
  minChurn = 2, maxChurn = 12, targetAccepts = 2, headroomLowWatermark = 1, headroomHighWatermark = 3,
  ewmaHalfLife = 3, expectedYieldPerUnit = 0.17, maxRootDeltaPerEpoch = 24,
}: EpochFrontierParams) {
  const groups = new Map<string, string[]>();
  for (const id of evalHiddenIds) {
    const f = familyOf(id) ?? 'unknown';
    if (!groups.has(f)) groups.set(f, []);
    groups.get(f)!.push(id);
  }
  for (const arr of groups.values()) arr.sort((a, b) => (h12(`${seed}:${a}`) - h12(`${seed}:${b}`)) || (a < b ? -1 : 1));
  const famNames = [...groups.keys()].sort();
  const order: string[] = [];
  for (let i = 0; ; i++) {
    let any = false;
    for (const f of famNames) { const arr = groups.get(f)!; if (i < arr.length) { order.push(arr[i]!); any = true; } }
    if (!any) break;
  }
  const orderIdx = new Map(order.map((id, i) => [id, i] as const));
  const K = Math.min(activeWindow ?? order.length, order.length);

  let reservePtr = 0;
  const active = new Map<string, number>();
  const retired = new Set<string>();
  let cumulativeActivated = 0, cumulativeRetired = 0, initialized = false;
  let injectedSinceLastStep = 0;
  let ewmaAccepts: number | null = null;
  const ewmaAlpha = 1 - Math.pow(0.5, 1 / Math.max(0.5, ewmaHalfLife));

  const activateNext = (n: number, epoch: number): number => {
    let a = 0;
    while (a < n && reservePtr < order.length) {
      const id = order[reservePtr++]!;
      if (!active.has(id) && !retired.has(id)) { active.set(id, epoch); a++; cumulativeActivated++; }
    }
    return a;
  };
  const retireOldest = (n: number): number => {
    const sorted = [...active.entries()].sort((x, y) => (x[1] - y[1]) || (orderIdx.get(x[0])! - orderIdx.get(y[0])!));
    let r = 0;
    for (let j = 0; j < n && j < sorted.length; j++) { const id = sorted[j]![0]; active.delete(id); retired.add(id); cumulativeRetired++; r++; }
    return r;
  };
  const snapshot = (epoch: number, activated: number, ret: number, rate: number): EpochFrontierSnapshot => ({
    epochId: epoch, activationSeed: seed, activeEvalHiddenCount: active.size,
    activated, retired: ret, churnRate: rate ?? 0, reserveRemaining: order.length - reservePtr,
    cumulativeActivated, cumulativeRetired,
    activeIds: new Set(active.keys()),
    activeRoot: rootHash(active.keys()), reserveRoot: rootHash(order.slice(reservePtr)), retiredRoot: rootHash(retired),
  });

  function stepEpoch(epoch: number, prevHonestAccepts: number | null, prevQualityAttempts: number | null = null): EpochFrontierSnapshot {
    if (!initialized) { initialized = true; const a = activateNext(K, epoch); injectedSinceLastStep = 0; return snapshot(epoch, a, 0, 0); }
    let ret = 0;
    if (Number.isFinite(maxAge)) {
      const aged = [...active.entries()].filter(([, ae]) => epoch - ae >= maxAge).map(([id]) => id);
      for (const id of aged) { active.delete(id); retired.add(id); cumulativeRetired++; ret++; }
    }
    if (mode === 'off' || mode === 'C0') {
      const a = activateNext(ret, epoch);
      injectedSinceLastStep = 0;
      return snapshot(epoch, a, ret, 0);
    }
    if (prevHonestAccepts !== null) ewmaAccepts = (ewmaAccepts === null) ? prevHonestAccepts : ewmaAlpha * prevHonestAccepts + (1 - ewmaAlpha) * ewmaAccepts;
    let rate: number;
    if (mode === 'C1') {
      rate = churnRate;
    } else if (mode === 'C2') {
      rate = (prevHonestAccepts !== null && prevHonestAccepts < lowAdvancesThreshold) ? (lowAdvancesBumpRate ?? (churnRate * 2)) : churnRate;
    } else if (mode === 'C4') {
      rate = minChurn;
    } else if (mode === 'C3' && prevQualityAttempts === 0) {
      rate = injectedSinceLastStep > 0 ? Math.min(maxChurn, Math.max(minChurn, injectedSinceLastStep)) : 0;
    } else {
      const recent = ewmaAccepts ?? targetAccepts;
      const deficit = targetAccepts - recent;
      if (recent <= headroomLowWatermark) {
        rate = Math.min(maxChurn, Math.max(minChurn, Math.ceil(Math.max(0, deficit) / Math.max(1e-6, expectedYieldPerUnit))));
      } else if (recent >= headroomHighWatermark) {
        rate = 0;
      } else {
        rate = minChurn;
      }
    }
    rate = Math.min(rate, maxRootDeltaPerEpoch);
    rate = Math.min(rate, Math.max(0, order.length - reservePtr));
    ret += retireOldest(rate);
    const a = activateNext(ret, epoch);
    injectedSinceLastStep = 0;
    return snapshot(epoch, a, ret, rate);
  }

  /**
   * Inject NEW eval_hidden ids into the reserve, preserving every prior rotation invariant
   * (active set, retired set, reservePtr, cumulative counters). The new ids are spliced
   * INTO order at the current reservePtr position so the next activateNext drains them
   * BEFORE the remaining genesis reserve — live-update churn gets exercised even when the
   * genesis reserve is still draining.
   *
   * Determinism: the new segment is family-interleaved + seed-sorted within family, using
   * the same h12(seed:id) ordering as the genesis order, so two calls with the same
   * (seed, ids, familyOfFn) produce byte-identical state.
   *
   * Ids already in active, retired, or order are skipped (idempotent). Returns the count
   * of NEW ids actually added.
   */
  function addReserveIds(newIds: readonly string[], familyOfFn: (id: string) => string): number {
    const unseen = newIds.filter((id) => !active.has(id) && !retired.has(id) && !orderIdx.has(id));
    if (unseen.length === 0) return 0;
    const newByFam = new Map<string, string[]>();
    for (const id of unseen) {
      const f = familyOfFn(id) ?? 'unknown';
      if (!newByFam.has(f)) newByFam.set(f, []);
      newByFam.get(f)!.push(id);
    }
    for (const arr of newByFam.values()) arr.sort((a, b) => (h12(`${seed}:${a}`) - h12(`${seed}:${b}`)) || (a < b ? -1 : 1));
    const newFamNames = [...newByFam.keys()].sort();
    const newOrderSegment: string[] = [];
    for (let i = 0; ; i++) {
      let any = false;
      for (const f of newFamNames) { const arr = newByFam.get(f)!; if (i < arr.length) { newOrderSegment.push(arr[i]!); any = true; } }
      if (!any) break;
    }
    order.splice(reservePtr, 0, ...newOrderSegment);
    injectedSinceLastStep += unseen.length;
    orderIdx.clear();
    for (let i = 0; i < order.length; i++) orderIdx.set(order[i]!, i);
    for (const f of newFamNames) if (!famNames.includes(f)) famNames.push(f);
    famNames.sort();
    for (const [f, ids] of newByFam) {
      if (!groups.has(f)) groups.set(f, []);
      for (const id of ids) groups.get(f)!.push(id);
    }
    return unseen.length;
  }

  // totalUnits is a LIVE getter — addReserveIds mutates `order` post-construction, so a
  // snapshot literal would go stale. Callers that read frontier.totalUnits get the current
  // length, not the genesis-time count.
  return { stepEpoch, addReserveIds, order, orderIdx, K, get totalUnits() { return order.length; }, familyOrder: famNames };
}

interface CorpusEventLike { readonly id: string; readonly split?: string; readonly logicalFamily?: string; readonly family?: string }
interface CorpusLike { readonly events: ReadonlyArray<CorpusEventLike> }
interface ProfileWithFrontier { readonly epochFrontier?: ({ mode?: EpochFrontierMode } & Partial<EpochFrontierParams>) | null }

/**
 * Build a launch EpochFrontier from a signed profile's `epochFrontier` block + a production corpus.
 * Returns null only when churn is off/absent. The launch coordinator MUST derive the genesis
 * activeFrontierRoot via `makeLaunchFrontier(profile, corpus).stepEpoch(0, null, null).activeRoot`.
 */
export function makeLaunchFrontier(profile: ProfileWithFrontier, corpus: CorpusLike): ReturnType<typeof makeEpochFrontier> | null {
  const fp = profile?.epochFrontier;
  if (!fp || fp.mode === 'off') return null;
  const evalHidden = corpus.events.filter((e) => e.split === 'eval_hidden');
  const evalHiddenIds = evalHidden.map((e) => e.id);
  const famById = new Map(evalHidden.map((e) => [e.id, e.logicalFamily ?? e.family ?? 'unknown']));
  const familyOf = (id: string): string => famById.get(id) ?? 'unknown';
  return makeEpochFrontier({
    evalHiddenIds, familyOf, mode: fp.mode, activeWindow: fp.activeWindow, minChurn: fp.minChurn,
    maxChurn: fp.maxChurn, headroomLowWatermark: fp.headroomLowWatermark, headroomHighWatermark: fp.headroomHighWatermark,
    ewmaHalfLife: fp.ewmaHalfLife, targetAccepts: fp.targetAccepts, expectedYieldPerUnit: fp.expectedYieldPerUnit,
    maxRootDeltaPerEpoch: fp.maxRootDeltaPerEpoch, maxAge: fp.maxAge ?? Infinity, seed: fp.seed,
  });
}

export const DEFAULT_EPOCH_FRONTIER_PROFILE = {
  mode: 'C3' as EpochFrontierMode,
  activeWindow: 96,
  minChurn: 2,
  maxChurn: 12,
  headroomLowWatermark: 1,
  headroomHighWatermark: 3,
  ewmaHalfLife: 3,
  targetAccepts: 2,
  expectedYieldPerUnit: 0.17,
  maxRootDeltaPerEpoch: 24,
  maxAge: Infinity,
  seed: 'frontier',
  baselineRecompute: 'activeRootChanged',
  majorDeltaPolicy: 'corpusRootChanged',
};
