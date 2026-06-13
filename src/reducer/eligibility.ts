/**
 * Eligibility tracking for Cortex credit issuance.
 *
 * Enforces the no-double-credit invariant:
 *   For any (epoch, miner, patchHash):
 *     - StateAdvance/ScreenerPassed: exactly one tier-credit issuance
 *     - PatchMerged: at most one previous accrual record
 *
 * This module models the coordinator's in-memory ledger used when
 * processing CortexStateAdvanced/CortexPatchAccepted and CortexEpochFinalized
 * events.
 * It is also used by the replay script (scripts/replay-reducer.mjs).
 */

// ── Event types ───────────────────────────────────────────────────────────────

/** Models a ScreenerPassed event: miner submitted a passing patch. */
export interface ScreenerPassedEvent {
  readonly epoch: bigint;
  readonly miner: string; // lowercase hex address
  readonly patchHash: string; // 0x-prefixed hex
}

/** Models a PatchMerged event: patch was accepted by the reducer. */
export interface PatchMergedEvent {
  readonly epoch: bigint;
  readonly miner: string; // lowercase hex address
  readonly patchHash: string; // 0x-prefixed hex
}

/** A record of a single credit issuance. */
export interface CreditIssuance {
  readonly epoch: bigint;
  readonly miner: string;
  readonly patchHash: string;
  /** Tier credits issued (from BotcoinMiningV3.getTier()). */
  readonly tierCredits: bigint;
}

/** A record of a previous merge accrual. */
export interface MultiplierAccrual {
  readonly epoch: bigint;
  readonly miner: string;
  readonly patchHash: string;
}

/** Eligibility ledger result for an epoch. */
export interface EpochEligibility {
  /** All credit issuances for this epoch (one per verified state advance). */
  readonly creditIssuances: CreditIssuance[];
  /**
   * All previous merge accruals for this epoch.
   * production launch sets the separate uplift to zero; this is retained so
   * historical/previous proof paths stay replayable.
   */
  readonly multiplierAccruals: MultiplierAccrual[];
  /**
   * Patches that were skipped (duplicate ScreenerPassed or duplicate merger).
   * Included for audit trail.
   */
  readonly duplicatesSkipped: { event: 'screener' | 'merger'; epoch: bigint; miner: string; patchHash: string }[];
}

// ── Ledger ────────────────────────────────────────────────────────────────────

/**
 * Build the eligibility ledger for an epoch from its event stream.
 *
 * Rules:
 *   1. For each unique (epoch, miner, patchHash) in StateAdvance/ScreenerPassed events,
 *      issue exactly one tier-credit.
 *   2. For each PatchMerged event whose (epoch, miner, patchHash) is also
 *      in the credit-issued set, record a previous accrual.
 *   3. Duplicate ScreenerPassed events (same tuple) are silently skipped
 *      and logged in duplicatesSkipped.
 *   4. PatchMerged events without a corresponding ScreenerPassed are skipped
 *      (cannot merge without screening — indicates data integrity issue).
 *
 * @param screenerEvents  - ScreenerPassed events for the epoch (any order)
 * @param mergedEvents    - PatchMerged events for the epoch (any order)
 * @param tierCreditsFor  - Callback to look up tier credits for a miner
 */
export function buildEpochEligibility(
  screenerEvents: ScreenerPassedEvent[],
  mergedEvents: PatchMergedEvent[],
  tierCreditsFor: (miner: string) => bigint,
): EpochEligibility {
  const seenScreener = new Set<string>(); // "epoch:miner:patchHash"
  const seenMerger = new Set<string>();

  const creditIssuances: CreditIssuance[] = [];
  const multiplierAccruals: MultiplierAccrual[] = [];
  const duplicatesSkipped: EpochEligibility['duplicatesSkipped'] = [];

  // Process screener-pass events
  for (const ev of screenerEvents) {
    const key = eligibilityKey(ev.epoch, ev.miner, ev.patchHash);
    if (seenScreener.has(key)) {
      duplicatesSkipped.push({ event: 'screener', epoch: ev.epoch, miner: ev.miner, patchHash: ev.patchHash });
      continue;
    }
    seenScreener.add(key);
    creditIssuances.push({
      epoch: ev.epoch,
      miner: ev.miner,
      patchHash: ev.patchHash,
      tierCredits: tierCreditsFor(ev.miner),
    });
  }

  // Process merger events
  for (const ev of mergedEvents) {
    const key = eligibilityKey(ev.epoch, ev.miner, ev.patchHash);

    // Must have passed screener first
    if (!seenScreener.has(key)) {
      // PatchMerged without ScreenerPassed — data integrity issue; skip
      duplicatesSkipped.push({ event: 'merger', epoch: ev.epoch, miner: ev.miner, patchHash: ev.patchHash });
      continue;
    }
    if (seenMerger.has(key)) {
      duplicatesSkipped.push({ event: 'merger', epoch: ev.epoch, miner: ev.miner, patchHash: ev.patchHash });
      continue;
    }
    seenMerger.add(key);
    multiplierAccruals.push({
      epoch: ev.epoch,
      miner: ev.miner,
      patchHash: ev.patchHash,
    });
  }

  return { creditIssuances, multiplierAccruals, duplicatesSkipped };
}

/** Canonical key for deduplication. */
function eligibilityKey(epoch: bigint, miner: string, patchHash: string): string {
  return `${epoch.toString()}:${miner.toLowerCase()}:${patchHash.toLowerCase()}`;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Count total tier credits earned by a miner in an epoch.
 * production launch credits are attached to verified state advances; screener-only
 * candidates do not receive credits.
 */
export function minerScreenerCredits(
  eligibility: EpochEligibility,
  miner: string,
): bigint {
  const m = miner.toLowerCase();
  let total = 0n;
  for (const ci of eligibility.creditIssuances) {
    if (ci.miner.toLowerCase() === m) {
      total += ci.tierCredits;
    }
  }
  return total;
}

/**
 * Returns true iff the miner has at least one previous merge accrual in this
 * epoch. The default CoreTex uplift is zero; use this as an audit helper only.
 */
export function minerHasMerge(eligibility: EpochEligibility, miner: string): boolean {
  const m = miner.toLowerCase();
  return eligibility.multiplierAccruals.some((a) => a.miner.toLowerCase() === m);
}
