/**
 * Stale merge-bonus calculation for CortexMergeBonus funding.
 *
 * Per reducer.md §Credit mechanics:
 *   MERGE_MULTIPLIER_BPS = 10000 (1.0×, no separate uplift)
 *   current cap: (MERGE_MULTIPLIER_BPS − 10000) × claimBase / 10000 per miner per epoch.
 *   State-advance credits are paid through normal epoch accounting instead.
 *
 * The cap is retained for compatibility with the stale CoreTexMergeBonus
 * contract, but production launch should not fund zero-uplift epochs.
 */

import type { EpochEligibility } from './eligibility.js';

// ── Constants ─────────────────────────────────────────────────────────────────

/** Default merge multiplier in basis points (1.0× = no separate uplift). */
export const MERGE_MULTIPLIER_BPS = 10_000n;
export const BPS_DIVISOR = 10_000n;

// ── Types ─────────────────────────────────────────────────────────────────────

/** Per-miner merge bonus leaf for the CortexMergeBonus Merkle tree. */
export interface MinerBonusLeaf {
  readonly miner: string;
  /** BOTCOIN bonus amount (in wei-equivalent units). */
  readonly bonusBotcoin: bigint;
  /**
   * Cap amount for on-chain enforcement.
   * bonusBotcoin MUST be ≤ capBotcoin.
   * capBotcoin = (MERGE_MULTIPLIER_BPS − 10000) × claimBase / 10000
   */
  readonly capBotcoin: bigint;
}

/** Input for a miner's claim base in an epoch. */
export interface MinerClaimBase {
  readonly miner: string;
  /**
   * The miner's pro-rata share of the epoch reward across both lanes.
   * claimBaseForMerger(epoch, miner) = epochReward × minerCredits / totalCredits
   * In BOTCOIN units (bigint).
   */
  readonly claimBase: bigint;
}

// ── Cap calculation ───────────────────────────────────────────────────────────

/**
 * Compute the bonus BOTCOIN for a single miner in an epoch.
 *
 * bonusBotcoin = (MERGE_MULTIPLIER_BPS − 10000) × claimBase / 10000
 *
 * The cap equals the bonus (they are the same in CoreTex — the bonus IS the max).
 * On-chain: CortexMergeBonus checks payout ≤ capBotcoin from the Merkle leaf.
 *
 * Returns 0n for miners with no merge accrual.
 */
export function computeMinerBonus(
  miner: string,
  claimBase: bigint,
  multiplierBps: bigint = MERGE_MULTIPLIER_BPS,
): MinerBonusLeaf {
  if (claimBase < 0n) {
    throw new RangeError(`computeMinerBonus: claimBase must be non-negative, got ${claimBase}`);
  }
  // bonus = (multiplierBps - 10000) * claimBase / 10000
  const upliftBps = multiplierBps - BPS_DIVISOR;
  const bonusBotcoin = (upliftBps * claimBase) / BPS_DIVISOR;
  return {
    miner: miner.toLowerCase(),
    bonusBotcoin,
    capBotcoin: bonusBotcoin, // cap = bonus in CoreTex (single-uplift)
  };
}

/**
 * Build the full set of MinerBonusLeaf entries for an epoch.
 *
 * Only miners with at least one merged patch and non-zero computed uplift get a
 * leaf. With the default 1.0× setting this intentionally returns no leaves.
 *
 * @param eligibility     - Eligibility ledger for the epoch
 * @param claimBases      - Per-miner claim bases (pro-rata epoch reward)
 * @param multiplierBps   - Multiplier in basis points (default 10000)
 */
export function buildEpochBonusLeaves(
  eligibility: EpochEligibility,
  claimBases: MinerClaimBase[],
  multiplierBps: bigint = MERGE_MULTIPLIER_BPS,
): MinerBonusLeaf[] {
  // Build lookup: miner → claimBase
  const claimBaseMap = new Map<string, bigint>();
  for (const cb of claimBases) {
    claimBaseMap.set(cb.miner.toLowerCase(), cb.claimBase);
  }

  // Deduplicate: one leaf per miner (single-uplift cap)
  const seenMiners = new Set<string>();
  const leaves: MinerBonusLeaf[] = [];

  for (const accrual of eligibility.multiplierAccruals) {
    const miner = accrual.miner.toLowerCase();
    if (seenMiners.has(miner)) {
      // Already have a leaf for this miner — single-uplift cap, skip
      continue;
    }
    seenMiners.add(miner);

    const claimBase = claimBaseMap.get(miner) ?? 0n;
    if (claimBase === 0n) {
      // Miner has no claim base — no bonus to pay
      continue;
    }

    const leaf = computeMinerBonus(miner, claimBase, multiplierBps);
    if (leaf.bonusBotcoin === 0n) {
      continue;
    }
    leaves.push(leaf);
  }

  // Sort by miner address for deterministic ordering
  leaves.sort((a, b) => a.miner.localeCompare(b.miner));

  return leaves;
}

/**
 * Compute the total BOTCOIN required to fund an epoch's merge bonuses.
 * This is the value passed to CortexMergeBonus.fundEpoch(epoch, root, totalBonus).
 */
export function computeEpochTotalBonus(leaves: MinerBonusLeaf[]): bigint {
  return leaves.reduce((sum, leaf) => sum + leaf.bonusBotcoin, 0n);
}

/**
 * Verify that a proposed bonus does not exceed the cap.
 * Used both off-chain (coordinator) and as a mirror of the on-chain check.
 */
export function assertBonusWithinCap(leaf: MinerBonusLeaf): void {
  if (leaf.bonusBotcoin > leaf.capBotcoin) {
    throw new Error(
      `multiplier cap violation: miner=${leaf.miner} bonus=${leaf.bonusBotcoin} cap=${leaf.capBotcoin}`,
    );
  }
}
