/**
 * Multiplier-cap calculation for CortexMergeBonus funding.
 *
 * Per reducer_v0.md §Credit mechanics:
 *   MERGE_MULTIPLIER_BPS = 15000 (1.5×)
 *   V0 cap: (MERGE_MULTIPLIER_BPS − 10000) × claimBase / 10000 per miner per epoch.
 *   Single merge in an epoch is sufficient; additional merges grant no extra uplift.
 *
 * The cap is encoded into each Merkle leaf (capBOTCOIN field) for on-chain enforcement.
 */

import type { EpochEligibility } from './eligibility.js';

// ── Constants ─────────────────────────────────────────────────────────────────

/** Default merge multiplier in basis points (1.5× = 15000 bps). */
export const MERGE_MULTIPLIER_BPS = 15_000n;
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
 * The cap equals the bonus (they are the same in V0 — the bonus IS the max).
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
    capBotcoin: bonusBotcoin, // cap = bonus in V0 (single-uplift)
  };
}

/**
 * Build the full set of MinerBonusLeaf entries for an epoch.
 *
 * Only miners with at least one merged patch (multiplierAccrual) get a leaf.
 * The single-uplift cap means we compute ONE bonus per miner regardless of
 * how many patches they merged.
 *
 * @param eligibility     - Eligibility ledger for the epoch
 * @param claimBases      - Per-miner claim bases (pro-rata epoch reward)
 * @param multiplierBps   - Multiplier in basis points (default 15000)
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

    leaves.push(computeMinerBonus(miner, claimBase, multiplierBps));
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
