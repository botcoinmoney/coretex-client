/**
 * CoreTex V4 difficulty calculator.
 *
 * Adjusts the minImprovementPpm threshold for the next epoch based on how
 * many STATE_ADVANCE receipts were accepted and how many elevated (non-bogus)
 * quality attempts were observed in the completed epoch.
 *
 * All ppm values entering/leaving this module are bigint. Ratios are computed
 * as floating-point intermediates and then rounded back to bigint.
 */

export const MIN_IMPROVEMENT_PPM = 2_500n;
export const MAX_IMPROVEMENT_PPM = 150_000n;

export interface DifficultyInputs {
  /** Current minImprovementPpm value (bigint, in ppm). */
  readonly current: bigint;
  /** Number of accepted STATE_ADVANCE receipts in the epoch. */
  readonly observedAdvances: number;
  /** Configured target number of advances per epoch. */
  readonly targetAdvances: number;
  /** Number of elevated (non-bogus) quality attempts in the epoch. */
  readonly qualityAttempts: number;
  /**
   * Threshold above which qualityAttempts is considered "high".
   * Default: 4 * targetAdvances.
   */
  readonly qualityHighThreshold?: number;
  /**
   * Maximum multiplier applied when ramping up.
   * Default: 1.5.
   */
  readonly rampUpMaxRatio?: number;
  /**
   * Multiplier applied when decaying (0 advances AND many quality attempts).
   * Default: 0.85.
   */
  readonly decayRatio?: number;
  /**
   * Multiplier applied for a slow upward drift (some advances but below
   * target, and quality attempts > 0).
   * Default: 1.05.
   */
  readonly smallDriftRatio?: number;
}

export interface DifficultyOutput {
  /** Resulting minImprovementPpm, clamped to [MIN_IMPROVEMENT_PPM, MAX_IMPROVEMENT_PPM]. */
  readonly next: bigint;
  /** Reason code explaining which branch was taken. */
  readonly reason: 'ramp_up' | 'decay' | 'no_change' | 'small_drift_up' | 'small_drift_down';
  /** The ratio that was applied (1.0 = no change). */
  readonly ratioApplied: number;
  /** True if the unclamped next value was outside [MIN, MAX] and was clamped. */
  readonly clamped: boolean;
}

/**
 * Compute the next-epoch minImprovementPpm from epoch observations.
 */
export function nextMinImprovementPpm(inputs: DifficultyInputs): DifficultyOutput {
  const {
    current,
    observedAdvances,
    targetAdvances,
    qualityAttempts,
  } = inputs;

  const rampUpMaxRatio = inputs.rampUpMaxRatio ?? 1.5;
  const decayRatio = inputs.decayRatio ?? 0.85;
  const smallDriftRatio = inputs.smallDriftRatio ?? 1.05;
  const qualityHighThreshold = inputs.qualityHighThreshold ?? 4 * targetAdvances;

  let ratio: number;
  let reason: DifficultyOutput['reason'];

  if (targetAdvances <= 0) {
    // Guard: no meaningful target — leave unchanged.
    ratio = 1.0;
    reason = 'no_change';
  } else if (observedAdvances > targetAdvances) {
    // More advances than expected — raise difficulty.
    const raw = observedAdvances / targetAdvances;
    const bounded = Math.min(Math.max(raw, 1.0), rampUpMaxRatio);
    ratio = bounded;
    reason = 'ramp_up';
  } else if (observedAdvances === 0 && qualityAttempts >= qualityHighThreshold) {
    // No advances but lots of quality tries — miners are working hard and
    // close; make it easier to succeed by decaying the threshold.
    ratio = decayRatio;
    reason = 'decay';
  } else if (observedAdvances === 0 && qualityAttempts === 0) {
    // Nothing happening at all — drift down toward floor to attract miners.
    ratio = 0.95;
    reason = 'small_drift_down';
  } else if (observedAdvances < targetAdvances && qualityAttempts > 0) {
    // Some activity but below target — nudge difficulty up slowly.
    ratio = smallDriftRatio;
    reason = 'small_drift_up';
  } else {
    // Exactly at target (or no quality signal): leave unchanged.
    ratio = 1.0;
    reason = 'no_change';
  }

  const unclamped = BigInt(Math.round(Number(current) * ratio));
  const next = clampPpm(unclamped);
  const clamped = unclamped < MIN_IMPROVEMENT_PPM || unclamped > MAX_IMPROVEMENT_PPM;

  return { next, reason, ratioApplied: ratio, clamped };
}

// ---------------------------------------------------------------------------
// Histogram utility
// ---------------------------------------------------------------------------

export interface DifficultyHistogramEntry {
  readonly epoch: number;
  readonly current: bigint;
  readonly next: bigint;
  readonly reason: string;
}

export interface DifficultyHistogram {
  readonly byEpoch: DifficultyHistogramEntry[];
  readonly rampUps: number;
  readonly decays: number;
  readonly clampHits: number;
}

/**
 * Run the difficulty calculator over a sequence of epoch snapshots and return
 * a summary useful for calibration sweeps.
 *
 * Each snapshot must contain all DifficultyInputs fields plus an `epoch`
 * number.  The snapshots are processed in array order; `current` comes from
 * each snapshot as-is (callers can chain by passing the previous `next` as the
 * next `current` if desired).
 */
export function difficultyHistogram(
  snapshots: ReadonlyArray<DifficultyInputs & { readonly epoch: number }>,
): DifficultyHistogram {
  let rampUps = 0;
  let decays = 0;
  let clampHits = 0;
  const byEpoch: DifficultyHistogramEntry[] = [];

  for (const snapshot of snapshots) {
    const { epoch, ...inputs } = snapshot;
    const output = nextMinImprovementPpm(inputs);
    byEpoch.push({ epoch, current: inputs.current, next: output.next, reason: output.reason });
    if (output.reason === 'ramp_up') rampUps++;
    if (output.reason === 'decay') decays++;
    if (output.clamped) clampHits++;
  }

  return { byEpoch, rampUps, decays, clampHits };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function clampPpm(value: bigint): bigint {
  if (value < MIN_IMPROVEMENT_PPM) return MIN_IMPROVEMENT_PPM;
  if (value > MAX_IMPROVEMENT_PPM) return MAX_IMPROVEMENT_PPM;
  return value;
}
