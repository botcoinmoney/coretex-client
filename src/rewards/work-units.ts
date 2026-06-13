/**
 * CoreTex V4 work-credit policy.
 *
 * This module is deliberately pure and dependency-light: it is the verifier
 * mirror of BotcoinMiningV4.submitWorkReceipt(). The contract enforces signer,
 * solve-chain, stake tier, lane/outcome bounds, and the active policy hash.
 * CoreTex nodes use this file to reproduce the workUnitsBps that the
 * coordinator signed for a screener pass or state advance.
 *
 * Open-sourcing the policy should not make passes trivial to grind because the
 * pass calculation is over the current live parent root and hidden shard. The
 * formula is public; the epoch-secret-derived shard and changing live state are
 * the anti-gaming pressure.
 */

import { bytesToHex } from '../state/merkle.js';
import { keccak256 } from '../state/keccak256.js';
import { canonicalJson } from '../canonical/json.js';

export const WORK_BPS_DIVISOR = 10_000n;
export const LANE_CORETEX = 2;
export const OUTCOME_CORETEX_SCREENER_PASS = 1;
export const OUTCOME_CORETEX_STATE_ADVANCE = 2;
export const CORTEX_RULES_VERSION = 0xC0;

export interface StateAdvanceWorkTier {
  readonly minQualifiedScreenerPassesSinceLastStateAdvance: string | bigint | number;
  readonly workUnitsBps: string | bigint | number;
}

export interface CoreTexWorkPolicy {
  readonly name: string;
  readonly version: number;
  readonly rulesVersion: number;
  readonly lane: number;
  readonly bpsDivisor: string | bigint | number;
  readonly screenerPass: {
    readonly outcome: number;
    readonly minLocalModelDeltaPpm: string | bigint | number;
    readonly maxRelevantNearCollisionPpm: string | bigint | number;
    readonly workUnitsBps: string | bigint | number;
    readonly calibration: {
      readonly scoreScalePpm: string | bigint | number;
      readonly minDeltaPpm: string | bigint | number;
      readonly remainingHeadroomBps: string | bigint | number;
      readonly noiseFloorMultiplierBps: string | bigint | number;
      readonly plateauEasingMaxBps: string | bigint | number;
      /**
       * Floor the screener threshold as a fraction of the real state-advance
       * acceptance threshold. This keeps screeners easier than advances while
       * preventing them from becoming cheap credit as baseline headroom shrinks.
       */
      readonly stateAdvanceThresholdFloorBps?: string | bigint | number;
      readonly antiGamingProbeMultiplierBps: string | bigint | number;
      readonly maxAntiGamingPenaltyBps: string | bigint | number;
      readonly maxThresholdPpm: string | bigint | number;
    };
  };
  readonly stateAdvance: {
    readonly outcome: number;
    readonly minDeterministicDeltaPpm: string | bigint | number;
    readonly minLocalModelDeltaPpm: string | bigint | number;
    readonly requireLiveStateAdvance: boolean;
    readonly difficultyCounter: 'qualifiedScreenerPassesSinceLastStateAdvance';
    readonly tiers: readonly StateAdvanceWorkTier[];
  };
  readonly antiGaming: {
    readonly currentParentStateRootRequired: boolean;
    readonly hiddenShardDerivedFromEpochSecret: boolean;
    readonly uniquePatchHashPerEpochMiner: boolean;
    readonly modelNoRegressionRequiredForStateAdvance: boolean;
  };
}

export const DEFAULT_CORETEX_WORK_POLICY: CoreTexWorkPolicy = Object.freeze({
  name: 'botcoin-coretex-work-policy',
  version: 3,
  rulesVersion: CORTEX_RULES_VERSION,
  lane: LANE_CORETEX,
  bpsDivisor: '10000',
  screenerPass: Object.freeze({
    outcome: OUTCOME_CORETEX_SCREENER_PASS,
    minLocalModelDeltaPpm: '0',
    maxRelevantNearCollisionPpm: '250000',
    workUnitsBps: '10000',
    calibration: Object.freeze({
      scoreScalePpm: '1000000',
      minDeltaPpm: '50',
      remainingHeadroomBps: '5',
      noiseFloorMultiplierBps: '20000',
      plateauEasingMaxBps: '5000',
      stateAdvanceThresholdFloorBps: '5000',
      antiGamingProbeMultiplierBps: '20000',
      maxAntiGamingPenaltyBps: '50000',
      maxThresholdPpm: '150000',
    }),
  }),
  stateAdvance: Object.freeze({
    outcome: OUTCOME_CORETEX_STATE_ADVANCE,
    minDeterministicDeltaPpm: '1',
    minLocalModelDeltaPpm: '0',
    requireLiveStateAdvance: true,
    difficultyCounter: 'qualifiedScreenerPassesSinceLastStateAdvance',
    tiers: Object.freeze([
      Object.freeze({ minQualifiedScreenerPassesSinceLastStateAdvance: '0', workUnitsBps: '30000' }),
      Object.freeze({ minQualifiedScreenerPassesSinceLastStateAdvance: '25', workUnitsBps: '40000' }),
      Object.freeze({ minQualifiedScreenerPassesSinceLastStateAdvance: '100', workUnitsBps: '60000' }),
      Object.freeze({ minQualifiedScreenerPassesSinceLastStateAdvance: '250', workUnitsBps: '90000' }),
      Object.freeze({ minQualifiedScreenerPassesSinceLastStateAdvance: '500', workUnitsBps: '120000' }),
    ]),
  }),
  antiGaming: Object.freeze({
    currentParentStateRootRequired: true,
    hiddenShardDerivedFromEpochSecret: true,
    uniquePatchHashPerEpochMiner: true,
    modelNoRegressionRequiredForStateAdvance: true,
  }),
});

export interface ComputeCoreTexWorkUnitsInput {
  readonly outcome: number;
  readonly qualifiedScreenerPassesSinceLastStateAdvance?: string | bigint | number;
  readonly policy?: CoreTexWorkPolicy;
}

export interface CoreTexWorkQualificationInput extends ComputeCoreTexWorkUnitsInput {
  readonly deterministicDeltaPpm: string | bigint | number;
  readonly baselineScorePpm?: string | bigint | number;
  readonly recentNoiseFloorPpm?: string | bigint | number;
  readonly recentScreenerPasses?: string | bigint | number;
  readonly recentStateAdvances?: string | bigint | number;
  readonly targetStateAdvances?: string | bigint | number;
  readonly recentProbePassRatePpm?: string | bigint | number;
  readonly stateAdvanceThresholdPpm?: string | bigint | number;
  readonly localModelDeltaPpm?: string | bigint | number;
  readonly relevantNearCollisionPpm?: string | bigint | number;
  readonly parentMatchesLiveRoot: boolean;
  readonly liveStateAdvanced?: boolean;
}

export interface CoreTexWorkQualification {
  readonly qualified: boolean;
  readonly reason: 'OK'
    | 'W01_UNKNOWN_OUTCOME'
    | 'W02_STALE_PARENT'
    | 'W03_DETERMINISTIC_DELTA_TOO_LOW'
    | 'W04_LOCAL_MODEL_REGRESSION'
    | 'W05_RELEVANT_NEAR_COLLISION'
    | 'W06_STATE_NOT_ADVANCED';
  readonly workUnitsBps: bigint;
  readonly requiredDeterministicDeltaPpm: bigint;
}

export interface ComputeCoreTexScreenerThresholdInput {
  readonly baselineScorePpm?: string | bigint | number;
  readonly recentNoiseFloorPpm?: string | bigint | number;
  /**
   * Accepted screener passes in the recent controller window. This is used only
   * as bounded plateau evidence, never as a direct reward shortcut.
   */
  readonly recentScreenerPasses?: string | bigint | number;
  /** Accepted state advances in the same recent controller window. */
  readonly recentStateAdvances?: string | bigint | number;
  /** Target state advances for the controller window. */
  readonly targetStateAdvances?: string | bigint | number;
  /**
   * Random/hillclimb/abuse-probe pass rate in ppm. Any nonzero probe pass rate
   * raises the threshold; clean probes leave the threshold unchanged.
   */
  readonly recentProbePassRatePpm?: string | bigint | number;
  /**
   * The real state-advance acceptance threshold in ppm:
   * minImprovementPpm + replayTolerancePpm + production baselineVariancePpm.
   */
  readonly stateAdvanceThresholdPpm?: string | bigint | number;
  readonly policy?: CoreTexWorkPolicy;
}

export function computeCoreTexWorkUnitsBps(input: ComputeCoreTexWorkUnitsInput): bigint {
  const policy = input.policy ?? DEFAULT_CORETEX_WORK_POLICY;
  assertValidCoreTexWorkPolicy(policy);

  if (input.outcome === policy.screenerPass.outcome) {
    return toBigInt(policy.screenerPass.workUnitsBps, 'screenerPass.workUnitsBps');
  }
  if (input.outcome !== policy.stateAdvance.outcome) {
    throw new RangeError(`unknown CoreTex outcome ${input.outcome}`);
  }

  const count = toBigInt(
    input.qualifiedScreenerPassesSinceLastStateAdvance ?? 0n,
    'qualifiedScreenerPassesSinceLastStateAdvance',
  );
  let selected = toBigInt(policy.stateAdvance.tiers[0]!.workUnitsBps, 'stateAdvance.tiers[0].workUnitsBps');
  for (const [i, tier] of policy.stateAdvance.tiers.entries()) {
    const min = toBigInt(
      tier.minQualifiedScreenerPassesSinceLastStateAdvance,
      `stateAdvance.tiers[${i}].minQualifiedScreenerPassesSinceLastStateAdvance`,
    );
    if (count >= min) {
      selected = toBigInt(tier.workUnitsBps, `stateAdvance.tiers[${i}].workUnitsBps`);
    }
  }
  return selected;
}

export function computeCoreTexScreenerThresholdPpm(input: ComputeCoreTexScreenerThresholdInput = {}): bigint {
  const policy = input.policy ?? DEFAULT_CORETEX_WORK_POLICY;
  assertValidCoreTexWorkPolicy(policy);

  const calibration = policy.screenerPass.calibration;
  const scale = toBigInt(calibration.scoreScalePpm, 'screenerPass.calibration.scoreScalePpm');
  const baseline = clamp(
    toBigInt(input.baselineScorePpm ?? 0n, 'baselineScorePpm'),
    0n,
    scale,
  );
  const remaining = scale - baseline;
  const minDelta = toBigInt(calibration.minDeltaPpm, 'screenerPass.calibration.minDeltaPpm');
  const headroomDelta =
    (remaining * toBigInt(calibration.remainingHeadroomBps, 'screenerPass.calibration.remainingHeadroomBps')) / WORK_BPS_DIVISOR;
  const noiseDelta =
    (toBigInt(input.recentNoiseFloorPpm ?? 0n, 'recentNoiseFloorPpm')
      * toBigInt(calibration.noiseFloorMultiplierBps, 'screenerPass.calibration.noiseFloorMultiplierBps')) / WORK_BPS_DIVISOR;
  const stateAdvanceFloorBps = toBigInt(
    calibration.stateAdvanceThresholdFloorBps ?? 0n,
    'screenerPass.calibration.stateAdvanceThresholdFloorBps',
  );
  if (stateAdvanceFloorBps > 0n && input.stateAdvanceThresholdPpm === undefined) {
    throw new RangeError('stateAdvanceThresholdPpm is required when stateAdvanceThresholdFloorBps is enabled');
  }
  const stateAdvanceThreshold = toBigInt(input.stateAdvanceThresholdPpm ?? 0n, 'stateAdvanceThresholdPpm');
  if (stateAdvanceFloorBps > 0n && stateAdvanceThreshold <= 0n) {
    throw new RangeError('stateAdvanceThresholdPpm must be positive when stateAdvanceThresholdFloorBps is enabled');
  }
  const stateAdvanceFloorDelta = stateAdvanceThreshold > 0n && stateAdvanceFloorBps > 0n
    ? ceilDiv(stateAdvanceThreshold * stateAdvanceFloorBps, WORK_BPS_DIVISOR)
    : 0n;
  const plateauEasingMaxBps = toBigInt(calibration.plateauEasingMaxBps, 'screenerPass.calibration.plateauEasingMaxBps');
  let adjustedHeadroomDelta = headroomDelta;
  const targetStateAdvances = toBigInt(input.targetStateAdvances ?? 0n, 'targetStateAdvances');
  if (targetStateAdvances > 0n) {
    const recentStateAdvances = min(toBigInt(input.recentStateAdvances ?? 0n, 'recentStateAdvances'), targetStateAdvances);
    const recentScreenerPasses = toBigInt(input.recentScreenerPasses ?? 0n, 'recentScreenerPasses');
    const stateAdvanceGap = targetStateAdvances - recentStateAdvances;
    const supportedGap = min(recentScreenerPasses, stateAdvanceGap);
    const easingBps = min(plateauEasingMaxBps, (plateauEasingMaxBps * supportedGap) / targetStateAdvances);
    adjustedHeadroomDelta = (headroomDelta * (WORK_BPS_DIVISOR - easingBps)) / WORK_BPS_DIVISOR;
  }

  const probePassRate = clamp(
    toBigInt(input.recentProbePassRatePpm ?? 0n, 'recentProbePassRatePpm'),
    0n,
    scale,
  );
  const antiGamingPenaltyBps = min(
    toBigInt(calibration.maxAntiGamingPenaltyBps, 'screenerPass.calibration.maxAntiGamingPenaltyBps'),
    (probePassRate * toBigInt(calibration.antiGamingProbeMultiplierBps, 'screenerPass.calibration.antiGamingProbeMultiplierBps')) / scale,
  );
  const maxThreshold = toBigInt(calibration.maxThresholdPpm, 'screenerPass.calibration.maxThresholdPpm');

  const rawThreshold = max(max(minDelta, stateAdvanceFloorDelta), max(adjustedHeadroomDelta, noiseDelta));
  const penalizedThreshold = (rawThreshold * (WORK_BPS_DIVISOR + antiGamingPenaltyBps)) / WORK_BPS_DIVISOR;
  const dynamicCeiling = stateAdvanceThreshold > 0n ? min(maxThreshold, stateAdvanceThreshold) : maxThreshold;
  return min(penalizedThreshold, dynamicCeiling);
}

export function evaluateCoreTexWorkQualification(input: CoreTexWorkQualificationInput): CoreTexWorkQualification {
  const policy = input.policy ?? DEFAULT_CORETEX_WORK_POLICY;
  assertValidCoreTexWorkPolicy(policy);

  if (input.outcome !== policy.screenerPass.outcome && input.outcome !== policy.stateAdvance.outcome) {
    return { qualified: false, reason: 'W01_UNKNOWN_OUTCOME', workUnitsBps: 0n, requiredDeterministicDeltaPpm: 0n };
  }
  if (!input.parentMatchesLiveRoot) {
    return { qualified: false, reason: 'W02_STALE_PARENT', workUnitsBps: 0n, requiredDeterministicDeltaPpm: 0n };
  }

  const deterministicDelta = toSignedBigInt(input.deterministicDeltaPpm, 'deterministicDeltaPpm');
  const localModelDelta = toSignedBigInt(input.localModelDeltaPpm ?? 0n, 'localModelDeltaPpm');
  const isStateAdvance = input.outcome === policy.stateAdvance.outcome;
  const thresholdInput: {
    baselineScorePpm?: string | bigint | number;
    recentNoiseFloorPpm?: string | bigint | number;
    recentScreenerPasses?: string | bigint | number;
    recentStateAdvances?: string | bigint | number;
    targetStateAdvances?: string | bigint | number;
    recentProbePassRatePpm?: string | bigint | number;
    stateAdvanceThresholdPpm?: string | bigint | number;
    policy: CoreTexWorkPolicy;
  } = { policy };
  if (input.baselineScorePpm !== undefined) thresholdInput.baselineScorePpm = input.baselineScorePpm;
  if (input.recentNoiseFloorPpm !== undefined) thresholdInput.recentNoiseFloorPpm = input.recentNoiseFloorPpm;
  if (input.recentScreenerPasses !== undefined) thresholdInput.recentScreenerPasses = input.recentScreenerPasses;
  if (input.recentStateAdvances !== undefined) thresholdInput.recentStateAdvances = input.recentStateAdvances;
  if (input.targetStateAdvances !== undefined) thresholdInput.targetStateAdvances = input.targetStateAdvances;
  if (input.recentProbePassRatePpm !== undefined) thresholdInput.recentProbePassRatePpm = input.recentProbePassRatePpm;
  if (input.stateAdvanceThresholdPpm !== undefined) thresholdInput.stateAdvanceThresholdPpm = input.stateAdvanceThresholdPpm;
  const screenerThreshold = computeCoreTexScreenerThresholdPpm(thresholdInput);
  const stateAdvanceThreshold = input.stateAdvanceThresholdPpm !== undefined
    ? toBigInt(input.stateAdvanceThresholdPpm, 'stateAdvanceThresholdPpm')
    : 0n;
  const minDeterministic = isStateAdvance
    ? max(max(
        toBigInt(policy.stateAdvance.minDeterministicDeltaPpm, 'stateAdvance.minDeterministicDeltaPpm'),
        screenerThreshold,
      ), stateAdvanceThreshold)
    : screenerThreshold;
  const minLocal = toBigInt(
    isStateAdvance ? policy.stateAdvance.minLocalModelDeltaPpm : policy.screenerPass.minLocalModelDeltaPpm,
    isStateAdvance ? 'stateAdvance.minLocalModelDeltaPpm' : 'screenerPass.minLocalModelDeltaPpm',
  );

  if (deterministicDelta < minDeterministic) {
    return {
      qualified: false,
      reason: 'W03_DETERMINISTIC_DELTA_TOO_LOW',
      workUnitsBps: 0n,
      requiredDeterministicDeltaPpm: minDeterministic,
    };
  }
  if (localModelDelta < minLocal) {
    return { qualified: false, reason: 'W04_LOCAL_MODEL_REGRESSION', workUnitsBps: 0n, requiredDeterministicDeltaPpm: minDeterministic };
  }

  const nearCollision = input.relevantNearCollisionPpm;
  if (nearCollision !== undefined) {
    const maxCollision = toBigInt(policy.screenerPass.maxRelevantNearCollisionPpm, 'screenerPass.maxRelevantNearCollisionPpm');
    if (toBigInt(nearCollision, 'relevantNearCollisionPpm') > maxCollision) {
      return { qualified: false, reason: 'W05_RELEVANT_NEAR_COLLISION', workUnitsBps: 0n, requiredDeterministicDeltaPpm: minDeterministic };
    }
  }

  if (isStateAdvance && policy.stateAdvance.requireLiveStateAdvance && input.liveStateAdvanced !== true) {
    return { qualified: false, reason: 'W06_STATE_NOT_ADVANCED', workUnitsBps: 0n, requiredDeterministicDeltaPpm: minDeterministic };
  }

  return {
    qualified: true,
    reason: 'OK',
    workUnitsBps: computeCoreTexWorkUnitsBps(input),
    requiredDeterministicDeltaPpm: minDeterministic,
  };
}

export function coreTexWorkPolicyHash(policy: CoreTexWorkPolicy = DEFAULT_CORETEX_WORK_POLICY): string {
  assertValidCoreTexWorkPolicy(policy);
  // safe-integer policy: this hash is mirrored by integer-only consumers.
  return bytesToHex(keccak256(new TextEncoder().encode(canonicalJson(policy, { numbers: 'safe-integer' }))));
}

export function assertValidCoreTexWorkPolicy(policy: CoreTexWorkPolicy): void {
  if (policy.name.length === 0) throw new RangeError('policy.name is required');
  if (policy.version <= 0) throw new RangeError('policy.version must be positive');
  if (policy.rulesVersion !== CORTEX_RULES_VERSION) throw new RangeError('policy.rulesVersion must be 0xC0');
  if (policy.lane !== LANE_CORETEX) throw new RangeError('policy.lane must be CoreTex');
  if (toBigInt(policy.bpsDivisor, 'bpsDivisor') !== WORK_BPS_DIVISOR) {
    throw new RangeError('policy.bpsDivisor must be 10000');
  }
  if (policy.screenerPass.outcome !== OUTCOME_CORETEX_SCREENER_PASS) {
    throw new RangeError('policy.screenerPass.outcome must be 1');
  }
  const calibration = policy.screenerPass.calibration;
  const scoreScale = toBigInt(calibration.scoreScalePpm, 'screenerPass.calibration.scoreScalePpm');
  const minDelta = toBigInt(calibration.minDeltaPpm, 'screenerPass.calibration.minDeltaPpm');
  const maxThreshold = toBigInt(calibration.maxThresholdPpm, 'screenerPass.calibration.maxThresholdPpm');
  const plateauEasingMaxBps = toBigInt(calibration.plateauEasingMaxBps, 'screenerPass.calibration.plateauEasingMaxBps');
  const stateAdvanceThresholdFloorBps = toBigInt(
    calibration.stateAdvanceThresholdFloorBps ?? 0n,
    'screenerPass.calibration.stateAdvanceThresholdFloorBps',
  );
  const maxAntiGamingPenaltyBps = toBigInt(calibration.maxAntiGamingPenaltyBps, 'screenerPass.calibration.maxAntiGamingPenaltyBps');
  if (scoreScale !== 1_000_000n) throw new RangeError('scoreScalePpm must be 1000000');
  if (minDelta < 10n) throw new RangeError('screener minimum delta is too low');
  if (maxThreshold < minDelta) throw new RangeError('screener max threshold must be >= min delta');
  if (toBigInt(calibration.remainingHeadroomBps, 'screenerPass.calibration.remainingHeadroomBps') === 0n) {
    throw new RangeError('remainingHeadroomBps must be positive');
  }
  if (toBigInt(calibration.noiseFloorMultiplierBps, 'screenerPass.calibration.noiseFloorMultiplierBps') < WORK_BPS_DIVISOR) {
    throw new RangeError('noiseFloorMultiplierBps must be at least 1x');
  }
  if (plateauEasingMaxBps > WORK_BPS_DIVISOR) {
    throw new RangeError('plateauEasingMaxBps must be <= 10000');
  }
  if (stateAdvanceThresholdFloorBps > WORK_BPS_DIVISOR) {
    throw new RangeError('stateAdvanceThresholdFloorBps must be <= 10000');
  }
  if (toBigInt(calibration.antiGamingProbeMultiplierBps, 'screenerPass.calibration.antiGamingProbeMultiplierBps') === 0n) {
    throw new RangeError('antiGamingProbeMultiplierBps must be positive');
  }
  if (maxAntiGamingPenaltyBps > 10n * WORK_BPS_DIVISOR) {
    throw new RangeError('maxAntiGamingPenaltyBps must be <= 100000');
  }
  if (policy.stateAdvance.outcome !== OUTCOME_CORETEX_STATE_ADVANCE) {
    throw new RangeError('policy.stateAdvance.outcome must be 2');
  }
  const screenerBps = toBigInt(policy.screenerPass.workUnitsBps, 'screenerPass.workUnitsBps');
  if (screenerBps !== WORK_BPS_DIVISOR) {
    throw new RangeError('screener pass must stay exactly 1x');
  }
  if (policy.stateAdvance.tiers.length === 0) {
    throw new RangeError('stateAdvance.tiers must not be empty');
  }

  let prevMin = -1n;
  let prevBps = 0n;
  for (const [i, tier] of policy.stateAdvance.tiers.entries()) {
    const min = toBigInt(
      tier.minQualifiedScreenerPassesSinceLastStateAdvance,
      `stateAdvance.tiers[${i}].minQualifiedScreenerPassesSinceLastStateAdvance`,
    );
    const bps = toBigInt(tier.workUnitsBps, `stateAdvance.tiers[${i}].workUnitsBps`);
    if (min <= prevMin) throw new RangeError('stateAdvance.tiers must have strictly increasing min counts');
    if (bps < 3n * WORK_BPS_DIVISOR) throw new RangeError('state advance must be at least 3x');
    if (bps < prevBps) throw new RangeError('stateAdvance.tiers bps must be nondecreasing');
    prevMin = min;
    prevBps = bps;
  }
  if (toBigInt(policy.stateAdvance.tiers[0]!.minQualifiedScreenerPassesSinceLastStateAdvance, 'stateAdvance.tiers[0].min') !== 0n) {
    throw new RangeError('first stateAdvance tier must start at 0');
  }
}

function toBigInt(value: string | bigint | number, label: string): bigint {
  if (typeof value === 'bigint') {
    if (value < 0n) throw new RangeError(`${label} must be non-negative`);
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new RangeError(`${label} must be a non-negative safe integer`);
    return BigInt(value);
  }
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new RangeError(`${label} must be a non-negative decimal string`);
  }
  return BigInt(value);
}

function toSignedBigInt(value: string | bigint | number, label: string): bigint {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new RangeError(`${label} must be a safe integer`);
    return BigInt(value);
  }
  if (!/^-?(0|[1-9][0-9]*)$/.test(value)) {
    throw new RangeError(`${label} must be a signed decimal string`);
  }
  return BigInt(value);
}

function min(a: bigint, b: bigint): bigint {
  return a < b ? a : b;
}

function max(a: bigint, b: bigint): bigint {
  return a > b ? a : b;
}

function clamp(value: bigint, lo: bigint, hi: bigint): bigint {
  return min(max(value, lo), hi);
}

function ceilDiv(numerator: bigint, denominator: bigint): bigint {
  if (denominator <= 0n) throw new RangeError('ceilDiv denominator must be positive');
  return (numerator + denominator - 1n) / denominator;
}
