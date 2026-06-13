import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

let rewards;
try {
  rewards = await import('../../dist/rewards/index.js');
} catch (e) {
  console.error('Could not import from dist/. Run `npm run build` first.');
  console.error('Error:', e.message);
  process.exit(1);
}

const {
  WORK_BPS_DIVISOR,
  LANE_CORETEX,
  OUTCOME_CORETEX_SCREENER_PASS,
  OUTCOME_CORETEX_STATE_ADVANCE,
  CORETEX_WORK_RULES_VERSION,
  DEFAULT_CORETEX_WORK_POLICY,
  computeCoreTexWorkUnitsBps,
  computeCoreTexScreenerThresholdPpm,
  evaluateCoreTexWorkQualification,
  coreTexWorkPolicyHash,
  assertValidCoreTexWorkPolicy,
} = rewards;

const LAUNCH_STATE_ADVANCE_THRESHOLD_PPM = 2_750;

function legacyDynamicScreenerPolicy() {
  const policy = structuredClone(DEFAULT_CORETEX_WORK_POLICY);
  policy.screenerPass.calibration.stateAdvanceThresholdFloorBps = '0';
  return policy;
}

describe('CoreTex V4 work-unit policy', () => {
  test('default policy pins V4 lane constants', () => {
    assert.equal(WORK_BPS_DIVISOR, 10_000n);
    assert.equal(LANE_CORETEX, 2);
    assert.equal(OUTCOME_CORETEX_SCREENER_PASS, 1);
    assert.equal(OUTCOME_CORETEX_STATE_ADVANCE, 2);
    assert.equal(CORETEX_WORK_RULES_VERSION, 0xC0);
    assert.equal(DEFAULT_CORETEX_WORK_POLICY.version, 3);
    assert.doesNotThrow(() => assertValidCoreTexWorkPolicy(DEFAULT_CORETEX_WORK_POLICY));
  });

  test('screener pass is exactly 1x', () => {
    assert.equal(
      computeCoreTexWorkUnitsBps({ outcome: OUTCOME_CORETEX_SCREENER_PASS }),
      10_000n,
    );
  });

  test('state advance scales by qualified screener passes since last advance', () => {
    const cases = [
      [0n, 30_000n],
      [24n, 30_000n],
      [25n, 40_000n],
      [99n, 40_000n],
      [100n, 60_000n],
      [249n, 60_000n],
      [250n, 90_000n],
      [499n, 90_000n],
      [500n, 120_000n],
      [5_000n, 120_000n],
    ];
    for (const [count, expected] of cases) {
      assert.equal(
        computeCoreTexWorkUnitsBps({
          outcome: OUTCOME_CORETEX_STATE_ADVANCE,
          qualifiedScreenerPassesSinceLastStateAdvance: count,
        }),
        expected,
      );
    }
  });

  test('operator can calibrate difficulty tiers without changing verifier code', () => {
    const policy = structuredClone(DEFAULT_CORETEX_WORK_POLICY);
    policy.stateAdvance.tiers = [
      { minQualifiedScreenerPassesSinceLastStateAdvance: '0', workUnitsBps: '30000' },
      { minQualifiedScreenerPassesSinceLastStateAdvance: '3', workUnitsBps: '50000' },
      { minQualifiedScreenerPassesSinceLastStateAdvance: '7', workUnitsBps: '150000' },
    ];

    assert.equal(
      computeCoreTexWorkUnitsBps({
        outcome: OUTCOME_CORETEX_STATE_ADVANCE,
        qualifiedScreenerPassesSinceLastStateAdvance: 6,
        policy,
      }),
      50_000n,
    );
    assert.equal(
      computeCoreTexWorkUnitsBps({
        outcome: OUTCOME_CORETEX_STATE_ADVANCE,
        qualifiedScreenerPassesSinceLastStateAdvance: 7,
        policy,
      }),
      150_000n,
    );
  });

  test('screener threshold adapts to baseline headroom and measured noise', () => {
    const policy = legacyDynamicScreenerPolicy();
    assert.equal(
      computeCoreTexScreenerThresholdPpm({ baselineScorePpm: 0, recentNoiseFloorPpm: 0, policy }),
      500n,
    );
    assert.equal(
      computeCoreTexScreenerThresholdPpm({ baselineScorePpm: 900_000, recentNoiseFloorPpm: 0, policy }),
      50n,
    );
    assert.equal(
      computeCoreTexScreenerThresholdPpm({ baselineScorePpm: 900_000, recentNoiseFloorPpm: 80, policy }),
      160n,
    );
    assert.equal(
      computeCoreTexScreenerThresholdPpm({ baselineScorePpm: 0, recentNoiseFloorPpm: 10_000, policy }),
      20_000n,
    );
  });

  test('state-threshold floor fails closed when the real state threshold is absent', () => {
    assert.throws(
      () => computeCoreTexScreenerThresholdPpm({ baselineScorePpm: 288_438, recentNoiseFloorPpm: 0 }),
      /stateAdvanceThresholdPpm is required/,
    );
    assert.throws(
      () => computeCoreTexScreenerThresholdPpm({
        baselineScorePpm: 288_438,
        recentNoiseFloorPpm: 0,
        stateAdvanceThresholdPpm: 0,
      }),
      /stateAdvanceThresholdPpm must be positive/,
    );
  });

  test('screener threshold is floored by the real state-advance threshold when supplied', () => {
    const launchStateThreshold = 2_750n;
    const expectedFloor = 1_375n;
    assert.equal(
      computeCoreTexScreenerThresholdPpm({
        baselineScorePpm: 288_438,
        recentNoiseFloorPpm: 0,
        stateAdvanceThresholdPpm: launchStateThreshold,
      }),
      expectedFloor,
    );
    assert.equal(
      computeCoreTexScreenerThresholdPpm({
        baselineScorePpm: 900_000,
        recentNoiseFloorPpm: 0,
        stateAdvanceThresholdPpm: launchStateThreshold,
      }),
      expectedFloor,
    );
    assert.equal(
      computeCoreTexScreenerThresholdPpm({
        baselineScorePpm: 900_000,
        recentNoiseFloorPpm: 1_000,
        stateAdvanceThresholdPpm: launchStateThreshold,
      }),
      2_000n,
    );
    assert.equal(
      computeCoreTexScreenerThresholdPpm({
        baselineScorePpm: 900_000,
        recentNoiseFloorPpm: 1_000_000,
        stateAdvanceThresholdPpm: launchStateThreshold,
      }),
      launchStateThreshold,
      'probe/noise hardening cannot push the screener above the state-advance threshold',
    );
  });

  test('screener threshold moves monotonically with baseline improvement', () => {
    const policy = legacyDynamicScreenerPolicy();
    // Better baseline score => less remaining headroom => lower required threshold.
    const t0 = computeCoreTexScreenerThresholdPpm({ baselineScorePpm: 0, recentNoiseFloorPpm: 0, policy });
    const t25 = computeCoreTexScreenerThresholdPpm({ baselineScorePpm: 250_000, recentNoiseFloorPpm: 0, policy });
    const t50 = computeCoreTexScreenerThresholdPpm({ baselineScorePpm: 500_000, recentNoiseFloorPpm: 0, policy });
    const t75 = computeCoreTexScreenerThresholdPpm({ baselineScorePpm: 750_000, recentNoiseFloorPpm: 0, policy });
    const t90 = computeCoreTexScreenerThresholdPpm({ baselineScorePpm: 900_000, recentNoiseFloorPpm: 0, policy });

    assert.ok(t0 >= t25 && t25 >= t50 && t50 >= t75 && t75 >= t90);
    assert.deepEqual([t0, t25, t50, t75, t90], [500n, 375n, 250n, 125n, 50n]);
  });

  test('screener threshold rises monotonically with measured noise', () => {
    const policy = legacyDynamicScreenerPolicy();
    const t0 = computeCoreTexScreenerThresholdPpm({ baselineScorePpm: 900_000, recentNoiseFloorPpm: 0, policy });
    const t10 = computeCoreTexScreenerThresholdPpm({ baselineScorePpm: 900_000, recentNoiseFloorPpm: 10, policy });
    const t40 = computeCoreTexScreenerThresholdPpm({ baselineScorePpm: 900_000, recentNoiseFloorPpm: 40, policy });
    const t80 = computeCoreTexScreenerThresholdPpm({ baselineScorePpm: 900_000, recentNoiseFloorPpm: 80, policy });
    const t120 = computeCoreTexScreenerThresholdPpm({ baselineScorePpm: 900_000, recentNoiseFloorPpm: 120, policy });

    assert.ok(t0 <= t10 && t10 <= t40 && t40 <= t80 && t80 <= t120);
    assert.deepEqual([t0, t10, t40, t80, t120], [50n, 50n, 80n, 160n, 240n]);
  });

  test('screener threshold eases only the headroom component under state-advance plateau pressure', () => {
    const policy = legacyDynamicScreenerPolicy();
    assert.equal(
      computeCoreTexScreenerThresholdPpm({
        baselineScorePpm: 0,
        recentNoiseFloorPpm: 0,
        targetStateAdvances: 2,
        recentStateAdvances: 0,
        recentScreenerPasses: 1,
        policy,
      }),
      375n,
    );
    assert.equal(
      computeCoreTexScreenerThresholdPpm({
        baselineScorePpm: 0,
        recentNoiseFloorPpm: 0,
        targetStateAdvances: 2,
        recentStateAdvances: 0,
        recentScreenerPasses: 2,
        policy,
      }),
      250n,
    );
    assert.equal(
      computeCoreTexScreenerThresholdPpm({
        baselineScorePpm: 0,
        recentNoiseFloorPpm: 300,
        targetStateAdvances: 2,
        recentStateAdvances: 0,
        recentScreenerPasses: 2,
        policy,
      }),
      600n,
      'clean-noise floor is never eased away',
    );
  });

  test('screener threshold hardens when random or hillclimb probes pass', () => {
    const policy = legacyDynamicScreenerPolicy();
    assert.equal(
      computeCoreTexScreenerThresholdPpm({
        baselineScorePpm: 0,
        recentNoiseFloorPpm: 0,
        recentProbePassRatePpm: 50_000,
        policy,
      }),
      550n,
    );
    assert.equal(
      computeCoreTexScreenerThresholdPpm({
        baselineScorePpm: 0,
        recentNoiseFloorPpm: 0,
        recentProbePassRatePpm: 1_000_000,
        policy,
      }),
      1_500n,
    );
  });

  test('screener threshold hard-clamps at policy min and max', () => {
    const policy = legacyDynamicScreenerPolicy();
    // minDelta clamp (50ppm default)
    assert.equal(
      computeCoreTexScreenerThresholdPpm({ baselineScorePpm: 999_999, recentNoiseFloorPpm: 0, policy }),
      50n,
    );
    // maxThreshold clamp (150000ppm default)
    assert.equal(
      computeCoreTexScreenerThresholdPpm({ baselineScorePpm: 0, recentNoiseFloorPpm: 1_000_000, policy }),
      150_000n,
    );
  });

  test('qualification requires current parent root and real signal', () => {
    assert.deepEqual(
      evaluateCoreTexWorkQualification({
        outcome: OUTCOME_CORETEX_SCREENER_PASS,
        deterministicDeltaPpm: 1_375,
        baselineScorePpm: 0,
        stateAdvanceThresholdPpm: LAUNCH_STATE_ADVANCE_THRESHOLD_PPM,
        localModelDeltaPpm: 0,
        parentMatchesLiveRoot: true,
      }),
      { qualified: true, reason: 'OK', workUnitsBps: 10_000n, requiredDeterministicDeltaPpm: 1_375n },
    );

    assert.equal(
      evaluateCoreTexWorkQualification({
        outcome: OUTCOME_CORETEX_SCREENER_PASS,
        deterministicDeltaPpm: 1,
        parentMatchesLiveRoot: false,
      }).reason,
      'W02_STALE_PARENT',
    );

    assert.equal(
      evaluateCoreTexWorkQualification({
        outcome: OUTCOME_CORETEX_SCREENER_PASS,
        deterministicDeltaPpm: 0,
        baselineScorePpm: 0,
        stateAdvanceThresholdPpm: LAUNCH_STATE_ADVANCE_THRESHOLD_PPM,
        parentMatchesLiveRoot: true,
      }).reason,
      'W03_DETERMINISTIC_DELTA_TOO_LOW',
    );

    assert.equal(
      evaluateCoreTexWorkQualification({
        outcome: OUTCOME_CORETEX_SCREENER_PASS,
        deterministicDeltaPpm: 49,
        baselineScorePpm: 900_000,
        stateAdvanceThresholdPpm: LAUNCH_STATE_ADVANCE_THRESHOLD_PPM,
        parentMatchesLiveRoot: true,
      }).reason,
      'W03_DETERMINISTIC_DELTA_TOO_LOW',
    );

    // Exact-threshold boundary: pass at threshold, fail below threshold.
    const dynamicThreshold = computeCoreTexScreenerThresholdPpm({
      baselineScorePpm: 900_000,
      recentNoiseFloorPpm: 80,
      stateAdvanceThresholdPpm: LAUNCH_STATE_ADVANCE_THRESHOLD_PPM,
    });
    const passAtThreshold = evaluateCoreTexWorkQualification({
      outcome: OUTCOME_CORETEX_SCREENER_PASS,
      deterministicDeltaPpm: Number(dynamicThreshold),
      baselineScorePpm: 900_000,
      recentNoiseFloorPpm: 80,
      stateAdvanceThresholdPpm: LAUNCH_STATE_ADVANCE_THRESHOLD_PPM,
      parentMatchesLiveRoot: true,
    });
    const failBelowThreshold = evaluateCoreTexWorkQualification({
      outcome: OUTCOME_CORETEX_SCREENER_PASS,
      deterministicDeltaPpm: Number(dynamicThreshold - 1n),
      baselineScorePpm: 900_000,
      recentNoiseFloorPpm: 80,
      stateAdvanceThresholdPpm: LAUNCH_STATE_ADVANCE_THRESHOLD_PPM,
      parentMatchesLiveRoot: true,
    });
    assert.equal(passAtThreshold.qualified, true);
    assert.equal(passAtThreshold.requiredDeterministicDeltaPpm, dynamicThreshold);
    assert.equal(failBelowThreshold.reason, 'W03_DETERMINISTIC_DELTA_TOO_LOW');
    assert.equal(failBelowThreshold.requiredDeterministicDeltaPpm, dynamicThreshold);

    const plateauEasedPass = evaluateCoreTexWorkQualification({
      outcome: OUTCOME_CORETEX_SCREENER_PASS,
      deterministicDeltaPpm: 1_375,
      baselineScorePpm: 0,
      recentNoiseFloorPpm: 0,
      stateAdvanceThresholdPpm: LAUNCH_STATE_ADVANCE_THRESHOLD_PPM,
      targetStateAdvances: 2,
      recentStateAdvances: 0,
      recentScreenerPasses: 2,
      parentMatchesLiveRoot: true,
    });
    assert.equal(plateauEasedPass.qualified, true);
    assert.equal(plateauEasedPass.requiredDeterministicDeltaPpm, 1_375n);
  });

  test('state advance requires live advance and local model no-regression', () => {
    assert.equal(
      evaluateCoreTexWorkQualification({
        outcome: OUTCOME_CORETEX_STATE_ADVANCE,
        deterministicDeltaPpm: LAUNCH_STATE_ADVANCE_THRESHOLD_PPM,
        baselineScorePpm: 0,
        stateAdvanceThresholdPpm: LAUNCH_STATE_ADVANCE_THRESHOLD_PPM,
        localModelDeltaPpm: 0,
        parentMatchesLiveRoot: true,
        liveStateAdvanced: false,
      }).reason,
      'W06_STATE_NOT_ADVANCED',
    );

    assert.equal(
      evaluateCoreTexWorkQualification({
        outcome: OUTCOME_CORETEX_STATE_ADVANCE,
        deterministicDeltaPpm: LAUNCH_STATE_ADVANCE_THRESHOLD_PPM,
        baselineScorePpm: 0,
        stateAdvanceThresholdPpm: LAUNCH_STATE_ADVANCE_THRESHOLD_PPM,
        localModelDeltaPpm: -1,
        parentMatchesLiveRoot: true,
        liveStateAdvanced: true,
      }).reason,
      'W04_LOCAL_MODEL_REGRESSION',
    );

    assert.deepEqual(
      evaluateCoreTexWorkQualification({
        outcome: OUTCOME_CORETEX_STATE_ADVANCE,
        deterministicDeltaPpm: LAUNCH_STATE_ADVANCE_THRESHOLD_PPM,
        baselineScorePpm: 0,
        stateAdvanceThresholdPpm: LAUNCH_STATE_ADVANCE_THRESHOLD_PPM,
        localModelDeltaPpm: 0,
        parentMatchesLiveRoot: true,
        liveStateAdvanced: true,
        qualifiedScreenerPassesSinceLastStateAdvance: 500,
      }),
      { qualified: true, reason: 'OK', workUnitsBps: 120_000n, requiredDeterministicDeltaPpm: 2_750n },
    );

    // State-advance minimum deterministic delta uses max(policy.min, screenerThreshold, real state threshold).
    const withLowNoise = evaluateCoreTexWorkQualification({
      outcome: OUTCOME_CORETEX_STATE_ADVANCE,
      deterministicDeltaPpm: 2_749,
      baselineScorePpm: 0,
      recentNoiseFloorPpm: 0,
      stateAdvanceThresholdPpm: LAUNCH_STATE_ADVANCE_THRESHOLD_PPM,
      localModelDeltaPpm: 0,
      parentMatchesLiveRoot: true,
      liveStateAdvanced: true,
    });
    const withHighNoise = evaluateCoreTexWorkQualification({
      outcome: OUTCOME_CORETEX_STATE_ADVANCE,
      deterministicDeltaPpm: 2_749,
      baselineScorePpm: 0,
      recentNoiseFloorPpm: 50_000,
      stateAdvanceThresholdPpm: LAUNCH_STATE_ADVANCE_THRESHOLD_PPM,
      localModelDeltaPpm: 0,
      parentMatchesLiveRoot: true,
      liveStateAdvanced: true,
    });

    assert.equal(withLowNoise.reason, 'W03_DETERMINISTIC_DELTA_TOO_LOW');
    assert.equal(withLowNoise.requiredDeterministicDeltaPpm, 2_750n);
    assert.equal(withHighNoise.reason, 'W03_DETERMINISTIC_DELTA_TOO_LOW');
    assert.equal(withHighNoise.requiredDeterministicDeltaPpm, 2_750n);
  });

  test('relevant near-collision scorer is a gate, not a reward shortcut', () => {
    assert.equal(
      evaluateCoreTexWorkQualification({
        outcome: OUTCOME_CORETEX_SCREENER_PASS,
        deterministicDeltaPpm: 5_000,
        baselineScorePpm: 0,
        stateAdvanceThresholdPpm: LAUNCH_STATE_ADVANCE_THRESHOLD_PPM,
        localModelDeltaPpm: 0,
        relevantNearCollisionPpm: 250_001,
        parentMatchesLiveRoot: true,
      }).reason,
      'W05_RELEVANT_NEAR_COLLISION',
    );
  });

  test('policy hash is stable and changes when tiers change', () => {
    const h1 = coreTexWorkPolicyHash(DEFAULT_CORETEX_WORK_POLICY);
    const h2 = coreTexWorkPolicyHash(DEFAULT_CORETEX_WORK_POLICY);
    assert.match(h1, /^0x[0-9a-f]{64}$/);
    assert.equal(h1, h2);

    const policy = structuredClone(DEFAULT_CORETEX_WORK_POLICY);
    policy.stateAdvance.tiers[1].workUnitsBps = '41000';
    assert.notEqual(coreTexWorkPolicyHash(policy), h1);
  });

  test('invalid policies fail closed', () => {
    const badFirstTier = structuredClone(DEFAULT_CORETEX_WORK_POLICY);
    badFirstTier.stateAdvance.tiers[0].minQualifiedScreenerPassesSinceLastStateAdvance = '1';
    assert.throws(() => assertValidCoreTexWorkPolicy(badFirstTier), /first stateAdvance tier/);

    const badScreener = structuredClone(DEFAULT_CORETEX_WORK_POLICY);
    badScreener.screenerPass.workUnitsBps = '20000';
    assert.throws(() => assertValidCoreTexWorkPolicy(badScreener), /screener pass/);

    const badCalibration = structuredClone(DEFAULT_CORETEX_WORK_POLICY);
    badCalibration.screenerPass.calibration.minDeltaPpm = '1';
    assert.throws(() => assertValidCoreTexWorkPolicy(badCalibration), /minimum delta/);
  });
});
