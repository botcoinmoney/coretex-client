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
  evaluateCoreTexWorkQualification,
  coreTexWorkPolicyHash,
  assertValidCoreTexWorkPolicy,
} = rewards;

describe('CoreTex V4 work-unit policy', () => {
  test('default policy pins V4 lane constants', () => {
    assert.equal(WORK_BPS_DIVISOR, 10_000n);
    assert.equal(LANE_CORETEX, 2);
    assert.equal(OUTCOME_CORETEX_SCREENER_PASS, 1);
    assert.equal(OUTCOME_CORETEX_STATE_ADVANCE, 2);
    assert.equal(CORETEX_WORK_RULES_VERSION, 0xC0);
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

  test('qualification requires current parent root and real signal', () => {
    assert.deepEqual(
      evaluateCoreTexWorkQualification({
        outcome: OUTCOME_CORETEX_SCREENER_PASS,
        deterministicDeltaPpm: 1,
        localModelDeltaPpm: 0,
        parentMatchesLiveRoot: true,
      }),
      { qualified: true, reason: 'OK', workUnitsBps: 10_000n },
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
        parentMatchesLiveRoot: true,
      }).reason,
      'W03_DETERMINISTIC_DELTA_TOO_LOW',
    );
  });

  test('state advance requires live advance and local model no-regression', () => {
    assert.equal(
      evaluateCoreTexWorkQualification({
        outcome: OUTCOME_CORETEX_STATE_ADVANCE,
        deterministicDeltaPpm: 10,
        localModelDeltaPpm: 0,
        parentMatchesLiveRoot: true,
        liveStateAdvanced: false,
      }).reason,
      'W06_STATE_NOT_ADVANCED',
    );

    assert.equal(
      evaluateCoreTexWorkQualification({
        outcome: OUTCOME_CORETEX_STATE_ADVANCE,
        deterministicDeltaPpm: 10,
        localModelDeltaPpm: -1,
        parentMatchesLiveRoot: true,
        liveStateAdvanced: true,
      }).reason,
      'W04_LOCAL_MODEL_REGRESSION',
    );

    assert.deepEqual(
      evaluateCoreTexWorkQualification({
        outcome: OUTCOME_CORETEX_STATE_ADVANCE,
        deterministicDeltaPpm: 10,
        localModelDeltaPpm: 0,
        parentMatchesLiveRoot: true,
        liveStateAdvanced: true,
        qualifiedScreenerPassesSinceLastStateAdvance: 500,
      }),
      { qualified: true, reason: 'OK', workUnitsBps: 120_000n },
    );
  });

  test('relevant near-collision scorer is a gate, not a reward shortcut', () => {
    assert.equal(
      evaluateCoreTexWorkQualification({
        outcome: OUTCOME_CORETEX_SCREENER_PASS,
        deterministicDeltaPpm: 10,
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
  });
});
