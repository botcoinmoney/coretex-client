import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

let difficulty;
try {
  difficulty = await import('../../dist/rewards/difficulty.js');
} catch (e) {
  console.error('Could not import from dist/. Run `npm run build` first.');
  console.error('Error:', e.message);
  process.exit(1);
}

const {
  MIN_IMPROVEMENT_PPM,
  MAX_IMPROVEMENT_PPM,
  nextMinImprovementPpm,
  difficultyHistogram,
} = difficulty;

describe('CoreTex V4 difficulty calculator', () => {
  test('constants are correct bigints', () => {
    assert.equal(MIN_IMPROVEMENT_PPM, 500n);
    assert.equal(MAX_IMPROVEMENT_PPM, 150_000n);
  });

  test('ramp up: observed > target scales difficulty up by bounded ratio', () => {
    // observed=10, target=5 → raw ratio=2.0, clamped to rampUpMaxRatio=1.5
    const current = 50_000n;
    const result = nextMinImprovementPpm({
      current,
      observedAdvances: 10,
      targetAdvances: 5,
      qualityAttempts: 8,
    });
    assert.equal(result.reason, 'ramp_up');
    assert.equal(result.ratioApplied, 1.5); // bounded at default rampUpMaxRatio
    assert.ok(result.next > current, 'next should be greater than current');
    assert.equal(result.next, 75_000n); // 50_000 * 1.5
    assert.equal(result.clamped, false);
  });

  test('ramp up: ratio within cap is applied directly', () => {
    // observed=6, target=5 → raw ratio=1.2, within cap of 1.5
    const current = 10_000n;
    const result = nextMinImprovementPpm({
      current,
      observedAdvances: 6,
      targetAdvances: 5,
      qualityAttempts: 0,
    });
    assert.equal(result.reason, 'ramp_up');
    assert.equal(result.ratioApplied, 1.2);
    assert.equal(result.next, 12_000n);
    assert.equal(result.clamped, false);
  });

  test('decay: observed=0 with high qualityAttempts decreases difficulty', () => {
    // qualityHighThreshold = 4 * targetAdvances = 4 * 5 = 20
    // qualityAttempts=20 >= 20 → decay
    const current = 20_000n;
    const result = nextMinImprovementPpm({
      current,
      observedAdvances: 0,
      targetAdvances: 5,
      qualityAttempts: 20,
    });
    assert.equal(result.reason, 'decay');
    assert.ok(result.next < current, 'next should be less than current');
    // 20_000 * 0.85 = 17_000
    assert.equal(result.next, 17_000n);
    assert.equal(result.clamped, false);
  });

  test('no change: observed === target leaves difficulty unchanged', () => {
    const current = 30_000n;
    const result = nextMinImprovementPpm({
      current,
      observedAdvances: 5,
      targetAdvances: 5,
      qualityAttempts: 3,
    });
    assert.equal(result.reason, 'no_change');
    assert.equal(result.next, current);
    assert.equal(result.ratioApplied, 1.0);
    assert.equal(result.clamped, false);
  });

  test('small drift down: observed=0 and qualityAttempts=0 drifts toward floor', () => {
    const current = 40_000n;
    const result = nextMinImprovementPpm({
      current,
      observedAdvances: 0,
      targetAdvances: 5,
      qualityAttempts: 0,
    });
    assert.equal(result.reason, 'small_drift_down');
    // 40_000 * 0.95 = 38_000
    assert.equal(result.next, 38_000n);
    assert.equal(result.clamped, false);
  });

  test('under-target recovery: observed < target with quality attempts eases difficulty', () => {
    // observed=2, target=5, qualityAttempts=10 → under_target_recovery
    const current = 20_000n;
    const result = nextMinImprovementPpm({
      current,
      observedAdvances: 2,
      targetAdvances: 5,
      qualityAttempts: 10,
    });
    assert.equal(result.reason, 'under_target_recovery');
    // 20_000 * 0.95 = 19_000
    assert.equal(result.next, 19_000n);
    assert.equal(result.clamped, false);
  });

  test('custom underTargetRecoveryRatio is respected', () => {
    const current = 20_000n;
    const result = nextMinImprovementPpm({
      current,
      observedAdvances: 2,
      targetAdvances: 5,
      qualityAttempts: 10,
      underTargetRecoveryRatio: 0.9,
    });
    assert.equal(result.reason, 'under_target_recovery');
    assert.equal(result.next, 18_000n);
  });

  test('ceiling clamp: ramp-up cannot exceed MAX_IMPROVEMENT_PPM', () => {
    // current=149_000, ratio=1.5 → unclamped=223_500, clamped to 150_000
    const current = 149_000n;
    const result = nextMinImprovementPpm({
      current,
      observedAdvances: 10,
      targetAdvances: 5,
      qualityAttempts: 8,
    });
    assert.equal(result.reason, 'ramp_up');
    assert.equal(result.next, MAX_IMPROVEMENT_PPM);
    assert.equal(result.clamped, true);
  });

  test('floor clamp: decay cannot go below MIN_IMPROVEMENT_PPM', () => {
    // current=600 * 0.85 = 510 → not clamped
    // Use a smaller current to force a floor hit: 550 * 0.85 = 468 < 500
    const current = 550n;
    const result = nextMinImprovementPpm({
      current,
      observedAdvances: 0,
      targetAdvances: 5,
      qualityAttempts: 20, // >= 4*5=20 → decay
    });
    assert.equal(result.reason, 'decay');
    assert.equal(result.next, MIN_IMPROVEMENT_PPM);
    assert.equal(result.clamped, true);
  });

  test('floor clamp: small_drift_down at floor stays at floor', () => {
    // current=600 * 0.85 (decay) = 510 → not clamped
    // current=520 * 0.95 = 494 < 500 → clamped
    const current = 520n;
    const result = nextMinImprovementPpm({
      current,
      observedAdvances: 0,
      targetAdvances: 5,
      qualityAttempts: 0,
    });
    assert.equal(result.reason, 'small_drift_down');
    assert.equal(result.next, MIN_IMPROVEMENT_PPM);
    assert.equal(result.clamped, true);
  });

  test('targetAdvances <= 0 returns current clamped with no_change', () => {
    const current = 50_000n;
    const result = nextMinImprovementPpm({
      current,
      observedAdvances: 5,
      targetAdvances: 0,
      qualityAttempts: 10,
    });
    assert.equal(result.reason, 'no_change');
    assert.equal(result.next, current);
    assert.equal(result.ratioApplied, 1.0);
  });

  test('custom qualityHighThreshold overrides default', () => {
    // qualityHighThreshold=30, qualityAttempts=20 → NOT high enough → no decay
    // Since observedAdvances=0 < targetAdvances=5 AND qualityAttempts(20) > 0,
    // the under_target_recovery branch fires instead.
    const current = 20_000n;
    const result = nextMinImprovementPpm({
      current,
      observedAdvances: 0,
      targetAdvances: 5,
      qualityAttempts: 20,
      qualityHighThreshold: 30,
    });
    // decay branch requires qualityAttempts >= qualityHighThreshold (20 < 30) → no decay
    // small_drift_down requires qualityAttempts === 0 → doesn't apply
    // under_target_recovery requires observedAdvances < targetAdvances AND qualityAttempts > 0 → fires
    assert.equal(result.reason, 'under_target_recovery');
    assert.equal(result.next, 19_000n); // 20_000 * 0.95
  });

  test('custom rampUpMaxRatio is respected', () => {
    const current = 10_000n;
    const result = nextMinImprovementPpm({
      current,
      observedAdvances: 10,
      targetAdvances: 5,
      qualityAttempts: 0,
      rampUpMaxRatio: 2.0,
    });
    assert.equal(result.reason, 'ramp_up');
    // raw ratio=2.0, capped at 2.0 → 10_000 * 2 = 20_000
    assert.equal(result.next, 20_000n);
  });

  test('calibration-only maxClampPpm override lets ramp-up exceed the pinned ceiling', () => {
    // Default behavior: 149_000 * 1.5 = 223_500 clamps to MAX (150_000).
    // With maxClampPpm=300_000 the calibration harness can measure the
    // response surface above the pinned ceiling.
    const current = 149_000n;
    const result = nextMinImprovementPpm({
      current,
      observedAdvances: 10,
      targetAdvances: 5,
      qualityAttempts: 8,
      maxClampPpm: 300_000n,
    });
    assert.equal(result.reason, 'ramp_up');
    assert.equal(result.next, 223_500n); // 149_000 * 1.5, no longer clamped at 150_000
    assert.equal(result.clamped, false);
  });

  test('calibration-only minClampPpm override raises the effective floor', () => {
    // decay 10_000 * 0.85 = 8_500; with minClampPpm=9_000 it clamps up to 9_000.
    const current = 10_000n;
    const result = nextMinImprovementPpm({
      current,
      observedAdvances: 0,
      targetAdvances: 5,
      qualityAttempts: 20,
      minClampPpm: 9_000n,
    });
    assert.equal(result.reason, 'decay');
    assert.equal(result.next, 9_000n);
    assert.equal(result.clamped, true);
  });

  test('clamp overrides default to pinned constants when undefined / non-sensible', () => {
    // undefined → pinned MAX; a maxClampPpm <= floor is ignored (falls back to MAX).
    const a = nextMinImprovementPpm({ current: 149_000n, observedAdvances: 10, targetAdvances: 5, qualityAttempts: 8 });
    assert.equal(a.next, MAX_IMPROVEMENT_PPM);
    const b = nextMinImprovementPpm({ current: 149_000n, observedAdvances: 10, targetAdvances: 5, qualityAttempts: 8, maxClampPpm: 500n });
    assert.equal(b.next, MAX_IMPROVEMENT_PPM); // <= floor → ignored
    const c = nextMinImprovementPpm({ current: 10_000n, observedAdvances: 0, targetAdvances: 5, qualityAttempts: 20, minClampPpm: -5n });
    assert.equal(c.next, 8_500n); // negative floor ignored → normal decay, no clamp
    assert.equal(c.clamped, false);
  });

  test('difficultyHistogram: correct counts over a short sequence', () => {
    const snapshots = [
      // epoch 1: ramp up (10 > 5)
      { epoch: 1, current: 10_000n, observedAdvances: 10, targetAdvances: 5, qualityAttempts: 8 },
      // epoch 2: decay (0 advances, qualityAttempts=20 >= 4*5)
      { epoch: 2, current: 20_000n, observedAdvances: 0, targetAdvances: 5, qualityAttempts: 20 },
      // epoch 3: no change (observed==target)
      { epoch: 3, current: 30_000n, observedAdvances: 5, targetAdvances: 5, qualityAttempts: 3 },
      // epoch 4: ramp up clamped (pushes above 150_000)
      { epoch: 4, current: 149_000n, observedAdvances: 10, targetAdvances: 5, qualityAttempts: 5 },
      // epoch 5: small_drift_down
      { epoch: 5, current: 40_000n, observedAdvances: 0, targetAdvances: 5, qualityAttempts: 0 },
    ];

    const hist = difficultyHistogram(snapshots);

    assert.equal(hist.byEpoch.length, 5);
    assert.equal(hist.rampUps, 2);
    assert.equal(hist.decays, 1);
    assert.equal(hist.clampHits, 1); // epoch 4 hits the ceiling

    // Spot-check individual entries
    assert.equal(hist.byEpoch[0]?.reason, 'ramp_up');
    assert.equal(hist.byEpoch[0]?.epoch, 1);
    assert.equal(hist.byEpoch[1]?.reason, 'decay');
    assert.equal(hist.byEpoch[2]?.reason, 'no_change');
    assert.equal(hist.byEpoch[3]?.next, MAX_IMPROVEMENT_PPM);
    assert.equal(hist.byEpoch[4]?.reason, 'small_drift_down');
  });
});
