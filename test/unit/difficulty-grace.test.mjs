import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  nextMinImprovementPpm,
  isMajorDelta,
} from '../../dist/index.js';

describe('major-delta grace', () => {
  test('grace flag short-circuits ramp-up', () => {
    const out = nextMinImprovementPpm({
      current: 10_000n,
      observedAdvances: 100,
      targetAdvances: 5,
      qualityAttempts: 200,
      majorDeltaActive: true,
    });
    assert.equal(out.next, 10_000n, 'threshold must be frozen at current');
    assert.equal(out.reason, 'major_delta_grace');
    assert.equal(out.ratioApplied, 1.0);
    assert.equal(out.clamped, false);
  });

  test('grace flag short-circuits decay', () => {
    const out = nextMinImprovementPpm({
      current: 10_000n,
      observedAdvances: 0,
      targetAdvances: 5,
      qualityAttempts: 100,
      majorDeltaActive: true,
    });
    assert.equal(out.next, 10_000n);
    assert.equal(out.reason, 'major_delta_grace');
  });

  test('grace flag short-circuits drift', () => {
    const out = nextMinImprovementPpm({
      current: 10_000n,
      observedAdvances: 2,
      targetAdvances: 5,
      qualityAttempts: 5,
      majorDeltaActive: true,
    });
    assert.equal(out.next, 10_000n);
    assert.equal(out.reason, 'major_delta_grace');
  });

  test('grace flag clamps current to MIN if it would underflow', () => {
    // current below MIN is clamped to MIN even under grace — the grace
    // is "freeze at the calibrated current", not "freeze at literal current"
    // when the calibrated current was already at the floor.
    const out = nextMinImprovementPpm({
      current: 100n,
      observedAdvances: 100,
      targetAdvances: 5,
      qualityAttempts: 200,
      majorDeltaActive: true,
    });
    assert.equal(out.next, 2_500n, 'clamps to MIN_IMPROVEMENT_PPM floor');
    assert.equal(out.reason, 'major_delta_grace');
  });

  test('majorDeltaActive=false leaves all existing branches intact', () => {
    const noGrace = nextMinImprovementPpm({
      current: 10_000n,
      observedAdvances: 10,
      targetAdvances: 5,
      qualityAttempts: 8,
      majorDeltaActive: false,
    });
    const omitted = nextMinImprovementPpm({
      current: 10_000n,
      observedAdvances: 10,
      targetAdvances: 5,
      qualityAttempts: 8,
    });
    assert.deepEqual(noGrace, omitted, 'explicit false must equal omitted');
    assert.equal(noGrace.reason, 'ramp_up');
  });
});

describe('isMajorDelta', () => {
  test('returns true when delta meets threshold', () => {
    assert.equal(isMajorDelta(15_000, 10_000, 5_000), true);
    assert.equal(isMajorDelta(15_001, 10_000, 5_000), true);
  });

  test('returns false when delta is below threshold', () => {
    assert.equal(isMajorDelta(14_999, 10_000, 5_000), false);
    assert.equal(isMajorDelta(10_000, 10_000, 5_000), false);
  });

  test('returns false on net-removal deltas', () => {
    assert.equal(isMajorDelta(10_000, 15_000, 5_000), false);
  });

  test('zero threshold accepts every additive delta', () => {
    assert.equal(isMajorDelta(10_001, 10_000, 0), true);
    assert.equal(isMajorDelta(10_000, 10_000, 0), true);
  });
});
