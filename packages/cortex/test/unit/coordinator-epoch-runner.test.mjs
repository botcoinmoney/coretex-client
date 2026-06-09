import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { frontierCount, mergeCoordinatorEpochMetrics } from '../../../../scripts/coretex-coordinator-epoch-runner.mjs';

describe('coretex coordinator epoch runner metrics merge', () => {
  test('missing CLI flags do not erase metrics-file counters', () => {
    const merged = mergeCoordinatorEpochMetrics({
      prevHonestAccepts: 7,
      prevQualityAttempts: 19,
      acceptedFingerprintReusePpm: 780_000,
    }, ['--epoch', '2']);

    assert.equal(merged.prevHonestAccepts, 7);
    assert.equal(merged.prevQualityAttempts, 19);
    assert.equal(merged.acceptedFingerprintReusePpm, 780_000);
  });

  test('explicit CLI flags override metrics-file counters', () => {
    const merged = mergeCoordinatorEpochMetrics({
      prevHonestAccepts: 7,
      prevQualityAttempts: 19,
    }, ['--prev-honest-accepts', '2', '--prev-quality-attempts', '3']);

    assert.equal(merged.prevHonestAccepts, 2);
    assert.equal(merged.prevQualityAttempts, 3);
  });

  test('missing metrics default to zero only when neither file nor flag supplies them', () => {
    const merged = mergeCoordinatorEpochMetrics({}, []);
    assert.equal(merged.prevHonestAccepts, 0);
    assert.equal(merged.prevQualityAttempts, 0);
  });

  test('frontier counts accept current numeric evolve output and old array output', () => {
    assert.equal(frontierCount(17), 17);
    assert.equal(frontierCount(['a', 'b', 'c']), 3);
    assert.equal(frontierCount(undefined), 0);
  });
});
