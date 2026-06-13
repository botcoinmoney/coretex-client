import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  deriveBaselineSampleSeed,
  summarizeBaselineComposites,
} from '../../../../scripts/lib/baseline-recalibration.mjs';

describe('baseline recalibration script helpers', () => {
  test('fixed seed mode reuses one hidden pack within a cron tick', () => {
    const seed = '0x' + 'ab'.repeat(32);
    assert.equal(deriveBaselineSampleSeed(seed, 0, 'fixed'), seed);
    assert.equal(deriveBaselineSampleSeed(seed, 29, 'fixed'), seed);
  });

  test('rotating seed mode derives distinct sample packs explicitly', () => {
    const seed = '0x' + 'cd'.repeat(32);
    const s0 = deriveBaselineSampleSeed(seed, 0, 'rotating');
    const s1 = deriveBaselineSampleSeed(seed, 1, 'rotating');
    assert.match(s0, /^0x[0-9a-f]{64}$/);
    assert.match(s1, /^0x[0-9a-f]{64}$/);
    assert.notEqual(s0, seed);
    assert.notEqual(s0, s1);
  });

  test('rejects malformed seed policy inputs', () => {
    assert.throws(() => deriveBaselineSampleSeed('0x1234', 0, 'fixed'), /baseline seed/);
    assert.throws(() => deriveBaselineSampleSeed('0x' + 'ab'.repeat(32), -1, 'fixed'), /sampleIndex/);
    assert.throws(() => deriveBaselineSampleSeed('0x' + 'ab'.repeat(32), 0, 'bad'), /sample seed mode/);
  });

  test('summarizes baseline composites in ppm', () => {
    const s = summarizeBaselineComposites([0.05, 0.07]);
    assert.equal(s.mean, 0.060000000000000005);
    assert.equal(s.baselineParentScorePpm, 60000);
    assert.ok(s.stddevPpm > 0);
  });
});
