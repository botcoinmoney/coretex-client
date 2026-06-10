/**
 * Order-preservation guard for length bucketing in the canonical Qwen reranker
 * runner (packages/cortex/scripts/reranker_runner.py, _score_pairs).
 *
 * Length bucketing sorts prompts by tokenized length, scores them in
 * near-uniform-length buckets (less wasted pad compute), then scatters the
 * per-sequence scores back to their ORIGINAL input index. The returned score
 * order MUST be identical to the input order — that is what keeps the harness
 * pairTraceHash/scoreArrayHash (which see input order) unaffected by bucketing.
 *
 * The runner exposes the pure bucket/un-bucket index math via a stdlib-only
 * --bucket-index-selftest oracle (no torch/transformers): feed a known
 * permutation of varied-length prompts and assert the scattered output is the
 * identity permutation. This test spawns that oracle and asserts the invariant.
 * It SKIPS — loudly — only when python3 is genuinely unavailable.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const RUNNER = fileURLToPath(new URL('../../scripts/reranker_runner.py', import.meta.url));

function python3Available() {
  const probe = spawnSync('python3', ['--version'], { encoding: 'utf8' });
  return !probe.error && probe.status === 0;
}

function selftest(lengths, innerBatch) {
  const res = spawnSync('python3', [RUNNER, '--bucket-index-selftest'], {
    encoding: 'utf8',
    input: lengths === undefined ? '' : JSON.stringify({ lengths, innerBatch }),
  });
  assert.equal(res.status, 0, `runner exited ${res.status}: ${res.stderr}`);
  return JSON.parse(res.stdout);
}

const HAVE_PYTHON = python3Available();
if (!HAVE_PYTHON) {
  // eslint-disable-next-line no-console
  console.error(
    '\n!!! reranker-length-bucketing-order: python3 is NOT available on this host — '
    + 'the length-bucketing order-preservation guard is being SKIPPED. !!!\n',
  );
}

describe('reranker length bucketing — order preservation (bucket/un-bucket index math)', () => {
  test('default fixed permutation: scattered output is the identity (order preserved)', { skip: !HAVE_PYTHON && 'python3 unavailable' }, () => {
    const r = selftest();
    assert.equal(r.orderPreserved, true, 'scattered scores did NOT map back to input order');
    assert.equal(r.coverageOk, true, 'buckets did not cover every original index exactly once');
    assert.deepEqual(r.scatteredOutput, [...Array(r.lengths.length).keys()]);
  });

  test('buckets are sorted ascending by length and are inner_batch-sized', { skip: !HAVE_PYTHON && 'python3 unavailable' }, () => {
    const lengths = [37, 5, 5, 128, 64, 5, 900, 12, 12, 256, 1, 2048, 64, 3];
    const innerBatch = 3;
    const r = selftest(lengths, innerBatch);
    // Sorting key is global (length, original-index): the FLATTENED bucket lengths
    // must be non-decreasing across the whole sequence.
    const flatLengths = r.bucketLengths.flat();
    for (let i = 1; i < flatLengths.length; i++) {
      assert.ok(flatLengths[i] >= flatLengths[i - 1], `bucket lengths not ascending at ${i}: ${flatLengths}`);
    }
    // Every bucket except possibly the last is exactly inner_batch wide.
    for (let b = 0; b < r.buckets.length - 1; b++) {
      assert.equal(r.buckets[b].length, innerBatch, `non-final bucket ${b} is not inner_batch wide`);
    }
    assert.ok(r.buckets[r.buckets.length - 1].length <= innerBatch);
    assert.equal(r.orderPreserved, true);
  });

  test('order is preserved across several permutations + batch sizes (incl. duplicate lengths + ragged final bucket)', { skip: !HAVE_PYTHON && 'python3 unavailable' }, () => {
    const cases = [
      { lengths: [10, 3, 3, 99, 1, 50, 3, 7], innerBatch: 3 },
      { lengths: [1, 1, 1, 1, 1], innerBatch: 8 },               // all-equal lengths
      { lengths: [2048, 1024, 512, 256, 128, 64], innerBatch: 1 }, // strictly descending, batch 1
      { lengths: [5, 4, 3, 2, 1], innerBatch: 2 },                 // ragged final bucket
      { lengths: [42], innerBatch: 8 },                            // single prompt
      { lengths: [], innerBatch: 8 },                              // empty
    ];
    for (const { lengths, innerBatch } of cases) {
      const r = selftest(lengths, innerBatch);
      assert.equal(r.orderPreserved, true, `order NOT preserved for lengths=${JSON.stringify(lengths)} innerBatch=${innerBatch}`);
      assert.equal(r.coverageOk, true, `coverage broken for lengths=${JSON.stringify(lengths)} innerBatch=${innerBatch}`);
      assert.deepEqual(r.scatteredOutput, [...Array(lengths.length).keys()]);
    }
  });

  test('inner_batch < 1 is clamped to 1 (no crash, order preserved)', { skip: !HAVE_PYTHON && 'python3 unavailable' }, () => {
    const r = selftest([3, 1, 2], 0);
    assert.equal(r.orderPreserved, true);
    assert.equal(r.coverageOk, true);
    // Each bucket holds exactly one element when clamped to 1.
    for (const b of r.buckets) assert.equal(b.length, 1);
  });
});
