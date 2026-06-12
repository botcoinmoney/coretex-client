/**
 * Deterministic self-check for the reranker score-array parity differ
 * (packages/coretex/scripts/reranker-parity-diff.mjs).
 *
 * The differ is the CI-safe half of the scorer parity release gate: it takes
 * two {"scores":[...]} arrays (e.g. CPU fp32 vs 4090 fp32 from the full-pair
 * box harness) and gates the max per-pair score delta, reported as a
 * conservative ppm upper bound, against a budget (default 250 ppm, the launch
 * replayTolerancePpm). This test exercises the differ's verdict + exit-code
 * logic with synthetic score files — NO torch, NO model, no network — so it
 * runs in the fast unit suite and in `coretex:parity-gate`.
 *
 * It does NOT re-derive scores; it pins the differ's gate semantics:
 *   - identical arrays            -> BIT_IDENTICAL, exit 0
 *   - tiny delta inside budget    -> WITHIN_TOLERANCE, exit 0
 *   - delta over budget           -> EXCEEDS_TOLERANCE, exit 1
 *   - length mismatch / bad input -> exit 2 (usage/operator error)
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { tmpdir } from 'node:os';

const here = dirname(fileURLToPath(import.meta.url));
const differ = resolve(here, '..', '..', 'scripts', 'reranker-parity-diff.mjs');

function writeScores(dir, name, scores) {
  const p = join(dir, name);
  writeFileSync(p, JSON.stringify({ scores }));
  return p;
}

function runDiffer(refPath, cmpPath, extra = []) {
  const res = spawnSync(process.execPath, [differ, refPath, cmpPath, ...extra], {
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
  });
  let parsed = null;
  try { parsed = JSON.parse(res.stdout.trim()); } catch { /* exit 2 paths print to stderr */ }
  return { status: res.status, out: parsed, stderr: res.stderr };
}

describe('reranker-parity-diff — gate self-check', () => {
  let dir;
  test('setup tmp', () => { dir = mkdtempSync(join(tmpdir(), 'parity-diff-')); });

  test('bit-identical arrays => BIT_IDENTICAL, exit 0', () => {
    const ref = writeScores(dir, 'ref-id.json', [0.1, 0.5, 0.9, 0.42]);
    const cmp = writeScores(dir, 'cmp-id.json', [0.1, 0.5, 0.9, 0.42]);
    const r = runDiffer(ref, cmp);
    assert.equal(r.status, 0);
    assert.equal(r.out.verdict, 'BIT_IDENTICAL');
    assert.equal(r.out.maxAbsScoreDeltaPpm, 0);
    assert.equal(r.out.pairsWithAnyDelta, 0);
  });

  test('tiny delta inside the ppm budget => WITHIN_TOLERANCE, exit 0', () => {
    // 1e-5 abs delta = 10 ppm, well under the default 250 ppm budget.
    const ref = writeScores(dir, 'ref-tol.json', [0.10000, 0.5, 0.9]);
    const cmp = writeScores(dir, 'cmp-tol.json', [0.10001, 0.5, 0.9]);
    const r = runDiffer(ref, cmp);
    assert.equal(r.status, 0);
    assert.equal(r.out.verdict, 'WITHIN_TOLERANCE');
    assert.ok(r.out.maxAbsScoreDeltaPpm <= r.out.budgetPpm);
    assert.equal(r.out.pairsWithAnyDelta, 1);
  });

  test('delta over budget => EXCEEDS_TOLERANCE, exit 1', () => {
    // 1e-3 abs delta = 1000 ppm > 250 ppm budget.
    const ref = writeScores(dir, 'ref-bad.json', [0.100, 0.5, 0.9]);
    const cmp = writeScores(dir, 'cmp-bad.json', [0.101, 0.5, 0.9]);
    const r = runDiffer(ref, cmp);
    assert.equal(r.status, 1);
    assert.equal(r.out.verdict, 'EXCEEDS_TOLERANCE');
    assert.ok(r.out.maxAbsScoreDeltaPpm > r.out.budgetPpm);
  });

  test('custom --budget-ppm tightens the gate', () => {
    // 5 ppm delta passes the default budget but fails a 1 ppm budget.
    const ref = writeScores(dir, 'ref-bud.json', [0.100000, 0.5]);
    const cmp = writeScores(dir, 'cmp-bud.json', [0.100005, 0.5]);
    const loose = runDiffer(ref, cmp, ['--budget-ppm', '250']);
    assert.equal(loose.status, 0);
    assert.equal(loose.out.verdict, 'WITHIN_TOLERANCE');
    const tight = runDiffer(ref, cmp, ['--budget-ppm', '1']);
    assert.equal(tight.status, 1);
    assert.equal(tight.out.verdict, 'EXCEEDS_TOLERANCE');
  });

  test('length mismatch => operator error exit 2 (not a silent pass)', () => {
    const ref = writeScores(dir, 'ref-len.json', [0.1, 0.2, 0.3]);
    const cmp = writeScores(dir, 'cmp-len.json', [0.1, 0.2]);
    const r = runDiffer(ref, cmp);
    assert.equal(r.status, 2);
    assert.equal(r.out, null);
    assert.match(r.stderr, /length mismatch/);
  });

  test('cleanup tmp', () => { rmSync(dir, { recursive: true, force: true }); });
});
