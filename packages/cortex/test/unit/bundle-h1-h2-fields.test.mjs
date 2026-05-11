/**
 * Phase H1/H2 bundle profile fields — declared optional on
 * EvaluatorProfile and validated all-or-nothing for the baseline
 * group. See docs/CORETEX_V4_INDEFINITE_SCALABILITY_HARDENING_PLAN.md.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

import {
  buildBundleManifest,
  verifyBundleManifest,
  qwen3Reranker06BManifest,
  bgeM3DenseManifest,
  memRerankerManifest,
} from '../../dist/index.js';

const repoRoot = fileURLToPath(new URL('../../../..', import.meta.url));

const VALID_REV_A = '0123456789abcdef0123456789abcdef01234567';
const VALID_REV_B = '89abcdef0123456789abcdef0123456789abcdef';
const VALID_REV_C = 'cafebabedeadbeefcafebabedeadbeefcafebabe';

function biEnc() {
  return bgeM3DenseManifest({
    revision: VALID_REV_A,
    files: [{ path: 'model.safetensors', sha256: 'a'.repeat(64), bytes: 1 }],
  });
}
function reranker() {
  return qwen3Reranker06BManifest({
    revision: VALID_REV_B,
    files: [{ path: 'model.safetensors', sha256: 'b'.repeat(64), bytes: 1 }],
  });
}
function labeling() {
  return memRerankerManifest({
    modelId: 'memreranker/4B',
    revision: VALID_REV_C,
    files: [{ path: 'model.safetensors', sha256: 'c'.repeat(64), bytes: 1 }],
  });
}

describe('EvaluatorProfile H1/H2 fields', () => {
  test('default-built bundle has neither majorDeltaThreshold nor baseline-* fields', () => {
    const m = buildBundleManifest({
      repoRoot,
      corpusRoot: '0x' + '11'.repeat(32),
      corpusFiles: [],
      biEncoder: biEnc(),
      reranker: reranker(),
      labelingReranker: labeling(),
    });
    assert.equal(m.evaluator.profile.majorDeltaThreshold, undefined);
    assert.equal(m.evaluator.profile.baselineParentScorePpm, undefined);
    assert.equal(m.evaluator.profile.baselineVariancePpm, undefined);
    assert.equal(m.evaluator.profile.baselineSamples, undefined);
    assert.equal(m.evaluator.profile.baselineEvalSeedHex, undefined);
    // Defaults must still verify clean.
    assert.deepEqual(verifyBundleManifest(m, repoRoot), []);
  });

  test('majorDeltaThreshold accepts non-negative integer', () => {
    const m = buildBundleManifest({
      repoRoot,
      corpusRoot: '0x' + '11'.repeat(32),
      corpusFiles: [],
      biEncoder: biEnc(),
      reranker: reranker(),
      labelingReranker: labeling(),
      evaluatorProfile: { majorDeltaThreshold: 1000 },
    });
    assert.equal(m.evaluator.profile.majorDeltaThreshold, 1000);
    assert.deepEqual(verifyBundleManifest(m, repoRoot), []);
  });

  test('majorDeltaThreshold rejects negative / non-integer', () => {
    assert.throws(() => buildBundleManifest({
      repoRoot,
      corpusRoot: '0x' + '11'.repeat(32),
      corpusFiles: [],
      biEncoder: biEnc(),
      reranker: reranker(),
      labelingReranker: labeling(),
      evaluatorProfile: { majorDeltaThreshold: -1 },
    }), /majorDeltaThreshold/);
    assert.throws(() => buildBundleManifest({
      repoRoot,
      corpusRoot: '0x' + '11'.repeat(32),
      corpusFiles: [],
      biEncoder: biEnc(),
      reranker: reranker(),
      labelingReranker: labeling(),
      evaluatorProfile: { majorDeltaThreshold: 1.5 },
    }), /majorDeltaThreshold/);
  });

  test('baseline-* fields accepted all-together', () => {
    const m = buildBundleManifest({
      repoRoot,
      corpusRoot: '0x' + '11'.repeat(32),
      corpusFiles: [],
      biEncoder: biEnc(),
      reranker: reranker(),
      labelingReranker: labeling(),
      evaluatorProfile: {
        baselineParentScorePpm: 250_000,
        baselineVariancePpm: 50,
        baselineSamples: 3,
        baselineEvalSeedHex: '0x' + 'ab'.repeat(32),
      },
    });
    assert.equal(m.evaluator.profile.baselineParentScorePpm, 250_000);
    assert.equal(m.evaluator.profile.baselineSamples, 3);
    assert.deepEqual(verifyBundleManifest(m, repoRoot), []);
  });

  test('partial baseline (parent only, missing variance) is rejected', () => {
    assert.throws(() => buildBundleManifest({
      repoRoot,
      corpusRoot: '0x' + '11'.repeat(32),
      corpusFiles: [],
      biEncoder: biEnc(),
      reranker: reranker(),
      labelingReranker: labeling(),
      evaluatorProfile: { baselineParentScorePpm: 250_000 },
    }), /baseline/);
  });

  test('partial baseline (samples only, missing the rest) is rejected', () => {
    assert.throws(() => buildBundleManifest({
      repoRoot,
      corpusRoot: '0x' + '11'.repeat(32),
      corpusFiles: [],
      biEncoder: biEnc(),
      reranker: reranker(),
      labelingReranker: labeling(),
      evaluatorProfile: { baselineSamples: 3 },
    }), /baseline/);
  });

  test('baselineEvalSeedHex must be 32 bytes hex with 0x prefix', () => {
    assert.throws(() => buildBundleManifest({
      repoRoot,
      corpusRoot: '0x' + '11'.repeat(32),
      corpusFiles: [],
      biEncoder: biEnc(),
      reranker: reranker(),
      labelingReranker: labeling(),
      evaluatorProfile: {
        baselineParentScorePpm: 250_000,
        baselineVariancePpm: 0,
        baselineSamples: 1,
        baselineEvalSeedHex: 'not-a-hex-string',
      },
    }), /baselineEvalSeedHex/);
  });

  test('negative baselineParentScorePpm is rejected', () => {
    assert.throws(() => buildBundleManifest({
      repoRoot,
      corpusRoot: '0x' + '11'.repeat(32),
      corpusFiles: [],
      biEncoder: biEnc(),
      reranker: reranker(),
      labelingReranker: labeling(),
      evaluatorProfile: {
        baselineParentScorePpm: -1,
        baselineVariancePpm: 0,
        baselineSamples: 1,
        baselineEvalSeedHex: '0x' + 'ab'.repeat(32),
      },
    }), /baselineParentScorePpm/);
  });
});
