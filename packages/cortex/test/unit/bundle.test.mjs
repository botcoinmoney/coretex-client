import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

import {
  buildBundleManifest,
  verifyBundleManifest,
  qwen3Reranker06BManifest,
  bgeM3DenseManifest,
  memRerankerManifest,
  QWEN3_RERANKER_DEFAULT_REVISION,
  BGE_M3_DEFAULT_LAYOUT,
} from '../../dist/index.js';

const repoRoot = fileURLToPath(new URL('../../../..', import.meta.url));

const VALID_REV_A = '0123456789abcdef0123456789abcdef01234567';
const VALID_REV_B = '89abcdef0123456789abcdef0123456789abcdef';
const VALID_REV_C = 'cafebabedeadbeefcafebabedeadbeefcafebabe';

function bgeManifestFixture(rev = VALID_REV_A) {
  return bgeM3DenseManifest({
    revision: rev,
    files: [{ path: 'model.safetensors', sha256: 'a'.repeat(64), bytes: 1 }],
  });
}

function rerankerFixture(rev = VALID_REV_B) {
  return qwen3Reranker06BManifest({
    revision: rev,
    files: [{ path: 'model.safetensors', sha256: 'b'.repeat(64), bytes: 1 }],
  });
}

function labelingFixture(rev = VALID_REV_C) {
  return memRerankerManifest({
    modelId: 'memreranker/4B',
    revision: rev,
    files: [{ path: 'model.safetensors', sha256: 'c'.repeat(64), bytes: 1 }],
  });
}

describe('CoreTex client bundle manifest', () => {
  test('builds and verifies a deterministic manifest with bi-encoder + reranker + labeling', () => {
    const manifest = buildBundleManifest({
      repoRoot,
      corpusRoot: '0x' + '11'.repeat(32),
      corpusFiles: [],
      biEncoder: bgeManifestFixture(),
      reranker: rerankerFixture(),
      labelingReranker: labelingFixture(),
    });

    assert.equal(manifest.schemaVersion, 'coretex.client-bundle.v2');
    assert.equal(manifest.substrate.wordCount, 1024);
    assert.equal(manifest.substrate.packedBytes, 32768);
    assert.equal(manifest.model.biEncoder.modelId, 'BAAI/bge-m3');
    assert.equal(manifest.model.reranker.modelId, 'Qwen/Qwen3-Reranker-0.6B');
    assert.equal(manifest.model.labelingReranker.modelId, 'memreranker/4B');
    assert.equal(manifest.evaluator.profile.acceleratorPolicy, 'cpu_only');
    assert.equal(manifest.evaluator.profile.primaryMetric, 'ndcg@10');
    assert.ok(manifest.evaluator.profile.compositeWeights.w_retrieval >= 0.7);
    assert.match(manifest.bundleHash, /^0x[0-9a-f]{64}$/);
    assert.deepEqual(verifyBundleManifest(manifest, repoRoot), []);
  });

  test('rejects mutable / placeholder revisions on bi-encoder and reranker', () => {
    for (const revision of ['main', 'latest', 'HEAD', 'placeholder', 'TODO', 'v0.1.0', 'release-tag']) {
      const ranked = qwen3Reranker06BManifest({ revision, files: [{ path: 'm', sha256: 'a'.repeat(64), bytes: 1 }] });
      assert.throws(() => buildBundleManifest({
        repoRoot,
        corpusRoot: '0x' + '11'.repeat(32),
        corpusFiles: [],
        biEncoder: bgeManifestFixture(),
        reranker: ranked,
        labelingReranker: labelingFixture(),
      }), /revision/);
    }
  });

  test('rejects identical labeling and production reranker', () => {
    const same = qwen3Reranker06BManifest({ revision: VALID_REV_B, files: [{ path: 'm', sha256: 'b'.repeat(64), bytes: 1 }] });
    assert.throws(() => buildBundleManifest({
      repoRoot,
      corpusRoot: '0x' + '11'.repeat(32),
      corpusFiles: [],
      biEncoder: bgeManifestFixture(),
      reranker: same,
      labelingReranker: same,
    }), /labelingReranker/);
  });

  test('default Qwen3 manifest pins revision and per-file SHA-256s', () => {
    assert.match(QWEN3_RERANKER_DEFAULT_REVISION, /^[0-9a-f]{40}$/);
    const model = qwen3Reranker06BManifest();
    assert.equal(model.revision, QWEN3_RERANKER_DEFAULT_REVISION);
    assert.ok(model.files.length >= 10);
    assert.ok(model.files.every((file) => /^[0-9a-f]{64}$/.test(file.sha256)));
    assert.ok(model.files.every((file) => Number.isSafeInteger(file.bytes) && file.bytes > 0));
  });

  test('BGE-M3 default layout fits within 256-byte slot', () => {
    assert.equal(BGE_M3_DEFAULT_LAYOUT.headerBytes, 9);
    assert.equal(BGE_M3_DEFAULT_LAYOUT.quantization, 'int8');
    // int8 payload is 4-byte scale + dim bytes and must fit in the 256-byte slot.
    assert.ok(4 + BGE_M3_DEFAULT_LAYOUT.dim + BGE_M3_DEFAULT_LAYOUT.headerBytes <= 256);
  });
});
