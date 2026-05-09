import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

import {
  buildBundleManifest,
  verifyBundleManifest,
  qwen3Reranker06BManifest,
  QWEN3_RERANKER_DEFAULT_REVISION,
} from '../../dist/index.js';

const repoRoot = fileURLToPath(new URL('../../../..', import.meta.url));

describe('CoreTex client bundle manifest', () => {
  test('builds and verifies a deterministic manifest', () => {
    const model = qwen3Reranker06BManifest('0123456789abcdef0123456789abcdef01234567', [
      {
        path: 'model.safetensors',
        sha256: 'a'.repeat(64),
        bytes: 1,
      },
    ]);
    const manifest = buildBundleManifest({
      repoRoot,
      corpusRoot: '0x' + '11'.repeat(32),
      corpusFiles: ['benchmark/fixtures/season1/coretex_season1_10000.json'],
      model,
    });

    assert.equal(manifest.schemaVersion, 'coretex.client-bundle.v1');
    assert.equal(manifest.substrate.wordCount, 1024);
    assert.equal(manifest.substrate.packedBytes, 32768);
    assert.equal(manifest.model.modelId, 'Qwen/Qwen3-Reranker-0.6B');
    assert.match(manifest.bundleHash, /^0x[0-9a-f]{64}$/);
    assert.deepEqual(verifyBundleManifest(manifest, repoRoot), []);
  });

  test('requires a pinned model revision', () => {
    for (const revision of ['main', 'latest', 'HEAD', 'placeholder', 'TODO', 'v0.1.0', 'release-tag']) {
      const model = qwen3Reranker06BManifest(revision, [
        { path: 'model.safetensors', sha256: 'a'.repeat(64), bytes: 1 },
      ]);
      assert.throws(() => buildBundleManifest({
        repoRoot,
        corpusRoot: '0x' + '11'.repeat(32),
        corpusFiles: ['benchmark/fixtures/season1/coretex_season1_10000.json'],
        model,
      }), /model.revision/);
    }
  });

  test('default Qwen3 manifest pins revision and per-file SHA-256s', () => {
    assert.match(QWEN3_RERANKER_DEFAULT_REVISION, /^[0-9a-f]{40}$/);
    const model = qwen3Reranker06BManifest();
    assert.equal(model.revision, QWEN3_RERANKER_DEFAULT_REVISION);
    assert.ok(model.files.length >= 10);
    assert.ok(model.files.every((file) => /^[0-9a-f]{64}$/.test(file.sha256)));
    assert.ok(model.files.every((file) => Number.isSafeInteger(file.bytes) && file.bytes > 0));
  });
});
