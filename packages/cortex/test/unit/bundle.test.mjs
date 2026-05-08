import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

import {
  buildBundleManifest,
  verifyBundleManifest,
  qwen3Reranker06BManifest,
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
    const model = qwen3Reranker06BManifest('main', [
      { path: 'model.safetensors', sha256: 'a'.repeat(64) },
    ]);
    assert.throws(() => buildBundleManifest({
      repoRoot,
      corpusRoot: '0x' + '11'.repeat(32),
      corpusFiles: ['benchmark/fixtures/season1/coretex_season1_10000.json'],
      model,
    }), /model.revision/);
  });
});
