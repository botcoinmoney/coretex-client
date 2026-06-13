import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

import {
  assertBundleBindingAtStartup,
  buildBundleManifest,
  bgeM3DenseManifest,
  evaluateClientVersionPolicy,
  memRerankerManifest,
  qwen3Reranker06BManifest,
  verifyBundleManifest,
  withRecomputedBundleHash,
} from '../../dist/index.js';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));

function makeManifestWithClientPolicy(policy) {
  const manifest = buildBundleManifest({
    repoRoot,
    corpusRoot: '0x' + '11'.repeat(32),
    corpusFiles: [],
    biEncoder: bgeM3DenseManifest({
      revision: '0123456789abcdef0123456789abcdef01234567',
      files: [{ path: 'model.safetensors', sha256: 'a'.repeat(64), bytes: 1 }],
    }),
    reranker: qwen3Reranker06BManifest({
      revision: '89abcdef0123456789abcdef0123456789abcdef',
      files: [{ path: 'model.safetensors', sha256: 'b'.repeat(64), bytes: 1 }],
    }),
    labelingReranker: memRerankerManifest({
      modelId: 'memreranker/4B',
      revision: 'cafebabedeadbeefcafebabedeadbeefcafebabe',
      files: [{ path: 'model.safetensors', sha256: 'c'.repeat(64), bytes: 1 }],
    }),
  });
  return withRecomputedBundleHash({
    ...manifest,
    evaluator: {
      ...manifest.evaluator,
      profile: {
        ...manifest.evaluator.profile,
        clientVersionPolicy: policy,
      },
    },
  });
}

describe('client version policy', () => {
  test('validateProfile accepts semver policy fields', () => {
    const manifest = makeManifestWithClientPolicy({
      minimumVersion: '0.7.0',
      recommendedVersion: '0.7.2',
      hardFailOutdated: true,
    });
    assert.deepEqual(verifyBundleManifest(manifest, repoRoot), []);
  });

  test('evaluateClientVersionPolicy marks outdated clients', () => {
    const result = evaluateClientVersionPolicy(
      { minimumVersion: '0.7.0', hardFailOutdated: true },
      '0.6.9',
    );
    assert.equal(result.ok, false);
    assert.equal(result.code, 'client-version-outdated');
  });

  test('assertBundleBindingAtStartup fails closed when policy is hard-fail', () => {
    const manifest = makeManifestWithClientPolicy({
      minimumVersion: '0.7.0',
      hardFailOutdated: true,
    });
    assert.throws(
      () =>
        assertBundleBindingAtStartup({
          manifest,
          onChainCoreVersionHash: manifest.bundleHash,
          installedRuntimeVersions: {
            torch: '2.6.0',
            transformers: '4.55.1',
            huggingface_hub: '0.36.2',
            tokenizers: '0.21.4',
          },
          clientVersion: '0.6.5',
        }),
      /outdated client refused/,
    );
  });

  test('assertBundleBindingAtStartup allows explicit override for emergency continuity', () => {
    const manifest = makeManifestWithClientPolicy({
      minimumVersion: '0.7.0',
      hardFailOutdated: true,
    });
    assert.doesNotThrow(() =>
      assertBundleBindingAtStartup({
        manifest,
        onChainCoreVersionHash: manifest.bundleHash,
        installedRuntimeVersions: {
          torch: '2.6.0',
          transformers: '4.55.1',
          huggingface_hub: '0.36.2',
          tokenizers: '0.21.4',
        },
        clientVersion: '0.6.5',
        allowOutdatedClient: true,
      }),
    );
  });

  test('assertBundleBindingAtStartup does not brick when client version is omitted during rollout', () => {
    const manifest = makeManifestWithClientPolicy({
      minimumVersion: '0.7.0',
      hardFailOutdated: true,
    });
    assert.doesNotThrow(() =>
      assertBundleBindingAtStartup({
        manifest,
        onChainCoreVersionHash: manifest.bundleHash,
        installedRuntimeVersions: {
          torch: '2.6.0',
          transformers: '4.55.1',
          huggingface_hub: '0.36.2',
          tokenizers: '0.21.4',
        },
      }),
    );
  });

  test('assertBundleBindingAtStartup emits warning when client version is omitted with pinned policy', () => {
    const manifest = makeManifestWithClientPolicy({
      minimumVersion: '0.7.0',
      hardFailOutdated: true,
    });
    let stderr = '';
    const originalWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk, ...rest) => {
      stderr += String(chunk);
      return true;
    });
    try {
      assert.doesNotThrow(() =>
        assertBundleBindingAtStartup({
          manifest,
          onChainCoreVersionHash: manifest.bundleHash,
          installedRuntimeVersions: {
            torch: '2.6.0',
            transformers: '4.55.1',
            huggingface_hub: '0.36.2',
            tokenizers: '0.21.4',
          },
        }),
      );
    } finally {
      process.stderr.write = originalWrite;
    }
    assert.match(stderr, /client version policy is pinned but no client version was provided/);
  });
});
