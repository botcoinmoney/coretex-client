/**
 * Bundle profile must pin baseRpcConfig (chain id, block time,
 * targetBlockOffset, replayBlockhashLookbackBlocks).
 *
 * Per docs/CORETEX_V4_ONCHAIN_RANDOMNESS_PLAN.md — replay watchers
 * need the chain config + lookback depth alongside the bundle so they
 * can verify per-patch eval seeds were derived against the correct
 * future blockhash.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { DEFAULT_PROFILE, DEFAULT_BASE_RPC_CONFIG, verifyBundleManifest, buildBundleManifest } from '../../dist/index.js';

const REPO_ROOT = '/root/cortex'; // tests run with package CWD; unused by validateProfile

function makeManifestWithProfile(profile) {
  return {
    schemaVersion: 'coretex.client-bundle.v2',
    generatedAt: '2026-05-11T00:00:00.000Z',
    bundleName: 'test',
    substrate: { wordCount: 1024, packedBytes: 32768, specs: [], implementation: [] },
    corpus: { root: `0x${'00'.repeat(32)}`, files: [] },
    evaluator: { files: [], profile },
    model: {
      biEncoder: { modelId: 'BAAI/bge-m3', revision: 'a' + 'b'.repeat(39), files: [], retrievalKeyLayout: { dim: 1024, dtype: 'float32' } },
      reranker: { modelId: 'Qwen/Qwen3-Reranker-0.6B', revision: 'c' + 'd'.repeat(39), files: [] },
      labelingReranker: { modelId: 'memreranker/4B', revision: 'e' + 'f'.repeat(39), files: [] },
    },
    replay: { commands: [], coordinatorCacheOptional: true, snapshots: [] },
    signing: { coordinatorPublicKey: '', evaluatorPublicKey: '' },
    bundleHash: `0x${'11'.repeat(32)}`,
  };
}

describe('DEFAULT_BASE_RPC_CONFIG', () => {
  test('is exported and has Base mainnet values', () => {
    assert.equal(DEFAULT_BASE_RPC_CONFIG.chainId, 8453);
    assert.equal(DEFAULT_BASE_RPC_CONFIG.blockTimeSeconds, 2);
    assert.equal(DEFAULT_BASE_RPC_CONFIG.targetBlockOffset, 30, 'default offset ≈ 60 s on Base — aligned with per-miner rate limit');
    // Must cover one full epoch (24 h = 43_200 blocks @ 2 s) + the offset.
    const minLookback = 43_200 + 30;
    assert.ok(DEFAULT_BASE_RPC_CONFIG.replayBlockhashLookbackBlocks >= minLookback, 'lookback must cover one epoch + offset');
  });
});

describe('DEFAULT_PROFILE.baseRpcConfig', () => {
  test('is present and matches the exported default', () => {
    assert.deepEqual(DEFAULT_PROFILE.baseRpcConfig, DEFAULT_BASE_RPC_CONFIG);
  });
});

describe('validateProfile — baseRpcConfig', () => {
  // We exercise validateProfile indirectly through verifyBundleManifest
  // since the validator isn't a public export. Each test mutates the
  // default profile, builds a manifest, and checks the error list.

  test('a bundle with the default config validates clean (no rpc-related errors)', () => {
    const m = makeManifestWithProfile(DEFAULT_PROFILE);
    const errors = verifyBundleManifest(m, REPO_ROOT);
    const rpcErrors = errors.filter((e) => /baseRpcConfig/.test(e));
    assert.deepEqual(rpcErrors, [], `unexpected rpc errors: ${JSON.stringify(rpcErrors)}`);
  });

  test('refuses missing baseRpcConfig', () => {
    const profile = { ...DEFAULT_PROFILE };
    delete profile.baseRpcConfig;
    const m = makeManifestWithProfile(profile);
    const errors = verifyBundleManifest(m, REPO_ROOT);
    assert.ok(errors.some((e) => /baseRpcConfig is required/.test(e)), `expected required-field error in ${JSON.stringify(errors)}`);
  });

  test('refuses non-positive chainId', () => {
    const profile = { ...DEFAULT_PROFILE, baseRpcConfig: { ...DEFAULT_BASE_RPC_CONFIG, chainId: 0 } };
    const m = makeManifestWithProfile(profile);
    const errors = verifyBundleManifest(m, REPO_ROOT);
    assert.ok(errors.some((e) => /chainId/.test(e)));
  });

  test('refuses non-positive blockTimeSeconds', () => {
    const profile = { ...DEFAULT_PROFILE, baseRpcConfig: { ...DEFAULT_BASE_RPC_CONFIG, blockTimeSeconds: 0 } };
    const m = makeManifestWithProfile(profile);
    const errors = verifyBundleManifest(m, REPO_ROOT);
    assert.ok(errors.some((e) => /blockTimeSeconds/.test(e)));
  });

  test('refuses non-positive targetBlockOffset', () => {
    const profile = { ...DEFAULT_PROFILE, baseRpcConfig: { ...DEFAULT_BASE_RPC_CONFIG, targetBlockOffset: 0 } };
    const m = makeManifestWithProfile(profile);
    const errors = verifyBundleManifest(m, REPO_ROOT);
    assert.ok(errors.some((e) => /targetBlockOffset/.test(e)));
  });

  test('refuses too-short replayBlockhashLookbackBlocks (must cover one epoch + offset)', () => {
    const profile = {
      ...DEFAULT_PROFILE,
      baseRpcConfig: { ...DEFAULT_BASE_RPC_CONFIG, replayBlockhashLookbackBlocks: 100 },
    };
    const m = makeManifestWithProfile(profile);
    const errors = verifyBundleManifest(m, REPO_ROOT);
    assert.ok(errors.some((e) => /replayBlockhashLookbackBlocks/.test(e) && /must cover/.test(e)));
  });

  test('accepts a different chain config so long as the lookback math holds', () => {
    // A faster-block-time chain still validates if the lookback covers
    // its epoch — the rule is "lookback >= epoch_seconds / block_time + offset",
    // not a hard-coded number.
    const fastChain = { chainId: 1, blockTimeSeconds: 1, targetBlockOffset: 60, replayBlockhashLookbackBlocks: 90_000 };
    const profile = { ...DEFAULT_PROFILE, baseRpcConfig: fastChain };
    const m = makeManifestWithProfile(profile);
    const errors = verifyBundleManifest(m, REPO_ROOT);
    const rpcErrors = errors.filter((e) => /baseRpcConfig/.test(e));
    assert.deepEqual(rpcErrors, []);
  });
});
