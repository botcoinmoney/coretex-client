import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';

import {
  buildCorpusDelta,
  buildEpochRotationManifest,
  hashCorpusDelta,
  signEpochRotationManifest,
  verifyEpochRotationManifestSignature,
} from '../../dist/index.js';

function event(id) {
  return {
    id,
    family: 'long_horizon',
    taskType: 'test:session',
    isProtected: false,
    epochCommitted: 1,
    sourceRef: `test:${id}`,
    queryText: `query ${id}`,
    truthText: `truth ${id}`,
    isStaleTruth: false,
    relevant: true,
    distractors: ['wrong-a', 'wrong-b'],
    relations: ['session:test'],
    expectedStateRegions: ['memory_index', 'relations'],
    validFromEpoch: 1,
    expiresAtEpoch: 0,
    noveltyBucket: 'medium',
    hardnessSignal: 0.5,
  };
}

describe('epoch rotation manifest', () => {
  test('binds corpus delta, challenge book, bundle hash, and difficulty', () => {
    const corpus = {
      events: { near_collision: [], temporal: [], long_horizon: [] },
      sources: {},
      corpusRoot: '0x' + '00'.repeat(32),
    };
    const delta = buildCorpusDelta(corpus, [event('a')], [], 8);
    const manifest = buildEpochRotationManifest({
      epoch: 8,
      delta,
      challengeBook: { epoch: 8, ids: delta.addedIds },
      bundleHash: '0x' + '11'.repeat(32),
      minImprovementPpm: 2500,
      advancesObserved: 12,
      qualityAttemptsObserved: 40,
      generatedAt: '2026-05-09T00:00:00.000Z',
    });

    assert.equal(manifest.previousCorpusRoot, delta.previousRoot);
    assert.equal(manifest.nextCorpusRoot, delta.nextRoot);
    assert.equal(manifest.corpusDeltaHash, hashCorpusDelta(delta));
    assert.equal(manifest.minImprovementPpm, 2500);
    assert.match(manifest.challengeBookHash, /^0x[0-9a-f]{64}$/);
  });

  test('signs and verifies the manifest', () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const corpus = {
      events: { near_collision: [], temporal: [], long_horizon: [] },
      sources: {},
      corpusRoot: '0x' + '00'.repeat(32),
    };
    const delta = buildCorpusDelta(corpus, [event('signed')], [], 9);
    const manifest = buildEpochRotationManifest({
      epoch: 9,
      delta,
      challengeBook: { epoch: 9, ids: delta.addedIds },
      bundleHash: '0x' + '22'.repeat(32),
      minImprovementPpm: 3000,
      advancesObserved: 15,
      qualityAttemptsObserved: 32,
      generatedAt: '2026-05-09T00:00:00.000Z',
    });
    const signed = signEpochRotationManifest(
      manifest,
      privateKey.export({ type: 'pkcs1', format: 'pem' }),
      'test-key',
    );

    assert.equal(signed.signer.keyId, 'test-key');
    assert.equal(verifyEpochRotationManifestSignature(
      signed,
      publicKey.export({ type: 'pkcs1', format: 'pem' }),
    ), true);
    assert.equal(verifyEpochRotationManifestSignature(
      { ...signed, minImprovementPpm: 1 },
      publicKey.export({ type: 'pkcs1', format: 'pem' }),
    ), false);
  });
});
