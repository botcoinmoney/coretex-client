import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';

import {
  buildCorpusDelta,
  buildEpochRotationManifest,
  hashCorpusDelta,
  signEpochRotationManifest,
  verifyEpochRotationManifestSignature,
  splitForRecord,
  computeCorpusRoot,
} from '../../dist/index.js';

const BI_ENCODER = { modelId: 'BAAI/bge-m3', revision: 'a'.repeat(40) };
const LAYOUT = { dim: 32, quantization: 'int8', headerBytes: 9 };

function event(id, corpusEpoch = 0) {
  const split = splitForRecord(id, corpusEpoch);
  return {
    id,
    family: 'long_horizon',
    domain: 'companies',
    split,
    queryText: `query ${id}`,
    truthDocuments: [{ id: `${id}::truth`, text: `truth ${id}`, isCurrent: true }],
    hardNegatives: [
      { id: `${id}::neg0`, text: `wrong-a ${id}` },
      { id: `${id}::neg1`, text: `wrong-b ${id}` },
    ],
    qrels: [
      { documentId: `${id}::truth`, relevance: 1.0 },
      { documentId: `${id}::neg0`, relevance: 0.0 },
      { documentId: `${id}::neg1`, relevance: 0.2 },
    ],
    protected: false,
    provenance: { source: 'synthetic_challenge', sourceHash: '0x' + 'aa'.repeat(32) },
    embeddings: {
      modelId: BI_ENCODER.modelId,
      revision: BI_ENCODER.revision,
      layout: LAYOUT,
      query: new Uint8Array(LAYOUT.dim + 4),
      perTruth: new Map([[`${id}::truth`, new Uint8Array(LAYOUT.dim + 4)]]),
      perNegative: new Map([
        [`${id}::neg0`, new Uint8Array(LAYOUT.dim + 4)],
        [`${id}::neg1`, new Uint8Array(LAYOUT.dim + 4)],
      ]),
    },
  };
}

function emptyCorpus(corpusEpoch = 0) {
  return {
    events: [],
    byId: new Map(),
    corpusRoot: computeCorpusRoot([]),
    corpusEpoch,
    biEncoderModelId: BI_ENCODER.modelId,
    biEncoderRevision: BI_ENCODER.revision,
    biEncoderRetrievalKeyLayout: LAYOUT,
    labelingModelId: 'memreranker/4B',
    labelingModelRevision: 'b'.repeat(40),
  };
}

const labelingProvenance = {
  modelId: 'memreranker/4B',
  revision: 'b'.repeat(40),
  runtime: 'torch-transformers@2.4.* / 4.46.* (cpu)',
  batchHash: 'c'.repeat(64),
};

describe('epoch rotation manifest', () => {
  test('binds corpus delta, challenge book, bundle hash, and difficulty', () => {
    const corpus = emptyCorpus(0);
    const delta = buildCorpusDelta({
      previousCorpus: corpus,
      additions: [event('a', 0)],
      removals: [],
      epoch: 8,
      labelingProvenance,
      generatedAt: '2026-05-09T00:00:00.000Z',
    });
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
    const corpus = emptyCorpus(0);
    const delta = buildCorpusDelta({
      previousCorpus: corpus,
      additions: [event('signed', 0)],
      removals: [],
      epoch: 9,
      labelingProvenance,
      generatedAt: '2026-05-09T00:00:00.000Z',
    });
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
