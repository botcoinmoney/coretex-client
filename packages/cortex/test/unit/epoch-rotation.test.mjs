import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';

import {
  buildCorpusDelta,
  buildEpochRotationManifest,
  hashCorpusDelta,
  makeEpochFrontier,
  pruneEpochFrontierState,
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
      baselineParentScorePpm: 288438,
      baselineVarianceSource: 'unavailable',
      fixedPackRepeatabilityPpm: 0,
      screenerThresholdPpm: 347,
      recentNoiseFloorPpm: 12,
      controller: {
        inputs: { current: '2500', observedAdvances: 12, targetAdvances: 3, qualityAttempts: 40 },
        output: { next: '3750', reason: 'ramp_up', ratioApplied: 1.5, clamped: false },
        reason: 'ramp_up',
      },
      activeFrontierRoot: '0x' + '09'.repeat(32),
      hiddenSeedCommit: '0x' + 'cc'.repeat(32),
      advancesObserved: 12,
      qualityAttemptsObserved: 40,
      generatedAt: '2026-05-09T00:00:00.000Z',
    });

    assert.equal(manifest.previousCorpusRoot, delta.previousRoot);
    assert.equal(manifest.nextCorpusRoot, delta.nextRoot);
    assert.equal(manifest.corpusDeltaHash, hashCorpusDelta(delta));
    assert.equal(manifest.minImprovementPpm, 2500);
    assert.equal(manifest.baselineParentScorePpm, 288438);
    assert.equal(manifest.screenerThresholdPpm, 347);
    assert.equal(manifest.controller.reason, 'ramp_up');
    assert.equal(manifest.activeFrontierRoot, '0x' + '09'.repeat(32));
    assert.equal(manifest.hiddenSeedCommit, '0x' + 'cc'.repeat(32));
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

describe('pruneEpochFrontierState (hidden-row retirement support)', () => {
  const state = {
    schemaVersion: 'coretex.epoch-frontier-state.v1',
    order: ['a', 'b', 'c', 'd', 'e'],
    reservePtr: 3, // a,b,c consumed; d,e in reserve
    active: [['a', 1], ['c', 2]],
    retired: ['b'],
    cumulativeActivated: 3,
    cumulativeRetired: 1,
    initialized: true,
    injectedSinceLastStep: 0,
    ewmaAccepts: 0.5,
  };

  test('drops unknown ids from order/active/retired and shifts reservePtr', () => {
    const known = new Set(['a', 'c', 'e']); // b removed (before ptr), d removed (after ptr)
    const { state: pruned, prunedOrderIds, prunedActiveIds, prunedRetiredIds } = pruneEpochFrontierState(state, (id) => known.has(id));
    assert.deepEqual(pruned.order, ['a', 'c', 'e']);
    assert.equal(pruned.reservePtr, 2, 'one pruned id ahead of the pointer shifts it left by one');
    assert.deepEqual(pruned.active, [['a', 1], ['c', 2]]);
    assert.deepEqual(pruned.retired, []);
    assert.deepEqual(prunedOrderIds, ['b', 'd']);
    assert.deepEqual(prunedActiveIds, []);
    assert.deepEqual(prunedRetiredIds, ['b']);
    assert.equal(pruned.cumulativeRetired, 1, 'cumulative counters preserved');
  });

  test('reports forced ACTIVE prunes (each is an activeFrontierRoot change)', () => {
    const known = new Set(['b', 'c', 'd', 'e']);
    const { state: pruned, prunedActiveIds } = pruneEpochFrontierState(state, (id) => known.has(id));
    assert.deepEqual(prunedActiveIds, ['a']);
    assert.deepEqual(pruned.active, [['c', 2]]);
  });

  test('pruned state re-hydrates makeEpochFrontier where the unpruned state throws', () => {
    const survivors = ['a', 'c', 'e'];
    const familyOf = () => 'temporal';
    assert.throws(() => makeEpochFrontier({
      evalHiddenIds: survivors, familyOf, mode: 'C3', activeWindow: 2, seed: 'p', initialState: state,
    }), /unknown id/);
    const { state: pruned } = pruneEpochFrontierState(state, (id) => survivors.includes(id));
    const frontier = makeEpochFrontier({
      evalHiddenIds: survivors, familyOf, mode: 'C3', activeWindow: 2, seed: 'p', initialState: pruned,
    });
    const snap = frontier.stepEpoch(3, 1, 2);
    assert.ok(snap.activeRoot && !/^0x0+$/.test(snap.activeRoot));
  });

  test('rejects unsupported schema', () => {
    assert.throws(() => pruneEpochFrontierState({ ...state, schemaVersion: 'bogus' }, () => true), /unsupported schema/);
  });
});
