import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { createRetrievalDataSource } from '../../dist/index.js';

const BUNDLE_HASH = `0x${'ab'.repeat(32)}`;
const ALT_BUNDLE_HASH = `0x${'cd'.repeat(32)}`;

const CORPUS_ROOT = `0x${'11'.repeat(32)}`;
const RETRIEVAL_KEY_LAYOUT = { dim: 243, quantization: 'int8', headerBytes: 9 };

function emptyEmbedding() {
  return {
    modelId: 'BAAI/bge-m3',
    revision: '0123456789abcdef0123456789abcdef01234567',
    layout: RETRIEVAL_KEY_LAYOUT,
    query: new Uint8Array([1, 2, 3]),
    perTruth: new Map([['truth-1', new Uint8Array([4, 5, 6])]]),
    perNegative: new Map([['neg-1', new Uint8Array([7, 8, 9])]]),
  };
}

function fixtureEvent(id, split, opts = {}) {
  return {
    id,
    family: opts.family ?? 'near_collision',
    domain: opts.domain ?? 'companies',
    split,
    queryText: opts.queryText ?? `query for ${id}`,
    truthDocuments: [{ id: 'truth-1', text: 'truth doc', isCurrent: true }],
    hardNegatives: [{ id: 'neg-1', text: 'distractor doc' }],
    qrels: [{ documentId: 'truth-1', relevance: 1.0 }],
    protected: split !== 'train_visible',
    provenance: { source: 'synthetic_challenge', sourceHash: `0x${'ee'.repeat(32)}` },
    embeddings: emptyEmbedding(),
  };
}

function fixtureCorpus() {
  const events = [
    fixtureEvent('rec-visible', 'train_visible'),
    fixtureEvent('rec-calibration', 'calibration'),
    fixtureEvent('rec-hidden', 'eval_hidden'),
    fixtureEvent('rec-canary', 'canary'),
  ];
  return {
    events,
    byId: new Map(events.map((e) => [e.id, e])),
    corpusRoot: CORPUS_ROOT,
    corpusEpoch: 0,
    biEncoderRevision: '0123456789abcdef0123456789abcdef01234567',
    biEncoderModelId: 'BAAI/bge-m3',
    biEncoderRetrievalKeyLayout: RETRIEVAL_KEY_LAYOUT,
    labelingModelRevision: 'fedcba9876543210fedcba9876543210fedcba98',
    labelingModelId: 'memreranker/4B',
  };
}

function fixtureManifest(bundleHash = BUNDLE_HASH) {
  return { bundleHash };
}

function makeFactoryOpts(overrides = {}) {
  return {
    corpus: fixtureCorpus(),
    bundleManifest: fixtureManifest(),
    bundleHash: BUNDLE_HASH,
    screen: () => ({ ok: 'screen' }),
    evaluate: () => ({ ok: 'evaluate' }),
    ...overrides,
  };
}

describe('createRetrievalDataSource', () => {
  test('refuses bundle hash that disagrees with manifest', () => {
    assert.throws(
      () => createRetrievalDataSource({
        ...makeFactoryOpts(),
        bundleManifest: fixtureManifest(ALT_BUNDLE_HASH),
      }),
      /bundle manifest hash/,
    );
  });

  test('passes screen and evaluate bodies through to host callbacks', async () => {
    const seen = [];
    const ds = createRetrievalDataSource(makeFactoryOpts({
      screen: (body) => { seen.push(['screen', body]); return { ok: 'screen' }; },
      evaluate: (body) => { seen.push(['evaluate', body]); return { ok: 'evaluate' }; },
    }));
    await ds.screen({ miner: '0xabc' });
    await ds.evaluate({ patch: '0x1234' });
    assert.deepEqual(seen, [
      ['screen', { miner: '0xabc' }],
      ['evaluate', { patch: '0x1234' }],
    ]);
  });

  test('passes async evaluate + getResult through when wired', async () => {
    const seen = [];
    const ds = createRetrievalDataSource(makeFactoryOpts({
      evaluateAsync: (body) => { seen.push(['async', body]); return { status: 'pending', patchHash: '0xab' }; },
      getResult: (patchHash) => { seen.push(['result', patchHash]); return { status: 'complete', score: 42 }; },
    }));
    assert.deepEqual(await ds.evaluateAsync({ patch: '0xfeed' }), { status: 'pending', patchHash: '0xab' });
    assert.deepEqual(await ds.getResult(`0x${'cd'.repeat(32)}`), { status: 'complete', score: 42 });
    assert.deepEqual(seen, [
      ['async', { patch: '0xfeed' }],
      ['result', `0x${'cd'.repeat(32)}`],
    ]);
  });

  test('omits async callbacks from data source when host does not wire them', () => {
    const ds = createRetrievalDataSource(makeFactoryOpts());
    assert.equal(ds.evaluateAsync, undefined);
    assert.equal(ds.getResult, undefined);
  });

  test('serves train_visible corpus records and masks hidden / canary / calibration', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts());
    const visible = await ds.getCorpusRecord('rec-visible');
    assert.equal(visible.id, 'rec-visible');
    assert.equal(visible.split, 'train_visible');

    const hidden = await ds.getCorpusRecord('rec-hidden');
    assert.deepEqual(hidden, { error: 'coretex-corpus-hidden', recordId: 'rec-hidden', split: 'eval_hidden' });

    const canary = await ds.getCorpusRecord('rec-canary');
    assert.deepEqual(canary, { error: 'coretex-corpus-hidden', recordId: 'rec-canary', split: 'canary' });

    const calibration = await ds.getCorpusRecord('rec-calibration');
    assert.deepEqual(calibration, { error: 'coretex-corpus-calibration-restricted', recordId: 'rec-calibration' });

    const missing = await ds.getCorpusRecord('not-real');
    assert.deepEqual(missing, { error: 'coretex-corpus-not-found', recordId: 'not-real' });
  });

  test('opens calibration access when allowCalibrationReads=true', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts({ allowCalibrationReads: true }));
    const calibration = await ds.getCorpusRecord('rec-calibration');
    assert.equal(calibration.id, 'rec-calibration');
    assert.equal(calibration.split, 'calibration');
  });

  test('serves embeddings only for non-hidden records', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts());
    const visible = await ds.getCorpusRecordEmbedding('rec-visible');
    assert.equal(visible.modelId, 'BAAI/bge-m3');
    assert.equal(visible.queryHex, '010203');
    assert.equal(visible.perTruth['truth-1'], '040506');
    assert.equal(visible.perNegative['neg-1'], '070809');

    const hidden = await ds.getCorpusRecordEmbedding('rec-hidden');
    assert.deepEqual(hidden, { error: 'coretex-embedding-hidden', recordId: 'rec-hidden', split: 'eval_hidden' });
  });

  test('returns the bundle manifest only for the matching hash', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts());
    const ok = await ds.getBundle(BUNDLE_HASH);
    assert.equal(ok.bundleHash, BUNDLE_HASH);
    const ok2 = await ds.getBundle(BUNDLE_HASH.toUpperCase());
    assert.equal(ok2.bundleHash, BUNDLE_HASH);

    const wrong = await ds.getBundle(ALT_BUNDLE_HASH);
    assert.deepEqual(wrong, { error: 'coretex-bundle-not-found', bundleHash: ALT_BUNDLE_HASH });
  });

  test('default coverage hints summarize train_visible records only', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts());
    const hints = await ds.getCoverageHints();
    assert.equal(hints.corpusRoot, CORPUS_ROOT);
    assert.equal(hints.recordCount, 1);
    assert.equal(hints.records.length, 1);
    assert.equal(hints.records[0].id, 'rec-visible');
  });

  test('uses a host coverage-hints override when provided', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts({
      getCoverageHintsForCurrent: () => ({ override: true }),
    }));
    const hints = await ds.getCoverageHints();
    assert.deepEqual(hints, { override: true });
  });

  test('forwards optional substrate and bundle hooks when configured', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts({
      getCurrentSubstrate: () => ({ stateRoot: 'current' }),
      getSubstrate: (root) => ({ stateRoot: root }),
      getPatch: (h) => ({ patch: h }),
      getEvalReport: (h) => ({ report: h }),
      getChallengeBook: (epoch) => ({ epoch: epoch.toString() }),
      getCorpusDelta: (epoch) => ({ delta: epoch.toString() }),
      getClientBundle: (hash) => ({ clientBundle: hash }),
      health: () => ({ ok: true }),
    }));
    assert.deepEqual(await ds.getCurrentSubstrate(), { stateRoot: 'current' });
    assert.deepEqual(await ds.getSubstrate('0xabc'), { stateRoot: '0xabc' });
    assert.deepEqual(await ds.getPatch('0x111'), { patch: '0x111' });
    assert.deepEqual(await ds.getEvalReport('0x222'), { report: '0x222' });
    assert.deepEqual(await ds.getChallengeBook(7n), { epoch: '7' });
    assert.deepEqual(await ds.getCorpusDelta(8n), { delta: '8' });
    assert.deepEqual(await ds.getClientBundle('0xc0re'), { clientBundle: '0xc0re' });
    assert.deepEqual(await ds.health(), { ok: true });
  });
});
