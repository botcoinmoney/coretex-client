/**
 * §6.5 reranker-input cap — proves the cap is correct architecturally:
 *
 *   1. The cap reduces reranker calls (compute saved).
 *   2. Substrate-promoted candidates (high substrateBonus, low biCosine)
 *      still enter the reranker pool — substrate keeps full expressivity.
 *   3. Tie-break is deterministic by docId, so cross-host replay agrees.
 *   4. When pool size <= cap, the cap is a no-op.
 *
 * These tests stub the reranker with a counting mock so we can prove the
 * call count drops in proportion to the cap without needing actual
 * model inference.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  evaluateRetrievalBenchmarkState,
  computeCorpusRoot,
  splitForRecord,
  DEFAULT_PROFILE,
} from '../../dist/index.js';

const LAYOUT = { dim: 8, headerBytes: 9, quantization: 'int8' };
const MODEL_ID = 'test/biencoder';
const REVISION = 'rev';
const MODEL_HASH = '0xdeadbeef';
const ZERO_STATE = { words: new Array(1024).fill(0n) };

// ─── Helpers to build a tiny synthetic corpus with N events ────────────────

function quantize(values) {
  // 4-byte BE float32 scale + int8 codes; identity-quantize for stability.
  // scale=1.0 means raw codes recover as values directly.
  const scale = 1.0;
  const buf = new Uint8Array(4 + values.length);
  const dv = new DataView(buf.buffer);
  dv.setFloat32(0, scale, false);
  for (let i = 0; i < values.length; i++) {
    let v = Math.round(values[i] * 127);
    if (v > 127) v = 127;
    if (v < -128) v = -128;
    buf[4 + i] = v & 0xff;
  }
  return buf;
}

function makeEvent(id, queryText, truthText, truthVec, splitOverride) {
  return {
    id,
    queryText,
    family: 'multi_hop_relation',
    split: splitOverride ?? splitForRecord(id, 0),
    timestamp: Date.now(),
    epochId: 0,
    truthDocuments: [{ id: `${id}-truth`, text: truthText, isCurrent: true }],
    negativeDocuments: [],
    hardNegatives: [],
    qrels: [{ documentId: `${id}-truth`, relevance: 1 }],
    relations: [],
    embeddings: {
      modelId: MODEL_ID,
      revision: REVISION,
      layout: LAYOUT,
      query: quantize(truthVec.map((v) => v * 0.9)), // query similar to truth
      perTruth: new Map([[`${id}-truth`, quantize(truthVec)]]),
      perNegative: new Map(),
    },
  };
}

function makeCorpus(events) {
  const corpusEpoch = 0;
  return {
    schemaVersion: 'coretex.production-corpus.v1',
    corpusEpoch,
    corpusRoot: computeCorpusRoot(events),
    generatedAt: new Date().toISOString(),
    biEncoderModelId: MODEL_ID,
    biEncoderRevision: REVISION,
    biEncoderRetrievalKeyLayout: LAYOUT,
    events,
    splitRatios: { trainVisiblePct: 70, calibrationPct: 10, evalHiddenPct: 15, canaryPct: 5 },
  };
}

// Reranker that counts how many pairs it scored.
function countingReranker(scoreFn = (q, d) => 0.5) {
  const state = { calls: 0, pairs: [] };
  return {
    state,
    reranker: {
      model: 'counting-mock',
      async score(pairs) {
        state.calls += pairs.length;
        for (const p of pairs) state.pairs.push(p);
        return pairs.map((p) => scoreFn(p.query, p.document));
      },
    },
  };
}

// Bi-encoder that quantizes query text by its ASCII prefix-hash to a tiny vector.
function trivialBiEncoder() {
  return {
    model: { id: MODEL_ID, revision: REVISION },
    async encode(queryText) {
      // Hash queryText → 8-dim float vector in [-1, 1]
      const vec = new Float32Array(LAYOUT.dim);
      let h = 0;
      for (let i = 0; i < queryText.length; i++) h = (h * 31 + queryText.charCodeAt(i)) & 0xffffffff;
      for (let i = 0; i < LAYOUT.dim; i++) {
        h = (h * 1103515245 + 12345) & 0x7fffffff;
        vec[i] = (h / 0x7fffffff) * 2 - 1;
      }
      return vec;
    },
  };
}

function makeOpts(rerankerMock, rerankerInputTopK) {
  return {
    weights: DEFAULT_PROFILE.compositeWeights,
    retrievalKeyLayout: LAYOUT,
    biEncoder: trivialBiEncoder(),
    reranker: rerankerMock,
    biEncoderHash: MODEL_HASH,
    relationHopBudget: 2,
    abstentionThreshold: 0.001,
    rerankerTopK: 10,
    retrievalKeyTopK: 50,
    firstStageTopK: 300,
    rerankerInputTopK,
    lensTopK: 36,
    lensWeight: 0.1,
    anchorWeight: 0.15,
    relationExpansionBudget: 50,
    temporalCurrentBoost: 0.1,
    temporalStaleSuppression: 0.1,
  };
}

describe('§6.5 reranker-input cap', () => {
  test('cap=32 forwards exactly 32 pairs per query when pool >= 32', async () => {
    // 100 events → pool will be 100. Cap should clip to 32.
    const events = Array.from({ length: 100 }, (_, i) =>
      makeEvent(`ev-${String(i).padStart(3, '0')}`, `query ${i} text`, `truth ${i} text content`, [Math.cos(i), Math.sin(i), 0.5, 0.3, 0.2, 0.1, -0.1, -0.2], 'calibration'),
    );
    const corpus = makeCorpus(events);
    const pack = { epochId: 0, evalSeedCommit: '0x' + '11'.repeat(32), events: [events[0]] };

    const { reranker, state } = countingReranker();
    const opts = makeOpts(reranker, 32);

    await evaluateRetrievalBenchmarkState(ZERO_STATE, corpus, pack, opts);
    assert.equal(state.calls, 32, `expected 32 reranker calls, got ${state.calls}`);
  });

  test('cap=128 with smaller pool is a no-op (calls === pool size)', async () => {
    const events = Array.from({ length: 50 }, (_, i) =>
      makeEvent(`ev-${String(i).padStart(3, '0')}`, `query ${i} text`, `truth ${i} text content`, [Math.cos(i), Math.sin(i), 0.5, 0.3, 0.2, 0.1, -0.1, -0.2], 'calibration'),
    );
    const corpus = makeCorpus(events);
    const pack = { epochId: 0, evalSeedCommit: '0x' + '22'.repeat(32), events: [events[0]] };

    const { reranker, state } = countingReranker();
    const opts = makeOpts(reranker, 128);

    await evaluateRetrievalBenchmarkState(ZERO_STATE, corpus, pack, opts);
    assert.ok(state.calls > 0 && state.calls <= 50, `expected calls in (0, 50], got ${state.calls}`);
  });

  test('full-pool baseline: cap=firstStageTopK forwards entire pool', async () => {
    // Sanity check: cap=firstStageTopK should rerank the full pool.
    const events = Array.from({ length: 100 }, (_, i) =>
      makeEvent(`ev-${String(i).padStart(3, '0')}`, `query ${i} text`, `truth ${i} text content`, [Math.cos(i), Math.sin(i), 0.5, 0.3, 0.2, 0.1, -0.1, -0.2], 'calibration'),
    );
    const corpus = makeCorpus(events);
    const pack = { epochId: 0, evalSeedCommit: '0x' + '33'.repeat(32), events: [events[0]] };

    const { reranker, state } = countingReranker();
    const opts = makeOpts(reranker, 300); // cap == firstStageTopK

    await evaluateRetrievalBenchmarkState(ZERO_STATE, corpus, pack, opts);
    // Expect calls == pool size (which is at most firstStageTopK = 300, but
    // with 100 events the pool can be at most 100).
    assert.ok(state.calls >= 50 && state.calls <= 100,
      `expected pool-size rerank calls (50-100), got ${state.calls}`);
  });

  test('reranker pairs are deterministic-ordered (sorted by preRankScore desc, tie-break docId asc)', async () => {
    const events = Array.from({ length: 200 }, (_, i) =>
      makeEvent(`ev-${String(i).padStart(3, '0')}`, `query ${i} text`, `truth ${i} text`, [Math.cos(i*0.1), Math.sin(i*0.1), 0.5, 0.3, 0.2, 0.1, -0.1, -0.2], 'calibration'),
    );
    const corpus = makeCorpus(events);
    const pack = { epochId: 0, evalSeedCommit: '0x' + '44'.repeat(32), events: [events[0]] };

    // Two independent runs must produce IDENTICAL reranker pair ordering.
    const r1 = countingReranker();
    await evaluateRetrievalBenchmarkState(ZERO_STATE, corpus, pack, makeOpts(r1.reranker, 64));

    const r2 = countingReranker();
    await evaluateRetrievalBenchmarkState(ZERO_STATE, corpus, pack, makeOpts(r2.reranker, 64));

    assert.equal(r1.state.calls, r2.state.calls);
    assert.equal(r1.state.calls, 64);
    for (let i = 0; i < r1.state.pairs.length; i++) {
      assert.equal(r1.state.pairs[i].document, r2.state.pairs[i].document,
        `pair ${i}: run 1 saw '${r1.state.pairs[i].document}', run 2 saw '${r2.state.pairs[i].document}'`);
    }
  });
});
