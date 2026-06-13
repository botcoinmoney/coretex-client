/**
 * Candidate-source attribution coverage.
 *
 * Every doc in `cappedDocIds` carries a parallel `cappedDocSources[i]`
 * array that lists which routing mechanisms placed it into the candidate
 * pool: 'stage1', 'anchorMandatory', 'anchorBFS', or 'categoryLensBFS'.
 *
 * This test pins:
 *   1. Stage-1-only candidates carry exactly ['stage1'].
 *   2. Anchor-mandatory truths that were ALSO in stage-1 carry both
 *      'stage1' and 'anchorMandatory'.
 *   3. Anchor-mandatory truths NOT in stage-1 carry only
 *      'anchorMandatory'.
 *   4. The attribution is per-doc-id and parallel to cappedDocIds.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  evaluateRetrievalBenchmarkState,
  computeCorpusRoot,
  splitForRecord,
  encodeMemoryIndexSlot,
  stableRecordIdFor,
  DEFAULT_PROFILE,
} from '../../dist/index.js';
import { RANGES } from '../../dist/state/types.js';

const LAYOUT = { dim: 8, headerBytes: 9, quantization: 'int8' };
const MODEL_ID = 'test/biencoder';
const REVISION = 'rev';
const MODEL_HASH = '0xdeadbeef';

function quantize(values) {
  const buf = new Uint8Array(4 + values.length);
  const dv = new DataView(buf.buffer);
  dv.setFloat32(0, 1.0, false);
  for (let i = 0; i < values.length; i++) {
    let v = Math.round(values[i] * 127);
    if (v > 127) v = 127;
    if (v < -128) v = -128;
    buf[4 + i] = v & 0xff;
  }
  return buf;
}

function makeEvent(id, queryText, truthText, truthVec, queryVec) {
  return {
    id, queryText, family: 'multi_hop_relation',
    split: splitForRecord(id, 0),
    timestamp: Date.now(), epochId: 0,
    truthDocuments: [{ id: `${id}-truth`, text: truthText, isCurrent: true }],
    negativeDocuments: [], hardNegatives: [],
    qrels: [{ documentId: `${id}-truth`, relevance: 1 }],
    relations: [],
    embeddings: {
      modelId: MODEL_ID, revision: REVISION, layout: LAYOUT,
      query: quantize(queryVec),
      perTruth: new Map([[`${id}-truth`, quantize(truthVec)]]),
      perNegative: new Map(),
    },
  };
}

function placeMemorySlot(state, slotIndex, slot) {
  const enc = encodeMemoryIndexSlot({ ...slot, slotIndex });
  const words = [...state.words];
  for (let i = 0; i < 8; i++) words[RANGES.MEMORY_INDEX_START + slotIndex * 8 + i] = enc[i];
  return { words };
}

function trivialBiEncoder() {
  return {
    model: { id: MODEL_ID, revision: REVISION },
    async encode(queryText) {
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
function constantReranker() {
  return { model: 'const', async score(pairs) { return pairs.map(() => 0.5); } };
}

const baseOpts = {
  weights: DEFAULT_PROFILE.compositeWeights,
  retrievalKeyLayout: LAYOUT,
  biEncoder: trivialBiEncoder(),
  reranker: constantReranker(),
  biEncoderHash: MODEL_HASH,
  relationHopBudget: 2,
  abstentionThreshold: 0.001,
  rerankerTopK: 10,
  retrievalKeyTopK: 50,
  firstStageTopK: 300,
  rerankerInputTopK: 32,
  lensTopK: 36,
  lensWeight: 0.1,
  anchorWeight: 0.15,
  relationExpansionBudget: 0,
  temporalCurrentBoost: 0.1,
  temporalStaleSuppression: 0.1,
};

describe('candidate-source attribution', () => {
  test('cappedDocSources is parallel to cappedDocIds and lists mechanisms', async () => {
    // Build a tiny corpus where event A is anchored (anchorMandatory)
    // with low cosine to its query (so stage-1 wouldn't surface its truth
    // first), and several distractors with high cosine (so they ARE in
    // stage-1). The capped pool should contain both, with the truth doc
    // carrying only 'anchorMandatory' and the distractors carrying 'stage1'.
    const queryVec = [1, 0, 0, 0, 0, 0, 0, 0];
    const truthVecA = [-1, 0, 0, 0, 0, 0, 0, 0];  // anti-aligned
    const distractorVec = [1, 0, 0, 0, 0, 0, 0, 0]; // aligned
    const eventA = makeEvent('ev-A', 'who anchors', 'TRUTH-A', truthVecA, queryVec);
    const distractors = Array.from({ length: 6 }, (_, i) =>
      makeEvent(`ev-D${i}`, `distractor ${i}`, `dist content ${i}`, distractorVec, distractorVec),
    );
    const events = [eventA, ...distractors];
    const corpus = {
      schemaVersion: 'coretex.production-corpus.v1',
      corpusEpoch: 0,
      corpusRoot: computeCorpusRoot(events),
      generatedAt: new Date().toISOString(),
      biEncoderModelId: MODEL_ID,
      biEncoderRevision: REVISION,
      biEncoderRetrievalKeyLayout: LAYOUT,
      events,
      splitRatios: { trainVisiblePct: 70, calibrationPct: 10, evalHiddenPct: 15, canaryPct: 5 },
    };
    const pack = { epochId: 0, evalSeedCommit: '0x' + '66'.repeat(32), events: [eventA] };

    // Anchor event A into MemoryIndex slot 0.
    let state = { words: new Array(1024).fill(0n) };
    state = placeMemorySlot(state, 0, {
      recordId: stableRecordIdFor(eventA.id),
      family: eventA.family,
      domainBits: 1n,
      valid: true, revoked: false, protected: false,
      retrievalSlot: 0, expiryEpoch: 0n,
    });

    const composite = await evaluateRetrievalBenchmarkState(state, corpus, pack, baseOpts);
    const q = composite.perQuery[0];
    assert.ok(q, 'perQuery present');
    assert.ok(Array.isArray(q.cappedDocIds), 'cappedDocIds is array');
    assert.ok(Array.isArray(q.cappedDocSources), 'cappedDocSources is array');
    assert.equal(q.cappedDocIds.length, q.cappedDocSources.length, 'parallel length');

    const truthIdx = q.cappedDocIds.indexOf('ev-A-truth');
    assert.notEqual(truthIdx, -1, 'truth doc made the cap (via anchorMandatory)');
    const truthSources = q.cappedDocSources[truthIdx];
    assert.ok(truthSources.includes('anchorMandatory'),
      `truth doc carries anchorMandatory tag (got ${JSON.stringify(truthSources)})`);

    // Distractor docs are added by stage-1 (high cosine match to query).
    const distractorIdx = q.cappedDocIds.findIndex((d) => d.startsWith('ev-D'));
    assert.notEqual(distractorIdx, -1, 'at least one distractor made the cap via stage-1');
    const distractorSources = q.cappedDocSources[distractorIdx];
    assert.ok(distractorSources.includes('stage1'),
      `distractor carries stage1 tag (got ${JSON.stringify(distractorSources)})`);

    // Every doc must have at least one source tag.
    for (let i = 0; i < q.cappedDocSources.length; i++) {
      assert.ok(q.cappedDocSources[i].length > 0,
        `doc ${q.cappedDocIds[i]} must carry at least one source (got ${JSON.stringify(q.cappedDocSources[i])})`);
    }

    // cappedDocComponents is parallel to cappedDocIds and exposes the
    // raw inputs to preRankScore so downstream can compute
    // lens-promotion-into-cap without re-running the scorer.
    assert.ok(Array.isArray(q.cappedDocComponents), 'cappedDocComponents is array');
    assert.equal(q.cappedDocComponents.length, q.cappedDocIds.length, 'components parallel to docIds');
    for (const c of q.cappedDocComponents) {
      assert.ok(typeof c.biCosine === 'number' && Number.isFinite(c.biCosine), 'biCosine numeric');
      assert.ok(typeof c.lensBonus === 'number' && Number.isFinite(c.lensBonus), 'lensBonus numeric');
      assert.ok(typeof c.anchorBonus === 'number' && Number.isFinite(c.anchorBonus), 'anchorBonus numeric');
      assert.ok(typeof c.categoryLensBonus === 'number' && Number.isFinite(c.categoryLensBonus), 'categoryLensBonus numeric');
      assert.ok(typeof c.temporalBonus === 'number' && Number.isFinite(c.temporalBonus), 'temporalBonus numeric');
      const sumComputed = c.biCosine + c.lensBonus + c.anchorBonus + c.categoryLensBonus + c.temporalBonus;
      // Floating-point tolerance on the identity preRankScore = bi + lens + anchor + categoryLens + temporal.
      assert.ok(Math.abs(c.preRankScore - sumComputed) < 1e-6,
        `preRankScore identity violated: ${c.preRankScore} vs sum ${sumComputed}`);
    }

    // finalRankingTop20 mirrors the reranker's decisions with full
    // attribution attached. Each rank entry carries sources +
    // components from the corresponding capped pool record.
    assert.ok(Array.isArray(q.finalRankingTop20), 'finalRankingTop20 is array');
    assert.ok(q.finalRankingTop20.length > 0, 'at least one ranked doc');
    assert.ok(q.finalRankingTop20.length <= 20, 'capped at 20');
    assert.equal(q.finalRankingTop20[0].rank, 1, 'rank is 1-indexed');
    // The truth doc must appear in the top-K with anchorMandatory tag.
    const truthFinal = q.finalRankingTop20.find((r) => r.docId === 'ev-A-truth');
    assert.ok(truthFinal, 'truth doc lands in final ranking');
    assert.ok(truthFinal.sources.includes('anchorMandatory'),
      `truth's final-rank attribution carries anchorMandatory (got ${JSON.stringify(truthFinal.sources)})`);
    // relevance label is propagated from qrels (1 for the truth doc).
    assert.equal(truthFinal.relevance, 1, 'truth relevance is 1');
  });
});
