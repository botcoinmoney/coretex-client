/**
 * Substrate-viability Phase B knobs. These let a viability run decompose
 * where Phase B (corpus-native category-lens BFS) lift actually comes from:
 *
 *   categoryLensTraversalDirection: 'forward' | 'bidirectional'
 *     'forward'       — follow only forward edges (question → answer-entity).
 *                       A sibling question's truth is reached only if a direct
 *                       forward edge exists.
 *     'bidirectional' — also follow inverse edges (entity ← all questions
 *                       pointing at it). This is the lever that closes the
 *                       semantic cluster around an answer entity and is the
 *                       only source of true "generalized" (non-anchor,
 *                       inverse-edge) routing lift. Default.
 *
 *   categoryLensBonusEnabled (default true)
 *     false — Phase-B-added docs stay in the candidate pool (inclusion-only)
 *             but receive NO categoryLensBonus. Isolates EXPANSION (reaching
 *             the doc) from BIASING (the additive nudge up the pre-rank).
 *
 *   categoryLensBonusWeight (default = lensWeight)
 *     overrides the Phase B bonus scale independently of the retrieval-key
 *     lens bonus.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  evaluateRetrievalBenchmarkState,
  computeCorpusRoot,
  splitForRecord,
  encodeMemoryIndexSlot,
  encodeRelationCategoryLens,
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

function makeEvent(id, queryText, truthText, truthVec, queryVec, family = 'multi_hop_relation', relations = []) {
  return {
    id, queryText, family,
    split: splitForRecord(id, 0),
    timestamp: Date.now(), epochId: 0,
    truthDocuments: [{ id: `${id}-truth`, text: truthText, isCurrent: true }],
    negativeDocuments: [], hardNegatives: [],
    qrels: [{ documentId: `${id}-truth`, relevance: 1 }],
    relations,
    embeddings: {
      modelId: MODEL_ID, revision: REVISION, layout: LAYOUT,
      query: quantize(queryVec),
      perTruth: new Map([[`${id}-truth`, quantize(truthVec)]]),
      perNegative: new Map(),
    },
  };
}

function trivialBiEncoder() {
  return {
    model: { id: MODEL_ID, revision: REVISION },
    async encode(qt) {
      const v = new Float32Array(LAYOUT.dim);
      let h = 0;
      for (let i = 0; i < qt.length; i++) h = (h * 31 + qt.charCodeAt(i)) & 0xffffffff;
      for (let i = 0; i < LAYOUT.dim; i++) {
        h = (h * 1103515245 + 12345) & 0x7fffffff;
        v[i] = (h / 0x7fffffff) * 2 - 1;
      }
      return v;
    },
  };
}
function constantReranker() {
  return { model: 'const', async score(pairs) { return pairs.map(() => 0.5); } };
}

function placeMemorySlot(words, slotIndex, slot) {
  const enc = encodeMemoryIndexSlot({ ...slot, slotIndex });
  for (let i = 0; i < 8; i++) words[RANGES.MEMORY_INDEX_START + slotIndex * 8 + i] = enc[i];
}
function placeCategoryLens(words, entryIndex, lens) {
  words[RANGES.RELATIONS_START + entryIndex] = encodeRelationCategoryLens({ ...lens, entryIndex });
}

function baseOpts(overrides) {
  return {
    weights: DEFAULT_PROFILE.compositeWeights,
    retrievalKeyLayout: LAYOUT,
    biEncoder: trivialBiEncoder(),
    reranker: constantReranker(),
    biEncoderHash: MODEL_HASH,
    relationHopBudget: 3,
    abstentionThreshold: 0.001,
    rerankerTopK: 10,
    retrievalKeyTopK: 50,
    firstStageTopK: 1,
    rerankerInputTopK: 50,
    lensTopK: 36,
    lensWeight: 0.1,
    anchorWeight: 0.15,
    relationExpansionBudget: 12,
    categoryLensExpansionBudget: 12,
    temporalCurrentBoost: 0.1,
    temporalStaleSuppression: 0.1,
    ...overrides,
  };
}

function buildCorpus(events) {
  return {
    schemaVersion: 'coretex.production-corpus.v1',
    corpusEpoch: 0,
    corpusRoot: computeCorpusRoot(events),
    generatedAt: new Date().toISOString(),
    biEncoderModelId: MODEL_ID,
    biEncoderRevision: REVISION,
    biEncoderRetrievalKeyLayout: LAYOUT,
    events,
    byId: new Map(events.map((e) => [e.id, e])),
    splitRatios: { trainVisiblePct: 70, calibrationPct: 10, evalHiddenPct: 15, canaryPct: 5 },
  };
}

// ev-A is the only stage-1 hit. ev-A has a FORWARD edge to ev-B. ev-D has a
// forward edge pointing AT ev-A — so ev-D is reachable from ev-A only via the
// INVERSE edge. This separates forward-only Phase B (reaches ev-B, not ev-D)
// from bidirectional (reaches both).
function makeForwardAndInverseCorpus() {
  const queryVec = [1, 0, 0, 0, 0, 0, 0, 0];
  const aligned  = [1, 0, 0, 0, 0, 0, 0, 0];
  const anti     = [-1, 0, 0, 0, 0, 0, 0, 0];
  const eventA = makeEvent('ev-A', 'query about A', 'TRUTH-A', aligned, queryVec, 'multi_hop_relation', [
    { other_id: 'ev-B', edgeType: 'supports' },
  ]);
  // Repaired-qrel aliasing: ev-A's relevant set includes both sibling truths.
  eventA.qrels = [
    { documentId: 'ev-A-truth', relevance: 1 },
    { documentId: 'ev-B-truth', relevance: 1 },
    { documentId: 'ev-D-truth', relevance: 1 },
  ];
  const eventB = makeEvent('ev-B', 'query about B', 'TRUTH-B', anti, queryVec);
  // ev-D forward→ev-A. ev-D's truth is anti-aligned so stage-1 never finds it.
  const eventD = makeEvent('ev-D', 'query about D', 'TRUTH-D', anti, queryVec, 'multi_hop_relation', [
    { other_id: 'ev-A', edgeType: 'supports' },
  ]);
  return buildCorpus([eventA, eventB, eventD]);
}

function anchorOnlyAState() {
  const words = new Array(1024).fill(0n);
  placeMemorySlot(words, 0, {
    recordId: stableRecordIdFor('ev-A'),
    family: 'multi_hop_relation',
    domainBits: 1n, valid: true, revoked: false, protected: false,
    retrievalSlot: 0, expiryEpoch: 0n,
  });
  placeCategoryLens(words, 127, { edgeType: 'supports', weight: 0x8000 });
  return { words };
}

describe('Phase B viability knob: categoryLensTraversalDirection', () => {
  test("'bidirectional' (default) reaches the inverse-edge sibling (ev-D)", async () => {
    const corpus = makeForwardAndInverseCorpus();
    const pack = { epochId: 0, evalSeedCommit: '0x' + 'a1'.repeat(32), events: [corpus.events[0]] };
    const composite = await evaluateRetrievalBenchmarkState(anchorOnlyAState(), corpus, pack, baseOpts({
      categoryLensTraversalDirection: 'bidirectional',
    }));
    const q = composite.perQuery[0];
    assert.notEqual(q.cappedDocIds.indexOf('ev-B-truth'), -1, 'forward sibling ev-B reached');
    assert.notEqual(q.cappedDocIds.indexOf('ev-D-truth'), -1, 'inverse sibling ev-D reached under bidirectional');
    const dSources = q.cappedDocSources[q.cappedDocIds.indexOf('ev-D-truth')];
    assert.ok(dSources.includes('categoryLensBFS'), 'ev-D reached via Phase B');
  });

  test("'forward' reaches the forward sibling (ev-B) but NOT the inverse-only sibling (ev-D)", async () => {
    const corpus = makeForwardAndInverseCorpus();
    const pack = { epochId: 0, evalSeedCommit: '0x' + 'a2'.repeat(32), events: [corpus.events[0]] };
    const composite = await evaluateRetrievalBenchmarkState(anchorOnlyAState(), corpus, pack, baseOpts({
      categoryLensTraversalDirection: 'forward',
    }));
    const q = composite.perQuery[0];
    assert.notEqual(q.cappedDocIds.indexOf('ev-B-truth'), -1, 'forward sibling ev-B still reached under forward-only');
    assert.equal(q.cappedDocIds.indexOf('ev-D-truth'), -1,
      'inverse-only sibling ev-D must NOT be reached under forward-only traversal');
  });

  test("omitting direction defaults to bidirectional (back-compat)", async () => {
    const corpus = makeForwardAndInverseCorpus();
    const pack = { epochId: 0, evalSeedCommit: '0x' + 'a3'.repeat(32), events: [corpus.events[0]] };
    const composite = await evaluateRetrievalBenchmarkState(anchorOnlyAState(), corpus, pack, baseOpts({
      // categoryLensTraversalDirection omitted
    }));
    const q = composite.perQuery[0];
    assert.notEqual(q.cappedDocIds.indexOf('ev-D-truth'), -1,
      'default traversal must behave as bidirectional and reach ev-D');
  });
});

describe('Phase B viability knob: categoryLensBonusEnabled / categoryLensBonusWeight', () => {
  function componentFor(q, docId) {
    const idx = q.cappedDocIds.indexOf(docId);
    assert.notEqual(idx, -1, `${docId} present in capped pool`);
    return { idx, c: q.cappedDocComponents[idx], sources: q.cappedDocSources[idx] };
  }

  test('bonusEnabled default → Phase-B doc carries a positive categoryLensBonus', async () => {
    const corpus = makeForwardAndInverseCorpus();
    const pack = { epochId: 0, evalSeedCommit: '0x' + 'b1'.repeat(32), events: [corpus.events[0]] };
    const composite = await evaluateRetrievalBenchmarkState(anchorOnlyAState(), corpus, pack, baseOpts({}));
    const { c, sources } = componentFor(composite.perQuery[0], 'ev-B-truth');
    assert.ok(sources.includes('categoryLensBFS'), 'ev-B reached via Phase B');
    assert.ok(c.categoryLensBonus > 0, `categoryLensBonus must be positive when enabled (got ${c.categoryLensBonus})`);
  });

  test('bonusEnabled=false → doc stays in pool (inclusion-only) but categoryLensBonus is exactly 0', async () => {
    const corpus = makeForwardAndInverseCorpus();
    const pack = { epochId: 0, evalSeedCommit: '0x' + 'b2'.repeat(32), events: [corpus.events[0]] };
    const composite = await evaluateRetrievalBenchmarkState(anchorOnlyAState(), corpus, pack, baseOpts({
      categoryLensBonusEnabled: false,
    }));
    const { c, sources } = componentFor(composite.perQuery[0], 'ev-B-truth');
    assert.ok(sources.includes('categoryLensBFS'),
      'inclusion-only: ev-B must still be in the pool via Phase B even with bonus disabled');
    assert.equal(c.categoryLensBonus, 0, 'categoryLensBonus must be exactly 0 when disabled');
  });

  test('bonusWeight overrides the scale (larger weight → larger bonus, same normalised lens weight)', async () => {
    const corpus = makeForwardAndInverseCorpus();
    const packLo = { epochId: 0, evalSeedCommit: '0x' + 'b3'.repeat(32), events: [corpus.events[0]] };
    const packHi = { epochId: 0, evalSeedCommit: '0x' + 'b4'.repeat(32), events: [corpus.events[0]] };
    const lo = await evaluateRetrievalBenchmarkState(anchorOnlyAState(), corpus, packLo, baseOpts({
      categoryLensBonusWeight: 0.1,
    }));
    const hi = await evaluateRetrievalBenchmarkState(anchorOnlyAState(), corpus, packHi, baseOpts({
      categoryLensBonusWeight: 0.4,
    }));
    const cLo = componentFor(lo.perQuery[0], 'ev-B-truth').c;
    const cHi = componentFor(hi.perQuery[0], 'ev-B-truth').c;
    assert.ok(cHi.categoryLensBonus > cLo.categoryLensBonus,
      `bonusWeight=0.4 (${cHi.categoryLensBonus}) must exceed bonusWeight=0.1 (${cLo.categoryLensBonus})`);
    // 4× the weight on the same normalised lens weight → ~4× the bonus.
    assert.ok(Math.abs(cHi.categoryLensBonus - 4 * cLo.categoryLensBonus) < 1e-6,
      'bonus scales linearly with bonusWeight');
  });

  test('bonusWeight defaults to lensWeight when omitted', async () => {
    const corpus = makeForwardAndInverseCorpus();
    const packA = { epochId: 0, evalSeedCommit: '0x' + 'b5'.repeat(32), events: [corpus.events[0]] };
    const packB = { epochId: 0, evalSeedCommit: '0x' + 'b6'.repeat(32), events: [corpus.events[0]] };
    const omitted = await evaluateRetrievalBenchmarkState(anchorOnlyAState(), corpus, packA, baseOpts({
      lensWeight: 0.1,
    }));
    const explicit = await evaluateRetrievalBenchmarkState(anchorOnlyAState(), corpus, packB, baseOpts({
      lensWeight: 0.1,
      categoryLensBonusWeight: 0.1,
    }));
    const cOmitted = componentFor(omitted.perQuery[0], 'ev-B-truth').c;
    const cExplicit = componentFor(explicit.perQuery[0], 'ev-B-truth').c;
    assert.ok(Math.abs(cOmitted.categoryLensBonus - cExplicit.categoryLensBonus) < 1e-9,
      'omitted bonusWeight must equal explicit bonusWeight=lensWeight');
  });
});
