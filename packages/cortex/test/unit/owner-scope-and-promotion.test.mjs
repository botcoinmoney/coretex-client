/**
 * Owner-scoped retrieval (Layer-2 validity fix) + non-flooding promotion split.
 *
 * ownerScopeMode='restrict' restricts stage-1 to the query's PUBLIC owner store
 * (events tagged with query.ownerEntityId), so a high-cosine doc owned by a
 * DIFFERENT entity is excluded — the realistic, well-posed task. Default 'off'
 * keeps the legacy full-pool behavior.
 *
 * categoryLensFinalBonusWeight splits the category-lens bonus: ADMISSION
 * (pre-rank cap inclusion) vs FINAL (reorder). Inclusion-only (final≈0) lets a
 * routed doc enter the cap but leaves final order to the reranker — fixing the
 * P2 flood where a large final additive bonus swamped the reranker.
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

/** A memory event owning one truth doc, tagged with an owner entity. */
function memEvent(id, truthText, truthVec, entityIds, relations = []) {
  return {
    id, queryText: truthText, family: 'multi_hop_relation',
    split: splitForRecord(id, 0), timestamp: Date.now(), epochId: 0,
    truthDocuments: [{ id: `${id}-truth`, text: truthText, isCurrent: true }],
    hardNegatives: [], qrels: [{ documentId: `${id}-truth`, relevance: 1 }],
    relations, entityIds,
    embeddings: {
      modelId: MODEL_ID, revision: REVISION, layout: LAYOUT,
      query: quantize(truthVec),
      perTruth: new Map([[`${id}-truth`, quantize(truthVec)]]),
      perNegative: new Map(),
    },
  };
}

/** A query event with a public owner scope; gold is `goldDocId`. */
function queryEvent(id, queryVec, ownerEntityId, ownerScoped, qrels) {
  return {
    id, queryText: `query ${id}`, family: 'multi_hop_relation',
    split: 'eval_hidden', timestamp: Date.now(), epochId: 0,
    truthDocuments: [], hardNegatives: [], qrels,
    relations: [], ownerEntityId, ownerScoped,
    embeddings: {
      modelId: MODEL_ID, revision: REVISION, layout: LAYOUT,
      query: quantize(queryVec), perTruth: new Map(), perNegative: new Map(),
    },
  };
}

function constantReranker() {
  return { model: 'const', async score(pairs) { return pairs.map(() => 0.5); } };
}
function trivialBiEncoder() {
  return { model: { id: MODEL_ID, revision: REVISION }, async encode() { return new Float32Array(LAYOUT.dim); } };
}

function baseOpts(overrides) {
  return {
    weights: DEFAULT_PROFILE.compositeWeights,
    retrievalKeyLayout: LAYOUT,
    biEncoder: trivialBiEncoder(),
    reranker: constantReranker(),
    biEncoderHash: MODEL_HASH,
    relationHopBudget: 3, abstentionThreshold: 0.001, rerankerTopK: 10, retrievalKeyTopK: 50,
    firstStageTopK: 50, rerankerInputTopK: 50, lensTopK: 36, lensWeight: 0.1, anchorWeight: 0.15,
    relationExpansionBudget: 12, categoryLensExpansionBudget: 12,
    temporalCurrentBoost: 0.1, temporalStaleSuppression: 0.1,
    ...overrides,
  };
}

function buildCorpus(events) {
  return {
    schemaVersion: 'coretex.production-corpus.v1', corpusEpoch: 0,
    corpusRoot: computeCorpusRoot(events), generatedAt: new Date().toISOString(),
    biEncoderModelId: MODEL_ID, biEncoderRevision: REVISION, biEncoderRetrievalKeyLayout: LAYOUT,
    events, byId: new Map(events.map((e) => [e.id, e])),
    entities: [
      { id: 'e_x', canonicalName: 'Owner X', aliases: ['X'] },
      { id: 'e_y', canonicalName: 'Owner Y', aliases: ['Y'] },
    ],
    splitRatios: { trainVisiblePct: 70, calibrationPct: 10, evalHiddenPct: 15, canaryPct: 5 },
  };
}

// Owner X owns docX1 (the gold, surface-DISSIMILAR to the query) + docX2.
// Owner Y owns docY1, which is HIGHLY similar to the query (pooled stage-1
// would rank it first). Owner-scope must exclude docY1 (different owner).
function makeTwoOwnerCorpus() {
  const queryVec = [1, 0, 0, 0, 0, 0, 0, 0];
  const similar  = [1, 0, 0, 0, 0, 0, 0, 0];   // docY1: aligned with query
  const dissim   = [0, 1, 0, 0, 0, 0, 0, 0];   // docX1: orthogonal (buried)
  const other    = [0, 0, 1, 0, 0, 0, 0, 0];   // docX2
  const memX1 = memEvent('memX1', 'TRUTH-X1', dissim, ['e_x']);
  const memX2 = memEvent('memX2', 'TRUTH-X2', other, ['e_x']);
  const memY1 = memEvent('memY1', 'TRUTH-Y1', similar, ['e_y']);
  const q = queryEvent('q1', queryVec, 'e_x', true, [{ documentId: 'memX1-truth', relevance: 1 }]);
  return { corpus: buildCorpus([memX1, memX2, memY1, q]), q };
}

const emptyState = () => ({ words: new Array(1024).fill(0n) });
const packOf = (q) => ({ epochId: 0, evalSeedCommit: '0x' + 'a1'.repeat(32), events: [q] });

describe('owner-scoped retrieval', () => {
  test("restrict: stage-1 pool excludes a high-cosine doc owned by a different entity", async () => {
    const { corpus, q } = makeTwoOwnerCorpus();
    const composite = await evaluateRetrievalBenchmarkState(emptyState(), corpus, packOf(q), baseOpts({ ownerScopeMode: 'restrict' }));
    const pq = composite.perQuery[0];
    assert.equal(pq.cappedDocIds.indexOf('memY1-truth'), -1, 'different-owner doc must be excluded under owner-scope');
    assert.notEqual(pq.cappedDocIds.indexOf('memX1-truth'), -1, 'owner gold doc present');
    assert.notEqual(pq.cappedDocIds.indexOf('memX2-truth'), -1, "owner's other doc present");
  });

  test("off (default): full pool includes the different-owner doc", async () => {
    const { corpus, q } = makeTwoOwnerCorpus();
    const composite = await evaluateRetrievalBenchmarkState(emptyState(), corpus, packOf(q), baseOpts({ ownerScopeMode: 'off' }));
    const pq = composite.perQuery[0];
    assert.notEqual(pq.cappedDocIds.indexOf('memY1-truth'), -1, 'full pool includes other-owner doc when unscoped');
  });

  test("restrict is a no-op when the query is not ownerScoped", async () => {
    const { corpus } = makeTwoOwnerCorpus();
    const qUnscoped = queryEvent('q2', [1, 0, 0, 0, 0, 0, 0, 0], 'e_x', false, [{ documentId: 'memX1-truth', relevance: 1 }]);
    const corpus2 = buildCorpus([...corpus.events.filter((e) => e.id !== 'q1'), qUnscoped]);
    const composite = await evaluateRetrievalBenchmarkState(emptyState(), corpus2, packOf(qUnscoped), baseOpts({ ownerScopeMode: 'restrict' }));
    const pq = composite.perQuery[0];
    assert.notEqual(pq.cappedDocIds.indexOf('memY1-truth'), -1, 'unscoped query keeps full pool even under restrict');
  });
});

// A categoryLens edge tags an IRRELEVANT doc. With a large FINAL bonus it gets a
// big finalReorderingScore boost (flood); with final bonus 0 it does not.
function makeLensFloodCorpus() {
  const queryVec = [1, 0, 0, 0, 0, 0, 0, 0];
  const seedVec  = [1, 0, 0, 0, 0, 0, 0, 0];   // memS: stage-1 hit
  const junkVec  = [0, 1, 0, 0, 0, 0, 0, 0];   // memJ: irrelevant, reached via lens edge from memS
  // memS --supports--> memJ (so categoryLensBFS tags memJ).
  const memS = memEvent('memS', 'SEED', seedVec, ['e_x'], [{ other_id: 'memJ', edgeType: 'supports' }]);
  const memJ = memEvent('memJ', 'JUNK', junkVec, ['e_x']);
  const q = queryEvent('qF', queryVec, 'e_x', false, [{ documentId: 'memS-truth', relevance: 1 }]);
  return { corpus: buildCorpus([memS, memJ, q]), q };
}
function lensState() {
  const words = new Array(1024).fill(0n);
  words[RANGES.RELATIONS_START + 127] = encodeRelationCategoryLens({ entryIndex: 127, edgeType: 'supports', weight: 0x8000 });
  return { words };
}

describe('non-flooding promotion (admission vs final bonus split)', () => {
  test("inclusion-only (categoryLensFinalBonusWeight=0): lens-tagged junk gets NO final-reorder boost", async () => {
    const { corpus, q } = makeLensFloodCorpus();
    const composite = await evaluateRetrievalBenchmarkState(lensState(), corpus, packOf(q),
      baseOpts({ categoryLensBonusWeight: 10, categoryLensFinalBonusWeight: 0 }));
    const pq = composite.perQuery[0];
    const junk = pq.finalRankingTop20.find((r) => r.docId === 'memJ-truth');
    assert.ok(junk, 'junk doc present in ranking');
    assert.ok(junk.sources.includes('categoryLensBFS'), 'junk reached via categoryLensBFS (admitted)');
    // finalReorderingScore == rerankerScore (no categoryLens final bonus, no other bonuses fire).
    assert.ok(Math.abs(junk.finalReorderingScore - junk.rerankerScore) < 1e-9,
      `inclusion-only: final score must equal reranker score, got ${junk.finalReorderingScore} vs ${junk.rerankerScore}`);
  });

  test("legacy (final bonus defaults to admission): lens-tagged junk DOES get a final-reorder boost (flood)", async () => {
    const { corpus, q } = makeLensFloodCorpus();
    const composite = await evaluateRetrievalBenchmarkState(lensState(), corpus, packOf(q),
      baseOpts({ categoryLensBonusWeight: 10 })); // no final-bonus override → defaults to 10
    const pq = composite.perQuery[0];
    const junk = pq.finalRankingTop20.find((r) => r.docId === 'memJ-truth');
    assert.ok(junk, 'junk doc present');
    assert.ok(junk.finalReorderingScore - junk.rerankerScore > 0.5,
      `legacy: final score should exceed reranker score by the lens bonus, got delta ${junk.finalReorderingScore - junk.rerankerScore}`);
  });
});

// memB (bridge) ranks high under the reranker; memA (answer) is lens-linked to it
// but the reranker scores it low. Score-inheritance should lift memA's FINAL score
// toward alpha×memB, while a NON-linked low doc gets no lift.
function makeInheritanceCorpus() {
  const queryVec = [1, 0, 0, 0, 0, 0, 0, 0];
  const bridgeVec = [1, 0, 0, 0, 0, 0, 0, 0];  // memB: high biCosine (reranker hi)
  const ansVec    = [0, 1, 0, 0, 0, 0, 0, 0];  // memA: surface-dissimilar (reranker lo)
  // memA --supports--> memB so the bidirectional BFS links them.
  const memB = memEvent('memB', 'BRIDGE', bridgeVec, ['e_x']);
  const memA = memEvent('memA', 'ANSWER', ansVec, ['e_x'], [{ other_id: 'memB', edgeType: 'supports' }]);
  const q = queryEvent('qI', queryVec, 'e_x', false, [{ documentId: 'memA-truth', relevance: 1 }]);
  return { corpus: buildCorpus([memB, memA, q]), q };
}
// Reranker: high score for the bridge text, low for everything else.
function bridgeAwareReranker() {
  return { model: 'br', async score(pairs) { return pairs.map((p) => p.document === 'BRIDGE' ? 0.9 : 0.1); } };
}

describe('score-inheritance (categoryLensScoreInheritance)', () => {
  test("alpha>0: lens-linked answer inherits a bounded fraction of its bridge's reranker score", async () => {
    const { corpus, q } = makeInheritanceCorpus();
    const opts = baseOpts({ reranker: bridgeAwareReranker(), categoryLensFinalBonusWeight: 0, categoryLensScoreInheritance: 0.8 });
    const composite = await evaluateRetrievalBenchmarkState(lensState(), corpus, packOf(q), opts);
    const pq = composite.perQuery[0];
    const a = pq.finalRankingTop20.find((r) => r.docId === 'memA-truth');
    assert.ok(a, 'answer present');
    assert.ok(a.sources.includes('categoryLensBFS'), 'answer linked via lens edge');
    // raw reranker 0.1; inherited = 0.8 × bridge 0.9 = 0.72 ⇒ finalReorderingScore ≈ 0.72.
    assert.ok(Math.abs(a.rerankerScore - 0.1) < 1e-9, `raw reranker stays 0.1, got ${a.rerankerScore}`);
    assert.ok(a.finalReorderingScore > 0.6, `inherited final score should be ~0.72, got ${a.finalReorderingScore}`);
  });

  test("alpha=0 (default): no inheritance — answer keeps its raw reranker score", async () => {
    const { corpus, q } = makeInheritanceCorpus();
    const opts = baseOpts({ reranker: bridgeAwareReranker(), categoryLensFinalBonusWeight: 0 });
    const composite = await evaluateRetrievalBenchmarkState(lensState(), corpus, packOf(q), opts);
    const pq = composite.perQuery[0];
    const a = pq.finalRankingTop20.find((r) => r.docId === 'memA-truth');
    assert.ok(a, 'answer present');
    assert.ok(Math.abs(a.finalReorderingScore - 0.1) < 1e-9,
      `no inheritance ⇒ final == raw reranker 0.1, got ${a.finalReorderingScore}`);
  });
});
