/**
 * Split-budget regression: anchor-graph BFS (Phase A) and corpus-native
 * category-lens BFS (Phase B) now consume independent budgets:
 *
 *   relationExpansionBudget        — Phase A (anchor-to-anchor BFS)
 *   categoryLensExpansionBudget    — Phase B (category-lens BFS), optional;
 *                                    default = relationExpansionBudget
 *
 * On launch-corpus scale the shared-budget coupling let Phase B flood the
 * candidate pool with hundreds of plausible-but-irrelevant docs and
 * displace anchor-mandatory truths from the reranker's top-10. The split
 * lets the operator pin categoryLensExpansionBudget=0 while keeping
 * Phase A (anchor-graph relation routing) intact.
 *
 * Tests:
 *   1. categoryLensExpansionBudget=0 suppresses categoryLensBFS even when
 *      category-lens entries exist in the substrate.
 *   2. With Phase B suppressed, Phase A (anchorBFS) still functions —
 *      anchor-graph BFS does not silently piggy-back on Phase B's budget.
 *   3. Omitting categoryLensExpansionBudget falls back to
 *      relationExpansionBudget for backwards compatibility with older
 *      profiles.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  evaluateRetrievalBenchmarkState,
  computeCorpusRoot,
  splitForRecord,
  encodeMemoryIndexSlot,
  encodeRelationEdge,
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
function placeRelationEdge(words, entryIndex, edge) {
  words[RANGES.RELATIONS_START + entryIndex] = encodeRelationEdge({ ...edge, entryIndex });
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
    temporalCurrentBoost: 0.1,
    temporalStaleSuppression: 0.1,
    ...overrides,
  };
}

// Three events: A queries about itself; A has a corpus relation to B
// (edgeType='supports'); A has another relation to C ('supersedes'). B and
// C are anti-aligned to ev-A's query so stage-1 alone never surfaces
// them — Phase B's category-lens BFS via the corpus relation is the only
// path their truths can enter the pool. This is the regime where the
// categoryLensBFS source tag is meaningful: a doc that ONLY exists in the
// pool because Phase B added it.
function makeCorpusWithRelations() {
  const queryVec = [1, 0, 0, 0, 0, 0, 0, 0];
  const aVec     = [1, 0, 0, 0, 0, 0, 0, 0];
  const bVec     = [-1, 0, 0, 0, 0, 0, 0, 0];
  const cVec     = [-1, 0, 0, 0, 0, 0, 0, 0];
  const eventA = makeEvent('ev-A', 'query about A', 'TRUTH-A', aVec, queryVec, 'multi_hop_relation', [
    { other_id: 'ev-B', edgeType: 'supports' },
    { other_id: 'ev-C', edgeType: 'supersedes' },
  ]);
  // Repaired-qrel aliasing: A.qrels includes B and C's truths as relevant.
  eventA.qrels = [
    { documentId: 'ev-A-truth', relevance: 1 },
    { documentId: 'ev-B-truth', relevance: 1 },
    { documentId: 'ev-C-truth', relevance: 1 },
  ];
  const eventB = makeEvent('ev-B', 'query about B', 'TRUTH-B', bVec, queryVec);
  const eventC = makeEvent('ev-C', 'query about C', 'TRUTH-C', cVec, queryVec);
  const events = [eventA, eventB, eventC];
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

describe('split relation/categoryLens budgets', () => {
  test('categoryLensExpansionBudget=0 suppresses Phase B (categoryLensBFS source tag absent)', async () => {
    const corpus = makeCorpusWithRelations();
    const pack = { epochId: 0, evalSeedCommit: '0x' + 'aa'.repeat(32), events: [corpus.events[0]] };
    // Substrate: anchor ev-A (slot 0). Category-lens entries for both
    // 'supports' and 'supersedes' edgeTypes — would expand to B and C if
    // Phase B were active.
    const words = new Array(1024).fill(0n);
    placeMemorySlot(words, 0, {
      recordId: stableRecordIdFor('ev-A'),
      family: 'multi_hop_relation',
      domainBits: 1n, valid: true, revoked: false, protected: false,
      retrievalSlot: 0, expiryEpoch: 0n,
    });
    placeCategoryLens(words, 126, { edgeType: 'supports', weight: 0x8000 });
    placeCategoryLens(words, 127, { edgeType: 'supersedes', weight: 0x8000 });
    const state = { words };

    const composite = await evaluateRetrievalBenchmarkState(state, corpus, pack, baseOpts({
      relationExpansionBudget: 12,
      categoryLensExpansionBudget: 0,
    }));
    const q = composite.perQuery[0];
    const tagSets = q.cappedDocSources ?? [];
    const everyCategoryLensTag = tagSets.flat();
    assert.equal(everyCategoryLensTag.includes('categoryLensBFS'), false,
      `categoryLensExpansionBudget=0 must suppress Phase B (saw: ${JSON.stringify(tagSets)})`);
  });

  test('relationExpansionBudget>0 + categoryLensExpansionBudget=0 still allows anchor BFS (Phase A)', async () => {
    const corpus = makeCorpusWithRelations();
    const pack = { epochId: 0, evalSeedCommit: '0x' + 'bb'.repeat(32), events: [corpus.events[0]] };
    // Substrate: anchor BOTH ev-A and ev-B, with a substrate-internal
    // relation edge from slot 0 (ev-A) → slot 1 (ev-B). Phase A BFS should
    // surface ev-B's truth even with Phase B disabled.
    const words = new Array(1024).fill(0n);
    placeMemorySlot(words, 0, {
      recordId: stableRecordIdFor('ev-A'),
      family: 'multi_hop_relation',
      domainBits: 1n, valid: true, revoked: false, protected: false,
      retrievalSlot: 0, expiryEpoch: 0n,
    });
    placeMemorySlot(words, 1, {
      recordId: stableRecordIdFor('ev-B'),
      family: 'multi_hop_relation',
      domainBits: 1n, valid: true, revoked: false, protected: false,
      retrievalSlot: 1, expiryEpoch: 0n,
    });
    placeRelationEdge(words, 0, { sourceSlot: 0, targetSlot: 1, edgeType: 'supports', weight: 1 });
    const state = { words };

    const composite = await evaluateRetrievalBenchmarkState(state, corpus, pack, baseOpts({
      relationExpansionBudget: 12,
      categoryLensExpansionBudget: 0,
    }));
    const q = composite.perQuery[0];
    const idx = q.cappedDocIds.indexOf('ev-B-truth');
    assert.notEqual(idx, -1, "Phase A must surface ev-B's truth via anchorBFS even with Phase B off");
    const sources = q.cappedDocSources[idx];
    assert.ok(sources.includes('anchorBFS') || sources.includes('anchorMandatory'),
      `ev-B's truth must carry anchorBFS or anchorMandatory tag (got ${JSON.stringify(sources)})`);
    // And no categoryLensBFS docs anywhere.
    const allTags = q.cappedDocSources.flat();
    assert.equal(allTags.includes('categoryLensBFS'), false,
      'no categoryLensBFS expected when Phase B is disabled');
  });

  test('omitting categoryLensExpansionBudget falls back to relationExpansionBudget (back-compat)', async () => {
    const corpus = makeCorpusWithRelations();
    const pack = { epochId: 0, evalSeedCommit: '0x' + 'cc'.repeat(32), events: [corpus.events[0]] };
    const words = new Array(1024).fill(0n);
    placeMemorySlot(words, 0, {
      recordId: stableRecordIdFor('ev-A'),
      family: 'multi_hop_relation',
      domainBits: 1n, valid: true, revoked: false, protected: false,
      retrievalSlot: 0, expiryEpoch: 0n,
    });
    placeCategoryLens(words, 127, { edgeType: 'supports', weight: 0x8000 });
    const state = { words };

    // Omit categoryLensExpansionBudget — should default to relationExpansionBudget=12,
    // allowing Phase B to run (and surface ev-B's truth via category-lens BFS).
    const composite = await evaluateRetrievalBenchmarkState(state, corpus, pack, baseOpts({
      relationExpansionBudget: 12,
      // categoryLensExpansionBudget intentionally omitted
    }));
    const q = composite.perQuery[0];
    const idx = q.cappedDocIds.indexOf('ev-B-truth');
    assert.notEqual(idx, -1, "Phase B (back-compat fallback) must surface ev-B's truth");
    const sources = q.cappedDocSources[idx];
    assert.ok(sources.includes('categoryLensBFS'),
      `ev-B's truth must carry categoryLensBFS tag under back-compat (got ${JSON.stringify(sources)})`);
  });
});
