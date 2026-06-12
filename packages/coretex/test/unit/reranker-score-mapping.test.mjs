/**
 * Regression test for the reranker-score-to-doc misattribution bug.
 *
 * Earlier code computed `scores[i] = rerankerScoresTopN[i]` over the
 * `rerankerCandidates` array (which is `anchorMandatory ++ preRankFill`,
 * reordered relative to `candidates`), then mapped scores back onto
 * `candidates` by positional index. When any anchor-mandatory doc was
 * not already the highest-preRank doc — i.e. nearly every substrate-
 * routed query on hard families — scores attached to the wrong docs.
 *
 * This test engineers the exact failure mode: a query whose truth doc
 * has LOW first-stage cosine but is anchored by the substrate. With the
 * bug, the truth doc ends up scored 0 and a distractor wins top-1; with
 * the fix, the truth doc receives its reranker score and lands at top-1.
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
    id,
    queryText,
    family: 'multi_hop_relation',
    split: splitForRecord(id, 0),
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
      query: quantize(queryVec),
      perTruth: new Map([[`${id}-truth`, quantize(truthVec)]]),
      perNegative: new Map(),
    },
  };
}

function withWords(state, indexed) {
  const words = [...state.words];
  for (const [i, v] of indexed) words[i] = v;
  return { words };
}

function placeMemorySlot(state, slotIndex, slot) {
  const enc = encodeMemoryIndexSlot({ ...slot, slotIndex });
  const indexed = enc.map((v, i) => [RANGES.MEMORY_INDEX_START + slotIndex * 8 + i, v]);
  return withWords(state, indexed);
}

// Reranker that maps document text → deterministic score. The truth doc
// text is engineered to score MUCH higher than the distractor's, so if
// scores attach to the right docs the truth ranks first.
function textScoringReranker() {
  return {
    model: 'text-mapping-mock',
    async score(pairs) {
      return pairs.map((p) => (p.document.includes('TRUTH-FOR-A') ? 0.99 : 0.01));
    },
  };
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

function makeOpts(rerankerInputTopK) {
  return {
    weights: DEFAULT_PROFILE.compositeWeights,
    retrievalKeyLayout: LAYOUT,
    biEncoder: trivialBiEncoder(),
    reranker: textScoringReranker(),
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

describe('reranker score-to-doc mapping (regression)', () => {
  test('anchor-mandatory truth doc receives its own reranker score, not a sibling candidate s', async () => {
    // Event A's truth doc is engineered as the answer for the query.
    // Its stage-1 cosine is LOW (different truth vector vs query vec) so
    // preRank places A near the bottom. Events B..F have HIGH cosine so
    // they sit at top of `candidates`. The substrate activates anchor A
    // (memorySlot != null), forcing A into `anchorMandatory` even though
    // it is not the top-preRank doc — exactly the condition the bug
    // mishandled.
    const queryVec = [1, 0, 0, 0, 0, 0, 0, 0];
    const truthVecA = [-1, 0, 0, 0, 0, 0, 0, 0];  // anti-aligned → low cosine
    const distractorVec = [1, 0, 0, 0, 0, 0, 0, 0]; // aligned → high cosine
    const eventA = makeEvent('ev-A', 'who anchored this query', 'TRUTH-FOR-A content', truthVecA, queryVec);
    const distractors = Array.from({ length: 8 }, (_, i) =>
      makeEvent(`ev-D${i}`, `distractor ${i}`, `distractor content ${i}`, distractorVec, distractorVec),
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
    const pack = { epochId: 0, evalSeedCommit: '0x' + '55'.repeat(32), events: [eventA] };

    // Build a substrate that anchors event A into MemoryIndex slot 0.
    let state = { words: new Array(1024).fill(0n) };
    state = placeMemorySlot(state, 0, {
      recordId: stableRecordIdFor(eventA.id),
      family: eventA.family,
      domainBits: 1n,
      valid: true,
      revoked: false,
      protected: false,
      retrievalSlot: 0,
      expiryEpoch: 0n,
    });

    // With cap=3 the pool is forced to drop most candidates. Without
    // anchor-mandatory, A would be dropped (its preRank is the lowest).
    // The substrate's anchor force-includes A. The bug attached A's
    // reranker score to whichever distractor sat at candidates[0].
    const composite = await evaluateRetrievalBenchmarkState(state, corpus, pack, makeOpts(3));
    assert.equal(composite.perQuery.length, 1);
    const q = composite.perQuery[0];
    // Truth at rank 1 → nDCG@10 = 1.0. Bug would put a distractor first,
    // giving truth nDCG@10 ≤ 1/log2(3) ≈ 0.6309.
    assert.equal(q.nDCG10, 1, `truth doc must be ranked first under anchor routing; nDCG@10=${q.nDCG10}`);
    assert.equal(q.mrr10, 1, `truth doc MRR must be 1.0; got ${q.mrr10}`);
  });
});
