import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  DEFAULT_PROFILE,
  computeCorpusRoot,
  encodeRelationCategoryLens,
  evaluateRetrievalBenchmarkState,
  splitForRecord,
} from '../../dist/index.js';
import { RANGES } from '../../dist/state/types.js';

const LAYOUT = { dim: 8, headerBytes: 9, quantization: 'int8' };
const MODEL_ID = 'test/biencoder';
const REVISION = 'rev';

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

function makeEvent({ id, family = 'near_collision', queryText, truthText, truthVec, queryVec, qrels, relations = [] }) {
  return {
    id,
    family,
    domain: 'test',
    split: splitForRecord(id, 0),
    queryText,
    truthDocuments: [{ id: `${id}::truth`, text: truthText, isCurrent: true }],
    hardNegatives: [],
    qrels: qrels ?? [{ documentId: `${id}::truth`, relevance: 1 }],
    protected: false,
    relations,
    provenance: {
      source: 'synthetic_challenge',
      challengeSeed: '0x' + '00'.repeat(16),
      challengeId: 'test',
      sourceHash: '0x' + '11'.repeat(32),
    },
    embeddings: {
      modelId: MODEL_ID,
      revision: REVISION,
      layout: LAYOUT,
      query: quantize(queryVec),
      perTruth: new Map([[`${id}::truth`, quantize(truthVec)]]),
      perNegative: new Map(),
    },
  };
}

function constantReranker() {
  return { model: 'const', async score(pairs) { return pairs.map(() => 0.5); } };
}

function unusedBiEncoder() {
  return {
    model: { id: MODEL_ID, revision: REVISION },
    async encode() {
      return new Float32Array(LAYOUT.dim);
    },
  };
}

describe('category-lens relation hit diagnostic', () => {
  test('counts corpus-native category-lens success even when memorySlot is null', async () => {
    const queryVec = [1, 0, 0, 0, 0, 0, 0, 0];
    const nearVec = [1, 0, 0, 0, 0, 0, 0, 0];
    const targetVec = [-1, 0, 0, 0, 0, 0, 0, 0];

    const target = makeEvent({
      id: 'target-entity',
      queryText: 'target profile',
      truthText: 'The answer is target entity.',
      truthVec: targetVec,
      queryVec: targetVec,
    });
    const near = makeEvent({
      id: 'near-neighbor',
      queryText: 'near neighbor',
      truthText: 'A related near neighbor.',
      truthVec: nearVec,
      queryVec: nearVec,
      relations: [{ other_id: target.id, edgeType: 'derived_from' }],
    });
    const query = makeEvent({
      id: 'query-event',
      family: 'multi_hop_relation',
      queryText: 'Which entity is derived from the near neighbor?',
      truthText: 'Local duplicate answer text that stage one misses.',
      truthVec: targetVec,
      queryVec,
      relations: [{ other_id: target.id, edgeType: 'derived_from' }],
      qrels: [
        { documentId: 'query-event::truth', relevance: 1 },
        { documentId: 'target-entity::truth', relevance: 1 },
      ],
    });

    const events = [query, near, target];
    const corpus = {
      events,
      byId: new Map(events.map((e) => [e.id, e])),
      corpusRoot: computeCorpusRoot(events),
      corpusEpoch: 0,
      biEncoderModelId: MODEL_ID,
      biEncoderRevision: REVISION,
      biEncoderRetrievalKeyLayout: LAYOUT,
      labelingModelId: 'labeler',
      labelingModelRevision: 'rev',
    };
    const pack = { epochId: 0, evalSeedCommit: '0x' + '44'.repeat(32), events: [query] };

    const words = new Array(1024).fill(0n);
    words[RANGES.RELATIONS_START + 127] = encodeRelationCategoryLens({
      entryIndex: 127,
      edgeType: 'derived_from',
      weight: 0xffff,
    });

    const score = await evaluateRetrievalBenchmarkState({ words }, corpus, pack, {
      weights: DEFAULT_PROFILE.compositeWeights,
      retrievalKeyLayout: LAYOUT,
      biEncoder: unusedBiEncoder(),
      reranker: constantReranker(),
      biEncoderHash: '0xdeadbeef',
      relationHopBudget: 2,
      abstentionThreshold: 0.001,
      rerankerTopK: 10,
      retrievalKeyTopK: 50,
      firstStageTopK: 1,
      rerankerInputTopK: 10,
      lensTopK: 36,
      lensWeight: 1,
      anchorWeight: 0,
      relationExpansionBudget: 4,
      temporalCurrentBoost: 0.1,
      temporalStaleSuppression: 0.1,
    });

    const q = score.perQuery[0];
    assert.ok(q, 'per-query breakdown present');
    assert.equal(q.multiHopHit, false, 'slot-based multiHopHit remains false without MemoryIndex anchors');
    assert.equal(q.categoryLensRelationHit, true);
    assert.equal(score.categoryLensRelationHit10, 1);

    const targetRank = q.finalRankingTop20.find((r) => r.docId === 'target-entity::truth');
    assert.ok(targetRank, 'target truth is ranked');
    assert.equal(targetRank.relevance, 1);
    assert.ok(targetRank.sources.includes('categoryLensBFS'));
    assert.ok(targetRank.sources.every((source) => source !== 'anchorMandatory'));
    assert.ok(q.nDCG10 > 0);
    assert.ok(q.mrr10 > 0);
  });
});
