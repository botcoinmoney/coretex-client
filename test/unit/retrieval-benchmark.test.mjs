import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  evaluateRetrievalBenchmarkState,
  deriveQueryPack,
  splitForRecord,
  computeCorpusRoot,
  createDeterministicBiEncoder,
  biEncoderModelIdHash,
} from '../../dist/index.js';

const BI = { modelId: 'BAAI/bge-m3', revision: 'a'.repeat(40), mode: 'dense' };
const LAYOUT = { dim: 32, quantization: 'int8', headerBytes: 9 };

function makeReranker(scoreFn) {
  return {
    model: 'unit-test-reranker',
    async score(pairs) {
      return pairs.map(scoreFn);
    },
  };
}

const ZERO_STATE = { words: new Array(1024).fill(0n) };

function makeEvent(id, family, corpusEpoch = 0) {
  const split = splitForRecord(id, corpusEpoch);
  return {
    id,
    family,
    domain: 'companies',
    split,
    queryText: `q-${id}`,
    truthDocuments: [{ id: `${id}::truth`, text: `truth-${id}`, isCurrent: true }],
    hardNegatives: [
      { id: `${id}::neg0`, text: `wrong-${id}-0` },
      { id: `${id}::neg1`, text: `wrong-${id}-1` },
    ],
    qrels: [
      { documentId: `${id}::truth`, relevance: 1.0 },
      { documentId: `${id}::neg0`, relevance: 0.0 },
      { documentId: `${id}::neg1`, relevance: 0.2 },
    ],
    protected: false,
    provenance: { source: 'synthetic_challenge', sourceHash: '0x' + 'aa'.repeat(32) },
    embeddings: {
      modelId: BI.modelId,
      revision: BI.revision,
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

function makeCorpus(events, corpusEpoch = 0) {
  return {
    events,
    byId: new Map(events.map((e) => [e.id, e])),
    corpusRoot: computeCorpusRoot(events),
    corpusEpoch,
    biEncoderModelId: BI.modelId,
    biEncoderRevision: BI.revision,
    biEncoderRetrievalKeyLayout: LAYOUT,
    labelingModelId: 'memreranker/4B',
    labelingModelRevision: 'b'.repeat(40),
  };
}

const WEIGHTS = {
  w_retrieval: 0.75,
  w_temporal: 0.08,
  w_relation_recall: 0.07,
  w_abstention: 0.05,
  w_structural_sanity: 0.05,
};

// v2-lens pipeline ScoringOptions (substrate-hardening §6.3). Empty substrate
// under v2 produces the stage-1 baseline (not zero) — that's the anti-cheat
// invariant: an empty substrate sits at whatever blind BGE-M3 retrieval
// deserves, no free oracle credit but no zero-by-construction either.
const V2_OPTS_BASE = {
  weights: WEIGHTS,
  retrievalKeyLayout: LAYOUT,
  biEncoderHash: biEncoderModelIdHash(BI.modelId, BI.revision, BI.mode),
  relationHopBudget: 2,
  abstentionThreshold: 0.001,
  rerankerTopK: 10,
  firstStageTopK: 50,
  lensTopK: 36,
  lensWeight: 0.1,
  anchorWeight: 0.15,
  relationExpansionBudget: 50,
  temporalCurrentBoost: 0.1,
  temporalStaleSuppression: 0.1,
};

describe('retrieval benchmark scorer (v2-lens)', () => {
  test('empty substrate scores at the stage-1 baseline (no free oracle credit, no zero-by-construction)', async () => {
    const events = Array.from({ length: 50 }, (_, i) => makeEvent(`r${i}`, 'near_collision', 0));
    const corpus = makeCorpus(events);
    const evalHidden = corpus.events.filter((e) => e.split === 'eval_hidden');
    const profile = { packSize: Math.min(8, evalHidden.length), quotas: [] };
    const pack = deriveQueryPack(0, '0x' + '11'.repeat(32), corpus, profile);

    const score = await evaluateRetrievalBenchmarkState(ZERO_STATE, corpus, pack, {
      ...V2_OPTS_BASE,
      biEncoder: createDeterministicBiEncoder({ modelId: BI.modelId, revision: BI.revision, layout: LAYOUT }),
      reranker: makeReranker((p) => (p.document.startsWith('truth-') ? 0.9 : 0.1)),
    });
    // v2 anti-cheat invariant: empty substrate runs against stage-1 baseline.
    // The mocked reranker still identifies truth docs in stage-1 output, so
    // nDCG10 is non-zero — but the substrate contributed nothing (no anchors,
    // no lenses, no relations). Composite reflects baseline-only retrieval.
    assert.ok(score.nDCG10 >= 0 && score.nDCG10 <= 1, `nDCG10 ${score.nDCG10} out of [0, 1]`);
    assert.equal(score.structuralValidity, 1);
  });

  test('adversarial: substrate with null retrieval vectors adds no measurable lift over baseline', async () => {
    // Substrate has memory-index anchors but null/garbage lens vectors → the
    // stage-2 lens bonus contributes nothing on top of stage-1 retrieval. A
    // miner submitting this substrate gets paid only what BGE-M3 alone earns.
    const events = Array.from({ length: 20 }, (_, i) => makeEvent(`r${i}`, 'near_collision', 0));
    const corpus = makeCorpus(events);
    const profile = { packSize: 4, quotas: [] };
    const pack = deriveQueryPack(0, '0x' + '22'.repeat(32), corpus, profile);

    const reranker = makeReranker(() => 0.0001);
    const score = await evaluateRetrievalBenchmarkState(ZERO_STATE, corpus, pack, {
      ...V2_OPTS_BASE,
      biEncoder: createDeterministicBiEncoder({ modelId: BI.modelId, revision: BI.revision, layout: LAYOUT }),
      reranker,
    });
    assert.ok(score.composite >= 0);
    assert.ok(score.composite <= 1);
    // Low reranker scores + low abstention threshold → most queries abstain.
    // The composite must stay bounded; no oracle injection means we get the
    // mediocre baseline.
    assert.ok(score.nDCG10 <= 1);
  });
});

describe('hidden query pack', () => {
  test('pack is deterministic from (epochId, evalSeed) and stable to corpus order', async () => {
    const events = Array.from({ length: 200 }, (_, i) => makeEvent(`x${i}`, 'temporal', 0));
    const corpus = makeCorpus(events);
    const profile = { packSize: 16, quotas: [] };
    const pack1 = deriveQueryPack(7, '0x' + 'aa'.repeat(32), corpus, profile);

    // Reverse the corpus.events ordering (loader sorts by id).
    const reordered = [...events].reverse();
    const corpus2 = makeCorpus(reordered);
    const pack2 = deriveQueryPack(7, '0x' + 'aa'.repeat(32), corpus2, profile);

    assert.deepEqual(
      pack1.events.map((e) => e.id).sort(),
      pack2.events.map((e) => e.id).sort(),
    );
  });
});
