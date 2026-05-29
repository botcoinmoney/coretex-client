/**
 * aspect_constraint EXPERIMENTAL boost — unit controls (reads PUBLIC memory-doc aspect tags + subject,
 * NEVER the query's qrels/truths/negs). Asserts:
 *   - OFF (no flags) == baseline composite (byte-identical no-op);
 *   - boost <= 0 == OFF (no-op);
 *   - ON boosts ONLY a public same-subject matching-aspect candidate (nDCG rises);
 *   - wrong-SUBJECT same-aspect does NOT move; wrong-ASPECT same-subject does NOT move.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  evaluateRetrievalBenchmarkState, computeCorpusRoot, createDeterministicBiEncoder, biEncoderModelIdHash,
} from '../../dist/index.js';

const BI = { modelId: 'BAAI/bge-m3', revision: 'a'.repeat(40), mode: 'dense' };
const LAYOUT = { dim: 32, quantization: 'int8', headerBytes: 9 };
const ZERO_STATE = { words: new Array(1024).fill(0n) };
const WEIGHTS = { w_retrieval: 0.75, w_temporal: 0.08, w_relation_recall: 0.07, w_abstention: 0.05, w_structural_sanity: 0.05 };
const UNIVERSE = 'e_universe';
const emb = () => new Uint8Array(LAYOUT.dim + 4);
const makeReranker = () => ({ model: 't', async score(pairs) { return pairs.map(() => 0.5); } }); // all-equal → finalBonus orders

// PUBLIC memory-doc event (build-v2 `mem_*` shape) — carries aspectTags + subject the scorer reads.
function memDoc(docId, subject, aspectTags) {
  return {
    id: `mem_${docId}`, family: 'near_collision', domain: 'd', split: 'train_visible', queryText: `t-${docId}`,
    truthDocuments: [{ id: docId, text: `t-${docId}`, isCurrent: true, ...(aspectTags ? { aspectTags } : {}) }],
    hardNegatives: [], qrels: [{ documentId: docId, relevance: 1.0 }], protected: false, entityIds: [UNIVERSE, subject],
    provenance: { source: 'synthetic_challenge', sourceHash: '0x' + 'aa'.repeat(32) },
    embeddings: { modelId: BI.modelId, revision: BI.revision, layout: LAYOUT, query: emb(), perTruth: new Map([[docId, emb()]]), perNegative: new Map() },
  };
}
// aspect query: gold sorts AFTER the distractor (docId order) so without the boost it is NOT top-ranked.
function aspectQuery(qid, subject, goldId, distractorId) {
  return {
    id: qid, family: 'aspect_constraint', domain: 'd', split: 'eval_hidden',
    queryText: `For Aisha Costa, what is the latency detail?`, subjectEntityId: subject,
    truthDocuments: [{ id: goldId, text: `t-${goldId}`, isCurrent: true }],
    hardNegatives: [{ id: distractorId, text: `t-${distractorId}` }],
    qrels: [{ documentId: goldId, relevance: 1.0 }, { documentId: distractorId, relevance: 0.0 }],
    protected: false,
    provenance: { source: 'synthetic_challenge', sourceHash: '0x' + 'aa'.repeat(32) },
    embeddings: { modelId: BI.modelId, revision: BI.revision, layout: LAYOUT, query: emb(), perTruth: new Map([[goldId, emb()]]), perNegative: new Map([[distractorId, emb()]]) },
  };
}
function corpusOf(events) {
  return { events, byId: new Map(events.map((e) => [e.id, e])), corpusRoot: computeCorpusRoot(events), corpusEpoch: 0,
    biEncoderModelId: BI.modelId, biEncoderRevision: BI.revision, biEncoderRetrievalKeyLayout: LAYOUT, labelingModelId: 'm', labelingModelRevision: 'b'.repeat(40) };
}
const BASE = {
  weights: WEIGHTS, retrievalKeyLayout: LAYOUT, biEncoderHash: biEncoderModelIdHash(BI.modelId, BI.revision, BI.mode),
  relationHopBudget: 2, abstentionThreshold: 0.001, rerankerTopK: 10, firstStageTopK: 50, lensTopK: 36, lensWeight: 0.1,
  anchorWeight: 0.15, relationExpansionBudget: 50, temporalCurrentBoost: 0.1, temporalStaleSuppression: 0.1, policyAtomsMode: true,
};
const ASPECT_ON = { enableAspectConstraintAtoms: true, policyAspectIntentAdmission: true, policyAspectBoost: 0.2, policyGenericEntityIds: [UNIVERSE] };

async function score(corpus, q, extra) {
  const pack = { events: [q], corpusRoot: corpus.corpusRoot, epochId: 0 };
  return (await evaluateRetrievalBenchmarkState(ZERO_STATE, corpus, pack, {
    ...BASE, ...extra, biEncoder: createDeterministicBiEncoder({ modelId: BI.modelId, revision: BI.revision, layout: LAYOUT }), reranker: makeReranker(),
  })).nDCG10;
}

describe('aspect_constraint boost — public-source + subject-scoped controls', () => {
  test('ON boosts a PUBLIC same-subject matching-aspect candidate (nDCG rises); OFF + boost<=0 are no-ops', async () => {
    // gold (zzz, S1, [latency]) sorts after distractor (aaa, S1, no aspect) → needs the boost to top-rank.
    const q = aspectQuery('q_match', 'e_S1', 'zzz_gold', 'aaa_dist');
    const corpus = corpusOf([q, memDoc('zzz_gold', 'e_S1', ['latency', 'cost']), memDoc('aaa_dist', 'e_S1', undefined)]);
    const off = await score(corpus, q);
    const on = await score(corpus, q, ASPECT_ON);
    const zero = await score(corpus, q, { ...ASPECT_ON, policyAspectBoost: 0 });
    const neg = await score(corpus, q, { ...ASPECT_ON, policyAspectBoost: -0.2 });
    assert.ok(on > off, `ON (${on}) should boost the matching same-subject gold above OFF (${off})`);
    assert.equal(zero, off, 'boost 0 is a no-op');
    assert.equal(neg, off, 'negative boost is a no-op');
  });

  test('wrong-SUBJECT same-aspect does NOT move (subject scope holds)', async () => {
    // gold (zzz, S1) has NO matching aspect; the only [latency] doc is a DIFFERENT subject (S2) → no boost.
    const q = aspectQuery('q_wsub', 'e_S1', 'zzz_gold', 'aaa_dist');
    const corpus = corpusOf([q, memDoc('zzz_gold', 'e_S1', ['cost']), memDoc('aaa_dist', 'e_S2', ['latency'])]);
    const off = await score(corpus, q);
    const on = await score(corpus, q, ASPECT_ON);
    assert.equal(on, off, 'a wrong-subject latency doc must not be boosted');
  });

  test('wrong-ASPECT same-subject does NOT move', async () => {
    // gold (zzz, S1, [cost]) is same-subject but wrong aspect (intent=latency) → no boost.
    const q = aspectQuery('q_wasp', 'e_S1', 'zzz_gold', 'aaa_dist');
    const corpus = corpusOf([q, memDoc('zzz_gold', 'e_S1', ['cost']), memDoc('aaa_dist', 'e_S1', ['cost'])]);
    const off = await score(corpus, q);
    const on = await score(corpus, q, ASPECT_ON);
    assert.equal(on, off, 'a wrong-aspect same-subject doc must not be boosted');
  });
});
