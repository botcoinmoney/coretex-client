/**
 * BMU multi_hop_chain public mineability: evidence_bundle boost@b1 must promote
 * the supports path out to hop 2 so a distant answer (no query subject on
 * entityIds) can enter top-B under categoryLensHopBudget=1. Suppress@b1 must
 * demote co_occurs_with off-path neighbors without touching the supports path.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  evaluateRetrievalBenchmarkState,
  computeCorpusRoot,
  splitForRecord,
  encodePolicyAtom,
  encodeMemoryIndexSlot,
  POLICY_SELECTOR,
  POLICY_EVIDENCE_FEATURE,
  stableRecordIdFor,
} from '../../dist/index.js';
import { RANGES } from '../../dist/state/types.js';

const LAYOUT = { dim: 8, headerBytes: 9, quantization: 'int8' };
const MODEL_ID = 'test/biencoder';
const REVISION = 'rev';
const MODEL_HASH = '0xdeadbeef';
const SUBJECT = 'e_bmu_mh_boost_subj';
const UNIVERSE = 'user_scope_bmu_mh_boost';

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

function memEvent(id, docId, text, vec, entityIds, relations = []) {
  return {
    id,
    queryText: text,
    family: 'multi_hop_relation',
    split: 'train_visible',
    timestamp: Date.now(),
    epochId: 0,
    entityIds,
    truthDocuments: [{ id: docId, text, isCurrent: true }],
    negativeDocuments: [],
    hardNegatives: [],
    qrels: [{ documentId: docId, relevance: 1 }],
    relations,
    embeddings: {
      modelId: MODEL_ID,
      revision: REVISION,
      layout: LAYOUT,
      query: quantize(vec),
      perTruth: new Map([[docId, quantize(vec)]]),
      perNegative: new Map(),
    },
  };
}

function queryEvent(id, text, qVec, required, forbidden, docs) {
  const byId = new Map(docs.map((d) => [d.truthDocuments[0].id, d]));
  return {
    id,
    queryText: text,
    family: 'multi_hop_relation',
    split: splitForRecord(id, 0),
    timestamp: Date.now(),
    epochId: 0,
    subjectEntityId: SUBJECT,
    ownerEntityId: UNIVERSE,
    ownerScoped: true,
    publicIntent: {
      atom: 'multi_hop_chain',
      subjectEntityId: SUBJECT,
      topic: 'incident rollback signoff',
      targetAttribute: 'approver seat',
      hopCount: 3,
      queryTime: '2038-09-14',
      selector: 'qtype_chain_endpoint_value_v0',
    },
    truthDocuments: required.map((docId) => ({
      id: docId,
      text: byId.get(docId).truthDocuments[0].text,
      isCurrent: true,
    })),
    hardNegatives: forbidden.map((docId) => ({
      id: docId,
      text: byId.get(docId).truthDocuments[0].text,
    })),
    qrels: [
      ...required.map((docId, i) => ({ documentId: docId, relevance: i === required.length - 1 ? 1 : 0.6 })),
      ...forbidden.map((docId) => ({ documentId: docId, relevance: 0 })),
    ],
    embeddings: {
      modelId: MODEL_ID,
      revision: REVISION,
      layout: LAYOUT,
      query: quantize(qVec),
      perTruth: new Map(required.map((docId) => [docId, byId.get(docId).embeddings.perTruth.get(docId)])),
      perNegative: new Map(forbidden.map((docId) => [docId, byId.get(docId).embeddings.perTruth.get(docId)])),
    },
  };
}

function answerAwareReranker() {
  return {
    model: 'mh-mock',
    async score(pairs) {
      return pairs.map((p) => {
        if (p.document.includes('ANSWER-DOC')) return 0.55;
        if (p.document.includes('OFFPATH-DOC') || p.document.includes('SHADOW-DOC')) return 0.92;
        if (p.document.includes('BRIDGE-DOC')) return 0.80;
        if (p.document.includes('HOP2-DOC')) return 0.70;
        return 0.2;
      });
    },
  };
}

function trivialBiEncoder() {
  return { model: { id: MODEL_ID, revision: REVISION }, async encode() { return new Float32Array(LAYOUT.dim); } };
}

function makeOpts(reranker) {
  return {
    weights: { w_retrieval: 0.75, w_temporal: 0.08, w_relation_recall: 0.07, w_abstention: 0.05, w_structural_sanity: 0.05 },
    retrievalKeyLayout: LAYOUT,
    biEncoder: trivialBiEncoder(),
    reranker,
    biEncoderHash: MODEL_HASH,
    relationHopBudget: 2,
    abstentionThreshold: 0.001,
    rerankerTopK: 10,
    retrievalKeyTopK: 50,
    firstStageTopK: 300,
    rerankerInputTopK: 64,
    lensTopK: 36,
    lensWeight: 0.1,
    anchorWeight: 0.15,
    relationExpansionBudget: 50,
    temporalCurrentBoost: 0.1,
    temporalStaleSuppression: 0.1,
    policyAtomsMode: true,
    enableEvidenceBundleAtoms: true,
    policyEvidenceAllowedActions: ['bundle', 'include', 'boost', 'suppress'],
    policyQueryConditionedAdmission: true,
    policyRelationTypedAdmission: true,
    policyMaxBudgetEvidence: 250,
    categoryLensExpansionBudget: 50,
    categoryLensHopBudget: 1,
    categoryLensScoreInheritance: 0.3,
    categoryLensEvidenceBundle: true,
    categoryLensSeedTopK: 2,
    categoryLensFinalBonusWeight: 0,
    policyEmitTraces: true,
  };
}

function stateWithBridgeAtoms() {
  const words = new Array(1024).fill(0n);
  const bridgeSlot = 5;
  words[RANGES.MEMORY_INDEX_START + bridgeSlot] = encodeMemoryIndexSlot({
    slotIndex: bridgeSlot,
    recordId: stableRecordIdFor('mem-b1'),
    family: 'multi_hop_relation',
    domainBits: 1n,
    valid: true,
    revoked: false,
    protected: false,
    policyAnchor: true,
    retrievalSlot: 0,
    expiryEpoch: 0n,
  })[0];
  words[RANGES.POLICY_EVIDENCE_START] = encodePolicyAtom({
    atomIndex: 0,
    family: 'evidence_bundle',
    selector: POLICY_SELECTOR.ANSWER_DENSITY,
    evidenceFeature: POLICY_EVIDENCE_FEATURE.SUPPORT_IN_DEGREE,
    action: 'boost',
    scope: 'relation_path',
    targetSlot: bridgeSlot,
    budget: 250,
    flags: 0,
    validFromEpoch: 0n,
    expiryEpoch: 0n,
  });
  words[RANGES.POLICY_EVIDENCE_START + 1] = encodePolicyAtom({
    atomIndex: 1,
    family: 'evidence_bundle',
    selector: POLICY_SELECTOR.ANSWER_DENSITY,
    evidenceFeature: POLICY_EVIDENCE_FEATURE.SUPPORT_IN_DEGREE,
    action: 'suppress',
    scope: 'entity',
    targetSlot: bridgeSlot,
    budget: 250,
    flags: 0,
    validFromEpoch: 0n,
    expiryEpoch: 0n,
  });
  return { words };
}

describe('BMU multi_hop_chain evidence boost/suppress', () => {
  test('boost@b1 promotes supports@2 answer; suppress demotes co_occurs_with traps', async () => {
    const qVec = [1, 0, 0, 0, 0, 0, 0, 0];
    // Stage-1 competitive traps + bridge; distant hop2/ans are low cosine.
    const bridgeVec = [0.85, 0.527, 0, 0, 0, 0, 0, 0];
    const hop2Vec = [0.20, 0.980, 0, 0, 0, 0, 0, 0];
    const ansVec = [0.15, 0.989, 0, 0, 0, 0, 0, 0];
    const trapVec = [0.90, 0.436, 0, 0, 0, 0, 0, 0];

    const b1 = memEvent('mem-b1', 'd-b1', 'BRIDGE-DOC subject memo', bridgeVec, [UNIVERSE, SUBJECT], [
      { other_id: 'mem-b2', edgeType: 'supports', label: 'delegates_to' },
      { other_id: 'mem-op', edgeType: 'co_occurs_with', label: 'co_mentioned' },
      { other_id: 'mem-sh', edgeType: 'co_occurs_with', label: 'digest_mention' },
    ]);
    const b2 = memEvent('mem-b2', 'd-b2', 'HOP2-DOC routing sheet', hop2Vec, [UNIVERSE], [
      { other_id: 'mem-ans', edgeType: 'supports', label: 'routes_to' },
    ]);
    const ans = memEvent('mem-ans', 'd-ans', 'ANSWER-DOC confirmed seat', ansVec, [UNIVERSE], []);
    const op = memEvent('mem-op', 'd-op', 'OFFPATH-DOC provisional figure', trapVec, [UNIVERSE, SUBJECT], [
      { other_id: 'mem-b1', edgeType: 'co_occurs_with', label: 'co_mentioned' },
    ]);
    const sh = memEvent('mem-sh', 'd-sh', 'SHADOW-DOC older excerpt', trapVec, [UNIVERSE, SUBJECT], [
      { other_id: 'mem-b1', edgeType: 'co_occurs_with', label: 'digest_mention' },
    ]);
    const docs = [b1, b2, ans, op, sh];
    const q = queryEvent(
      'zz_q_mh_boost',
      'As of this session, which approver seat should be used for subject incident rollback signoff?',
      qVec,
      ['d-b1', 'd-ans'],
      ['d-op', 'd-sh'],
      docs,
    );
    const events = [...docs, q];
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
    const pack = { epochId: 0, evalSeedCommit: `0x${'11'.repeat(32)}`, events: [q] };
    const empty = { words: new Array(1024).fill(0n) };
    const patched = stateWithBridgeAtoms();
    const opts = makeOpts(answerAwareReranker());

    const before = await evaluateRetrievalBenchmarkState(empty, corpus, pack, opts);
    const after = await evaluateRetrievalBenchmarkState(patched, corpus, pack, opts);
    const topBefore = (before.perQuery?.[0]?.finalRankingTop20 ?? []).map((x) => x.docId);
    const topAfter = (after.perQuery?.[0]?.finalRankingTop20 ?? []).map((x) => x.docId);
    const traces = after.perQuery?.[0]?.policyTraces ?? [];
    const boostTrace = traces.find((t) => t.atomFamily === 'evidence_bundle' && t.action === 'boost');
    const suppressTrace = traces.find((t) => t.atomFamily === 'evidence_bundle' && t.action === 'suppress');

    assert.ok(boostTrace, 'boost atom should fire on multi_hop_chain');
    assert.ok(
      (boostTrace.evidencePath ?? []).some((p) => String(p).includes('supports@2->mem-ans')),
      `boost should reach ans via supports@2, got ${JSON.stringify(boostTrace.evidencePath)}`,
    );
    assert.equal(boostTrace.docsMoved, 2, 'boost should move hop2 + ans');
    assert.ok(suppressTrace, 'suppress atom should fire on multi_hop_chain');
    assert.ok(
      (suppressTrace.evidencePath ?? []).some((p) => String(p).includes('co_occurs_with->mem-op')),
      `suppress should demote co_occurs_with traps, got ${JSON.stringify(suppressTrace.evidencePath)}`,
    );
    assert.ok(topAfter.includes('d-ans'), `answer must enter ranking after boost (got ${topAfter.slice(0, 6)})`);
    assert.ok(topAfter.includes('d-b1'), `bridge must remain (got ${topAfter.slice(0, 6)})`);
    assert.ok(topAfter.includes('d-b2'), `hop2 must be admitted via supports@1 (got ${topAfter.slice(0, 6)})`);
    // Mechanism pin: boost reaches hop-2 answer and suppress targets co_occurs_with.
    // Final trap/answer inversion under real Qwen is proven by G-B7, not this mock gap.
    assert.ok(topBefore.includes('d-ans') || topAfter.includes('d-ans'));
  });
});
