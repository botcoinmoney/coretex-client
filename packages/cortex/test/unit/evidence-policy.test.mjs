/**
 * EvidencePolicy mechanism test (candidate 3rd miner-facing surface), ADMISSION-ONLY.
 *
 * The opt-in CODEBOOK `high_density_evidence` policy atom (code=5) lifts a low-bi-cosine
 * but PUBLICLY-CORROBORATED answer (supports in-degree >= K) INTO the reranker cap; the
 * reranker then decides final order (non-flooding, mirrors relation inclusion-only). The
 * miner writes only the POLICY (K, weight); in-degree is public/auditable; no answer map.
 * Default off → byte-identical default path.
 *
 * Design: small rerank cap. The answer has LOW cosine (excluded from the cap under OFF)
 * but high supports in-degree; the reranker scores the answer text highest. With the policy
 * ON the answer is ADMITTED → reranked #1. OFF → excluded from the cap → not #1.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  evaluateRetrievalBenchmarkState, computeCorpusRoot, splitForRecord, encodeCodebookEntry, DEFAULT_PROFILE,
} from '../../dist/index.js';
import { RANGES } from '../../dist/state/types.js';

const LAYOUT = { dim: 8, headerBytes: 9, quantization: 'int8' };
const MODEL_ID = 'test/biencoder', REVISION = 'rev', MODEL_HASH = '0xdeadbeef';

function quantize(values) {
  const buf = new Uint8Array(4 + values.length); const dv = new DataView(buf.buffer); dv.setFloat32(0, 1.0, false);
  for (let i = 0; i < values.length; i++) { let v = Math.round(values[i] * 127); if (v > 127) v = 127; if (v < -128) v = -128; buf[4 + i] = v & 0xff; }
  return buf;
}
// makeEvent with explicit query/truth vecs + outgoing relations.
function makeEvent(id, queryText, truthText, truthVec, queryVec, relations = []) {
  return { id, queryText, family: 'multi_hop_relation', split: splitForRecord(id, 0), timestamp: Date.now(), epochId: 0,
    truthDocuments: [{ id: `${id}-truth`, text: truthText, isCurrent: true }], negativeDocuments: [], hardNegatives: [],
    qrels: [{ documentId: `${id}-truth`, relevance: 1 }], relations,
    embeddings: { modelId: MODEL_ID, revision: REVISION, layout: LAYOUT, query: quantize(queryVec), perTruth: new Map([[`${id}-truth`, quantize(truthVec)]]), perNegative: new Map() } };
}
// reranker scores the corroborated ANSWER text highest (so once admitted, it wins).
function answerScoringReranker() { return { model: 'ans-mock', async score(pairs) { return pairs.map((p) => (p.document.includes('CORROBORATED-ANSWER') ? 0.99 : 0.2)); } }; }
function trivialBiEncoder() { return { model: { id: MODEL_ID, revision: REVISION }, async encode() { return new Float32Array(LAYOUT.dim); } }; }
function makeOpts(evidencePolicyEnabled, rerankerInputTopK) {
  return { weights: DEFAULT_PROFILE.compositeWeights, retrievalKeyLayout: LAYOUT, biEncoder: trivialBiEncoder(), reranker: answerScoringReranker(), biEncoderHash: MODEL_HASH,
    relationHopBudget: 2, abstentionThreshold: 0.001, rerankerTopK: 10, retrievalKeyTopK: 50, firstStageTopK: 300, rerankerInputTopK,
    lensTopK: 36, lensWeight: 0.1, anchorWeight: 0.15, relationExpansionBudget: 50, temporalCurrentBoost: 0.1, temporalStaleSuppression: 0.1, evidencePolicyEnabled };
}
function withHighDensityAtom(state, k, weightPpm) {
  const enc = encodeCodebookEntry({ entryIndex: 0, code: 5, codeType: 'int8_scale_zero', valid: true, payload: (BigInt(weightPpm) << 16n) | BigInt(k), payloadCont: 0n });
  const words = [...state.words]; words[RANGES.CODEBOOK_START] = enc[0]; words[RANGES.CODEBOOK_START + 1] = enc[1]; return { words };
}
function answerRank(result) { const top = result.perQuery?.[0]?.finalRankingTop20 ?? []; const r = top.find((x) => x.docId === 'ev-Q-truth'); return r ? r.rank : 999; }

describe('EvidencePolicy high_density_evidence (admission-only, CODEBOOK policy atom)', () => {
  const queryVec = [1, 0, 0, 0, 0, 0, 0, 0];
  const answerVec = [0.30, 0.954, 0, 0, 0, 0, 0, 0];   // cosine ~0.30 (low → excluded under OFF, small cap)
  const distractorVec = [0.55, 0.835, 0, 0, 0, 0, 0, 0]; // cosine ~0.55 (fills the small cap)
  const corrVec = [0.1, 0.995, 0, 0, 0, 0, 0, 0];      // corroborators: low cosine, in-degree 0 (not boosted)
  function buildCorpus() {
    const q = makeEvent('ev-Q', 'who is the corroborated answer', 'CORROBORATED-ANSWER content', answerVec, queryVec);
    const corr = [0, 1, 2].map((i) => makeEvent(`ev-C${i}`, `corroborator ${i}`, `corr ${i}`, corrVec, corrVec, [{ other_id: 'ev-Q', edgeType: 'supports' }]));
    const dist = [0, 1, 2, 3].map((i) => makeEvent(`ev-D${i}`, `distractor ${i}`, `dist ${i}`, distractorVec, distractorVec));
    const events = [q, ...corr, ...dist];
    return { schemaVersion: 'coretex.production-corpus.v1', corpusEpoch: 0, corpusRoot: computeCorpusRoot(events), generatedAt: new Date().toISOString(),
      biEncoderModelId: MODEL_ID, biEncoderRevision: REVISION, biEncoderRetrievalKeyLayout: LAYOUT, events,
      splitRatios: { trainVisiblePct: 70, calibrationPct: 10, evalHiddenPct: 15, canaryPct: 5 } };
  }
  const CAP = 2; // small cap: the low-cosine answer is excluded under OFF, admitted by the policy under ON

  test('policy ON ADMITS the corroborated low-cosine answer into the cap → reranked #1; OFF excludes it', async () => {
    const corpus = buildCorpus();
    const pack = { epochId: 0, evalSeedCommit: '0x' + '55'.repeat(32), events: [corpus.events[0]] };
    const stateWithAtom = withHighDensityAtom({ words: new Array(1024).fill(0n) }, 2, 600000); // K=2 (<= in-degree 3), w=0.6
    const off = await evaluateRetrievalBenchmarkState(stateWithAtom, corpus, pack, makeOpts(false, CAP));
    const on = await evaluateRetrievalBenchmarkState(stateWithAtom, corpus, pack, makeOpts(true, CAP));
    const offRank = answerRank(off), onRank = answerRank(on);
    assert.equal(onRank, 1, `policy ON should admit + rerank the corroborated answer to #1 (got ${onRank})`);
    assert.ok(offRank > 1, `OFF should exclude the low-cosine answer from the small cap (rank ${offRank})`);
  });

  test('no atom → enabling policy is a no-op', async () => {
    const corpus = buildCorpus();
    const pack = { epochId: 0, evalSeedCommit: '0x' + '55'.repeat(32), events: [corpus.events[0]] };
    const empty = { words: new Array(1024).fill(0n) };
    const onNoAtom = await evaluateRetrievalBenchmarkState(empty, corpus, pack, makeOpts(true, CAP));
    const off = await evaluateRetrievalBenchmarkState(empty, corpus, pack, makeOpts(false, CAP));
    assert.equal(answerRank(onNoAtom), answerRank(off), 'enabling policy with no atom must not change ranking');
  });

  test('sub-threshold atom (K above in-degree) confers no admission boost', async () => {
    const corpus = buildCorpus();
    const pack = { epochId: 0, evalSeedCommit: '0x' + '55'.repeat(32), events: [corpus.events[0]] };
    const stateHiK = withHighDensityAtom({ words: new Array(1024).fill(0n) }, 9, 600000); // K=9 > in-degree 3
    const on = await evaluateRetrievalBenchmarkState(stateHiK, corpus, pack, makeOpts(true, CAP));
    const off = await evaluateRetrievalBenchmarkState(stateHiK, corpus, pack, makeOpts(false, CAP));
    assert.equal(answerRank(on), answerRank(off), 'K above in-degree must not admit (honest threshold)');
  });
});
