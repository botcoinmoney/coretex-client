/**
 * BMU replay-safety GOLDEN PIN against commit 57a29ea (coretex-a2-unbrick
 * head — the branch point of coretex-bmu-v1).
 *
 * The golden values below were CAPTURED FROM A 57a29ea BUILD (git worktree,
 * clean `npm ci` + build) by running this exact fixture through:
 *   1. deriveQueryPack           (r5 broad law),
 *   2. deriveScoredQueryPack     (r5 newest-first live-eval overlay law),
 *   3. evaluateRetrievalBenchmarkState (r5 composite; deterministic
 *      bi-encoder + injected reranker),
 * and verified byte-identical against the coretex-bmu-v1 build
 * (scratchpad replay-differential, 2026-07-07). This test pins that
 * equivalence permanently: with BMU NOT armed (r5 pipelineVersion, no BMU
 * pack opts), every code path this fixture exercises must keep producing
 * exactly these outputs. Any diff = an un-gated behavior change to the LIVE
 * r5 law — a replay break, never acceptable.
 *
 * ALSO the §13.3 P3 zero-flip soak gate (deterministic-decision layer):
 * 10,000 judge replays with sub-grid fp jitter inside the §13.2
 * certification margin must produce ZERO u(t) flips.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  deriveQueryPack,
  deriveScoredQueryPack,
  computeCorpusRoot,
  evaluateRetrievalBenchmarkState,
  createDeterministicBiEncoder,
  biEncoderModelIdHash,
  bmuJudgeTopB,
  computeBmuTaskUtility,
} from '../../dist/index.js';

const BI = { modelId: 'BAAI/bge-m3', revision: 'a'.repeat(40), mode: 'dense' };
const LAYOUT = { dim: 32, quantization: 'int8', headerBytes: 9 };
const ZERO_STATE = { words: new Array(1024).fill(0n) };

const FAMS = [
  ['temporal', 'temporal_update'],
  ['conflict_lifecycle', 'conflict_lifecycle'],
  ['multi_hop_relation', 'multi_session_bridge'],
  ['near_collision', 'abstention_missing'],
];

function ev(id, family, logical) {
  return {
    id, family, domain: 'companies', split: 'eval_hidden', queryText: `q-${id}`,
    truthDocuments: [{ id: `${id}-t`, text: `truth-${id}`, isCurrent: true }],
    hardNegatives: [{ id: `${id}-n`, text: `neg-${id}` }],
    qrels: [{ documentId: `${id}-t`, relevance: 1 }, { documentId: `${id}-n`, relevance: 0.2 }],
    protected: false, logicalFamily: logical, subjectEntityId: `ent-${id}`,
    provenance: { source: 'synthetic_challenge', sourceHash: '0x' + 'aa'.repeat(32) },
    embeddings: {
      modelId: BI.modelId, revision: BI.revision, layout: LAYOUT,
      query: new Uint8Array(LAYOUT.dim + 4),
      perTruth: new Map([[`${id}-t`, new Uint8Array(LAYOUT.dim + 4)]]),
      perNegative: new Map([[`${id}-n`, new Uint8Array(LAYOUT.dim + 4)]]),
    },
  };
}

function fixtureCorpus() {
  const events = [];
  for (const [fam, logical] of FAMS) {
    for (let i = 0; i < 12; i++) events.push(ev(`q_${fam}_${String(i).padStart(2, '0')}`, fam, logical));
    for (let i = 0; i < 4; i++) events.push(ev(`zz_e${String(130 + i).padStart(12, '0')}_q_${fam}_${i}`, fam, logical));
  }
  return {
    events, byId: new Map(events.map((e) => [e.id, e])),
    corpusRoot: computeCorpusRoot(events), corpusEpoch: 0,
    biEncoderModelId: BI.modelId, biEncoderRevision: BI.revision, biEncoderRetrievalKeyLayout: LAYOUT,
    labelingModelId: 'lm', labelingModelRevision: 'lr',
  };
}

const PROFILE = {
  packSize: 24,
  quotas: [
    { stratum: 'family=temporal', minCount: 4 },
    { stratum: 'family=conflict_lifecycle', minCount: 4 },
    { stratum: 'family=multi_hop_relation', minCount: 4 },
    { stratum: 'family=near_collision', minCount: 4 },
  ],
};
const SEED = '0x' + '5a'.repeat(32);

// ─── GOLDENS captured from the 57a29ea build (DO NOT REGENERATE lightly:
//     a change here means the un-armed r5 law drifted) ─────────────────────
const GOLDEN_BROAD_IDS = [
  'q_temporal_06', 'zz_e000000000131_q_temporal_1', 'q_temporal_03', 'q_temporal_07',
  'q_conflict_lifecycle_09', 'q_conflict_lifecycle_04', 'q_conflict_lifecycle_00', 'q_conflict_lifecycle_05',
  'q_multi_hop_relation_06', 'zz_e000000000133_q_multi_hop_relation_3', 'q_multi_hop_relation_01', 'q_multi_hop_relation_04',
  'zz_e000000000131_q_near_collision_1', 'q_near_collision_10', 'q_near_collision_01', 'q_near_collision_00',
  'q_multi_hop_relation_00', 'q_multi_hop_relation_09', 'q_near_collision_06', 'zz_e000000000132_q_near_collision_2',
  'zz_e000000000130_q_multi_hop_relation_0', 'q_conflict_lifecycle_07', 'q_temporal_11', 'q_near_collision_02',
];
const GOLDEN_OVERLAY_IDS = [
  'zz_e000000000132_q_multi_hop_relation_2', 'zz_e000000000133_q_near_collision_3',
  'zz_e000000000133_q_conflict_lifecycle_3', 'zz_e000000000133_q_temporal_3',
  'q_temporal_06', 'zz_e000000000131_q_temporal_1', 'q_temporal_03', 'q_temporal_07',
  'q_conflict_lifecycle_09', 'q_conflict_lifecycle_04', 'q_conflict_lifecycle_00', 'q_conflict_lifecycle_05',
  'q_multi_hop_relation_06', 'zz_e000000000133_q_multi_hop_relation_3', 'q_multi_hop_relation_01', 'q_multi_hop_relation_04',
  'zz_e000000000131_q_near_collision_1', 'q_near_collision_10', 'q_near_collision_01', 'q_near_collision_00',
  'q_multi_hop_relation_00', 'q_multi_hop_relation_09', 'zz_e000000000132_q_near_collision_2',
  'zz_e000000000130_q_multi_hop_relation_0',
];
const GOLDEN_COMPOSITE_PPM = 224171;
const GOLDEN_NDCG10 = 0.2322283527158809;

describe('r5 replay pin vs 57a29ea (BMU unarmed ⇒ byte-identical)', () => {
  const corpus = fixtureCorpus();

  test('deriveQueryPack (broad r5 law) reproduces the 57a29ea pack byte-for-byte', () => {
    const pack = deriveQueryPack(133, SEED, corpus, PROFILE);
    assert.deepEqual(pack.events.map((e) => e.id), GOLDEN_BROAD_IDS);
  });

  test('deriveScoredQueryPack (r5 newest-first overlay law) reproduces 57a29ea', () => {
    const activeIds = new Set(corpus.events.filter((e) => e.id.startsWith('zz_e')).map((e) => e.id));
    const pack = deriveScoredQueryPack(133, SEED, corpus, PROFILE, {
      activeIds,
      law: { limit: 4, familyPriority: ['temporal_update', 'conflict_lifecycle'] },
    });
    assert.deepEqual(pack.events.map((e) => e.id), GOLDEN_OVERLAY_IDS);
  });

  test('evaluateRetrievalBenchmarkState (r5 scoring) reproduces the 57a29ea composite exactly', async () => {
    const broad = deriveQueryPack(133, SEED, corpus, PROFILE);
    const reranker = { model: 'x', async score(pairs) { return pairs.map((p) => p.document.startsWith('truth-') ? 0.9 : 0.15); } };
    const score = await evaluateRetrievalBenchmarkState(ZERO_STATE, corpus, { ...broad, events: broad.events.slice(0, 8) }, {
      weights: { w_retrieval: 0.75, w_temporal: 0.08, w_relation_recall: 0.07, w_abstention: 0.05, w_structural_sanity: 0.05 },
      retrievalKeyLayout: LAYOUT,
      biEncoderHash: biEncoderModelIdHash(BI.modelId, BI.revision, BI.mode),
      biEncoder: createDeterministicBiEncoder({ modelId: BI.modelId, revision: BI.revision, layout: LAYOUT }),
      reranker,
      relationHopBudget: 2, abstentionThreshold: 0.001, rerankerTopK: 10, rerankerInputTopK: 128,
      firstStageTopK: 50, lensTopK: 36, lensWeight: 0.1, anchorWeight: 0.15, relationExpansionBudget: 50,
      temporalCurrentBoost: 0.1, temporalStaleSuppression: 0.1,
      pipelineVersion: 'coretex-retrieval-v2-policy-r5', policyAtomsMode: true,
    });
    assert.equal(Math.round(score.composite * 1_000_000), GOLDEN_COMPOSITE_PPM);
    assert.equal(score.nDCG10, GOLDEN_NDCG10);
  });
});

describe('§13.3 P3 zero-flip soak (judge-decision layer, 10k replays)', () => {
  test('10,000 sub-grid-jittered replays produce ZERO u(t) flips', () => {
    // Certified fixture: every doc sits ≥ 3 grid cells (3e-3) from the rank-B
    // boundary, per the §13.2 certification margin. The jitter models
    // CPU↔GPU fp drift far above the real 5-ppm band (±2e-4 in composite
    // space — 20% of a cell) — decisions must be immune by quantization.
    const GRID = 1e-3;
    const task = {
      family: 'temporal', budgetB: 3,
      requiredEvidence: ['req1', 'req2'], forbiddenEvidence: ['trap'],
      answer: { id: 'req1' }, motifGroupId: 'mg', templateId: 'tt',
    };
    const baseEntries = [
      { docId: 'req1', rerankerScore: 0.900, finalReorderingScore: 0.9500 },
      { docId: 'req2', rerankerScore: 0.850, finalReorderingScore: 0.9000 },
      { docId: 'fill', rerankerScore: 0.500, finalReorderingScore: 0.6000 },
      { docId: 'trap', rerankerScore: 0.400, finalReorderingScore: 0.5000 }, // 100 cells below rank-B
      { docId: 'far1', rerankerScore: 0.100, finalReorderingScore: 0.2000 },
      { docId: 'far2', rerankerScore: 0.100, finalReorderingScore: 0.1000 },
    ];
    // Deterministic LCG so the soak replays identically everywhere.
    let s = 0x12345678 >>> 0;
    const rnd = () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 2 ** 32; };
    const REPLAYS = 10_000;
    let flips = 0;
    for (let i = 0; i < REPLAYS; i++) {
      const jittered = baseEntries.map((e) => ({
        ...e,
        finalReorderingScore: e.finalReorderingScore + (rnd() - 0.5) * 4e-4,
        rerankerScore: e.rerankerScore + (rnd() - 0.5) * 4e-4,
      }));
      const topB = bmuJudgeTopB(jittered, task.budgetB, GRID);
      const u = computeBmuTaskUtility({ task, topB, abstainSignal: false });
      if (u.utility !== 1) flips++;
    }
    assert.equal(flips, 0, `${flips}/${REPLAYS} replays flipped u(t) — quantization law violated`);
  });
});
