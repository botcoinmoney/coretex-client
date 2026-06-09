/**
 * deriveQueryPack on V2-shaped corpora (item 4).
 *
 * The production hidden-pack derivation must work on the V2 family set
 * (near_collision / temporal / multi_hop_relation — NO long_horizon) and
 * preserve owner-scope fields on the sampled events (the scorer applies
 * owner-scope per query). This guards production-faithful pack derivation,
 * replacing the ad hoc calibration packs used during the rework.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  admitActiveLiveEvalEvents,
  deriveQueryPack,
  eventSatisfiesStratum,
  hiddenPackProfileFromEvaluatorProfile,
  loadProductionCorpus,
  packQuotaCoverage,
  splitForRecord,
  verifyQueryPack,
} from '../../dist/index.js';

const LAYOUT = { dim: 8, headerBytes: 9, quantization: 'int8' };
function ev(id, family, ownerEntityId, ownerScoped) {
  return {
    id, family, domain: 'd', split: 'eval_hidden', queryText: `q ${id}`,
    truthDocuments: [{ id: `${id}-t`, text: 't', isCurrent: true }], hardNegatives: [],
    qrels: [{ documentId: `${id}-t`, relevance: 1 }], protected: false,
    ...(ownerEntityId ? { ownerEntityId, ownerScoped } : {}),
    provenance: { source: 'synthetic_challenge', sourceHash: '0x' + '00'.repeat(32) },
    embeddings: { modelId: 'm', revision: 'r', layout: LAYOUT, query: new Uint8Array(4 + 8), perTruth: new Map(), perNegative: new Map() },
  };
}
// 30 events per V2 family, owner-scoped where relevant; mem (train_visible) filler.
const events = [];
for (let i = 0; i < 30; i++) events.push(ev(`nc${i}`, 'near_collision', `e_u${i}`, true));
for (let i = 0; i < 30; i++) events.push(ev(`tm${i}`, 'temporal', `e_u${i}`, true));
for (let i = 0; i < 30; i++) events.push(ev(`mh${i}`, 'multi_hop_relation', `e_u${i}`, true));
const corpus = { events, byId: new Map(events.map((e) => [e.id, e])), corpusRoot: '0x' + '00'.repeat(32), corpusEpoch: 0, biEncoderModelId: 'm', biEncoderRevision: 'r', biEncoderRetrievalKeyLayout: LAYOUT, labelingModelId: 'm', labelingModelRevision: 'r' };

// V2 quotas are FAMILY-keyed (not bucket-keyed): the V2->production hardness
// bucket is degenerate (hard-negatives aren't graded qrels in the bridge), so
// bucket=medium would not match. strataOf emits bare `family=X`.
// Generous slack (packSize 30 vs quota-sum 12) so this exercises the V2-FAMILY
// mechanism, not deriveQueryPack's tight-packing eviction edge. The production
// V2 profile likewise uses packSize 64 with quota-sum 32 (ample slack).
const V2_PROFILE = { packSize: 30, quotas: [
  { stratum: 'family=near_collision', minCount: 4 },
  { stratum: 'family=temporal', minCount: 4 },
  { stratum: 'family=multi_hop_relation', minCount: 4 },
] };

describe('deriveQueryPack on V2 families', () => {
  test('produces a deterministic pack satisfying V2 quotas (no long_horizon)', () => {
    const seed = '0x' + 'a5'.repeat(32);
    const pack = deriveQueryPack(7, seed, corpus, V2_PROFILE);
    assert.equal(pack.events.length, V2_PROFILE.packSize, 'pack hits exact size');
    for (const q of V2_PROFILE.quotas) {
      const got = pack.events.filter((e) => eventSatisfiesStratum(e, q.stratum)).length;
      assert.ok(got >= q.minCount, `quota ${q.stratum}: ${got} >= ${q.minCount}`);
    }
    // determinism
    const pack2 = deriveQueryPack(7, seed, corpus, V2_PROFILE);
    assert.deepEqual(pack.events.map((e) => e.id), pack2.events.map((e) => e.id), 'deterministic by (epoch, seed)');
  });

  test('owner-scope fields survive pack derivation (scorer scopes per query)', () => {
    const pack = deriveQueryPack(3, '0x' + 'b7'.repeat(32), corpus, V2_PROFILE);
    const scoped = pack.events.filter((e) => e.ownerScoped === true && e.ownerEntityId);
    assert.ok(scoped.length > 0, 'pack carries owner-scoped events with ownerEntityId');
  });

  test('deriveQueryPack rejects underfill instead of silently returning a short pack', () => {
    const tinyCorpus = {
      ...corpus,
      events: [ev('tiny0', 'temporal', 'e_u0', true)],
      byId: new Map(),
    };
    tinyCorpus.byId = new Map(tinyCorpus.events.map((e) => [e.id, e]));
    assert.throws(
      () => deriveQueryPack(1, '0x' + 'aa'.repeat(32), tinyCorpus, { packSize: 2, quotas: [] }),
      /cannot fill exact packSize/,
    );
  });

  test('active live eval overlay admits newest active rows replayably', () => {
    const seed = '0x' + 'c3'.repeat(32);
    const activeProfile = { packSize: 0, quotas: [] };
    const live = [
      ev('zz_e000000000001_q_coref_old', 'coreference', 'e_u_live', true),
      ev('zz_e000000000003_q_coref_new', 'coreference', 'e_u_live', true),
      ev('zz_e000000000002_q_relation_mid', 'relation_lifecycle', 'e_u_live', true),
      ev('zz_e000000000004_q_scope_new', 'scope_atom', 'e_u_live', true),
    ].map((e) => ({ ...e, logicalFamily: e.family }));
    const corpus2 = {
      ...corpus,
      events: [...corpus.events, ...live],
      byId: new Map([...corpus.events, ...live].map((e) => [e.id, e])),
    };
    const basePack = deriveQueryPack(9, seed, corpus2, activeProfile);
    const activeIds = new Set(live.map((e) => e.id));
    const overlay = admitActiveLiveEvalEvents(basePack, corpus2, {
      activeIds,
      limit: 3,
      familyPriority: ['coreference', 'relation_lifecycle', 'scope_atom'],
    });

    assert.deepEqual(overlay.pack.events.slice(0, 3).map((e) => e.id), [
      'zz_e000000000003_q_coref_new',
      'zz_e000000000002_q_relation_mid',
      'zz_e000000000004_q_scope_new',
    ]);
    assert.equal(overlay.added, 3);
    assert.equal(overlay.liveEvalInPack, 3);
    assert.deepEqual(overlay.familyCounts, { coreference: 1, relation_lifecycle: 1, scope_atom: 1 });
    assert.deepEqual(verifyQueryPack(overlay.pack, corpus2, activeProfile, {
      activeIds,
      limit: 3,
      familyPriority: ['coreference', 'relation_lifecycle', 'scope_atom'],
    }), { ok: true });
  });

  test('active live eval overlay prefers distinct public intents newest-first', () => {
    const seed = '0x' + 'd4'.repeat(32);
    const activeProfile = { packSize: 0, quotas: [] };
    const intentA = {
      atom: 'validity_atom',
      subjectEntityId: 'e_subject_a',
      attribute: 'api endpoint',
      queryTime: '2026-06-08',
      projectId: 'proj_a',
      sessionId: 'sess_a',
      topicId: 'topic_api_migration',
      taskId: 'task_a',
      userScopeId: 'e_u_live',
    };
    const intentB = { ...intentA, subjectEntityId: 'e_subject_b', projectId: 'proj_b', sessionId: 'sess_b', taskId: 'task_b' };
    const live = [
      { ...ev('zz_e000000000004_q_validity_a_confirm', 'validity_atom', 'e_u_live', true), logicalFamily: 'validity_atom', subjectEntityId: 'e_subject_a', publicIntent: intentA },
      { ...ev('zz_e000000000004_q_validity_a_active', 'validity_atom', 'e_u_live', true), logicalFamily: 'validity_atom', subjectEntityId: 'e_subject_a', publicIntent: intentA },
      { ...ev('zz_e000000000003_q_validity_b', 'validity_atom', 'e_u_live', true), logicalFamily: 'validity_atom', subjectEntityId: 'e_subject_b', publicIntent: intentB },
    ];
    const corpus2 = {
      ...corpus,
      events: [...corpus.events, ...live],
      byId: new Map([...corpus.events, ...live].map((e) => [e.id, e])),
    };
    const activeIds = new Set(live.map((e) => e.id));
    const overlay = admitActiveLiveEvalEvents(deriveQueryPack(10, seed, corpus2, activeProfile), corpus2, {
      activeIds,
      limit: 2,
      familyPriority: ['validity_atom'],
    });

    assert.deepEqual(overlay.pack.events.slice(0, 2).map((e) => e.id), [
      'zz_e000000000004_q_validity_a_active',
      'zz_e000000000003_q_validity_b',
    ]);
    assert.deepEqual(verifyQueryPack(overlay.pack, corpus2, activeProfile, {
      activeIds,
      limit: 2,
      familyPriority: ['validity_atom'],
    }), { ok: true });
  });

  test('active live eval overlay is bounded to the base pack size when replacing a non-empty pack', () => {
    const seed = '0x' + 'e5'.repeat(32);
    const basePack = deriveQueryPack(11, seed, corpus, { packSize: 2, quotas: [] });
    const live = [
      { ...ev('zz_e000000000005_q_scope_a', 'scope_atom', 'e_u_live', true), logicalFamily: 'scope_atom' },
      { ...ev('zz_e000000000005_q_coref_a', 'coreference', 'e_u_live', true), logicalFamily: 'coreference' },
    ];
    const corpus2 = {
      ...corpus,
      events: [...corpus.events, ...live],
      byId: new Map([...corpus.events, ...live].map((e) => [e.id, e])),
    };
    const overlay = admitActiveLiveEvalEvents(basePack, corpus2, {
      activeIds: new Set(live.map((e) => e.id)),
      limit: 2,
      familyPriority: ['scope_atom', 'coreference'],
    });
    assert.equal(overlay.pack.events.length, basePack.events.length);
    assert.deepEqual(overlay.pack.events.map((e) => e.id), [
      'zz_e000000000005_q_scope_a',
      'zz_e000000000005_q_coref_a',
    ]);
  });

  test('active live eval overlay preserves non-empty quota coverage when naive prepend would evict it', () => {
    const profile = {
      packSize: 4,
      quotas: [
        { stratum: 'family=temporal', minCount: 2 },
        { stratum: 'family=near_collision', minCount: 1 },
      ],
    };
    const basePack = {
      epochId: 12,
      evalSeedHex: '0x' + 'f6'.repeat(32),
      corpusRoot: corpus.corpusRoot,
      events: [
        ev('base_tm_0', 'temporal', 'e_u0', true),
        ev('base_tm_1', 'temporal', 'e_u1', true),
        ev('base_nc_0', 'near_collision', 'e_u2', true),
        ev('base_mh_0', 'multi_hop_relation', 'e_u3', true),
      ],
    };
    const live = [
      { ...ev('zz_e000000000006_q_scope_a', 'scope_atom', 'e_u_live', true), logicalFamily: 'scope_atom' },
      { ...ev('zz_e000000000006_q_coref_a', 'coreference', 'e_u_live', true), logicalFamily: 'coreference' },
    ];
    const corpus2 = {
      ...corpus,
      events: [...corpus.events, ...basePack.events, ...live],
      byId: new Map([...corpus.events, ...basePack.events, ...live].map((e) => [e.id, e])),
    };
    const naiveOverlay = [...live, ...basePack.events].slice(0, basePack.events.length);
    assert.equal(naiveOverlay.filter((e) => eventSatisfiesStratum(e, 'family=near_collision')).length, 0);
    const overlay = admitActiveLiveEvalEvents(basePack, corpus2, {
      activeIds: new Set(live.map((e) => e.id)),
      limit: 2,
      familyPriority: ['scope_atom', 'coreference'],
      profile,
    });

    assert.equal(overlay.pack.events.length, 4);
    assert.equal(overlay.added, 1);
    assert.ok(overlay.pack.events.some((e) => e.id === 'zz_e000000000006_q_scope_a'));
    assert.ok(overlay.pack.events.some((e) => e.id === 'base_nc_0'), 'near_collision quota row survives');
    assert.equal(overlay.pack.events.filter((e) => eventSatisfiesStratum(e, 'family=temporal')).length, 2);
    assert.equal(overlay.pack.events.filter((e) => eventSatisfiesStratum(e, 'family=near_collision')).length, 1);
  });

  test('v16 launch hidden pack excludes disabled aspect_constraint and overlay cannot reintroduce it', () => {
    const profilePath = new URL('../../../../release/calibration/2026-06-04-memory-atom-v16/evaluator-profile-v2-dgen1-policy-r5-atom-v16-300k-enabled.json', import.meta.url);
    const corpusPath = new URL('../../../../release/calibration/2026-06-04-memory-atom-v16/materialized/78336d1d/corpus.json', import.meta.url);
    const profile = JSON.parse(readFileSync(profilePath, 'utf8'));
    const corpus = loadProductionCorpus(corpusPath.pathname, { verifyCorpusRoot: false, verifySplits: false });
    const rawAspectCount = corpus.events.filter((e) => e.split === 'eval_hidden' && ((e.logicalFamily ?? e.family) === 'aspect_constraint')).length;
    assert.ok(rawAspectCount > 0, 'fixture must contain aspect eval_hidden rows so this test proves filtering');

    const hiddenPack = hiddenPackProfileFromEvaluatorProfile(profile);
    const pack = deriveQueryPack(0, '0x' + 'ab'.repeat(32), corpus, hiddenPack);
    assert.equal(pack.events.length, profile.hiddenPack.packSize);
    assert.equal(pack.events.filter((e) => (e.logicalFamily ?? e.family) === 'aspect_constraint').length, 0);
    assert.deepEqual(packQuotaCoverage(pack, hiddenPack).filter((q) => !q.satisfied), []);

    const liveAspect = {
      ...ev('zz_e000000000099_q_aspect_live', 'aspect_constraint', 'e_u_live', true),
      logicalFamily: 'aspect_constraint',
    };
    const corpus2 = {
      ...corpus,
      events: [...corpus.events, liveAspect],
      byId: new Map([...corpus.events, liveAspect].map((e) => [e.id, e])),
    };
    const overlay = admitActiveLiveEvalEvents(pack, corpus2, {
      activeIds: new Set([liveAspect.id]),
      limit: 1,
      familyPriority: ['aspect_constraint'],
      profile: hiddenPack,
    });
    assert.equal(overlay.added, 0);
    assert.equal(overlay.pack.events.filter((e) => (e.logicalFamily ?? e.family) === 'aspect_constraint').length, 0);
  });
});
