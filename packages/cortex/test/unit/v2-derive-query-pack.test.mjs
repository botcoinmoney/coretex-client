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
import { deriveQueryPack, eventSatisfiesStratum, splitForRecord } from '../../dist/index.js';

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
    assert.ok(pack.events.length <= V2_PROFILE.packSize, 'pack within size');
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
});
