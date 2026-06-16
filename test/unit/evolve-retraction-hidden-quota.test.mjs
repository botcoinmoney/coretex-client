/**
 * Generator-level gates for the evolve continuity hardening (audit defects 2-4):
 *   - retraction/tombstone emission: deterministic, continuity-labeled, never referenced
 *     by later supersession priors, mapped end-to-end through CorpusDelta.removedIds;
 *   - fresh eval_hidden minting against the CANONICAL splitForRecord (injected splitOf);
 *   - hidden-row aging (horizon, exclusion of frontier-active rows, per-epoch cap);
 *   - applyCorpusDelta removal handling (root + cache path);
 *   - backwards compatibility: defaults emit no retractions/retirements/mints.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { evolveCorpusDelta } from '../../scripts/lib/evolve-corpus.mjs';
import {
  applyCorpusDelta,
  buildCorpusDelta,
  buildCorpusRootLeafCache,
  computeCorpusRoot,
  liveTailQueryId,
  logicalQueryIdFromProductionEventId,
  productionEventIdForLogicalDoc,
  productionEventIdForLogicalQuery,
  splitForRecord,
} from '../../dist/index.js';

const BI = { modelId: 'BAAI/bge-m3', revision: 'a'.repeat(40) };
const LAYOUT = { dim: 8, quantization: 'int8', headerBytes: 9 };
const labelingProvenance = { modelId: 'memreranker/4B', revision: 'b'.repeat(40), runtime: 'cpu', batchHash: 'c'.repeat(64) };
const mockEmb = () => new Uint8Array(LAYOUT.dim + 4);

const baseLogical = {
  entities: [
    { id: 'e_universe', canonicalName: 'U', aliases: [] },
    ...Array.from({ length: 20 }, (_, i) => ({ id: `e_universe_s${i}`, canonicalName: `First${i} Last${i}`, aliases: [] })),
  ],
  docs: Array.from({ length: 20 }, (_, i) => ({ id: `d${i}`, kind: 'temporal_city', entityIds: ['e_universe', `e_universe_s${i}`], currentStaleFlag: false, text: 'prior' })),
  relations: [],
  queries: [],
};
// canonical split assignment over the production event id, exactly as the evolve script injects it
const canonicalSplitOf = (corpusEpoch) => (id, liveUpdateEpoch) => splitForRecord(
  liveUpdateEpoch !== undefined && liveUpdateEpoch !== null ? liveTailQueryId(id, liveUpdateEpoch) : id,
  corpusEpoch,
);

describe('evolve retraction/tombstone emission', () => {
  test('defaults are backwards compatible: no retractions, retirements, or hidden mints', () => {
    const d = evolveCorpusDelta({ baseLogical, epoch: 2, seed: 's', churnFraction: 0.5 });
    assert.deepEqual(d.retractedDocIds, []);
    assert.deepEqual(d.retiredQueryIds, []);
    assert.deepEqual(d.freshEvalHiddenQueryIds, []);
    assert.equal(d.retractionFraction, 0);
    assert.ok(d.addedDocs.every((doc) => doc.kind !== 'retraction_record'));
  });

  test('retraction is deterministic, tracks the fraction, and emits one tombstone per retracted fact', () => {
    const mk = () => evolveCorpusDelta({ baseLogical, epoch: 3, seed: 's', churnFraction: 0.2, retractionFraction: 0.4 });
    const a = mk();
    const b = mk();
    assert.equal(JSON.stringify(a), JSON.stringify(b), 'byte-identical replay');
    assert.ok(a.retractedDocIds.length >= 2, `~40% of 20 docs expected, got ${a.retractedDocIds.length}`);
    const tombstones = a.addedDocs.filter((doc) => doc.kind === 'retraction_record');
    assert.equal(tombstones.length, a.retractedDocIds.length, 'one tombstone per retracted fact');
    for (const t of tombstones) {
      assert.equal(t.shape, 'retraction_record');
      assert.ok(a.retractedDocIds.includes(t.retractsDocId), 'tombstone names the doc it withdraws');
      assert.match(t.text, /withdrawn|no longer applies/i);
      assert.equal(t.liveUpdateEpoch, 3);
    }
  });

  test('retracted docs are never referenced by this epoch qrels, hard negatives, or supersedes edges', () => {
    const d = evolveCorpusDelta({ baseLogical, epoch: 4, seed: 's', churnFraction: 1.0, retractionFraction: 0.5 });
    assert.ok(d.retractedDocIds.length > 0, 'fixture must retract');
    const retracted = new Set(d.retractedDocIds);
    for (const q of d.addedQueries) {
      for (const r of q.qrels ?? []) assert.ok(!retracted.has(r.docId), `qrel ${r.docId} references a retracted doc`);
      for (const n of q.hardNegatives ?? []) assert.ok(!retracted.has(n.docId), `hard negative ${n.docId} references a retracted doc`);
    }
    for (const r of d.addedRelations) {
      assert.ok(!retracted.has(r.dst), `relation dst ${r.dst} references a retracted doc`);
      assert.ok(!retracted.has(r.src), `relation src ${r.src} references a retracted doc`);
    }
  });

  test('hidden queries with positive qrels to retracted docs are retired', () => {
    const logical = {
      ...baseLogical,
      queries: [
        {
          id: 'q_retracted_truth',
          liveUpdateEpoch: 0,
          qrels: [{ docId: 'd0', relevance: 1.0 }],
        },
      ],
    };
    const d = evolveCorpusDelta({
      baseLogical: logical,
      epoch: 4,
      seed: 's',
      churnFraction: 0,
      retractionFraction: 1.0,
      evalHiddenPolicy: { splitOf: () => 'eval_hidden', minFreshPerEpoch: 0 },
    });
    assert.ok(d.retractedDocIds.includes('d0'));
    assert.ok(d.retiredQueryIds.includes('q_retracted_truth'));
  });

  test('tombstones are never retracted in a later epoch', () => {
    const e1 = evolveCorpusDelta({ baseLogical, epoch: 1, seed: 's', churnFraction: 0.2, retractionFraction: 1.0 });
    assert.equal(e1.retractedDocIds.length, baseLogical.docs.length, 'fraction 1.0 retracts every eligible fact');
    const threaded = {
      ...baseLogical,
      docs: [...baseLogical.docs.filter((doc) => !e1.retractedDocIds.includes(doc.id)), ...e1.addedDocs],
    };
    const e2 = evolveCorpusDelta({ baseLogical: threaded, epoch: 2, seed: 's', churnFraction: 0.2, retractionFraction: 1.0 });
    const tombstoneIds = new Set(e1.addedDocs.filter((doc) => doc.kind === 'retraction_record').map((doc) => doc.id));
    for (const id of e2.retractedDocIds) assert.ok(!tombstoneIds.has(id), `tombstone ${id} must not be retracted`);
  });
});

describe('evolve fresh eval_hidden quota + hidden-row aging', () => {
  test('mints fresh hidden queries to the quota against the canonical split', () => {
    const splitOf = canonicalSplitOf(0);
    const d = evolveCorpusDelta({
      baseLogical, epoch: 5, seed: 's', churnFraction: 0.1, retractionFraction: 0,
      evalHiddenPolicy: { splitOf, minFreshPerEpoch: 6 },
    });
    assert.ok(d.freshEvalHiddenQueryIds.length >= 6, `quota met: ${d.freshEvalHiddenQueryIds.length}`);
    const byId = new Map(d.addedQueries.map((q) => [q.id, q]));
    for (const id of d.freshEvalHiddenQueryIds) {
      assert.equal(splitOf(id, 5), 'eval_hidden', `${id} lands in eval_hidden under the canonical split`);
      const q = byId.get(id);
      assert.ok(q, `${id} is a real added query`);
      if (id.includes('_h')) {
        assert.ok(q.qrels.length === 1 && q.qrels[0].relevance === 1.0, 'minted hidden query is answerable');
        assert.ok(d.addedDocs.some((doc) => doc.id === q.qrels[0].docId), 'minted hidden query truth doc is added');
      }
    }
  });

  test('minting is bounded by maxMintedPerEpoch (root-delta budget)', () => {
    const splitOf = canonicalSplitOf(0);
    const d = evolveCorpusDelta({
      baseLogical, epoch: 5, seed: 's', churnFraction: 0, retractionFraction: 0,
      evalHiddenPolicy: { splitOf, minFreshPerEpoch: 50, maxMintedPerEpoch: 4 },
    });
    assert.ok(d.freshEvalHiddenQueryIds.length <= 4, `minting must stop at the budget, got ${d.freshEvalHiddenQueryIds.length}`);
  });

  test('hidden aging: horizon + oldest-first + frontier-active exclusion + per-epoch cap', () => {
    const splitOf = canonicalSplitOf(0);
    // synthesize a hidden history: genesis rows (mint epoch 0) + live rows minted at epochs 1/2
    const hiddenIds = [];
    for (let i = 0; hiddenIds.length < 4 && i < 20_000; i++) {
      const id = `q_hist_${i}`;
      if (splitForRecord(id, 0) === 'eval_hidden') hiddenIds.push(id);
    }
    const liveHidden = [];
    for (const mintEpoch of [1, 2]) {
      for (let salt = 0; ; salt++) {
        const id = `q_e${mintEpoch}_hist_h${salt}`;
        if (splitOf(id, mintEpoch) === 'eval_hidden') { liveHidden.push({ id, liveUpdateEpoch: mintEpoch }); break; }
      }
    }
    const logical = {
      ...baseLogical,
      queries: [
        ...hiddenIds.map((id) => ({ id, family: 'temporal_update' })),
        ...liveHidden.map((q) => ({ ...q, family: 'temporal_update' })),
      ],
    };
    const d = evolveCorpusDelta({
      baseLogical: logical, epoch: 4, seed: 's', churnFraction: 0,
      evalHiddenPolicy: {
        splitOf, minFreshPerEpoch: 0, retireAfterEpochs: 3, maxRetiredPerEpoch: 3,
        excludeRetireIds: new Set([hiddenIds[0]]),
      },
    });
    // epoch 4, horizon 3: genesis rows (age 4) and the epoch-1 live row (age 3) are due;
    // the epoch-2 live row (age 2) is NOT; hiddenIds[0] is frontier-active and protected.
    assert.ok(!d.retiredQueryIds.includes(hiddenIds[0]), 'frontier-active row is protected');
    assert.ok(!d.retiredQueryIds.includes(liveHidden[1].id), 'row inside the horizon is not retired');
    assert.equal(d.retiredQueryIds.length, 3, 'per-epoch retirement cap respected');
    for (const id of d.retiredQueryIds) {
      assert.ok(hiddenIds.slice(1).includes(id) || id === liveHidden[0].id, `${id} is a due hidden row`);
    }
    // oldest-first: all retired rows are genesis (mint epoch 0) before the epoch-1 row gets a slot
    assert.ok(d.retiredQueryIds.every((id) => hiddenIds.includes(id)), 'genesis rows age out before younger live rows');
  });
});

describe('removal end-to-end: removedIds through buildCorpusDelta/applyCorpusDelta + id resolvers', () => {
  function prodCorpus() {
    const events = [];
    for (const d of baseLogical.docs) {
      events.push({
        id: `mem_${d.id}`, family: 'near_collision', domain: 'deep', split: 'train_visible',
        queryText: d.text, truthDocuments: [{ id: d.id, text: d.text, isCurrent: true }],
        hardNegatives: [], qrels: [{ documentId: d.id, relevance: 1.0 }], protected: false, relations: [],
        provenance: { source: 'synthetic_challenge', sourceHash: '0x' + 'aa'.repeat(32) },
        embeddings: { modelId: BI.modelId, revision: BI.revision, layout: LAYOUT, query: mockEmb(), perTruth: new Map([[d.id, mockEmb()]]), perNegative: new Map() },
      });
    }
    // a live-tail mem doc + a live-tail query from a prior epoch, and a genesis hidden query
    events.push({
      id: 'zz_e000000000002_mem_d_e2_x', family: 'near_collision', domain: 'deep', split: 'train_visible',
      queryText: 'live doc', truthDocuments: [{ id: 'd_e2_x', text: 'live doc', isCurrent: true }],
      hardNegatives: [], qrels: [{ documentId: 'd_e2_x', relevance: 1.0 }], protected: false, relations: [],
      provenance: { source: 'synthetic_challenge', sourceHash: '0x' + 'aa'.repeat(32) },
      embeddings: { modelId: BI.modelId, revision: BI.revision, layout: LAYOUT, query: mockEmb(), perTruth: new Map([['d_e2_x', mockEmb()]]), perNegative: new Map() },
    });
    let genesisHidden = null;
    for (let i = 0; !genesisHidden && i < 20_000; i++) {
      if (splitForRecord(`q_hidden_${i}`, 0) === 'eval_hidden') genesisHidden = `q_hidden_${i}`;
    }
    events.push({
      id: genesisHidden, family: 'temporal', domain: 'deep', split: 'eval_hidden',
      queryText: 'hidden q', truthDocuments: [{ id: 'd0', text: 'prior', isCurrent: true }],
      hardNegatives: [], qrels: [{ documentId: 'd0', relevance: 1.0 }], protected: false, relations: [],
      provenance: { source: 'synthetic_challenge', sourceHash: '0x' + 'aa'.repeat(32) },
      embeddings: { modelId: BI.modelId, revision: BI.revision, layout: LAYOUT, query: mockEmb(), perTruth: new Map([['d0', mockEmb()]]), perNegative: new Map() },
    });
    return {
      corpus: {
        events, byId: new Map(events.map((e) => [e.id, e])), corpusRoot: computeCorpusRoot(events),
        corpusRootCache: buildCorpusRootLeafCache(events), corpusEpoch: 0,
        biEncoderModelId: BI.modelId, biEncoderRevision: BI.revision, biEncoderRetrievalKeyLayout: LAYOUT,
        labelingModelId: labelingProvenance.modelId, labelingModelRevision: labelingProvenance.revision,
      },
      genesisHidden,
    };
  }

  test('id resolvers map logical docs/queries to genesis and live-tail production events', () => {
    const { corpus, genesisHidden } = prodCorpus();
    assert.equal(productionEventIdForLogicalDoc(corpus, { id: 'd3' }), 'mem_d3');
    assert.equal(productionEventIdForLogicalDoc(corpus, { id: 'd_e2_x', liveUpdateEpoch: 2 }), 'zz_e000000000002_mem_d_e2_x');
    assert.equal(productionEventIdForLogicalDoc(corpus, { id: 'd_e2_x' }), 'zz_e000000000002_mem_d_e2_x', 'epoch recovered from the id pattern');
    assert.equal(productionEventIdForLogicalDoc(corpus, { id: 'd_missing' }), null);
    assert.equal(productionEventIdForLogicalQuery(corpus, { id: genesisHidden }), genesisHidden);
    assert.equal(productionEventIdForLogicalQuery(corpus, { id: 'q_missing' }), null);
    assert.equal(logicalQueryIdFromProductionEventId('zz_e000000000002_q_q_e2_s1_t'), 'q_e2_s1_t');
    assert.equal(logicalQueryIdFromProductionEventId(genesisHidden), genesisHidden);
  });

  test('removedIds remove events and reproduce the root on both the full and cache paths', () => {
    const { corpus, genesisHidden } = prodCorpus();
    const removals = ['mem_d0', 'zz_e000000000002_mem_d_e2_x', genesisHidden];
    const delta = buildCorpusDelta({
      previousCorpus: corpus, previousRootCache: corpus.corpusRootCache,
      additions: [], removals, epoch: 3, labelingProvenance,
    });
    assert.deepEqual([...delta.removedIds].sort(), [...removals].sort());
    assert.notEqual(delta.nextRoot, delta.previousRoot);
    // cache path
    const viaCache = applyCorpusDelta(corpus, delta, { rootCache: corpus.corpusRootCache, attachRootCache: true });
    // full recompute path
    const { corpusRootCache: _drop, ...noCache } = corpus;
    const viaFull = applyCorpusDelta(noCache, delta);
    for (const next of [viaCache, viaFull]) {
      assert.equal(next.corpusRoot, delta.nextRoot);
      for (const id of removals) assert.ok(!next.byId.has(id), `${id} removed`);
      assert.equal(next.events.length, corpus.events.length - removals.length);
    }
    assert.equal(computeCorpusRoot(viaFull.events), delta.nextRoot, 'recomputed root matches after removal');
  });
});
