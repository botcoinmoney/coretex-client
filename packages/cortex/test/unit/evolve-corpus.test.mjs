/**
 * Fix B — evolveCorpusDelta: deterministic live-update churn fuel.
 * CPU gates (the production embedding + corpusRoot-replay gate is the A100/pipeline step):
 *   - replay determinism: same (base, epoch, seed) → byte-identical delta;
 *   - live_churn_rate > 0 and tracks churnFraction;
 *   - distinct epochs produce distinct (new) structure;
 *   - delta queries are subject-grounded (subjectEntityId) and supersede/contradict held facts.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { evolveCorpusDelta } from '../../../../scripts/lib/evolve-corpus.mjs';
import {
  applyCorpusDelta,
  bridgeLogicalDeltaToProductionEvents,
  buildCorpusDelta,
  buildCorpusRootLeafCache,
  computeCorpusRoot,
  expectedSplitForRecord,
  isMemoryDocumentEventId,
  splitForRecord,
} from '../../dist/index.js';

// minimal base logical corpus: 1 universe + 40 subjects, each with one prior temporal doc.
const baseLogical = {
  entities: [
    { id: 'e_universe', canonicalName: 'Deep Memory Universe 0', aliases: [] },
    ...Array.from({ length: 40 }, (_, i) => ({ id: `e_universe_s${i}`, canonicalName: i % 3 === 0 ? `svc-${i}-pipeline-svc-${i}` : `First${i} Last${i}`, aliases: [] })),
  ],
  docs: Array.from({ length: 40 }, (_, i) => ({ id: `d${i}`, kind: 'temporal_city', entityIds: ['e_universe', `e_universe_s${i}`], currentStaleFlag: false, text: 'prior' })),
  relations: [],
  queries: [],
};

describe('Fix B — evolveCorpusDelta (deterministic live-update churn)', () => {
  test('replay determinism: same inputs → byte-identical delta', () => {
    const a = evolveCorpusDelta({ baseLogical, epoch: 3, seed: 'launch-frontier', churnFraction: 0.25 });
    const b = evolveCorpusDelta({ baseLogical, epoch: 3, seed: 'launch-frontier', churnFraction: 0.25 });
    assert.equal(JSON.stringify(a), JSON.stringify(b));
  });

  test('live_churn_rate > 0 and approximates churnFraction', () => {
    const d = evolveCorpusDelta({ baseLogical, epoch: 1, seed: 's', churnFraction: 0.25 });
    assert.ok(d.liveChurnRate > 0, 'live churn must be > 0 (the static-corpus failure was ~0)');
    assert.ok(d.churnedSubjects.length >= 4 && d.churnedSubjects.length <= 18, `~25% of 40 expected, got ${d.churnedSubjects.length}`);
    assert.ok(d.addedDocs.length > 0 && d.addedQueries.length > 0);
  });

  test('distinct epochs produce distinct new structure (fresh minable work each epoch)', () => {
    const e1 = evolveCorpusDelta({ baseLogical, epoch: 1, seed: 's', churnFraction: 0.5 });
    const e2 = evolveCorpusDelta({ baseLogical, epoch: 2, seed: 's', churnFraction: 0.5 });
    const ids1 = new Set(e1.addedDocs.map((d) => d.id));
    const overlap = e2.addedDocs.filter((d) => ids1.has(d.id));
    assert.equal(overlap.length, 0, 'epoch deltas must not collide on doc ids');
    assert.notEqual(JSON.stringify(e1.churnedSubjects), JSON.stringify(e2.churnedSubjects));
  });

  test('delta is subject-grounded and revises held facts (supersedes / contradicts)', () => {
    const d = evolveCorpusDelta({ baseLogical, epoch: 5, seed: 's', churnFraction: 1.0 });
    assert.ok(d.addedQueries.every((q) => typeof q.subjectEntityId === 'string' && q.subjectEntityId !== 'e_universe'), 'every delta query is subject-grounded');
    const edgeLabels = new Set(d.addedRelations.map((r) => r.label));
    assert.ok(edgeLabels.has('supersedes') || edgeLabels.has('contradicts'), 'delta must revise held facts via supersedes/contradicts edges');
    // supersedes edges point at a prior (held) doc id from the base corpus
    const baseDocIds = new Set(baseLogical.docs.map((x) => x.id));
    assert.ok(d.addedRelations.filter((r) => r.label === 'supersedes').every((r) => baseDocIds.has(r.dst)), 'supersedes targets a held base fact');
  });
});

describe('Fix B — production delta/root path (mock embeddings): logical delta → buildCorpusDelta → applyCorpusDelta → replay same root', () => {
  const BI = { modelId: 'BAAI/bge-m3', revision: 'a'.repeat(40) };
  const LAYOUT = { dim: 8, quantization: 'int8', headerBytes: 9 };
  const labelingProvenance = { modelId: 'memreranker/4B', revision: 'b'.repeat(40), runtime: 'cpu', batchHash: 'c'.repeat(64) };
  const mockEmb = () => new Uint8Array(LAYOUT.dim + 4); // deterministic mock — proves the delta/root wiring, not lift
  const prevCorpus = (corpusEpoch = 0) => ({
    events: [], byId: new Map(), corpusRoot: computeCorpusRoot([]), corpusEpoch,
    biEncoderModelId: BI.modelId, biEncoderRevision: BI.revision, biEncoderRetrievalKeyLayout: LAYOUT,
    labelingModelId: labelingProvenance.modelId, labelingModelRevision: labelingProvenance.revision,
  });
  const prevCorpusWithBaseMemory = (corpusEpoch = 0) => {
    const memEvents = baseLogical.docs.map((d) => ({
      id: `mem_${d.id}`, family: 'near_collision', domain: 'deep', split: 'train_visible',
      queryText: d.text, truthDocuments: [{ id: d.id, text: d.text, isCurrent: d.currentStaleFlag !== false }],
      hardNegatives: [], qrels: [{ documentId: d.id, relevance: 1.0 }], protected: false,
      entityIds: d.entityIds, provenance: { source: 'synthetic_challenge', sourceHash: '0x' + 'aa'.repeat(32) },
      embeddings: { modelId: BI.modelId, revision: BI.revision, layout: LAYOUT, query: mockEmb(), perTruth: new Map([[d.id, mockEmb()]]), perNegative: new Map() },
    }));
    const existingQuery = {
      id: 'q_existing_tail_guard', family: 'temporal', domain: 'deep', split: splitForRecord('q_existing_tail_guard', corpusEpoch),
      queryText: 'existing query for tail-sort guard', truthDocuments: [{ id: 'd0', text: 'p', isCurrent: false }],
      hardNegatives: [], qrels: [{ documentId: 'd0', relevance: 1.0 }], protected: false,
      provenance: { source: 'synthetic_challenge', sourceHash: '0x' + 'aa'.repeat(32) },
      embeddings: { modelId: BI.modelId, revision: BI.revision, layout: LAYOUT, query: mockEmb(), perTruth: new Map([['d0', mockEmb()]]), perNegative: new Map() },
    };
    const events = [...memEvents, existingQuery];
    return {
      events, byId: new Map(events.map((e) => [e.id, e])), corpusRoot: computeCorpusRoot(events),
      corpusRootCache: buildCorpusRootLeafCache(events), corpusEpoch,
      biEncoderModelId: BI.modelId, biEncoderRevision: BI.revision, biEncoderRetrievalKeyLayout: LAYOUT,
      labelingModelId: labelingProvenance.modelId, labelingModelRevision: labelingProvenance.revision,
    };
  };
  const docTextById = (logicalDelta) => new Map(logicalDelta.addedDocs.map((d) => [d.id, d.text]));
  // Build production events from the live-update logical delta — split assigned by the CANONICAL
  // splitForRecord (NOT evolveCorpus's local hint), matching what buildCorpusDelta validates.
  function prodEvents(logicalDelta, corpusEpoch) {
    const txt = docTextById(logicalDelta);
    return logicalDelta.addedQueries.map((q) => {
      const truths = (q.qrels ?? []).filter((r) => r.relevance > 0).map((r) => ({ id: r.docId, text: txt.get(r.docId) ?? '', isCurrent: true }));
      const negs = (q.hardNegatives ?? []).map((n) => ({ id: n.docId, text: txt.get(n.docId) ?? '' }));
      return {
        id: q.id, family: q.family === 'conflict_lifecycle' ? 'conflict_lifecycle' : 'temporal', domain: q.lane, split: splitForRecord(q.id, corpusEpoch),
        queryText: q.queryText, truthDocuments: truths, hardNegatives: negs,
        qrels: (q.qrels ?? []).map((r) => ({ documentId: r.docId, relevance: r.relevance })), protected: false,
        subjectEntityId: q.subjectEntityId, provenance: { source: 'synthetic_challenge', sourceHash: '0x' + 'aa'.repeat(32) },
        embeddings: { modelId: BI.modelId, revision: BI.revision, layout: LAYOUT, query: mockEmb(),
          perTruth: new Map(truths.map((t) => [t.id, mockEmb()])), perNegative: new Map(negs.map((n) => [n.id, mockEmb()])) },
      };
    });
  }

  const baseLogical = {
    entities: [{ id: 'e_universe', canonicalName: 'U', aliases: [] }, ...Array.from({ length: 20 }, (_, i) => ({ id: `e_universe_s${i}`, canonicalName: `First${i} Last${i}`, aliases: [] }))],
    docs: Array.from({ length: 20 }, (_, i) => ({ id: `d${i}`, kind: 'temporal_city', entityIds: ['e_universe', `e_universe_s${i}`], currentStaleFlag: false, text: 'p' })),
    relations: [], queries: [],
  };

  test('split assigned via canonical splitForRecord (buildCorpusDelta does NOT throw)', () => {
    const ld = evolveCorpusDelta({ baseLogical, epoch: 2, seed: 'frontier', churnFraction: 1.0 });
    const additions = prodEvents(ld, 0);
    // every production-record split must equal splitForRecord(id) or buildCorpusDelta throws.
    for (const e of additions) assert.equal(e.split, splitForRecord(e.id, 0));
    assert.doesNotThrow(() => buildCorpusDelta({ previousCorpus: prevCorpus(0), additions, removals: [], epoch: 2, labelingProvenance }));
  });

  test('delta → new corpusRoot, deterministic + replay-identical, applyCorpusDelta reconstructs it', () => {
    const ld = evolveCorpusDelta({ baseLogical, epoch: 3, seed: 'frontier', churnFraction: 0.5 });
    const mk = () => buildCorpusDelta({ previousCorpus: prevCorpus(0), additions: prodEvents(ld, 0), removals: [], epoch: 3, labelingProvenance });
    const d1 = mk(), d2 = mk();
    assert.equal(d1.nextRoot, d2.nextRoot, 'same logical delta + mock embeddings → identical corpusRoot (replay-stable)');
    assert.notEqual(d1.nextRoot, d1.previousRoot, 'delta advances the root');
    const evolved = applyCorpusDelta(prevCorpus(0), d1);
    assert.equal(evolved.corpusRoot, d1.nextRoot, 'applyCorpusDelta reconstructs the delta nextRoot');
    assert.ok(d1.addedIds.length > 0);
  });

  test('package bridge emits tail-sortable live memory/query ids for incremental roots', () => {
    const previousCorpus = prevCorpusWithBaseMemory(0);
    const ld = evolveCorpusDelta({ baseLogical, epoch: 6, seed: 'frontier', churnFraction: 1.0 });
    const addedDocEmbeddings = new Map(ld.addedDocs.map((d) => [d.id, mockEmb()]));
    const addedQueryEmbeddings = new Map(ld.addedQueries.map((q) => [q.id, mockEmb()]));
    const additions = bridgeLogicalDeltaToProductionEvents({
      previousCorpus,
      logicalDelta: ld,
      addedDocEmbeddings,
      addedQueryEmbeddings,
      biEncoder: { modelId: BI.modelId, revision: BI.revision, layout: LAYOUT },
    });

    const maxPreviousId = [...previousCorpus.byId.keys()].sort().at(-1);
    assert.ok(maxPreviousId, 'previous corpus must have a max id');
    assert.ok(additions.every((e) => e.id > maxPreviousId), 'live additions must tail-sort after existing v15-style ids');
    assert.ok(additions.filter((e) => isMemoryDocumentEventId(e.id)).every((e) => e.id.startsWith('zz_e000000000006_mem_')), 'live memory docs use epoch-prefixed tail-sort memory ids');
    assert.ok(additions.filter((e) => !isMemoryDocumentEventId(e.id)).every((e) => e.id.startsWith('zz_e000000000006_q_')), 'live queries use epoch-prefixed tail-sort query ids');
    for (const e of additions) assert.equal(e.split, expectedSplitForRecord(e.id, 0));

    const delta = buildCorpusDelta({
      previousCorpus,
      previousRootCache: previousCorpus.corpusRootCache,
      additions,
      removals: [],
      epoch: 6,
      labelingProvenance,
    });
    const evolved = applyCorpusDelta(previousCorpus, delta, { rootCache: previousCorpus.corpusRootCache, attachRootCache: true });
    assert.equal(evolved.corpusRoot, delta.nextRoot);
    assert.equal(evolved.corpusRootCache.root, delta.nextRoot);
  });

  test('package bridge keeps later live epochs tail-sortable after prior live query ids', () => {
    let corpus = prevCorpusWithBaseMemory(0);
    const applyLiveEpoch = (epoch) => {
      const logical = {
        ...baseLogical,
        docs: [...baseLogical.docs, ...[...corpus.byId.values()]
          .filter((e) => isMemoryDocumentEventId(e.id))
          .map((e) => ({
            id: e.truthDocuments[0].id,
            kind: 'temporal_city',
            entityIds: e.entityIds ?? ['e_universe'],
            currentStaleFlag: e.truthDocuments[0].isCurrent !== false,
            text: e.truthDocuments[0].text,
          }))],
      };
      const ld = evolveCorpusDelta({ baseLogical: logical, epoch, seed: 'frontier', churnFraction: 1.0 });
      const addedDocEmbeddings = new Map(ld.addedDocs.map((d) => [d.id, mockEmb()]));
      const addedQueryEmbeddings = new Map(ld.addedQueries.map((q) => [q.id, mockEmb()]));
      const additions = bridgeLogicalDeltaToProductionEvents({
        previousCorpus: corpus,
        logicalDelta: ld,
        addedDocEmbeddings,
        addedQueryEmbeddings,
        biEncoder: { modelId: BI.modelId, revision: BI.revision, layout: LAYOUT },
      });
      const maxPreviousId = [...corpus.byId.keys()].sort().at(-1);
      assert.ok(additions.every((e) => e.id > maxPreviousId), `epoch ${epoch} additions must tail-sort after ${maxPreviousId}`);
      const delta = buildCorpusDelta({
        previousCorpus: corpus,
        previousRootCache: corpus.corpusRootCache,
        additions,
        removals: [],
        epoch,
        labelingProvenance,
      });
      corpus = applyCorpusDelta(corpus, delta, { rootCache: corpus.corpusRootCache, attachRootCache: true });
      return additions;
    };

    const e1 = applyLiveEpoch(1);
    const e2 = applyLiveEpoch(2);
    assert.ok(e1.some((e) => e.id.startsWith('zz_e000000000001_q_')));
    assert.ok(e2.some((e) => e.id.startsWith('zz_e000000000002_mem_')));
    assert.ok(Math.max(...e2.map((e) => e.id.localeCompare('zz_e000000000001_q_'))) > 0);
  });

  // P0: live churn needs NEW PUBLIC MEMORY-DOC events (mem_*) so policy atoms / aspect maps / relations /
  // retrieval structure can see the updated memories — not only query events. Memory docs are train_visible
  // (expectedSplitForRecord), queries use splitForRecord; both must pass buildCorpusDelta/applyCorpusDelta.
  const memId = (id) => `mem_${id}`;
  function prodMemDocs(logicalDelta) {
    const relBySrc = new Map();
    for (const r of logicalDelta.addedRelations) { if (!relBySrc.has(r.src)) relBySrc.set(r.src, []); relBySrc.get(r.src).push(r); }
    return logicalDelta.addedDocs.map((d) => ({
      id: memId(d.id), family: 'near_collision', domain: d.lane, split: expectedSplitForRecord(memId(d.id), 0),
      queryText: d.text,
      truthDocuments: [{ id: d.id, text: d.text, isCurrent: d.currentStaleFlag === false ? false : true, ...(d.aspectTags ? { aspectTags: d.aspectTags } : {}) }],
      hardNegatives: [], qrels: [{ documentId: d.id, relevance: 1.0 }], protected: false,
      relations: (relBySrc.get(d.id) ?? []).map((r) => ({ other_id: memId(r.dst), edgeType: r.type, ...(r.label ? { label: r.label } : {}) })),
      entityIds: d.entityIds, provenance: { source: 'synthetic_challenge', sourceHash: '0x' + 'aa'.repeat(32) },
      embeddings: { modelId: BI.modelId, revision: BI.revision, layout: LAYOUT, query: mockEmb(), perTruth: new Map([[d.id, mockEmb()]]), perNegative: new Map() },
    }));
  }

  test('LIVE MEMORY-DOC delta: mem_* docs (train_visible) + relations + aspectTags + queries pass buildCorpusDelta→applyCorpusDelta', () => {
    const ld = evolveCorpusDelta({ baseLogical, epoch: 4, seed: 'frontier', churnFraction: 1.0 });
    // tag one delta doc with public aspect tags to prove the field flows through the mem-doc delta path.
    ld.addedDocs[0] = { ...ld.addedDocs[0], aspectTags: ['latency', 'cost'] };
    const memDocs = prodMemDocs(ld);
    const queries = prodEvents(ld, 0);
    assert.ok(memDocs.length > 0, 'live churn must add public memory docs, not only queries');
    // memory docs are train_visible; queries are splitForRecord — both must equal expectedSplitForRecord.
    for (const e of memDocs) assert.equal(e.split, 'train_visible');
    for (const e of [...memDocs, ...queries]) assert.equal(e.split, expectedSplitForRecord(e.id, 0));
    // the split-authority fix: buildCorpusDelta MUST accept train_visible mem_* docs (previously threw).
    const mk = () => buildCorpusDelta({ previousCorpus: prevCorpus(0), additions: [...memDocs, ...queries], removals: [], epoch: 4, labelingProvenance });
    assert.doesNotThrow(mk, 'mem_* train_visible docs must not be rejected by the split validator');
    const d1 = mk(), d2 = mk();
    assert.equal(d1.nextRoot, d2.nextRoot, 'replay-stable root');
    const evolved = applyCorpusDelta(prevCorpus(0), d1);
    assert.equal(evolved.corpusRoot, d1.nextRoot, 'applyCorpusDelta reconstructs the root with live memory docs');
    // public memory structure is visible on the merged corpus: aspectTags + the continuity label survive.
    const memEv = evolved.byId.get(memDocs[0].id);
    assert.deepEqual(memEv.truthDocuments[0].aspectTags, ['latency', 'cost'], 'public aspectTags survive into the merged corpus');
    const withLabel = [...memDocs, ...queries].flatMap((e) => e.relations ?? []).filter((r) => r.label);
    assert.ok(withLabel.some((r) => r.label === 'supersedes' || r.label === 'contradicts'), 'public continuity label (direction) is preserved on live relations');
  });
});
