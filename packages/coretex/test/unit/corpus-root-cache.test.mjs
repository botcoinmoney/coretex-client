import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import {
  applyCorpusDelta,
  buildCorpusDelta,
  buildCorpusRootLeafCache,
  buildCorpusRootLeafCacheFromLeaves,
  computeCorpusEventLeafHash,
  computeCorpusRoot,
  expectedSplitForRecord,
  updateCorpusRootLeafCache,
} from '../../dist/index.js';
import { loadMaterializedCorpusSlice } from '../../../../scripts/lib/load-materialized-corpus.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../../../..');

const BI = { modelId: 'BAAI/bge-m3', revision: 'a'.repeat(40) };
const LAYOUT = { dim: 8, quantization: 'int8', headerBytes: 9 };
const labelingProvenance = { modelId: 'memreranker/4B', revision: 'b'.repeat(40), runtime: 'unit', batchHash: 'c'.repeat(64) };
const emb = () => new Uint8Array(LAYOUT.dim + 4);

function memEvent(n) {
  const docId = `doc_${n}`;
  const id = `mem_${docId}`;
  return {
    id,
    family: 'near_collision',
    domain: 'unit',
    split: expectedSplitForRecord(id, 0),
    queryText: `memory ${n}`,
    truthDocuments: [{ id: docId, text: `memory ${n}`, isCurrent: true }],
    hardNegatives: [],
    qrels: [{ documentId: docId, relevance: 1.0 }],
    protected: false,
    provenance: { source: 'synthetic_challenge', sourceHash: '0x' + '00'.repeat(32) },
    embeddings: { modelId: BI.modelId, revision: BI.revision, layout: LAYOUT, query: emb(), perTruth: new Map([[docId, emb()]]), perNegative: new Map() },
  };
}

function corpus(events) {
  return {
    events,
    byId: new Map(events.map((e) => [e.id, e])),
    corpusRoot: computeCorpusRoot(events),
    corpusRootCache: buildCorpusRootLeafCache(events),
    corpusEpoch: 0,
    biEncoderModelId: BI.modelId,
    biEncoderRevision: BI.revision,
    biEncoderRetrievalKeyLayout: LAYOUT,
    labelingModelId: labelingProvenance.modelId,
    labelingModelRevision: labelingProvenance.revision,
  };
}

describe('corpus root leaf cache', () => {
  test('small corpus incremental update equals full computeCorpusRoot', () => {
    const baseEvents = Array.from({ length: 32 }, (_, i) => memEvent(i));
    const base = corpus(baseEvents);
    assert.equal(base.corpusRootCache.root, base.corpusRoot);

    const additions = [memEvent(100), memEvent(101)];
    const removals = [baseEvents[3].id, baseEvents[17].id];
    const nextEvents = baseEvents.filter((e) => !removals.includes(e.id)).concat(additions);

    const updated = updateCorpusRootLeafCache(base.corpusRootCache, { additions, removals });
    assert.equal(updated.root, computeCorpusRoot(nextEvents));
    assert.equal(updated.eventCount, nextEvents.length);
  });

  test('buildCorpusDelta/applyCorpusDelta use cache without changing root semantics', () => {
    const base = corpus(Array.from({ length: 64 }, (_, i) => memEvent(i)));
    const additions = [memEvent(200), memEvent(201)];

    const uncached = buildCorpusDelta({ previousCorpus: base, additions, removals: [], epoch: 1, labelingProvenance });
    const cached = buildCorpusDelta({ previousCorpus: base, previousRootCache: base.corpusRootCache, additions, removals: [], epoch: 1, labelingProvenance });
    assert.equal(cached.nextRoot, uncached.nextRoot);

    const next = applyCorpusDelta(base, cached, { rootCache: base.corpusRootCache, attachRootCache: true });
    assert.equal(next.corpusRoot, uncached.nextRoot);
    assert.equal(next.corpusRootCache.root, next.corpusRoot);
    assert.equal(next.corpusRootCache.eventCount, base.events.length + additions.length);
  });

  test('tail-sort additions use the Merkle forest fast path without changing root semantics', () => {
    const baseLeaves = Array.from({ length: 32768 }, (_, i) => {
      const hash = new Uint8Array(32);
      hash[0] = i & 0xff;
      hash[1] = (i >>> 8) & 0xff;
      return { id: `aa_${String(i).padStart(6, '0')}`, hash };
    });
    const base = buildCorpusRootLeafCacheFromLeaves(baseLeaves);
    const addition = { ...memEvent(999999), id: 'zz_mem_tail_000001', split: expectedSplitForRecord('zz_mem_tail_000001', 0) };
    const additionLeaf = { id: addition.id, hash: computeCorpusEventLeafHash(addition) };

    const t0 = Date.now();
    const updated = updateCorpusRootLeafCache(base, { additions: [addition], removals: [] });
    const elapsedMs = Date.now() - t0;

    const expected = buildCorpusRootLeafCacheFromLeaves([...baseLeaves, additionLeaf]);
    assert.equal(updated.root, expected.root);
    assert.equal(updated.eventCount, baseLeaves.length + 1);
    assert.ok(elapsedMs < 250, `tail-sort cached root update should avoid full Merkle rebuild; got ${elapsedMs}ms`);
  });

  test('v15 materialized slice cache update equals full recompute and stays sub-second scale', (t) => {
    const manifest = resolve(repoRoot, 'release/calibration/2026-05-21-memory-corpus-v2/materialized/ed096863/manifest.json');
    if (!existsSync(manifest)) {
      t.skip('v15 materialized cache is not present in this checkout');
      return;
    }

    const loaded = loadMaterializedCorpusSlice(
      'release/bundle/bundle-manifest-v2-dgen1-policy-r5-300k-calibration.json',
      2048,
      { minEvalHidden: 32 },
    );
    const base = loaded.corpus;
    assert.equal(base.corpusRootCache.root, base.corpusRoot);

    const removeId = base.events[10].id;
    const addition = { ...base.events[0], id: 'zz_unit_root_cache_added', queryText: `${base.events[0].queryText} root-cache-added` };
    const expectedEvents = base.events.filter((e) => e.id !== removeId).concat([addition]);

    const t0 = Date.now();
    const updated = updateCorpusRootLeafCache(base.corpusRootCache, { additions: [addition], removals: [removeId] });
    const elapsedMs = Date.now() - t0;

    assert.equal(updated.root, computeCorpusRoot(expectedEvents));
    assert.ok(elapsedMs < 1000, `cached root update should complete in <1s on 2k v15 slice; got ${elapsedMs}ms`);
  });
});
