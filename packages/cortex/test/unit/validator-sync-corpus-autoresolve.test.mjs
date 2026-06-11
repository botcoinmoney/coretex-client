/**
 * Validator auto-resolution of a historical epoch's corpus from PUBLIC artifacts.
 *
 * A cross-rotation eval-backlog entry pins an epoch's corpusRoot that differs
 * from the loaded scorer context. Rather than requiring the operator to pass
 * --corpus-for-root, the validator AUTO-RESOLVES that corpus by walking the
 * published, SIGNED corpus-delta chain forward from a known-materialized base,
 * applying applyCorpusDelta in order until the materialized root EQUALS the pin,
 * then INDEPENDENTLY re-merkleizing the reconstructed corpus before use.
 *
 * These exercise the EXPORTED pure primitives the wiring composes, deterministically
 * (no live RPC, no real scorer, no torch): the signed delta-chain walk, the
 * merkle-verify-before-use refusal, the safe-fail on a missing/unfetchable or
 * bad-signature delta, the bounded materialize-once cache, and the URL convention.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';

import {
  autoResolveCorpusByRoot,
  MaterializedCorpusCache,
  DEFAULT_MATERIALIZED_CORPUS_CACHE_LIMIT,
  corpusDeltaArtifactUrl,
  resolveScorerContextDecision,
  assertArtifactBoundToEntry,
} from '../../dist/validator-sync-cli.js';
import {
  buildCorpusDelta,
  applyCorpusDelta,
  computeCorpusRoot,
  signCorpusDelta,
  verifyCorpusDeltaSignature,
  splitForRecord,
} from '../../dist/index.js';

const BI = { modelId: 'BAAI/bge-m3', revision: 'a'.repeat(40) };
const LAYOUT = { dim: 8, quantization: 'int8', headerBytes: 9 };
const labelingProvenance = { modelId: 'memreranker/4B', revision: 'b'.repeat(40), runtime: 'unit', batchHash: 'c'.repeat(64) };
const emb = () => new Uint8Array(LAYOUT.dim + 4);

function event(id, corpusEpoch = 0) {
  return {
    id,
    family: 'near_collision',
    domain: 'unit',
    split: splitForRecord(id, corpusEpoch),
    queryText: `query ${id}`,
    truthDocuments: [{ id: `${id}::t`, text: `truth ${id}`, isCurrent: true }],
    hardNegatives: [],
    qrels: [{ documentId: `${id}::t`, relevance: 1.0 }],
    protected: false,
    provenance: { source: 'synthetic_challenge', sourceHash: '0x' + '00'.repeat(32) },
    embeddings: { modelId: BI.modelId, revision: BI.revision, layout: LAYOUT, query: emb(), perTruth: new Map([[`${id}::t`, emb()]]), perNegative: new Map() },
  };
}

function corpusFrom(events) {
  return {
    events,
    byId: new Map(events.map((e) => [e.id, e])),
    corpusRoot: computeCorpusRoot(events),
    corpusEpoch: 0,
    biEncoderModelId: BI.modelId,
    biEncoderRevision: BI.revision,
    biEncoderRetrievalKeyLayout: LAYOUT,
    labelingModelId: labelingProvenance.modelId,
    labelingModelRevision: labelingProvenance.revision,
  };
}

/**
 * Build a published, SIGNED corpus-delta chain: genesis (epoch 0) → C1 (delta
 * epoch 1) → C2 (delta epoch 2) → C3 (delta epoch 3). Returns the materialized
 * corpora and a `deltasByEpoch` map of SIGNED deltas the fetch dep serves.
 */
function buildChain(privateKey) {
  const genesisEvents = Array.from({ length: 4 }, (_, i) => event(`g${i}`));
  const genesis = corpusFrom(genesisEvents);

  const corpora = [genesis];
  const deltasByEpoch = new Map();
  let prev = genesis;
  for (let epoch = 1; epoch <= 3; epoch++) {
    const additions = [event(`r${epoch}_a`), event(`r${epoch}_b`)];
    const unsigned = buildCorpusDelta({ previousCorpus: prev, additions, removals: [], epoch, labelingProvenance, generatedAt: '2026-06-09T00:00:00.000Z' });
    const signed = signCorpusDelta(unsigned, privateKey, `epoch-key-${epoch}`);
    deltasByEpoch.set(epoch, signed);
    const next = applyCorpusDelta(prev, signed, { verifyRoot: true });
    corpora.push(next);
    prev = next;
  }
  return { genesis, corpora, deltasByEpoch };
}

/** Deps for autoResolveCorpusByRoot backed by an in-memory signed-delta chain. */
function depsFor(deltasByEpoch, publicKey, opts = {}) {
  const fetched = [];
  return {
    deps: {
      fetchDelta: async (epoch) => {
        fetched.push(epoch);
        if (opts.dropEpoch === epoch) return null; // unpublished
        return deltasByEpoch.get(epoch) ?? null;
      },
      verifyDeltaSignature: (d) => verifyCorpusDeltaSignature(d, publicKey),
      applyDelta: (corpus, d) => applyCorpusDelta(corpus, d, { verifyRoot: true }),
      computeRoot: (corpus) => computeCorpusRoot(corpus.events),
      ...(opts.onMaterialized ? { onMaterialized: opts.onMaterialized } : {}),
    },
    fetched,
  };
}

describe('corpusDeltaArtifactUrl — published per-epoch delta URL convention', () => {
  test('mirrors the continuity path artifact layout (trailing slash tolerant)', () => {
    assert.equal(corpusDeltaArtifactUrl('https://cdn/x', 5), 'https://cdn/x/epoch-rotations/corpus-delta-epoch-5.json');
    assert.equal(corpusDeltaArtifactUrl('https://cdn/x/', 5), 'https://cdn/x/epoch-rotations/corpus-delta-epoch-5.json');
  });
});

describe('autoResolveCorpusByRoot — walk the signed corpus-delta chain', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

  test('a target reachable by applying published deltas is auto-materialized (root merkle-verified)', async () => {
    const { genesis, corpora, deltasByEpoch } = buildChain(privateKey);
    const target = corpora[2].corpusRoot; // C2 — two rotations past genesis
    const { deps } = depsFor(deltasByEpoch, publicKey);
    const res = await autoResolveCorpusByRoot(genesis, target, 1, 3, deps);
    assert.equal(res.ok, true);
    assert.deepEqual(res.appliedEpochs, [1, 2]);
    // The returned corpus INDEPENDENTLY merkleizes to the pinned target.
    assert.equal(computeCorpusRoot(res.corpus.events).toLowerCase(), target.toLowerCase());
    assert.equal(res.corpus.corpusRoot.toLowerCase(), target.toLowerCase());
  });

  test('base already AT the target re-merkleizes and returns with no deltas applied', async () => {
    const { genesis, deltasByEpoch } = buildChain(privateKey);
    const { deps, fetched } = depsFor(deltasByEpoch, publicKey);
    const res = await autoResolveCorpusByRoot(genesis, genesis.corpusRoot, 1, 3, deps);
    assert.equal(res.ok, true);
    assert.deepEqual(res.appliedEpochs, []);
    assert.equal(fetched.length, 0); // no walk needed
  });

  test('a reconstructed corpus whose INDEPENDENT root does NOT match the pin is REFUSED (not used)', async () => {
    const { genesis, corpora, deltasByEpoch } = buildChain(privateKey);
    const target = corpora[1].corpusRoot; // C1
    const { deps } = depsFor(deltasByEpoch, publicKey);
    // Inject an applyDelta that returns a corpus whose CLAIMED corpusRoot is the
    // target (so the loop stops) but whose CONTENT merkleizes elsewhere — the
    // merkle-verify-before-use gate must refuse it.
    const tampered = {
      ...deps,
      applyDelta: (corpus, d) => {
        const real = applyCorpusDelta(corpus, d, { verifyRoot: true });
        return { ...real, corpusRoot: target, events: [...real.events, event('z_tamper')] };
      },
    };
    const res = await autoResolveCorpusByRoot(genesis, target, 1, 3, tampered);
    assert.equal(res.ok, false);
    assert.match(res.reason, /merkleizes to .* != target corpusRoot .* refusing to use/);
  });

  test('a missing/unpublished delta in the chain SAFE-FAILS (never rescored)', async () => {
    const { genesis, corpora, deltasByEpoch } = buildChain(privateKey);
    const target = corpora[3].corpusRoot; // C3 — needs deltas 1,2,3
    const { deps } = depsFor(deltasByEpoch, publicKey, { dropEpoch: 2 }); // delta 2 unpublished
    const res = await autoResolveCorpusByRoot(genesis, target, 1, 3, deps);
    assert.equal(res.ok, false);
    assert.match(res.reason, /corpus-delta for epoch 2 is not published/);
  });

  test('a delta whose signature FAILS under the pinned key SAFE-FAILS', async () => {
    const { genesis, corpora, deltasByEpoch } = buildChain(privateKey);
    const target = corpora[2].corpusRoot;
    // Verify against a DIFFERENT key → every signature is rejected.
    const wrong = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey;
    const { deps } = depsFor(deltasByEpoch, wrong);
    const res = await autoResolveCorpusByRoot(genesis, target, 1, 3, deps);
    assert.equal(res.ok, false);
    assert.match(res.reason, /signature INVALID under the TOFU-pinned epoch key/);
  });

  test('a delta that does NOT chain off the current corpus SAFE-FAILS (applyDelta throws)', async () => {
    const { genesis, corpora, deltasByEpoch } = buildChain(privateKey);
    const target = corpora[2].corpusRoot;
    // Serve delta-2 (chains off C1) at epoch 1 — it cannot apply to genesis.
    const broken = new Map(deltasByEpoch);
    broken.set(1, deltasByEpoch.get(2));
    const { deps } = depsFor(broken, publicKey);
    const res = await autoResolveCorpusByRoot(genesis, target, 1, 3, deps);
    assert.equal(res.ok, false);
    assert.match(res.reason, /applying corpus-delta for epoch 1 failed/);
  });

  test('the target not reached within the bound SAFE-FAILS (never rescored)', async () => {
    const { genesis, corpora, deltasByEpoch } = buildChain(privateKey);
    const target = corpora[3].corpusRoot; // needs 3 deltas
    const { deps } = depsFor(deltasByEpoch, publicKey);
    const res = await autoResolveCorpusByRoot(genesis, target, 1, 2, deps); // bound = 2
    assert.equal(res.ok, false);
    assert.match(res.reason, /not reached after applying 2 published delta/);
  });

  test('a target absent from the chain SAFE-FAILS rather than returning a wrong corpus', async () => {
    const { genesis, deltasByEpoch } = buildChain(privateKey);
    const bogus = '0x' + 'de'.repeat(32);
    const { deps } = depsFor(deltasByEpoch, publicKey);
    const res = await autoResolveCorpusByRoot(genesis, bogus, 1, 3, deps);
    assert.equal(res.ok, false);
  });
});

describe('end-to-end drain shape — auto-resolved corpus binds to the entry, override still works', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const addr = (byte) => `0x${byte.repeat(20)}`;
  const b32 = (byte) => `0x${byte.repeat(32)}`;

  test('an entry pinned to a historical root reachable by deltas auto-materializes the RIGHT corpus and binds (no --corpus-for-root)', async () => {
    const { genesis, corpora, deltasByEpoch } = buildChain(privateKey);
    // Entry pins C2's root (a historical corpus, differs from the loaded genesis).
    const historicalRoot = corpora[2].corpusRoot;
    const CORE_VERSION = b32('33');
    const entry = {
      epochId: 5,
      artifactHash: b32('cd'),
      miner: addr('a1'),
      parentStateRoot: b32('11'),
      corpusRoot: historicalRoot,
      coreVersionHash: CORE_VERSION,
      patchHash: b32('77'),
    };
    const loaded = { corpusRoot: genesis.corpusRoot, coreVersionHash: CORE_VERSION };

    // Without any operator override the pure decision reports the pins differ and
    // the corpus is not yet in the (operator) resolvable set → the wiring then
    // ATTEMPTS auto-resolution. Here we drive the auto-resolver directly.
    const decisionNoOverride = resolveScorerContextDecision(entry, loaded, new Set([genesis.corpusRoot.toLowerCase()]));
    assert.equal(decisionNoOverride.action, 'unavailable'); // not operator-resolvable → wiring auto-resolves next

    const { deps } = depsFor(deltasByEpoch, publicKey);
    const res = await autoResolveCorpusByRoot(genesis, entry.corpusRoot, 1, 6, deps);
    assert.equal(res.ok, true);
    // The auto-resolved corpus root == the entry's pin == the artifact's context
    // corpusRoot → the binding gate passes and the rescore can proceed.
    assert.equal(res.corpus.corpusRoot.toLowerCase(), entry.corpusRoot.toLowerCase());
    const artifact = {
      artifactHash: entry.artifactHash,
      epochId: entry.epochId,
      minerAddress: entry.miner,
      seedDerivation: { patchHash: entry.patchHash },
      context: { parentStateRoot: entry.parentStateRoot, corpusRoot: res.corpus.corpusRoot, coreVersionHash: entry.coreVersionHash },
    };
    assert.doesNotThrow(() => assertArtifactBoundToEntry(artifact, entry));
  });

  test('the operator --corpus-for-root override remains a shortcut (resolve-context, no walk)', () => {
    const { genesis, corpora } = buildChain(privateKey);
    const historicalRoot = corpora[1].corpusRoot;
    const entry = { corpusRoot: historicalRoot, coreVersionHash: b32('33') };
    const loaded = { corpusRoot: genesis.corpusRoot, coreVersionHash: b32('33') };
    // With the operator-supplied corpus in the resolvable set, the pure decision
    // short-circuits to resolve-context — the wiring uses the file directly and
    // never walks the delta chain.
    const d = resolveScorerContextDecision(entry, loaded, new Set([historicalRoot.toLowerCase()]));
    assert.equal(d.action, 'resolve-context');
  });
});

describe('MaterializedCorpusCache — bounded materialize-once', () => {
  test('a given root is materialized at most once across multiple lookups', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const { genesis, corpora, deltasByEpoch } = buildChain(privateKey);
    const cache = new MaterializedCorpusCache();
    cache.set(genesis.corpusRoot, genesis);
    const { deps, fetched } = depsFor(deltasByEpoch, publicKey, {
      onMaterialized: (corpus) => cache.set(corpus.corpusRoot, corpus),
    });

    const targetC2 = corpora[2].corpusRoot;
    // First entry resolves C2 — walks deltas 1,2 and caches the intermediates.
    const cachedFirst = cache.get(targetC2);
    assert.equal(cachedFirst, undefined);
    const r1 = await autoResolveCorpusByRoot(genesis, targetC2, 1, 3, deps);
    assert.equal(r1.ok, true);
    const fetchesAfterFirst = fetched.length;
    assert.ok(fetchesAfterFirst >= 2);

    // A SECOND backlog entry pinning the SAME root finds it in the cache — no
    // re-walk, no further fetches: the root is materialized at most once.
    const cachedSecond = cache.get(targetC2);
    assert.notEqual(cachedSecond, undefined);
    assert.equal(computeCorpusRoot(cachedSecond.events).toLowerCase(), targetC2.toLowerCase());
    assert.equal(fetched.length, fetchesAfterFirst); // no extra fetches

    // An entry pinning the INTERMEDIATE C1 also hits the cache (onMaterialized
    // recorded it during the first walk) — still no re-walk.
    const c1 = cache.get(corpora[1].corpusRoot);
    assert.notEqual(c1, undefined);
    assert.equal(c1.corpusRoot.toLowerCase(), corpora[1].corpusRoot.toLowerCase());
    assert.equal(fetched.length, fetchesAfterFirst);
  });

  test('LRU evicts the least-recently-used past the bound; recency refreshed on get', () => {
    const cache = new MaterializedCorpusCache(2);
    const mk = (root) => ({ corpusRoot: root, events: [] });
    const A = '0x' + 'a1'.repeat(32);
    const B = '0x' + 'b2'.repeat(32);
    const C = '0x' + 'c3'.repeat(32);
    cache.set(A, mk(A));
    cache.set(B, mk(B));
    assert.equal(cache.size, 2);
    // Touch A so B becomes least-recently-used.
    assert.notEqual(cache.get(A), undefined);
    cache.set(C, mk(C)); // evicts B (LRU), keeps A + C
    assert.equal(cache.has(A), true);
    assert.equal(cache.has(C), true);
    assert.equal(cache.has(B), false);
    assert.equal(cache.size, 2);
  });

  test('default bound is documented and > 0', () => {
    assert.ok(DEFAULT_MATERIALIZED_CORPUS_CACHE_LIMIT > 0);
    assert.equal(new MaterializedCorpusCache().size, 0);
  });
});
