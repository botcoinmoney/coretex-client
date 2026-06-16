/**
 * Loader for the materialized production-corpus artifact written by
 * scripts/materialize-production-corpus.mjs. This is a CALIBRATION-INTERNAL format that
 * preserves every in-memory field of ProductionCorpusEvent — including `logicalFamily`
 * and `band` — so the computeCorpusRoot of the loaded events matches the original
 * buildV2ProductionCorpus output byte-for-byte. (The canonical serializeProductionCorpus
 * now preserves these fields as well; this loader remains for the streaming artifact
 * format.)
 *
 * loadMaterializedCorpus(bundlePath, opts):
 *   - resolves the artifact dir from the bundleHash (tag = bundleHash[2..10])
 *   - asserts manifest matches bundleHash + sourceCorpusSha256 + sourceEmbSha256
 *   - streams events from the NDJSON sidecar with hex→Uint8Array decode
 *   - optional verifyCorpusRoot recomputes the root and compares with the manifest
 *
 * loadMaterializedCorpusSlice(bundlePath, n):
 *   - hydrates only the FIRST N events from the NDJSON sidecar (mechanics smokes only)
 *   - computes a NEW root over the slice; manifest root is NOT expected to match
 */
import { readFileSync, openSync, readSync, closeSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { distIndex, baseDir as repoRoot } from './_package-paths.mjs';

const C = await import(distIndex);
const { computeCorpusRoot, biEncoderModelIdHash, buildCorpusRootLeafCache, buildCorpusRootLeafCacheFromLeaves } = C;

function sha256File(p) { return '0x' + createHash('sha256').update(readFileSync(p)).digest('hex'); }
function hexToU8(hex) { return new Uint8Array(Buffer.from(hex, 'hex')); }

function resolveMaterializedRoot(opts = {}) {
  return resolve(repoRoot, opts.materializedRoot ?? process.env.CORETEX_MATERIALIZED_ROOT ?? 'release/calibration/2026-05-21-memory-corpus-v2/materialized');
}

function resolveArtifactPaths(bundlePath, opts = {}) {
  const bundle = JSON.parse(readFileSync(resolve(repoRoot, bundlePath), 'utf8'));
  const tag = (bundle.bundleHash ?? '0xunknown').slice(2, 10);
  const dir = resolve(resolveMaterializedRoot(opts), tag);
  return {
    bundle, tag, dir,
    corpusJson: resolve(dir, 'corpus.json'),
    ndjson: resolve(dir, 'corpus.json.events.ndjson'),
    rootLeaves: resolve(dir, 'corpus.json.root-leaves.ndjson'),
    manifest: resolve(dir, 'manifest.json'),
  };
}

function assertManifest(manifestPath, bundleHash, sourceCorpusPath, sourceEmbPath, profilePath) {
  if (!existsSync(manifestPath)) {
    throw new Error(`HARD FAIL: materialized artifact missing — run scripts/materialize-production-corpus.mjs first. expected: ${manifestPath}`);
  }
  const m = JSON.parse(readFileSync(manifestPath, 'utf8'));
  if (m.bundleHash !== bundleHash) {
    throw new Error(`HARD FAIL: materialized artifact bundleHash mismatch — artifact=${m.bundleHash} active=${bundleHash}. Re-run materialize.`);
  }
  if (!m.profileHash || typeof m.profileHash !== 'string' || !m.profileHash.startsWith('0x')) {
    throw new Error(`HARD FAIL: materialized manifest profileHash missing or invalid: ${m.profileHash}. Re-run materialize.`);
  }
  if (typeof m.eventCount !== 'number' || m.eventCount <= 0) {
    throw new Error(`HARD FAIL: materialized manifest eventCount invalid: ${m.eventCount}`);
  }
  if (!m.corpusRoot || !m.corpusRoot.startsWith('0x')) {
    throw new Error(`HARD FAIL: materialized manifest corpusRoot invalid: ${m.corpusRoot}`);
  }
  if (sourceCorpusPath) {
    const actual = sha256File(resolve(repoRoot, sourceCorpusPath));
    if (m.sourceCorpusSha256 !== actual) {
      throw new Error(`HARD FAIL: source corpus sha drift — artifact=${m.sourceCorpusSha256} actual=${actual}. Re-run materialize.`);
    }
  }
  if (sourceEmbPath) {
    const actual = sha256File(resolve(repoRoot, sourceEmbPath));
    if (m.sourceEmbSha256 !== actual) {
      throw new Error(`HARD FAIL: source embeddings sha drift — artifact=${m.sourceEmbSha256} actual=${actual}. Re-run materialize.`);
    }
  }
  if (profilePath) {
    // sha of profile file bytes — coarser than canonical profile hash but verifies the source profile is unchanged.
    const actual = sha256File(resolve(repoRoot, profilePath));
    if (m.sourceProfileSha256 && m.sourceProfileSha256 !== actual) {
      throw new Error(`HARD FAIL: source profile sha drift — artifact=${m.sourceProfileSha256} actual=${actual}. Re-run materialize.`);
    }
  }
  return m;
}

function hydrateEvent(e) {
  const out = {};
  for (const k of Object.keys(e)) {
    if (k === 'embeddings') continue;
    out[k] = e[k];
  }
  out.embeddings = {
    modelId: e.embeddings.modelId, revision: e.embeddings.revision, layout: e.embeddings.layout,
    query: hexToU8(e.embeddings.query),
    perTruth: new Map(Object.entries(e.embeddings.perTruth ?? {}).map(([k, v]) => [k, hexToU8(v)])),
    perNegative: new Map(Object.entries(e.embeddings.perNegative ?? {}).map(([k, v]) => [k, hexToU8(v)])),
  };
  return out;
}

function loadRootLeafCache(rootLeavesPath, expectedRoot) {
  if (!existsSync(rootLeavesPath)) return null;
  const fd = openSync(rootLeavesPath, 'r');
  const leaves = [];
  try {
    const buf = Buffer.alloc(16 * 1024 * 1024);
    let pending = '';
    while (true) {
      const r = readSync(fd, buf, 0, buf.length, null);
      if (r <= 0) break;
      pending += buf.toString('utf8', 0, r);
      let nl;
      while ((nl = pending.indexOf('\n')) >= 0) {
        const line = pending.slice(0, nl); pending = pending.slice(nl + 1);
        if (!line) continue;
        const leaf = JSON.parse(line);
        leaves.push({ id: leaf.id, hash: hexToU8(leaf.hash) });
      }
    }
    if (pending.length > 0) {
      const leaf = JSON.parse(pending);
      leaves.push({ id: leaf.id, hash: hexToU8(leaf.hash) });
    }
  } finally { closeSync(fd); }
  const cache = buildCorpusRootLeafCacheFromLeaves(leaves);
  if (cache.root.toLowerCase() !== expectedRoot.toLowerCase()) {
    throw new Error(`HARD FAIL: materialized root leaf cache mismatch — cache=${cache.root} manifest=${expectedRoot}`);
  }
  return cache;
}

/**
 * Stream up to `target` total events, biased so the result contains at least `minEvalHidden`
 * eval_hidden events. Reads NDJSON in order: keeps every eval_hidden, keeps train_visible up to
 * target - minEvalHidden, then keeps additional eval_hidden until target hit or stream ends.
 * Stops early when both quotas satisfied.
 */
function streamEventsSplitBalanced(ndjsonPath, target, minEvalHidden) {
  const fd = openSync(ndjsonPath, 'r');
  const trainVis = [], evalHidden = [];
  try {
    const buf = Buffer.alloc(16 * 1024 * 1024);
    let pending = '';
    while (true) {
      if (evalHidden.length >= minEvalHidden && trainVis.length + evalHidden.length >= target) break;
      const r = readSync(fd, buf, 0, buf.length, null);
      if (r <= 0) break;
      pending += buf.toString('utf8', 0, r);
      let nl;
      while ((nl = pending.indexOf('\n')) >= 0) {
        const line = pending.slice(0, nl); pending = pending.slice(nl + 1);
        if (!line) continue;
        const parsed = JSON.parse(line);
        if (parsed.split === 'eval_hidden') {
          if (trainVis.length + evalHidden.length < target || evalHidden.length < minEvalHidden) evalHidden.push(hydrateEvent(parsed));
        } else if (parsed.split === 'train_visible') {
          if (trainVis.length + evalHidden.length < target) trainVis.push(hydrateEvent(parsed));
        }
        if (evalHidden.length >= minEvalHidden && trainVis.length + evalHidden.length >= target) break;
      }
    }
  } finally { closeSync(fd); }
  return [...trainVis, ...evalHidden];
}

function streamEventsFiltered(ndjsonPath, maxN, filterFn) {
  const fd = openSync(ndjsonPath, 'r');
  const events = [];
  try {
    const buf = Buffer.alloc(16 * 1024 * 1024);
    let pending = '';
    while (true) {
      if (maxN != null && events.length >= maxN) break;
      const r = readSync(fd, buf, 0, buf.length, null);
      if (r <= 0) break;
      pending += buf.toString('utf8', 0, r);
      let nl;
      while ((nl = pending.indexOf('\n')) >= 0) {
        const line = pending.slice(0, nl); pending = pending.slice(nl + 1);
        if (!line) continue;
        const parsed = JSON.parse(line);
        if (!filterFn(parsed)) continue;
        events.push(hydrateEvent(parsed));
        if (maxN != null && events.length >= maxN) break;
      }
    }
  } finally { closeSync(fd); }
  return events;
}

function streamEvents(ndjsonPath, maxN) {
  const fd = openSync(ndjsonPath, 'r');
  const events = [];
  try {
    const buf = Buffer.alloc(16 * 1024 * 1024);
    let pending = '';
    while (true) {
      if (maxN != null && events.length >= maxN) break;
      const r = readSync(fd, buf, 0, buf.length, null);
      if (r <= 0) break;
      pending += buf.toString('utf8', 0, r);
      let nl;
      while ((nl = pending.indexOf('\n')) >= 0) {
        const line = pending.slice(0, nl); pending = pending.slice(nl + 1);
        if (!line) continue;
        const parsed = JSON.parse(line);
        events.push(hydrateEvent(parsed));
        if (maxN != null && events.length >= maxN) break;
      }
    }
  } finally { closeSync(fd); }
  return events;
}

/**
 * @param {string} bundlePath
 * @param {{sourceCorpusPath?:string, sourceEmbPath?:string, verifyCorpusRoot?:boolean, materializedRoot?:string}} [opts]
 */
export function loadMaterializedCorpus(bundlePath, opts = {}) {
  const { bundle, manifest, ndjson, corpusJson, rootLeaves } = resolveArtifactPaths(bundlePath, opts);
  const m = assertManifest(manifest, bundle.bundleHash, opts.sourceCorpusPath, opts.sourceEmbPath);
  if (!existsSync(ndjson)) throw new Error(`HARD FAIL: ndjson sidecar missing: ${ndjson}`);
  const head = JSON.parse(readFileSync(corpusJson, 'utf8'));
  const events = streamEvents(ndjson, null);
  const rootCache = loadRootLeafCache(rootLeaves, m.corpusRoot);
  if (opts.verifyCorpusRoot) {
    const computedFromEvents = computeCorpusRoot(events);
    if (computedFromEvents.toLowerCase() !== m.corpusRoot.toLowerCase()) {
      throw new Error(`HARD FAIL: materialized corpusRoot mismatch — manifest=${m.corpusRoot} ndjson=${computedFromEvents}`);
    }
    const computed = rootCache?.root ?? computedFromEvents;
    if (computed.toLowerCase() !== m.corpusRoot.toLowerCase()) {
      throw new Error(`HARD FAIL: materialized corpusRoot mismatch — manifest=${m.corpusRoot} computed=${computed}`);
    }
  }
  const corpus = {
    events, byId: new Map(events.map((e) => [e.id, e])),
    ...(rootCache ? { corpusRootCache: rootCache } : {}),
    ...(head.entities ? { entities: head.entities } : {}),
    corpusRoot: m.corpusRoot.toLowerCase(), corpusEpoch: head.corpusEpoch ?? 0,
    biEncoderModelId: m.biEncoder.modelId, biEncoderRevision: m.biEncoder.revision, biEncoderRetrievalKeyLayout: m.biEncoder.layout,
    labelingModelId: m.labelingModel.modelId, labelingModelRevision: m.labelingModel.revision,
  };
  return { corpus, manifest: m, BE: { modelId: m.biEncoder.modelId, revision: m.biEncoder.revision, retrievalKeyLayout: m.biEncoder.layout }, RR: m.labelingModel, LAYOUT: m.biEncoder.layout };
}

/**
 * Drop-in compat shape that mirrors buildV2ProductionCorpus return:
 *   { corpus, queryEvents, logical, LAYOUT, BE, RR, biEncoderHash, bundlePath }
 *
 * Used by the static A100 probes (oracle/conflict/abstention/temporal/relation_typed) so swap-in is
 * a one-line import change. Reads the materialized artifact (fast) + parses the raw logical-corpus
 * JSON once (the probes need it for entities/queries metadata; cheap vs the 16-min bridge rebuild).
 *
 * @param {string} bundlePath
 * @param {string} sourceCorpusPath  — used to parse logical + verify source-corpus SHA
 * @param {string} sourceEmbPath     — used to verify source-embeddings SHA
 */
export function loadV2CompatBundle(bundlePath, sourceCorpusPath, sourceEmbPath) {
  if (!sourceCorpusPath || !sourceEmbPath) throw new Error('loadV2CompatBundle: sourceCorpusPath + sourceEmbPath required');
  const loaded = loadMaterializedCorpus(bundlePath, { sourceCorpusPath, sourceEmbPath });
  const logical = JSON.parse(readFileSync(resolve(repoRoot, sourceCorpusPath), 'utf8'));
  const queryEvents = loaded.corpus.events.filter((e) => e.split === 'eval_hidden' || e.split === 'calibration' || e.split === 'canary');
  const biEncoderHash = biEncoderModelIdHash(loaded.BE.modelId, loaded.BE.revision, 'dense');
  return {
    corpus: loaded.corpus, queryEvents, logical,
    LAYOUT: loaded.LAYOUT, BE: loaded.BE, RR: loaded.RR,
    biEncoderHash, bundlePath, manifest: loaded.manifest,
  };
}

/**
 * Read only the first `n` events from the NDJSON sidecar; mechanics smoke tests.
 * The slice corpus has its OWN corpusRoot (computed over the slice), NOT the manifest root.
 * Optional `splitFilter` collects only events matching the predicate (useful when smokes need
 * at least some eval_hidden events).
 */
export function loadMaterializedCorpusSlice(bundlePath, n, opts = {}) {
  const { bundle, manifest, ndjson } = resolveArtifactPaths(bundlePath, opts);
  const m = assertManifest(manifest, bundle.bundleHash);
  if (!existsSync(ndjson)) throw new Error(`HARD FAIL: ndjson sidecar missing: ${ndjson}`);
  // minEvalHidden guarantees at least M eval_hidden events in the slice (needed for frontier);
  // splitFilter is a less-common arbitrary predicate.
  const events = (opts.minEvalHidden && opts.minEvalHidden > 0)
    ? streamEventsSplitBalanced(ndjson, n, opts.minEvalHidden)
    : (opts.splitFilter ? streamEventsFiltered(ndjson, n, opts.splitFilter) : streamEvents(ndjson, n));
  const idsInSlice = new Set(events.map((e) => e.id));
  // Drop events whose truth/neg doc ids are not in-slice — keeps the slice self-consistent
  // for evaluators that lookup truth docs by id.
  const filtered = events.filter((e) => {
    for (const t of e.truthDocuments ?? []) if (!idsInSlice.has(t.id) && !idsInSlice.has(`mem_${t.id}`)) return false;
    for (const h of e.hardNegatives ?? []) if (!idsInSlice.has(h.id) && !idsInSlice.has(`mem_${h.id}`)) return false;
    return true;
  });
  const rootCache = buildCorpusRootLeafCache(filtered);
  const root = rootCache.root;
  return {
    corpus: {
      events: filtered, byId: new Map(filtered.map((e) => [e.id, e])),
      corpusRootCache: rootCache,
      corpusRoot: root, corpusEpoch: 0,
      biEncoderModelId: m.biEncoder.modelId, biEncoderRevision: m.biEncoder.revision, biEncoderRetrievalKeyLayout: m.biEncoder.layout,
      labelingModelId: m.labelingModel.modelId, labelingModelRevision: m.labelingModel.revision,
    },
    manifest: m,
    BE: { modelId: m.biEncoder.modelId, revision: m.biEncoder.revision, retrievalKeyLayout: m.biEncoder.layout },
    RR: m.labelingModel, LAYOUT: m.biEncoder.layout,
    sliced: { requested: n, materializedCount: events.length, kept: filtered.length },
  };
}
