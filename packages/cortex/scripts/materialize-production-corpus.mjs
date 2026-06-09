#!/usr/bin/env node
/**
 * Build the canonical production corpus ONCE from pinned (corpus, embeddings, bundle, profile)
 * and write it to a materialized artifact pair (CorpusFileShape JSON header + NDJSON sidecar).
 * Every downstream harness (smokes + tracks) loads from this artifact via canonical
 * `loadProductionCorpus`, NEVER re-runs the 16-minute buildV2ProductionCorpus.
 *
 * Artifact layout:
 *   release/calibration/2026-05-21-memory-corpus-v2/materialized/<bundleHash8>/corpus.json
 *   release/calibration/2026-05-21-memory-corpus-v2/materialized/<bundleHash8>/corpus.json.events.ndjson
 *   release/calibration/2026-05-21-memory-corpus-v2/materialized/<bundleHash8>/manifest.json
 *
 * Manifest fields: gitCommit, bundleHash, profileHash, corpusRoot, BE/RR/layout pins,
 * sourceCorpusSha256, sourceEmbSha256, eventCount, materializedAtNote.
 *
 * Usage: node packages/cortex/scripts/materialize-production-corpus.mjs --profile <p> --bundle <b> --corpus <c> --emb <e> [--force]
 *   (scripts/materialize-production-corpus.mjs at the repo root is a forwarding shim)
 *   [--materialized-root release/calibration/.../materialized]
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync, createWriteStream, statSync, readdirSync, copyFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { argv, exit } from 'node:process';
import { execSync } from 'node:child_process';
import { distIndex, baseDir as repoRoot } from './lib/_package-paths.mjs';
import { buildV2ProductionCorpus } from './lib/build-v2-production-corpus.mjs';

const C = await import(distIndex);
const { computeCorpusEventLeafHash, buildCorpusRootLeafCacheFromLeaves } = C;

// Local profileHash: keccak/sha256 over a deterministic JSON of the profile (sorted keys).
// No canonical export exists; this gives a stable per-profile identity for the artifact manifest.
function canonicalJsonSorted(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJsonSorted).join(',')}]`;
  const keys = Object.keys(v).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJsonSorted(v[k])}`).join(',')}}`;
}
function computeProfileHashLocal(profile) {
  return '0x' + createHash('sha256').update(canonicalJsonSorted(profile)).digest('hex');
}

const u8ToHex = (u8) => Buffer.from(u8.buffer ?? u8, u8.byteOffset ?? 0, u8.byteLength ?? u8.length).toString('hex');
// Materialized event = the in-memory ProductionCorpusEvent verbatim, with embeddings hex-encoded.
// PRESERVES every field including logicalFamily + band, so the round-trip recomputes the SAME
// corpusRoot as the original buildV2ProductionCorpus build. (The canonical
// serializeProductionCorpus now preserves these fields too; this streaming writer remains for
// memory reasons — it never holds the full events array in one JSON string.)
function eventOnDisk(e) {
  const out = {};
  // Copy every own enumerable property as-is, EXCEPT embeddings which we hex-encode.
  for (const k of Object.keys(e)) {
    if (k === 'embeddings') continue;
    out[k] = e[k];
  }
  out.embeddings = {
    modelId: e.embeddings.modelId, revision: e.embeddings.revision, layout: e.embeddings.layout,
    query: u8ToHex(e.embeddings.query),
    perTruth: Object.fromEntries(Array.from(e.embeddings.perTruth.entries()).map(([k, v]) => [k, u8ToHex(v)])),
    perNegative: Object.fromEntries(Array.from(e.embeddings.perNegative.entries()).map(([k, v]) => [k, u8ToHex(v)])),
  };
  return out;
}

const flag = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 && i + 1 < argv.length ? argv[i + 1] : d; };
const has = (n) => argv.includes(`--${n}`);
const PROFILE_PATH = flag('profile');
const BUNDLE_PATH = flag('bundle');
const CORPUS_PATH = flag('corpus');
const EMB_PATH = flag('emb');
const FORCE = has('force');
const MATERIALIZED_ROOT = flag('materialized-root', process.env.CORETEX_MATERIALIZED_ROOT ?? 'release/calibration/2026-05-21-memory-corpus-v2/materialized');
if (!PROFILE_PATH || !BUNDLE_PATH || !CORPUS_PATH || !EMB_PATH) {
  console.error('HARD FAIL: --profile, --bundle, --corpus, --emb required'); exit(1);
}

const profile = JSON.parse(readFileSync(resolve(repoRoot, PROFILE_PATH), 'utf8'));
const bundle = JSON.parse(readFileSync(resolve(repoRoot, BUNDLE_PATH), 'utf8'));
const PIN_BE = bundle.model?.biEncoder;
const PIN_RR = bundle.model?.reranker;
const PIN_LAYOUT = PIN_BE?.retrievalKeyLayout
  ? { dim: PIN_BE.retrievalKeyLayout.dim, quantization: PIN_BE.retrievalKeyLayout.quantization, headerBytes: PIN_BE.retrievalKeyLayout.headerBytes }
  : null;
const sha256File = (p) => '0x' + createHash('sha256').update(readFileSync(resolve(repoRoot, p))).digest('hex');
const sourceCorpusSha = sha256File(CORPUS_PATH);
const sourceEmbSha = sha256File(EMB_PATH);
const bundleTag = (bundle.bundleHash ?? '0xunknown').slice(2, 10);

const ROOT_MAT = resolve(repoRoot, MATERIALIZED_ROOT);
const MAT_DIR = resolve(ROOT_MAT, bundleTag);
const CORPUS_JSON = resolve(MAT_DIR, 'corpus.json');
const NDJSON = `${CORPUS_JSON}.events.ndjson`;
const ROOT_LEAVES = `${CORPUS_JSON}.root-leaves.ndjson`;
const MANIFEST = resolve(MAT_DIR, 'manifest.json');

const profileHashLocal = computeProfileHashLocal(profile);

// ─── Cache check (direct): reuse if existing artifact under THIS bundleHash matches inputs ───
if (existsSync(MANIFEST) && !FORCE) {
  try {
    const m = JSON.parse(readFileSync(MANIFEST, 'utf8'));
    if (m.bundleHash === bundle.bundleHash
        && m.sourceCorpusSha256 === sourceCorpusSha
        && m.sourceEmbSha256 === sourceEmbSha
        && m.profileHash && m.profileHash.startsWith('0x')   // reject pre-fix artifacts that had null profileHash
        && m.sourceProfileSha256 && m.sourceBundleSha256     // require post-fix manifest shape
        && existsSync(CORPUS_JSON) && existsSync(NDJSON)) {
      console.log(`[materialize] CACHE HIT — artifact matches inputs; skipping rebuild`);
      console.log(`[materialize]   path: ${MAT_DIR}`);
      console.log(`[materialize]   bundleHash: ${m.bundleHash}`);
      console.log(`[materialize]   corpusRoot: ${m.corpusRoot}`);
      console.log(`[materialize]   eventCount: ${m.eventCount}`);
      console.log(`[materialize]   sizes: corpus.json=${statSync(CORPUS_JSON).size}B events.ndjson=${statSync(NDJSON).size}B`);
      exit(0);
    }
    console.log(`[materialize] cache stale (input sha or bundle changed) — checking sibling content-equivalence ...`);
  } catch (e) {
    console.log(`[materialize] cache manifest unreadable (${e.message}) — checking sibling content-equivalence ...`);
  }
}

// ─── Sibling content-equivalence: if another materialized/<x>/ dir's manifest matches the
//     CONTENT keys (sourceCorpusSha + sourceEmbSha + profileHash + corpusRoot) but its
//     bundleHash differs (e.g. canonical-code SHA change → new bundleHash, same corpus),
//     COPY its corpus.json + ndjson into MAT_DIR and write a new manifest with the new
//     bundleHash. Same materialization cost as cache hit; no 16-min rebuild. Matches the
//     "fix the design, don't reloop full rebuilds" rule.
if (existsSync(ROOT_MAT) && !FORCE) {
  const siblings = readdirSync(ROOT_MAT).sort((a, b) => {
    const aHasRootLeaves = existsSync(resolve(ROOT_MAT, a, 'corpus.json.root-leaves.ndjson')) ? 1 : 0;
    const bHasRootLeaves = existsSync(resolve(ROOT_MAT, b, 'corpus.json.root-leaves.ndjson')) ? 1 : 0;
    if (aHasRootLeaves !== bHasRootLeaves) return bHasRootLeaves - aHasRootLeaves;
    return a.localeCompare(b);
  });
  for (const sib of siblings) {
    if (sib === bundleTag) continue;
    const sibManifest = resolve(ROOT_MAT, sib, 'manifest.json');
    const sibCorpus = resolve(ROOT_MAT, sib, 'corpus.json');
    const sibNdjson = `${sibCorpus}.events.ndjson`;
    const sibRootLeaves = `${sibCorpus}.root-leaves.ndjson`;
    if (!existsSync(sibManifest) || !existsSync(sibCorpus) || !existsSync(sibNdjson)) continue;
    try {
      const sm = JSON.parse(readFileSync(sibManifest, 'utf8'));
      const sameModelPins =
        PIN_BE && PIN_RR && PIN_LAYOUT
        && sm.biEncoder?.modelId === PIN_BE.modelId
        && sm.biEncoder?.revision === PIN_BE.revision
        && JSON.stringify(sm.biEncoder?.layout) === JSON.stringify(PIN_LAYOUT)
        && sm.labelingModel?.modelId === PIN_RR.modelId
        && sm.labelingModel?.revision === PIN_RR.revision;
      const contentMatches =
        sm.sourceCorpusSha256 === sourceCorpusSha
        && sm.sourceEmbSha256 === sourceEmbSha
        && sameModelPins
        && sm.corpusRoot && sm.corpusRoot.startsWith('0x');
      if (!contentMatches) continue;
      mkdirSync(MAT_DIR, { recursive: true });
      copyFileSync(sibCorpus, CORPUS_JSON);
      copyFileSync(sibNdjson, NDJSON);
      if (existsSync(sibRootLeaves)) copyFileSync(sibRootLeaves, ROOT_LEAVES);
      const gitCommit = (() => { try { return execSync('git rev-parse HEAD', { cwd: repoRoot, stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim(); } catch { return 'unknown'; } })();
      const newManifest = {
        ...sm,
        bundleHash: bundle.bundleHash,
        profileHash: profileHashLocal,
        sourceProfileSha256: sha256File(PROFILE_PATH),
        sourceBundleSha256: sha256File(BUNDLE_PATH),
        ...(existsSync(sibRootLeaves) && sm.rootLeafCache ? {
          rootLeafCache: {
            ...sm.rootLeafCache,
            path: ROOT_LEAVES.replace(repoRoot + '/', ''),
          },
        } : {}),
        gitCommit,
        siblingCopyFrom: {
          bundleTag: sib,
          bundleHash: sm.bundleHash,
          profileHash: sm.profileHash ?? null,
          note: sm.profileHash === profileHashLocal
            ? 'content-equivalent corpus copied from sibling; corpus content + profile + embeddings unchanged'
            : 'content-equivalent corpus copied from sibling; evaluator profile changed but corpus inputs and BE/RR/layout pins are identical',
        },
      };
      writeFileSync(MANIFEST, JSON.stringify(newManifest, null, 2));
      console.log(`[materialize] SIBLING COPY — content-equivalent artifact found under materialized/${sib}/`);
      console.log(`[materialize]   sibling bundleHash: ${sm.bundleHash}`);
      console.log(`[materialize]   new bundleHash:     ${bundle.bundleHash}`);
      console.log(`[materialize]   corpusRoot:         ${sm.corpusRoot}`);
      console.log(`[materialize]   eventCount:         ${sm.eventCount}`);
      console.log(`[materialize]   path:               ${MAT_DIR}`);
      exit(0);
    } catch (e) {
      console.log(`[materialize]   sibling ${sib} manifest unreadable (${e.message}) — skipping`);
    }
  }
  console.log(`[materialize] no sibling content-equivalence found — rebuilding from canonical inputs`);
}

mkdirSync(MAT_DIR, { recursive: true });

console.log(`[materialize] building production corpus from canonical inputs ...`);
const t0 = Date.now();
const { corpus, BE, RR, LAYOUT } = buildV2ProductionCorpus({ corpusPath: CORPUS_PATH, embPath: EMB_PATH, bundlePath: BUNDLE_PATH });
const buildSec = ((Date.now() - t0) / 1000).toFixed(1);
console.log(`[materialize] built ${corpus.events.length} events in ${buildSec}s root=${corpus.corpusRoot.slice(0, 18)}…`);

// Write header JSON with EMPTY events array — readCorpusJsonHeader pulls meta from head/tail.
// Build it from the corpus directly (avoid serializeProductionCorpus which holds all events in memory).
const headerOnly = {
  schemaVersion: 'coretex.production-corpus.v1',
  corpusEpoch: corpus.corpusEpoch,
  biEncoder: { modelId: corpus.biEncoderModelId, revision: corpus.biEncoderRevision, layout: corpus.biEncoderRetrievalKeyLayout },
  labelingModel: { modelId: corpus.labelingModelId, revision: corpus.labelingModelRevision },
  events: [],
  ...(corpus.entities ? { entities: corpus.entities } : {}),
  corpusRoot: corpus.corpusRoot,
};
writeFileSync(CORPUS_JSON, JSON.stringify(headerOnly, null, 2));

// Stream NDJSON sidecar: serialize event-by-event so we never hold all on-disk events in memory.
const t1 = Date.now();
const stream = createWriteStream(NDJSON, { flags: 'w', highWaterMark: 16 * 1024 * 1024 });
const rootStream = createWriteStream(ROOT_LEAVES, { flags: 'w', highWaterMark: 16 * 1024 * 1024 });
let writes = 0;
const rootLeaves = [];
async function writeLine(line) {
  if (!stream.write(line)) await new Promise((res) => stream.once('drain', res));
}
async function writeRootLine(line) {
  if (!rootStream.write(line)) await new Promise((res) => rootStream.once('drain', res));
}
for (const e of corpus.events) {
  await writeLine(JSON.stringify(eventOnDisk(e)) + '\n');
  const hash = computeCorpusEventLeafHash(e);
  rootLeaves.push({ id: e.id, hash });
  await writeRootLine(JSON.stringify({ id: e.id, hash: Buffer.from(hash).toString('hex') }) + '\n');
  writes++;
  if (writes % 50_000 === 0) console.log(`[materialize] ndjson progress: ${writes}/${corpus.events.length}`);
}
await new Promise((res, rej) => { stream.end((err) => err ? rej(err) : res()); });
await new Promise((res, rej) => { rootStream.end((err) => err ? rej(err) : res()); });
const ndjsonSec = ((Date.now() - t1) / 1000).toFixed(1);
console.log(`[materialize] wrote ${writes} events to NDJSON in ${ndjsonSec}s`);
const rootCache = buildCorpusRootLeafCacheFromLeaves(rootLeaves);
if (rootCache.root.toLowerCase() !== corpus.corpusRoot.toLowerCase()) {
  console.error(`HARD FAIL: root leaf cache mismatch — cache=${rootCache.root} corpus=${corpus.corpusRoot}`);
  exit(1);
}

const gitCommit = (() => { try { return execSync('git rev-parse HEAD', { cwd: repoRoot, stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim(); } catch { return 'unknown'; } })();
const manifest = {
  schema: 'coretex.materialized-production-corpus.v1',
  materializedAtNote: 'stamp externally — replay path is deterministic from (sourceCorpusSha256, sourceEmbSha256, bundleHash, profileHash)',
  gitCommit,
  bundleHash: bundle.bundleHash,
  profileHash: computeProfileHashLocal(profile),
  corpusRoot: corpus.corpusRoot,
  biEncoder: { modelId: BE.modelId, revision: BE.revision, layout: LAYOUT },
  labelingModel: { modelId: RR.modelId, revision: RR.revision },
  sourceCorpusPath: CORPUS_PATH,
  sourceCorpusSha256: sourceCorpusSha,
  sourceEmbPath: EMB_PATH,
  sourceEmbSha256: sourceEmbSha,
  sourceProfileSha256: sha256File(PROFILE_PATH),
  sourceBundleSha256: sha256File(BUNDLE_PATH),
  bundlePath: BUNDLE_PATH,
  profilePath: PROFILE_PATH,
  eventCount: corpus.events.length,
  materializedCorpusJson: CORPUS_JSON.replace(repoRoot + '/', ''),
  materializedEventsNdjson: NDJSON.replace(repoRoot + '/', ''),
  rootLeafCache: {
    schema: rootCache.schema,
    path: ROOT_LEAVES.replace(repoRoot + '/', ''),
    eventCount: rootCache.eventCount,
    root: rootCache.root,
    builtFrom: 'materialization stream',
  },
};
writeFileSync(MANIFEST, JSON.stringify(manifest, null, 2));
console.log(`[materialize] manifest: ${MANIFEST}`);

// Round-trip verify: load via the CANONICAL loader (the same loadProductionCorpus the
// validator's verify/replay path uses) and re-compute corpusRoot.
console.log('[materialize] round-trip verify: loading materialized artifact (canonical loadProductionCorpus) ...');
const reloadedCorpus = C.loadProductionCorpus(CORPUS_JSON, { verifyCorpusRoot: true });
if (reloadedCorpus.corpusRoot.toLowerCase() !== corpus.corpusRoot.toLowerCase()) {
  console.error(`HARD FAIL: round-trip corpusRoot mismatch — built=${corpus.corpusRoot} reloaded=${reloadedCorpus.corpusRoot}`);
  exit(1);
}
if (reloadedCorpus.events.length !== corpus.events.length) {
  console.error(`HARD FAIL: round-trip event-count mismatch — built=${corpus.events.length} reloaded=${reloadedCorpus.events.length}`);
  exit(1);
}
console.log(`[materialize] ROUND-TRIP OK — events=${reloadedCorpus.events.length} root=${reloadedCorpus.corpusRoot.slice(0, 18)}…`);
console.log(`[materialize] DONE — artifact: ${MAT_DIR}`);
exit(0);
