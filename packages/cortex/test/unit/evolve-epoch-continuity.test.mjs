/**
 * Chained multi-epoch evolve continuity — drives the PRODUCTION script flow
 * (scripts/coretex-epoch-evolve.mjs as a child process), not hand-threaded library calls:
 *
 *   launch genesis -> epoch 1 -> epoch 2 -> epoch 3,
 *   each epoch consuming the previous epoch's outputs through the stable
 *   --logical-state / --frontier-state paths + the epoch checkpoint.
 *
 * Asserts (audit defects 1-5):
 *   - delta.previousRoot equals the previous epoch's MATERIALIZED corpus root every epoch;
 *   - epoch >= 2 HARD-FAILS when the previous checkpoint is missing / tampered / pointing
 *     at the genesis corpus; --launch-genesis is rejected for epoch != 1; missing
 *     --logical-state without --launch-genesis is rejected;
 *   - retraction tombstones + removedIds are emitted and applyCorpusDelta removes them;
 *   - the fresh eval_hidden quota is met every epoch and hard-fails when unmeetable;
 *   - maxRootDeltaPerEpoch is enforced (hard-fail, not silent emit);
 *   - state writes are atomic (no *.tmp-* residue; failed runs leave stable state untouched).
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  applyCorpusDelta,
  computeCorpusRoot,
  parseCorpusDelta,
  serializeProductionCorpus,
  splitForRecord,
} from '../../dist/index.js';

const repoRoot = resolve(fileURLToPath(new URL('.', import.meta.url)), '../../../..');
const SCRIPT = resolve(repoRoot, 'scripts/coretex-epoch-evolve.mjs');
const MANIFEST = 'release/calibration/2026-06-04-memory-atom-v16/coretex-launch-v16-artifacts.json';
const manifest = JSON.parse(readFileSync(resolve(repoRoot, MANIFEST), 'utf8'));
const bundle = JSON.parse(readFileSync(resolve(repoRoot, manifest.bundlePath), 'utf8'));
const launchProfile = JSON.parse(readFileSync(resolve(repoRoot, manifest.profilePath), 'utf8'));
const BE = bundle.model.biEncoder;
const RR = bundle.model.reranker;
const LAYOUT = {
  dim: BE.retrievalKeyLayout.dim,
  quantization: BE.retrievalKeyLayout.quantization,
  headerBytes: BE.retrievalKeyLayout.headerBytes,
};

const outRoot = resolve(repoRoot, `.local-wip/evolve-epoch-continuity-${process.pid}`);
const stableDir = join(outRoot, 'state');
const stableLogical = join(stableDir, 'logical-state.json');
const stableCheckpoint = join(stableDir, 'logical-state.checkpoint.json');
const stableFrontier = join(stableDir, 'frontier-state.json');
const profilePath = join(outRoot, 'profile-tiny-frontier.json');
const privateKeyPath = join(outRoot, 'epoch-private.pem');
const publicKeyPath = join(outRoot, 'epoch-public.pem');

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}
function mockEmbBytes(text) {
  const out = new Uint8Array(4 + LAYOUT.dim);
  new DataView(out.buffer).setFloat32(0, 1 / 127, false);
  let cursor = Buffer.alloc(0);
  for (let i = 0; i < LAYOUT.dim; i++) {
    if (i % 32 === 0) cursor = createHash('sha256').update(`${text}:${i / 32}`).digest();
    out[4 + i] = (cursor[i % 32] - 128) & 0xff;
  }
  return out;
}
function mkEmb(queryBytes, truthEntries, negativeEntries = []) {
  return {
    modelId: BE.modelId,
    revision: BE.revision,
    layout: LAYOUT,
    query: queryBytes,
    perTruth: new Map(truthEntries),
    perNegative: new Map(negativeEntries),
  };
}
// Evolved corpora carry live-query metadata (logicalFamily/band) that
// computeCorpusRoot hashes into the leaf; serializeProductionCorpus preserves
// those fields, so the canonical serializer round-trips evolved corpora
// root-stable (regression-tested in corpus-serializer-roundtrip.test.mjs).
function serializeCorpusPreservingMetadata(c) {
  return serializeProductionCorpus(c);
}
function findTmpResidue(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...findTmpResidue(p));
    else if (/\.tmp-\d+/.test(name)) out.push(p);
  }
  return out;
}
function runEvolve(args, { expectExit = 0 } = {}) {
  const r = spawnSync(process.execPath, [SCRIPT, ...args], { cwd: repoRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  assert.equal(r.status, expectExit, `expected exit ${expectExit}, got ${r.status}\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
  return r;
}

// ── tiny genesis fixture (6 subjects, 6 fact docs, 6 genesis eval_hidden queries) ──
const subjects = Array.from({ length: 6 }, (_, i) => ({
  id: `person_s${i}`,
  canonicalName: i % 2 === 0 ? `Avery Stone ${i}` : `chain-svc-${i}-pipeline-svc-${i}`,
  aliases: [i % 2 === 0 ? `Avery${i}` : `chain${i}`],
}));
const genesisLogical = {
  specVersion: 'coretex.logical-corpus.v1',
  phase: 'evolve-epoch-continuity-test',
  dgen1: { atomV16Metadata: true },
  entities: [{ id: 'e_universe', canonicalName: 'Universe' }, ...subjects],
  docs: subjects.map((s, i) => ({
    id: `d_base_${i}`, lane: 'deep', kind: 'temporal_city', entityIds: ['e_universe', s.id],
    text: `${s.canonicalName}'s supersession ledger sets city Oslo ${i}.`, currentStaleFlag: true,
  })),
  relations: [],
  queries: [],
};
const genesisEvalIds = [];
for (let i = 0; genesisEvalIds.length < 6 && i < 10_000; i++) {
  const id = `q_base_eval_${i}`;
  if (splitForRecord(id, 0) === 'eval_hidden') genesisEvalIds.push(id);
}
assert.equal(genesisEvalIds.length, 6, 'fixture must find 6 genesis eval_hidden ids');
// keep the genesis logical queries in the logical state so hidden-row aging sees them
genesisLogical.queries = genesisEvalIds.map((id, i) => ({
  id, lane: 'deep', family: 'temporal_update',
  queryText: `What is ${subjects[i % subjects.length].canonicalName}'s current city?`,
  qrels: [{ docId: `d_base_${i % subjects.length}`, relevance: 1.0, role: 'direct' }],
  subjectEntityId: subjects[i % subjects.length].id, ownerEntityId: 'e_universe', ownerScoped: true,
}));

function buildGenesisCorpus() {
  const events = [];
  const docEmb = new Map(genesisLogical.docs.map((d) => [d.id, mockEmbBytes(d.text)]));
  for (const d of genesisLogical.docs) {
    const emb = docEmb.get(d.id);
    events.push({
      id: `mem_${d.id}`, family: 'near_collision', domain: d.lane, split: 'train_visible',
      queryText: d.text, truthDocuments: [{ id: d.id, text: d.text, isCurrent: true }],
      hardNegatives: [], qrels: [{ documentId: d.id, relevance: 1.0 }], protected: false, relations: [],
      entityIds: d.entityIds, provenance: { source: 'e2e', sourceHash: '0x' + '00'.repeat(32) },
      embeddings: mkEmb(emb, [[d.id, emb]]),
    });
  }
  for (const q of genesisLogical.queries) {
    const truthId = q.qrels[0].docId;
    const tEmb = docEmb.get(truthId);
    events.push({
      id: q.id, family: 'temporal', domain: 'deep', split: 'eval_hidden',
      queryText: q.queryText, truthDocuments: [{ id: truthId, text: genesisLogical.docs.find((d) => d.id === truthId).text, isCurrent: true }],
      hardNegatives: [], qrels: [{ documentId: truthId, relevance: 1.0 }], protected: false, relations: [],
      provenance: { source: 'e2e', sourceHash: '0x' + '00'.repeat(32) },
      embeddings: mkEmb(mockEmbBytes(q.queryText), [[truthId, tEmb]]),
    });
  }
  return {
    events,
    byId: new Map(events.map((e) => [e.id, e])),
    corpusRoot: computeCorpusRoot(events),
    corpusEpoch: 0,
    biEncoderModelId: BE.modelId,
    biEncoderRevision: BE.revision,
    biEncoderRetrievalKeyLayout: LAYOUT,
    labelingModelId: RR.modelId,
    labelingModelRevision: RR.revision,
  };
}

let corpus;
const corpusPathFor = (epoch) => join(outRoot, `corpus-epoch-${epoch}.json`);
const outDirFor = (epoch) => join(outRoot, `epoch-${epoch}`);

const COMMON = [
  '--manifest', MANIFEST,
  '--profile', profilePath,
  '--private-key', privateKeyPath,
  '--public-key', publicKeyPath,
  '--key-id', 'evolve-continuity-test',
  '--parent-state-root', '0x' + '11'.repeat(32),
  '--mock-embeddings',
  '--seed', 'evolve-continuity-seed',
  '--churn', '1.0',
  '--retraction-fraction', '0.4',
  '--min-fresh-eval-hidden', '3',
  '--hidden-retire-horizon', '2',
  '--generated-at', '2026-06-09T00:00:00.000Z',
];
function epochArgs(epoch, { previousCorpusEpoch = epoch - 1, outDir = outDirFor(epoch), extra = [] } = {}) {
  // `extra` first: the script's flag() reader takes the FIRST occurrence, so test-case
  // overrides must precede the COMMON defaults.
  return [
    ...extra,
    ...COMMON,
    '--epoch', String(epoch),
    '--source-corpus', stableLogical,
    '--logical-state', stableLogical,
    '--frontier-state', stableFrontier,
    '--previous-corpus', corpusPathFor(previousCorpusEpoch),
    '--out-dir', outDir,
  ];
}
function readEpochOutputs(epoch) {
  const outDir = outDirFor(epoch);
  const out = JSON.parse(readFileSync(join(outDir, `epoch-evolve-output-${epoch}.json`), 'utf8'));
  const deltaFile = JSON.parse(readFileSync(join(outDir, `corpus-delta-epoch-${epoch}.json`), 'utf8'));
  const logicalDelta = JSON.parse(readFileSync(join(outDir, `logical-delta-epoch-${epoch}.json`), 'utf8'));
  const checkpoint = JSON.parse(readFileSync(join(outDir, `epoch-checkpoint-${epoch}.json`), 'utf8'));
  return { out, deltaFile, logicalDelta, checkpoint };
}
function applyAndMaterialize(epoch, deltaFile) {
  const delta = parseCorpusDelta(deltaFile);
  corpus = applyCorpusDelta(corpus, delta);
  writeFileSync(corpusPathFor(epoch), JSON.stringify(serializeCorpusPreservingMetadata(corpus), null, 2) + '\n');
  return delta;
}

describe('evolve multi-epoch continuity (production script flow, chained 3 epochs)', () => {
  before(() => {
    rmSync(outRoot, { recursive: true, force: true });
    mkdirSync(stableDir, { recursive: true });
    // tiny-frontier profile: same launch profile, but a 2-wide active window so hidden-pool
    // rotation/retirement is exercised at trivial scale.
    writeFileSync(profilePath, JSON.stringify({
      ...launchProfile,
      epochFrontier: { ...launchProfile.epochFrontier, activeWindow: 2 },
    }, null, 2) + '\n');
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    writeFileSync(privateKeyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }).toString());
    writeFileSync(publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }).toString());
    writeFileSync(stableLogical, JSON.stringify(genesisLogical, null, 2) + '\n');
    corpus = buildGenesisCorpus();
    writeFileSync(corpusPathFor(0), JSON.stringify(serializeCorpusPreservingMetadata(corpus), null, 2) + '\n');
  });
  after(() => {
    rmSync(outRoot, { recursive: true, force: true });
  });

  test('genesis bootstrap guards: --launch-genesis epoch-1-only, no silent genesis default', () => {
    // --launch-genesis is rejected for epoch != 1
    const r1 = runEvolve(epochArgs(2, { extra: ['--launch-genesis'] }), { expectExit: 1 });
    assert.match(r1.stderr, /--launch-genesis is only valid for --epoch 1/);
    // missing --logical-state without --launch-genesis is rejected (the silent-genesis defect)
    const r2 = runEvolve([
      ...COMMON, '--epoch', '1',
      '--source-corpus', stableLogical,
      '--previous-corpus', corpusPathFor(0),
      '--out-dir', join(outRoot, 'epoch-1-noflag'),
    ], { expectExit: 1 });
    assert.match(r2.stderr, /--logical-state is required/);
  });

  test('epoch 1: genesis -> R1, checkpoint + stable state threaded atomically', () => {
    const genesisRoot = corpus.corpusRoot;
    const genesisLogicalSha = sha256(stableLogical);
    runEvolve(epochArgs(1));
    const { out, deltaFile, checkpoint } = readEpochOutputs(1);
    assert.equal(out.previousCorpusRoot.toLowerCase(), genesisRoot.toLowerCase(), 'epoch 1 evolves FROM genesis');
    assert.equal(deltaFile.previousRoot.toLowerCase(), genesisRoot.toLowerCase());
    const delta = applyAndMaterialize(1, deltaFile);
    assert.equal(corpus.corpusRoot.toLowerCase(), out.nextCorpusRoot.toLowerCase(), 'replayed apply reproduces the announced R1');
    assert.notEqual(delta.nextRoot.toLowerCase(), genesisRoot.toLowerCase(), 'root advanced');
    // hidden quota met
    assert.ok(out.evolve.freshEvalHidden >= 3, `fresh eval_hidden ${out.evolve.freshEvalHidden} >= quota 3`);
    // stable state threaded back (not just the out-dir artifact) + checkpoint sibling
    assert.notEqual(sha256(stableLogical), genesisLogicalSha, 'stable logical-state path updated in place');
    assert.ok(existsSync(stableFrontier), 'stable frontier-state path written');
    assert.ok(existsSync(stableCheckpoint), 'checkpoint written next to the stable logical state');
    assert.equal(checkpoint.epoch, 1);
    assert.equal(checkpoint.corpusRoot.toLowerCase(), out.nextCorpusRoot.toLowerCase());
    assert.equal(checkpoint.logicalStateSha256, sha256(stableLogical));
    assert.equal(checkpoint.frontierStateSha256, sha256(stableFrontier));
    assert.deepEqual(JSON.parse(readFileSync(stableCheckpoint, 'utf8')), checkpoint);
    assert.deepEqual(findTmpResidue(outRoot), [], 'no tmp residue after atomic writes');
  });

  test('epoch 2 HARD-FAILS without epoch 1 checkpoint, on tamper, and on genesis previous-corpus', () => {
    const logicalShaBefore = sha256(stableLogical);
    const frontierShaBefore = sha256(stableFrontier);

    // (a) checkpoint missing
    renameSync(stableCheckpoint, `${stableCheckpoint}.bak`);
    const rMissing = runEvolve(epochArgs(2), { expectExit: 1 });
    assert.match(rMissing.stderr, /checkpoint not found/);
    renameSync(`${stableCheckpoint}.bak`, stableCheckpoint);

    // (b) tampered logical state vs checkpoint hash
    const original = readFileSync(stableLogical, 'utf8');
    writeFileSync(stableLogical, original + '\n');
    const rTamper = runEvolve(epochArgs(2), { expectExit: 1 });
    assert.match(rTamper.stderr, /does not match checkpoint\.logicalStateSha256/);
    writeFileSync(stableLogical, original);

    // (c) previous corpus is the GENESIS corpus, not epoch 1's materialized corpus
    const rGenesis = runEvolve(epochArgs(2, { previousCorpusEpoch: 0 }), { expectExit: 1 });
    assert.match(rGenesis.stderr, /checkpoint corpus root|previous corpus root/);

    // (d) missing frontier state path for epoch >= 2
    const rNoFrontier = runEvolve([
      ...COMMON, '--epoch', '2',
      '--source-corpus', stableLogical,
      '--logical-state', stableLogical,
      '--previous-corpus', corpusPathFor(1),
      '--out-dir', join(outRoot, 'epoch-2-nofrontier'),
    ], { expectExit: 1 });
    assert.match(rNoFrontier.stderr, /--frontier-state is required for epoch >= 2/);

    // failed runs must leave the stable state byte-identical (atomicity / fail-closed)
    assert.equal(sha256(stableLogical), logicalShaBefore, 'failed runs do not mutate stable logical state');
    assert.equal(sha256(stableFrontier), frontierShaBefore, 'failed runs do not mutate stable frontier state');
    assert.deepEqual(findTmpResidue(outRoot), [], 'no partial tmp files after failed runs');
  });

  test('epoch 2: consumes epoch 1 outputs; retractions + hidden retirement flow into removedIds', () => {
    const r1Root = corpus.corpusRoot;
    runEvolve(epochArgs(2));
    const { out, deltaFile, logicalDelta } = readEpochOutputs(2);
    assert.equal(deltaFile.previousRoot.toLowerCase(), r1Root.toLowerCase(), 'epoch 2 delta chains off the epoch 1 MATERIALIZED root');
    assert.ok(out.evolve.freshEvalHidden >= 3, 'hidden quota met at epoch 2');
    // hidden retirement: genesis hidden rows (mint epoch 0) are past the horizon (2) and only
    // the 2 frontier-active ids are protected, so retirement MUST fire.
    assert.ok(out.evolve.retiredHiddenQueries >= 1, `expected hidden retirement, got ${out.evolve.retiredHiddenQueries}`);
    assert.ok(deltaFile.removedIds.length >= out.evolve.retiredHiddenQueries, 'retired hidden rows are in removedIds');
    for (const retired of logicalDelta.retiredQueryIds) {
      assert.ok(genesisEvalIds.includes(retired) || /^q_e\d+_/.test(retired), `retired id ${retired} is a known hidden row`);
    }
    const removedSet = new Set(deltaFile.removedIds);
    const delta = applyAndMaterialize(2, deltaFile);
    assert.equal(corpus.corpusRoot.toLowerCase(), out.nextCorpusRoot.toLowerCase());
    for (const id of removedSet) {
      assert.ok(!corpus.byId.has(id), `removed id ${id} must not survive applyCorpusDelta`);
    }
    assert.ok(delta.removedIds.length === deltaFile.removedIds.length);
  });

  test('epoch 3: full chain; retraction tombstones present cumulatively; cap + quota hard-fail variants', () => {
    const r2Root = corpus.corpusRoot;

    // cap enforcement: a zero root-delta budget must hard-fail rather than emit
    const rCap = runEvolve(epochArgs(3, {
      outDir: join(outRoot, 'epoch-3-capfail'),
      extra: ['--max-root-delta-per-epoch', '0', '--min-fresh-eval-hidden', '0', '--prev-quality-attempts', '3', '--prev-honest-accepts', '0'],
    }), { expectExit: 1 });
    assert.match(rCap.stderr, /exceeds maxRootDeltaPerEpoch/);

    // quota enforcement: an unmeetable hidden quota must hard-fail
    const rQuota = runEvolve(epochArgs(3, {
      outDir: join(outRoot, 'epoch-3-quotafail'),
      extra: ['--min-fresh-eval-hidden', '9999'],
    }), { expectExit: 1 });
    assert.match(rQuota.stderr, /fresh eval_hidden queries < pinned quota/);

    // failed variants must not have advanced the stable state — the real epoch 3 still runs
    runEvolve(epochArgs(3));
    const { out, deltaFile } = readEpochOutputs(3);
    assert.equal(deltaFile.previousRoot.toLowerCase(), r2Root.toLowerCase(), 'epoch 3 delta chains off the epoch 2 MATERIALIZED root');
    applyAndMaterialize(3, deltaFile);
    assert.equal(corpus.corpusRoot.toLowerCase(), out.nextCorpusRoot.toLowerCase());

    // retraction tombstones: cumulative across the chain, tombstones + removedIds present
    let tombstones = 0;
    let retractedRemoved = 0;
    for (const epoch of [1, 2, 3]) {
      const { logicalDelta, out: epochOut } = readEpochOutputs(epoch);
      tombstones += logicalDelta.addedDocs.filter((d) => d.kind === 'retraction_record').length;
      retractedRemoved += epochOut.evolve.retractedDocs;
      assert.equal(
        logicalDelta.addedDocs.filter((d) => d.kind === 'retraction_record').length,
        logicalDelta.retractedDocIds.length,
        'one tombstone per retracted fact',
      );
    }
    assert.ok(tombstones >= 1, 'chain must emit retraction tombstones');
    assert.ok(retractedRemoved >= 1, 'chain must emit retraction removals');

    // every epoch's checkpoint chains corpus roots: checkpoint(N).previousCorpusRoot == checkpoint(N-1).corpusRoot
    const cp1 = readEpochOutputs(1).checkpoint;
    const cp2 = readEpochOutputs(2).checkpoint;
    const cp3 = readEpochOutputs(3).checkpoint;
    assert.equal(cp2.previousCorpusRoot.toLowerCase(), cp1.corpusRoot.toLowerCase());
    assert.equal(cp3.previousCorpusRoot.toLowerCase(), cp2.corpusRoot.toLowerCase());

    assert.deepEqual(findTmpResidue(outRoot), [], 'no tmp residue across the whole chain');
  });
});
