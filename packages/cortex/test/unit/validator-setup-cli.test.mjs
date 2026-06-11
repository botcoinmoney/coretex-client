/**
 * coretex-validator-setup — tiny-fixture end-to-end over a local file:// base
 * (NEVER the real 700MB launch payloads): manifest fetch, SHA-256 + byte-size
 * verified downloads into the state dir, in-package corpus materialization,
 * and the validator state file that makes sync one-command.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync, statSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  launchManifestUrl,
  payloadDownloadUrl,
  parseLaunchArtifactManifest,
  LAUNCH_ARTIFACT_MANIFEST_FILENAME,
} from '../../dist/validator-setup-cli.js';

const cliPath = fileURLToPath(new URL('../../dist/validator-setup-cli.js', import.meta.url));
const BUNDLE_HASH = `0x${'12'.repeat(32)}`;

let root;          // tmp root
let origin;        // simulated artifact host (file:// base)
let originUrl;
let corpusRoot;    // computed canonical corpus root of the tiny fixture

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function runSetup(cliArgs, env = {}) {
  return spawnSync(process.execPath, [cliPath, ...cliArgs], {
    encoding: 'utf8',
    cwd: root,
    env: {
      ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('CORETEX_'))),
      ...env,
    },
  });
}

before(async () => {
  root = mkdtempSync(join(tmpdir(), 'coretex-setup-cli-'));
  origin = join(root, 'origin');
  originUrl = pathToFileURL(origin).href;
  mkdirSync(origin, { recursive: true });

  const b64 = (arr) => Buffer.from(new Float32Array(arr).buffer).toString('base64');
  const logical = {
    docs: [
      { id: 'd1', text: 'Maya moved to Lisbon in 2024.', lane: 'travel' },
      { id: 'd2', text: 'Maya adopted a cat named Pixel.', lane: 'pets' },
    ],
    queries: [
      { id: 'q1', family: 'near_collision_probe', lane: 'travel', queryText: 'Where did Maya move?',
        qrels: [{ docId: 'd1', relevance: 1.0 }], hardNegatives: [{ docId: 'd2', category: 'distractor' }] },
    ],
    relations: [],
    entities: [],
  };
  writeFileSync(join(origin, 'tiny-corpus.json'), JSON.stringify(logical));
  writeFileSync(join(origin, 'tiny-embeddings.json'), JSON.stringify({
    docs: { d1: b64([0.1, 0.5, -0.3, 0.9]), d2: b64([-0.2, 0.4, 0.8, -0.1]) },
    queries: { q1: b64([0.15, 0.45, -0.25, 0.85]) },
  }));

  const bundle = {
    bundleHash: BUNDLE_HASH,
    corpus: { root: `0x${'00'.repeat(32)}` },
    model: {
      biEncoder: { modelId: 'BAAI/bge-m3', revision: 'test-be-rev', retrievalKeyLayout: { dim: 243, quantization: 'int8', headerBytes: 9 } },
      reranker: { modelId: 'Qwen/Qwen3-Reranker-0.6B', revision: 'test-rr-rev' },
    },
  };
  writeFileSync(join(origin, 'tiny-bundle.json'), JSON.stringify(bundle));
  writeFileSync(join(origin, 'tiny-profile.json'), JSON.stringify({ name: 'tiny-test-profile' }));

  // Compute the REAL corpus root via the canonical in-package mapping (the
  // same one the spawned materializer runs) and pin it into bundle + manifest.
  const { buildV2ProductionCorpus } = await import('../../scripts/lib/build-v2-production-corpus.mjs');
  const { corpus } = buildV2ProductionCorpus({
    corpusPath: join(origin, 'tiny-corpus.json'),
    embPath: join(origin, 'tiny-embeddings.json'),
    bundlePath: join(origin, 'tiny-bundle.json'),
  });
  corpusRoot = corpus.corpusRoot;
  bundle.corpus.root = corpusRoot;
  writeFileSync(join(origin, 'tiny-bundle.json'), JSON.stringify(bundle));

  const manifest = {
    schema: 'coretex.launch-artifacts.v1',
    name: 'tiny-launch-fixture',
    corpusRoot,
    payloads: [
      { role: 'corpus', path: 'release/x/tiny-corpus.json', fileName: 'tiny-corpus.json', sha256: sha256(join(origin, 'tiny-corpus.json')), bytes: statSync(join(origin, 'tiny-corpus.json')).size },
      { role: 'embeddings', path: 'release/x/tiny-embeddings.json', fileName: 'tiny-embeddings.json', sha256: sha256(join(origin, 'tiny-embeddings.json')), bytes: statSync(join(origin, 'tiny-embeddings.json')).size },
    ],
    materializedRoot: 'release/x/materialized',
    bundlePath: 'release/x/tiny-bundle.json',
    bundleHash: BUNDLE_HASH,
    bundleSha256: sha256(join(origin, 'tiny-bundle.json')),
    profilePath: 'release/x/tiny-profile.json',
    profileSha256: sha256(join(origin, 'tiny-profile.json')),
  };
  writeFileSync(join(origin, LAUNCH_ARTIFACT_MANIFEST_FILENAME), JSON.stringify(manifest));
});

after(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('launch manifest helpers', () => {
  test('launchManifestUrl appends the canonical manifest filename', () => {
    assert.equal(
      launchManifestUrl('https://example.test/coretex/launch/v16/'),
      `https://example.test/coretex/launch/v16/${LAUNCH_ARTIFACT_MANIFEST_FILENAME}`,
    );
  });

  test('payloadDownloadUrl prefers fileName over path basename', () => {
    assert.equal(payloadDownloadUrl('https://x.test/v16', { path: 'a/b/c.json', fileName: 'n.json' }), 'https://x.test/v16/n.json');
    assert.equal(payloadDownloadUrl('https://x.test/v16/', { path: 'a/b/c.json' }), 'https://x.test/v16/c.json');
  });

  test('parseLaunchArtifactManifest rejects wrong schemas and missing fields', () => {
    assert.throws(() => parseLaunchArtifactManifest({ schema: 'other.v1' }), /unsupported artifact manifest schema/);
    assert.throws(
      () => parseLaunchArtifactManifest({ schema: 'coretex.launch-artifacts.v1', payloads: [{ role: 'corpus', path: 'x', sha256: 'y' }] }),
      /missing corpusRoot/,
    );
  });
});

describe('coretex-validator-setup — tiny fixture over file:// (spawned)', () => {
  test('fresh setup downloads, verifies, materializes, and writes the one-command state file', { timeout: 120_000 }, () => {
    const stateDir = join(root, 'state');
    // --no-venv-bootstrap: a real multi-GB torch install is NOT a unit test
    // (the bootstrap LOGIC is covered in validator-runtime.test.mjs with a fake
    // spawner). This case proves artifact hydration + the state file.
    const proc = runSetup([
      '--artifact-base-url', originUrl,
      '--state-dir', stateDir,
      '--registry-deploy-block', '4242',
      '--no-venv-bootstrap',
    ]);
    assert.equal(proc.status, 0, `stdout: ${proc.stdout}\nstderr: ${proc.stderr}`);
    assert.match(proc.stdout, /READY corpusRoot=0x/);

    // Downloaded payloads verified byte-for-byte.
    for (const name of ['tiny-corpus.json', 'tiny-embeddings.json', 'tiny-bundle.json', 'tiny-profile.json']) {
      assert.equal(sha256(join(stateDir, 'artifacts', name)), sha256(join(origin, name)), `${name} drifted`);
    }

    // Materialized artifact carries the manifest corpusRoot.
    const tag = BUNDLE_HASH.slice(2, 10);
    const mat = JSON.parse(readFileSync(join(stateDir, 'materialized', tag, 'manifest.json'), 'utf8'));
    assert.equal(mat.corpusRoot.toLowerCase(), corpusRoot.toLowerCase());
    assert.ok(existsSync(join(stateDir, 'materialized', tag, 'corpus.json.events.ndjson')));

    // State file: sync needs no manual flags after this.
    const state = JSON.parse(readFileSync(join(stateDir, 'validator-sync-state.json'), 'utf8'));
    assert.equal(state.corpusRoot.toLowerCase(), corpusRoot.toLowerCase());
    assert.equal(state.bundleHash, BUNDLE_HASH);
    assert.equal(state.registryDeployBlock, 4242);
    assert.equal(state.setup.bundleManifestPath, join(stateDir, 'artifacts', 'tiny-bundle.json'));
    assert.equal(state.setup.corpusPath, join(stateDir, 'materialized', tag, 'corpus.json'));
    assert.equal(state.setup.artifactBaseUrl, originUrl);
    // The launch corpus is also retained DISTINCTLY as the durable replay ANCESTOR
    // (path + root) so historical corpus auto-resolution can walk forward from a
    // guaranteed ancestor even when sync's loaded corpus is overridden ahead of it.
    assert.equal(state.setup.baseCorpusPath, join(stateDir, 'materialized', tag, 'corpus.json'));
    assert.equal(state.setup.baseCorpusRoot.toLowerCase(), corpusRoot.toLowerCase());
  });

  test('--verify-only passes on a hydrated state dir and never downloads', { timeout: 60_000 }, () => {
    const proc = runSetup(['--artifact-base-url', originUrl, '--state-dir', join(root, 'state'), '--verify-only']);
    assert.equal(proc.status, 0, `stderr: ${proc.stderr}`);
    assert.doesNotMatch(proc.stdout, /FETCH/);
  });

  test('a corrupted payload with --no-download is a hard verification failure', { timeout: 60_000 }, () => {
    const stateDir = join(root, 'state-corrupt');
    mkdirSync(join(stateDir, 'artifacts'), { recursive: true });
    writeFileSync(join(stateDir, 'artifacts', 'tiny-corpus.json'), '{"tampered":true}');
    const proc = runSetup(['--artifact-base-url', originUrl, '--state-dir', stateDir, '--no-download']);
    assert.notEqual(proc.status, 0);
    assert.match(proc.stderr, /download disabled/);
  });

  test('--help exits 0 with usage', () => {
    const proc = runSetup(['--help']);
    assert.equal(proc.status, 0);
    assert.match(proc.stdout, /coretex-validator-setup/);
    assert.match(proc.stdout, /--artifact-base-url/);
  });

  test('--no-venv-bootstrap skips the venv (no torch install); summary on stderr, stdout clean', { timeout: 120_000 }, () => {
    const stateDir = join(root, 'state-novenv');
    const proc = runSetup([
      '--artifact-base-url', originUrl,
      '--state-dir', stateDir,
      '--no-venv-bootstrap',
      '--no-progress',
    ], { CI: '1' });
    assert.equal(proc.status, 0, `stdout: ${proc.stdout}\nstderr: ${proc.stderr}`);
    // No scorer venv was built, and no scorerPython recorded under opt-out.
    assert.ok(!existsSync(join(stateDir, 'scorer-venv')), 'opt-out must not create scorer-venv');
    const state = JSON.parse(readFileSync(join(stateDir, 'validator-sync-state.json'), 'utf8'));
    assert.equal(state.setup.scorerPython, undefined, 'opt-out records no scorerPython');
    // The PASS summary block is stderr-only — stdout carries [setup] log lines + READY.
    assert.match(proc.stderr, /coretex-validator-setup: PASS/);
    assert.doesNotMatch(proc.stdout, /coretex-validator-setup: PASS/);
    assert.match(proc.stdout, /READY corpusRoot=0x/);
  });
});
