/**
 * One-command sync defaults: from-block resolution, parent-substrate
 * bootstrap (launch/blank substrate vs previous-sync snapshot), blank
 * substrate synthesis, and client state-file round-trips.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  blankSubstrateState,
  blankSubstrateStateRoot,
  defaultEpochSigningPublicKeyUri,
  EPOCH_SIGNING_PUBLIC_KEY_ARTIFACT_PATH,
  readClientStateFile,
  resolveReplayFromBlock,
  resolveReplayParentBootstrap,
  clientRerankerPinsFromManifest,
} from '../../dist/client-sync-cli.js';
import { mergeClientStateFile } from '../../dist/client-setup-cli.js';
import { bytesToHex, merkleizeState, pack, unpack, PACKED_SIZE } from '../../dist/index.js';

const BLANK_ROOT = blankSubstrateStateRoot();
const OTHER_ROOT = `0x${'ab'.repeat(32)}`;

describe('blank/launch substrate synthesis', () => {
  test('blankSubstrateState is the canonical unpack of an all-zero packed state', () => {
    const blank = blankSubstrateState();
    assert.deepEqual(pack(blank), pack(unpack(new Uint8Array(PACKED_SIZE))));
    assert.equal(bytesToHex(merkleizeState(blank)), BLANK_ROOT);
    assert.match(BLANK_ROOT, /^0x[0-9a-f]{64}$/);
  });
});

describe('resolveReplayFromBlock precedence', () => {
  test('flag > env > snapshot cursor > state deploy block > env deploy block', () => {
    const full = {
      flag: '100',
      envReplayFromBlock: '200',
      envRegistryDeployBlock: '300',
      snapshotCursorBlock: 400,
      stateRegistryDeployBlock: 500,
    };
    assert.deepEqual(resolveReplayFromBlock(full), { fromBlock: 100n, source: 'flag' });
    assert.deepEqual(resolveReplayFromBlock({ ...full, flag: undefined }), { fromBlock: 200n, source: 'env' });
    assert.deepEqual(
      resolveReplayFromBlock({ ...full, flag: undefined, envReplayFromBlock: undefined }),
      { fromBlock: 401n, source: 'snapshot-cursor' },
    );
    assert.deepEqual(
      resolveReplayFromBlock({ ...full, flag: undefined, envReplayFromBlock: undefined, snapshotCursorBlock: undefined }),
      { fromBlock: 500n, source: 'state-deploy-block' },
    );
    assert.deepEqual(
      resolveReplayFromBlock({ envRegistryDeployBlock: '300' }),
      { fromBlock: 300n, source: 'env-deploy-block' },
    );
  });

  test('no from-block source is a hard error pointing at setup (replay is mandatory)', () => {
    assert.throws(() => resolveReplayFromBlock({}), /coretex-client-setup/);
  });
});

describe('resolveReplayParentBootstrap', () => {
  test('explicit --parent-state always wins', () => {
    assert.deepEqual(
      resolveReplayParentBootstrap({
        explicitParentStatePath: '/x/state.bin',
        snapshotAvailable: true,
        chainParentStateRoot: OTHER_ROOT,
        blankRoot: BLANK_ROOT,
        fromBlockSource: 'flag',
      }),
      { source: 'explicit-file' },
    );
  });

  test('previous-sync snapshot is used when available', () => {
    assert.deepEqual(
      resolveReplayParentBootstrap({
        snapshotAvailable: true,
        chainParentStateRoot: OTHER_ROOT,
        blankRoot: BLANK_ROOT,
        fromBlockSource: 'snapshot-cursor',
      }),
      { source: 'snapshot' },
    );
  });

  test('blank substrate bootstrap when the chain parent root equals the launch/blank root', () => {
    assert.deepEqual(
      resolveReplayParentBootstrap({
        snapshotAvailable: false,
        chainParentStateRoot: BLANK_ROOT.toUpperCase().replace('0X', '0x'),
        blankRoot: BLANK_ROOT,
        fromBlockSource: 'flag',
      }),
      { source: 'blank-substrate' },
    );
  });

  test('blank substrate bootstrap when replaying the full history from the registry deploy block', () => {
    for (const fromBlockSource of ['state-deploy-block', 'env-deploy-block']) {
      assert.deepEqual(
        resolveReplayParentBootstrap({
          snapshotAvailable: false,
          chainParentStateRoot: OTHER_ROOT,
          blankRoot: BLANK_ROOT,
          fromBlockSource,
        }),
        { source: 'blank-substrate' },
      );
    }
  });

  test('non-launch chain parent without snapshot/deploy-block replay is a hard error', () => {
    assert.throws(
      () => resolveReplayParentBootstrap({
        snapshotAvailable: false,
        chainParentStateRoot: OTHER_ROOT,
        blankRoot: BLANK_ROOT,
        fromBlockSource: 'flag',
      }),
      /cannot bootstrap replay parent substrate/,
    );
  });
});

describe('client state file round-trip (setup ↔ sync)', () => {
  function withTmpDir(fn) {
    const dir = mkdtempSync(join(tmpdir(), 'coretex-state-file-'));
    try {
      return fn(dir);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  test('mergeClientStateFile preserves setup-owned fields across sync updates', () => withTmpDir((dir) => {
    const statePath = join(dir, 'client-sync-state.json');
    mergeClientStateFile(statePath, {
      corpusRoot: OTHER_ROOT,
      registryDeployBlock: 123,
      setup: { bundleManifestPath: '/x/bundle.json', corpusPath: '/x/corpus.json', artifactBaseUrl: 'https://example.test/v16' },
    });
    // A later sync writes its own fields — setup fields must survive.
    mergeClientStateFile(statePath, {
      epoch: 7,
      corpusRoot: `0x${'cd'.repeat(32)}`,
      replay: { stateRoot: `0x${'ef'.repeat(32)}`, cursorBlock: 999, epochTransitions: { 7: 2 } },
    });
    const state = readClientStateFile(statePath);
    assert.equal(state.schema, 'coretex.client-sync-state.v1');
    assert.equal(state.epoch, 7);
    assert.equal(state.corpusRoot, `0x${'cd'.repeat(32)}`);
    assert.equal(state.registryDeployBlock, 123);
    assert.equal(state.setup.bundleManifestPath, '/x/bundle.json');
    assert.equal(state.setup.artifactBaseUrl, 'https://example.test/v16');
    assert.equal(state.replay.cursorBlock, 999);
    assert.equal(JSON.parse(readFileSync(statePath, 'utf8')).replay.epochTransitions[7], 2);
  }));

  test('readClientStateFile: null for missing, HARD ERROR for corrupt (never silent re-init)', () => withTmpDir((dir) => {
    assert.equal(readClientStateFile(join(dir, 'missing.json')), null);
    const corrupt = join(dir, 'corrupt.json');
    writeFileSync(corrupt, '{not json');
    assert.throws(() => readClientStateFile(corrupt), /corrupt client state file/);
  }));

  test('mergeClientStateFile hard-fails on a corrupt existing state file', () => withTmpDir((dir) => {
    const statePath = join(dir, 'state.json');
    writeFileSync(statePath, '{not json');
    assert.throws(() => mergeClientStateFile(statePath, { setup: {} }), /corrupt client state file/);
    // The corrupt file must be left untouched for operator recovery.
    assert.equal(readFileSync(statePath, 'utf8'), '{not json');
  }));

  test('mergeClientStateFile writes atomically (no .tmp leftovers, valid JSON)', () => withTmpDir((dir) => {
    const statePath = join(dir, 'state.json');
    mergeClientStateFile(statePath, { setup: { artifactBaseUrl: 'https://example.test/v16' } });
    const state = readClientStateFile(statePath);
    assert.equal(state.setup.artifactBaseUrl, 'https://example.test/v16');
    assert.deepEqual(readdirSync(dir).filter((f) => f.includes('.tmp-')), []);
  }));
});

describe('epoch signing public key default', () => {
  test('defaults to <artifact-base>/epoch-rotations/epoch-signing-public.pem', () => {
    assert.equal(
      defaultEpochSigningPublicKeyUri('https://example.test/v16/'),
      `https://example.test/v16/${EPOCH_SIGNING_PUBLIC_KEY_ARTIFACT_PATH}`,
    );
    assert.equal(EPOCH_SIGNING_PUBLIC_KEY_ARTIFACT_PATH, 'epoch-rotations/epoch-signing-public.pem');
    assert.equal(defaultEpochSigningPublicKeyUri(undefined), undefined);
  });
});

describe('clientRerankerPinsFromManifest', () => {
  test('reads the model.reranker pins hard from the bundle manifest', () => {
    assert.deepEqual(
      clientRerankerPinsFromManifest({ model: { reranker: { modelId: 'Qwen/Qwen3-Reranker-0.6B', revision: 'r1' } } }),
      { modelId: 'Qwen/Qwen3-Reranker-0.6B', revision: 'r1' },
    );
  });

  test('missing pins are a hard error (fail-closed)', () => {
    assert.throws(() => clientRerankerPinsFromManifest({}), /no model\.reranker\.modelId\/revision pins/);
    assert.throws(() => clientRerankerPinsFromManifest({ model: { reranker: { modelId: 'x' } } }), /pins/);
  });
});
