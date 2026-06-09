import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  ZERO_BYTES32,
  epochSecretCommit,
  mergeChainPins,
  readOnChainEpochPins,
} from '../../../../scripts/coretex-validator-sync.mjs';

const REGISTRY = `0x${'11'.repeat(20)}`;
const OTHER_REGISTRY = `0x${'12'.repeat(20)}`;
const MINING = `0x${'22'.repeat(20)}`;
const EPOCH = 9;
const SECRET = `0x${'33'.repeat(32)}`;
const COMMIT = epochSecretCommit(SECRET);
const CORE_VERSION = `0x${'44'.repeat(32)}`;
const CORPUS_ROOT = `0x${'55'.repeat(32)}`;
const FRONTIER_ROOT = `0x${'66'.repeat(32)}`;
const BASELINE_HASH = `0x${'77'.repeat(32)}`;
const PARENT_ROOT = `0x${'88'.repeat(32)}`;
const LIVE_ROOT = `0x${'99'.repeat(32)}`;

function addressWord(address) {
  return `0x${'00'.repeat(12)}${address.slice(2).toLowerCase()}`;
}

function chainMock({
  registryFromMining = REGISTRY,
  hiddenSeedCommit = COMMIT,
  miningEpochCommit = COMMIT,
  epochSecret = SECRET,
} = {}) {
  return async ({ to, signature }) => {
    if (to.toLowerCase() === MINING) {
      if (signature === 'coreTexRegistry()') return addressWord(registryFromMining);
      if (signature === 'epochCommit(uint64)') return miningEpochCommit;
      if (signature === 'epochSecret(uint64)') return epochSecret;
    }
    if (to.toLowerCase() === REGISTRY) {
      if (signature === 'epochParentStateRoot(uint64)') return PARENT_ROOT;
      if (signature === 'liveStateRoot(uint64)') return LIVE_ROOT;
      if (signature === 'transitionCount(uint64)') return `0x${'00'.repeat(31)}02`;
      if (signature === 'epochCoreVersionHash(uint64)') return CORE_VERSION;
      if (signature === 'epochCorpusRoot(uint64)') return CORPUS_ROOT;
      if (signature === 'epochActiveFrontierRoot(uint64)') return FRONTIER_ROOT;
      if (signature === 'epochBaselineManifestHash(uint64)') return BASELINE_HASH;
      if (signature === 'epochHiddenSeedCommit(uint64)') return hiddenSeedCommit;
    }
    throw new Error(`unexpected call ${to} ${signature}`);
  };
}

describe('validator sync on-chain pins and reveal binding', () => {
  test('matching mining reveal passes and exposes only reveal status metadata', async () => {
    const pins = await readOnChainEpochPins({
      rpcUrl: 'http://127.0.0.1:8545',
      registry: REGISTRY,
      miningContract: MINING,
      epoch: EPOCH,
      requireReveal: true,
      ethCall: chainMock(),
    });

    assert.equal(pins.coreVersionHash, CORE_VERSION);
    assert.equal(pins.parentStateRoot, PARENT_ROOT);
    assert.equal(pins.liveStateRoot, LIVE_ROOT);
    assert.equal(pins.transitionCount, 2);
    assert.equal(pins.corpusRoot, CORPUS_ROOT);
    assert.equal(pins.activeFrontierRoot, FRONTIER_ROOT);
    assert.equal(pins.baselineManifestHash, BASELINE_HASH);
    assert.equal(pins.hiddenSeedCommit, COMMIT);
    assert.equal(pins.evalReplayStatus, 'epoch_secret_revealed');
    assert.equal(pins.epochSecretRevealed, true);
    assert.equal(pins.epochSecret, undefined);
  });

  test('zero mining secret blocks post-reveal eval replay', async () => {
    await assert.rejects(
      () => readOnChainEpochPins({
        rpcUrl: 'http://127.0.0.1:8545',
        registry: REGISTRY,
        miningContract: MINING,
        epoch: EPOCH,
        requireReveal: true,
        ethCall: chainMock({ epochSecret: ZERO_BYTES32 }),
      }),
      /awaiting_epoch_secret_reveal/,
    );
  });

  test('zero mining secret during active epoch sync reports awaiting reveal', async () => {
    const pins = await readOnChainEpochPins({
      rpcUrl: 'http://127.0.0.1:8545',
      registry: REGISTRY,
      miningContract: MINING,
      epoch: EPOCH,
      requireReveal: false,
      ethCall: chainMock({ epochSecret: ZERO_BYTES32 }),
    });

    assert.equal(pins.evalReplayStatus, 'awaiting_epoch_secret_reveal');
    assert.equal(pins.epochSecretRevealed, false);
  });

  test('mismatched revealed secret fails hard', async () => {
    await assert.rejects(
      () => readOnChainEpochPins({
        rpcUrl: 'http://127.0.0.1:8545',
        registry: REGISTRY,
        miningContract: MINING,
        epoch: EPOCH,
        requireReveal: true,
        ethCall: chainMock({ epochSecret: `0x${'99'.repeat(32)}` }),
      }),
      /epochSecret commit/,
    );
  });

  test('mismatched mining epochCommit fails hard before reveal replay', async () => {
    await assert.rejects(
      () => readOnChainEpochPins({
        rpcUrl: 'http://127.0.0.1:8545',
        registry: REGISTRY,
        miningContract: MINING,
        epoch: EPOCH,
        requireReveal: true,
        ethCall: chainMock({ miningEpochCommit: `0x${'88'.repeat(32)}` }),
      }),
      /epochCommit/,
    );
  });

  test('mismatched registry returned by mining contract fails hard', async () => {
    await assert.rejects(
      () => readOnChainEpochPins({
        rpcUrl: 'http://127.0.0.1:8545',
        registry: REGISTRY,
        miningContract: MINING,
        epoch: EPOCH,
        requireReveal: true,
        ethCall: chainMock({ registryFromMining: OTHER_REGISTRY }),
      }),
      /coreTexRegistry/,
    );
  });

  test('chain pins override compatible offline pins and reject mismatches', () => {
    assert.deepEqual(
      mergeChainPins({ corpusRoot: CORPUS_ROOT }, { corpusRoot: CORPUS_ROOT, activeFrontierRoot: FRONTIER_ROOT }),
      { corpusRoot: CORPUS_ROOT, activeFrontierRoot: FRONTIER_ROOT },
    );
    assert.throws(
      () => mergeChainPins({ corpusRoot: `0x${'aa'.repeat(32)}` }, { corpusRoot: CORPUS_ROOT }),
      /registry pin mismatch corpusRoot/,
    );
  });
});

// ── compiled validator-sync CLI (packages/cortex/dist/validator-sync-cli.js) ──

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

import {
  checkCorpusDeltaContinuity,
  checkTofuKeyPin,
  writeTofuKeyPin,
  checkValidatorBundleVersion,
  deriveEpochSecretRevealStatus,
  policyAtomsModeFromManifest,
  sha256Fingerprint,
} from '../../dist/validator-sync-cli.js';

const cliPath = fileURLToPath(new URL('../../dist/validator-sync-cli.js', import.meta.url));
const ROOT_A = `0x${'aa'.repeat(32)}`;
const ROOT_B = `0x${'bb'.repeat(32)}`;

function withTmpDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'coretex-validator-sync-cli-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function runCli(cliArgs, env = {}) {
  return spawnSync(process.execPath, [cliPath, ...cliArgs], {
    encoding: 'utf8',
    env: {
      ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('CORETEX_') && !k.startsWith('BOTCOIN_') && k !== 'BASE_RPC_URL' && k !== 'EPOCH_ID')),
      ...env,
    },
  });
}

describe('validator-sync CLI — corpus-delta continuity', () => {
  test('continuity holds when delta.previousRoot equals the local previous corpus root', () => {
    assert.doesNotThrow(() => checkCorpusDeltaContinuity(ROOT_A, ROOT_A.toUpperCase().replace('0X', '0x')));
  });

  test('continuity failure is a hard error', () => {
    assert.throws(
      () => checkCorpusDeltaContinuity(ROOT_A, ROOT_B),
      /corpus-delta continuity: delta\.previousRoot .* != local previous corpus root/,
    );
  });

  test('an unavailable local previous corpus root is a hard error (no silent skip)', () => {
    assert.throws(
      () => checkCorpusDeltaContinuity(ROOT_A, undefined),
      /local previous corpus root unavailable/,
    );
  });
});

describe('validator-sync CLI — TOFU epoch signing key pinning', () => {
  const KEY_A = '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n';
  const KEY_B = '-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----\n';

  test('first sync has no pin; writing then re-checking the SAME key passes', () => withTmpDir((dir) => {
    const pinPath = join(dir, 'epoch-signing-key.pin.json');
    const first = checkTofuKeyPin(pinPath, KEY_A);
    assert.equal(first.pinned, false);
    assert.equal(first.fingerprint, sha256Fingerprint(KEY_A));
    writeTofuKeyPin(pinPath, KEY_A);
    const pin = JSON.parse(readFileSync(pinPath, 'utf8'));
    assert.equal(pin.schema, 'coretex.epoch-signing-key-pin.v1');
    assert.equal(pin.publicKeyPem, KEY_A);
    assert.equal(pin.fingerprint, sha256Fingerprint(KEY_A));
    const again = checkTofuKeyPin(pinPath, KEY_A);
    assert.equal(again.pinned, true);
  }));

  test('a served key differing from the pin is a hard error', () => withTmpDir((dir) => {
    const pinPath = join(dir, 'epoch-signing-key.pin.json');
    writeTofuKeyPin(pinPath, KEY_A);
    assert.throws(() => checkTofuKeyPin(pinPath, KEY_B), /TOFU key pin mismatch/);
  }));
});

describe('validator-sync CLI — bundle version self-check', () => {
  const LOCAL = `0x${'44'.repeat(32)}`;
  const CHAIN = `0x${'45'.repeat(32)}`;

  test('matching bundleHash passes', () => {
    assert.deepEqual(checkValidatorBundleVersion(LOCAL, LOCAL.toUpperCase().replace('0X', '0x'), false), { match: true });
  });

  test('mismatch is a hard "validator client outdated" error naming the required hash', () => {
    assert.throws(
      () => checkValidatorBundleVersion(LOCAL, CHAIN, false),
      (err) => {
        assert.match(err.message, /validator client outdated/);
        assert.match(err.message, new RegExp(`Required bundle hash: ${CHAIN}`));
        return true;
      },
    );
  });

  test('--allow-version-mismatch downgrades to a loud read-only warning', () => {
    const warnings = [];
    const result = checkValidatorBundleVersion(LOCAL, CHAIN, true, (m) => warnings.push(m));
    assert.deepEqual(result, { match: false });
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /validator client outdated/);
    assert.match(warnings[0], /READ-ONLY/);
  });
});

describe('validator-sync CLI — epoch secret reveal status + mode flags', () => {
  test('zero mining secret reports awaiting_epoch_secret_reveal', () => {
    assert.deepEqual(
      deriveEpochSecretRevealStatus(COMMIT, ZERO_BYTES32),
      { evalReplayStatus: 'awaiting_epoch_secret_reveal', epochSecretRevealed: false },
    );
  });

  test('a matching revealed secret reports epoch_secret_revealed', () => {
    assert.deepEqual(
      deriveEpochSecretRevealStatus(COMMIT, SECRET),
      { evalReplayStatus: 'epoch_secret_revealed', epochSecretRevealed: true },
    );
  });

  test('a mismatched revealed secret is a hard error', () => {
    assert.throws(
      () => deriveEpochSecretRevealStatus(COMMIT, `0x${'99'.repeat(32)}`),
      /epochSecret commit/,
    );
  });

  test('policyAtomsMode derives HARD from the manifest pipelineVersion', () => {
    assert.equal(policyAtomsModeFromManifest({ evaluator: { profile: { pipelineVersion: 'coretex-retrieval-v2-policy-r5' } } }), true);
    assert.equal(policyAtomsModeFromManifest({ evaluator: { profile: { pipelineVersion: 'coretex-retrieval-v2-lens-r4' } } }), false);
    assert.equal(policyAtomsModeFromManifest({}), false);
  });
});

describe('validator-sync CLI — mandatory inputs (spawned)', () => {
  const baseArgs = (manifestPath) => [
    '--epoch', '1',
    '--rpc-url', 'http://127.0.0.1:9',
    '--registry', `0x${'11'.repeat(20)}`,
    '--mining-contract', `0x${'22'.repeat(20)}`,
    ...(manifestPath ? ['--bundle-manifest', manifestPath] : []),
    '--rotation-manifest', 'file:///nonexistent/rotation.json',
    '--corpus-delta', 'file:///nonexistent/delta.json',
  ];

  test('a missing local bundle manifest is a hard error (version check is not optional)', () => {
    const proc = runCli(baseArgs(null));
    assert.notEqual(proc.status, 0);
    assert.match(proc.stderr, /--bundle-manifest or CORETEX_BUNDLE_MANIFEST is required/);
  });

  test('a missing epoch signing public key is a hard error (signatures are mandatory)', () => withTmpDir((dir) => {
    const manifestPath = join(dir, 'bundle.json');
    writeFileSync(manifestPath, JSON.stringify({
      bundleHash: `0x${'44'.repeat(32)}`,
      corpus: { root: ROOT_A },
      model: { reranker: { modelId: 'Qwen/Qwen3-Reranker-0.6B', revision: 'test-revision' } },
    }));
    const proc = runCli(baseArgs(manifestPath));
    assert.notEqual(proc.status, 0);
    assert.match(proc.stderr, /epoch signing public key is required \(signature verification is mandatory\)/);
  }));

  test('a bundle manifest without model.reranker pins is a hard error (fail-closed scorer)', () => withTmpDir((dir) => {
    const manifestPath = join(dir, 'bundle.json');
    writeFileSync(manifestPath, JSON.stringify({ bundleHash: `0x${'44'.repeat(32)}`, corpus: { root: ROOT_A } }));
    const proc = runCli(baseArgs(manifestPath));
    assert.notEqual(proc.status, 0);
    assert.match(proc.stderr, /no model\.reranker\.modelId\/revision pins/);
  }));

  test('verify-patch requires --hash', () => {
    const proc = runCli(['verify-patch']);
    assert.notEqual(proc.status, 0);
    assert.match(proc.stderr, /verify-patch requires --hash/);
  });

  test('verify-patch requires an artifact source', () => {
    const proc = runCli(['verify-patch', '--hash', `0x${'ab'.repeat(32)}`]);
    assert.notEqual(proc.status, 0);
    assert.match(proc.stderr, /CORETEX_ARTIFACT_BASE_URL/);
  });

  test('verify-patch binds the fetched artifact to the requested hash', () => withTmpDir((dir) => {
    const artifactPath = join(dir, 'artifact.json');
    writeFileSync(artifactPath, JSON.stringify({ artifactHash: `0x${'cd'.repeat(32)}` }));
    const proc = runCli(['verify-patch', '--hash', `0x${'ab'.repeat(32)}`, '--artifact-url', `file://${artifactPath}`]);
    assert.notEqual(proc.status, 0);
    assert.match(proc.stderr, /fetched artifact hash .* != requested/);
  }));
});
