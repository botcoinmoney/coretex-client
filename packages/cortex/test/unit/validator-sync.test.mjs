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
