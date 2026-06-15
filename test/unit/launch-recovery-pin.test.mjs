/**
 * Launch-recovery pin: shipped per-(chainId, epochId) recovery base that
 * lets a fresh client start replay AFTER a one-off operator-bootstrap event
 * without traversing receipts that have no score-attested eval artifact.
 *
 * These tests cover:
 *   - the pin module's lookup / decode / opt-out helpers
 *   - resolveReplayFromBlock precedence with the pin
 *   - pre-recovery snapshot discard behavior
 *   - resolveReplayParentBootstrap's launch-recovery source
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveLaunchRecoveryPin,
  listLaunchRecoveryPins,
  launchRecoveryParentState,
  launchRecoveryDisabledFromEnv,
} from '../../dist/replay/launch-recovery-pin.js';
import {
  resolveReplayFromBlock,
  resolveReplayParentBootstrap,
  blankSubstrateStateRoot,
} from '../../dist/client-sync-cli.js';
import { bytesToHex, merkleizeState } from '../../dist/index.js';

const BLANK_ROOT = blankSubstrateStateRoot();
const OTHER_ROOT = `0x${'ab'.repeat(32)}`;

describe('launch-recovery-pin module', () => {
  test('Base mainnet epoch-115 pin is shipped and self-consistent', () => {
    const pin = resolveLaunchRecoveryPin(8453, 115);
    assert.ok(pin, 'expected Base mainnet epoch-115 pin to be present');
    assert.equal(pin.chainId, 8453);
    assert.equal(pin.epochId, 115);
    assert.match(pin.parentStateRoot, /^0x[0-9a-f]{64}$/);
    assert.ok(pin.fromBlock > pin.attainedAtBlock, 'fromBlock must be strictly after attainedAtBlock');
    assert.equal(pin.parentStateRoot, '0x4c7e19e2bfec553d0b3f07bc55e6c3f968dd569d95359f9569574c1ccfe773af');
    assert.equal(pin.attainedAtTransitionIndex, 5);
    assert.equal(pin.baselineParentScorePpm, 278923);
    assert.match(pin.parentStatePackedHex, /^0x[0-9a-f]+$/);
  });

  test('packed substrate merkles to the pinned parentStateRoot (constant is internally consistent)', () => {
    const pin = resolveLaunchRecoveryPin(8453, 115);
    const state = launchRecoveryParentState(pin);
    const root = bytesToHex(merkleizeState(state)).toLowerCase();
    assert.equal(root, pin.parentStateRoot.toLowerCase());
  });

  test('returns undefined for unknown chain or epoch', () => {
    assert.equal(resolveLaunchRecoveryPin(1, 115), undefined);
    assert.equal(resolveLaunchRecoveryPin(8453, 9999), undefined);
  });

  test('listLaunchRecoveryPins returns every shipped pin', () => {
    const all = listLaunchRecoveryPins();
    assert.ok(all.length >= 1);
    assert.ok(all.some((p) => p.chainId === 8453 && p.epochId === 115));
  });

  test('launchRecoveryDisabledFromEnv: flag and env both opt out', () => {
    assert.equal(launchRecoveryDisabledFromEnv({ fullHistoryFlag: false, envFullHistory: undefined }), false);
    assert.equal(launchRecoveryDisabledFromEnv({ fullHistoryFlag: true, envFullHistory: undefined }), true);
    assert.equal(launchRecoveryDisabledFromEnv({ fullHistoryFlag: false, envFullHistory: '1' }), true);
    assert.equal(launchRecoveryDisabledFromEnv({ fullHistoryFlag: false, envFullHistory: 'true' }), true);
    assert.equal(launchRecoveryDisabledFromEnv({ fullHistoryFlag: false, envFullHistory: 'yes' }), true);
    assert.equal(launchRecoveryDisabledFromEnv({ fullHistoryFlag: false, envFullHistory: '0' }), false);
    assert.equal(launchRecoveryDisabledFromEnv({ fullHistoryFlag: false, envFullHistory: '' }), false);
  });
});

describe('resolveReplayFromBlock with launch-recovery pin', () => {
  const pin = resolveLaunchRecoveryPin(8453, 115);

  test('explicit --from-block wins over the pin', () => {
    const result = resolveReplayFromBlock({
      flag: '99',
      launchRecoveryPin: pin,
    });
    assert.equal(result.source, 'flag');
    assert.equal(result.fromBlock, 99n);
  });

  test('CORETEX_REPLAY_FROM_BLOCK wins over the pin', () => {
    const result = resolveReplayFromBlock({
      envReplayFromBlock: '777',
      launchRecoveryPin: pin,
    });
    assert.equal(result.source, 'env');
    assert.equal(result.fromBlock, 777n);
  });

  test('post-recovery snapshot wins over the pin', () => {
    const result = resolveReplayFromBlock({
      snapshotCursorBlock: pin.attainedAtBlock + 100,
      launchRecoveryPin: pin,
    });
    assert.equal(result.source, 'snapshot-cursor');
    assert.equal(result.fromBlock, BigInt(pin.attainedAtBlock + 100) + 1n);
  });

  test('pre-recovery snapshot is DISCARDED and the pin is used', () => {
    const result = resolveReplayFromBlock({
      snapshotCursorBlock: pin.attainedAtBlock - 1000,
      launchRecoveryPin: pin,
    });
    assert.equal(result.source, 'launch-recovery');
    assert.equal(result.fromBlock, BigInt(pin.fromBlock));
    assert.equal(result.recoveryAttainedAtBlock, pin.attainedAtBlock);
    assert.equal(result.preRecoverySnapshotDiscarded, true);
  });

  test('snapshot exactly at attainedAtBlock is acceptable (post-recovery)', () => {
    const result = resolveReplayFromBlock({
      snapshotCursorBlock: pin.attainedAtBlock,
      launchRecoveryPin: pin,
    });
    assert.equal(result.source, 'snapshot-cursor');
    assert.equal(result.fromBlock, BigInt(pin.attainedAtBlock) + 1n);
  });

  test('pin is used when no other source is present', () => {
    const result = resolveReplayFromBlock({ launchRecoveryPin: pin });
    assert.equal(result.source, 'launch-recovery');
    assert.equal(result.fromBlock, BigInt(pin.fromBlock));
    assert.equal(result.recoveryAttainedAtBlock, pin.attainedAtBlock);
    assert.equal(result.preRecoverySnapshotDiscarded, false);
  });

  test('launchRecoveryDisabled=true falls through to legacy precedence', () => {
    const result = resolveReplayFromBlock({
      launchRecoveryPin: pin,
      launchRecoveryDisabled: true,
      stateRegistryDeployBlock: 11111,
    });
    assert.equal(result.source, 'state-deploy-block');
    assert.equal(result.fromBlock, 11111n);
  });

  test('without a pin, existing precedence is preserved (snapshot-cursor wins over deploy-block)', () => {
    const result = resolveReplayFromBlock({
      snapshotCursorBlock: 12345,
      stateRegistryDeployBlock: 1,
    });
    assert.equal(result.source, 'snapshot-cursor');
    assert.equal(result.fromBlock, 12346n);
  });

  test('without a pin and without a snapshot, deploy-block is used (legacy path)', () => {
    const result = resolveReplayFromBlock({ stateRegistryDeployBlock: 42 });
    assert.equal(result.source, 'state-deploy-block');
    assert.equal(result.fromBlock, 42n);
  });
});

describe('resolveReplayParentBootstrap with launch-recovery source', () => {
  test('launch-recovery fromBlockSource selects the launch-recovery parent', () => {
    assert.deepEqual(
      resolveReplayParentBootstrap({
        snapshotAvailable: false,
        chainParentStateRoot: OTHER_ROOT,
        blankRoot: BLANK_ROOT,
        fromBlockSource: 'launch-recovery',
      }),
      { source: 'launch-recovery' },
    );
  });

  test('explicit --parent-state still wins over launch-recovery', () => {
    assert.deepEqual(
      resolveReplayParentBootstrap({
        explicitParentStatePath: '/x/state.bin',
        snapshotAvailable: false,
        chainParentStateRoot: OTHER_ROOT,
        blankRoot: BLANK_ROOT,
        fromBlockSource: 'launch-recovery',
      }),
      { source: 'explicit-file' },
    );
  });

  test('a usable snapshot still wins over launch-recovery (the post-recovery snapshot path)', () => {
    assert.deepEqual(
      resolveReplayParentBootstrap({
        snapshotAvailable: true,
        chainParentStateRoot: OTHER_ROOT,
        blankRoot: BLANK_ROOT,
        // In practice this snapshot would only be considered "available" when the
        // cursor is at or after the pin's attainedAtBlock — resolveReplayFromBlock
        // is the gate. Here we simulate the call shape resolveReplayParentBootstrap sees.
        fromBlockSource: 'snapshot-cursor',
      }),
      { source: 'snapshot' },
    );
  });
});
