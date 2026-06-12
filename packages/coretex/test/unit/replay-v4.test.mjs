import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  encodePatch,
  applyPatch,
  merkleizeState,
  bytesToHex,
  keccak256,
  computePatchHash,
  PATCH_TYPE,
  V4_EVENT_TOPICS,
  replayV4TransitionsFromLogs,
  replayV4TransitionFromLogs,
} from '../../dist/index.js';

function cleanState() {
  return { words: new Array(1024).fill(0n) };
}

function topicUint(value) {
  return '0x' + BigInt(value).toString(16).padStart(64, '0');
}

function topicAddress(addr) {
  return '0x' + addr.toLowerCase().replace(/^0x/, '').padStart(64, '0');
}

function wordHex(value) {
  if (typeof value === 'bigint' || typeof value === 'number') {
    return BigInt(value).toString(16).padStart(64, '0');
  }
  return value.replace(/^0x/, '').padStart(64, '0');
}

function bytesData(hex) {
  const raw = hex.replace(/^0x/, '');
  const len = raw.length / 2;
  const padded = raw.padEnd(Math.ceil(len / 32) * 64, '0');
  return '0x' + wordHex(64) + wordHex(len) + padded;
}

describe('CoreTex v4 replay', () => {
  test('replays CoretexPatchBytes plus CortexStateAdvanced logs', () => {
    const parent = cleanState();
    const parentRoot = merkleizeState(parent);
    const patch = {
      patchType: PATCH_TYPE.KEY_UPDATE,
      wordCount: 1,
      scoreDelta: 5000n,
      parentStateRoot: parentRoot,
      indices: [401],
      newWords: [12345n],
    };
    const patchBytes = encodePatch(patch);
    const patchHash = computePatchHash(patchBytes); // domain-prefixed (matches on-chain + replay/v4)
    const applied = applyPatch(parent, patch);
    assert.equal(applied.ok, true);
    const newStateRoot = bytesToHex(merkleizeState(applied.state));
    const miner = '0x1111111111111111111111111111111111111111';

    const logs = [
      {
        topics: [
          V4_EVENT_TOPICS.CoretexPatchBytes,
          topicUint(7),
          topicAddress(miner),
          patchHash,
        ],
        data: '0x' + wordHex('0x' + '22'.repeat(32)) + bytesData(bytesToHex(patchBytes)).slice(2),
      },
      {
        topics: [
          V4_EVENT_TOPICS.CortexStateAdvanced,
          topicUint(7),
          topicUint(2),
        ],
        data: '0x'
          + wordHex(bytesToHex(parentRoot))
          + wordHex(newStateRoot)
          + wordHex(patchHash)
          + wordHex('0x' + '33'.repeat(32))
          + wordHex(1),
      },
    ];

    const result = replayV4TransitionFromLogs(parent, logs);
    assert.equal(result.ok, true);
    assert.equal(result.reproducedStateRoot, newStateRoot);
    assert.equal(result.scoreDeltaPpm, '5000');
    assert.equal(result.wordCount, 1);
  });

  test('rejects tampered patch bytes', () => {
    const parent = cleanState();
    const parentRoot = merkleizeState(parent);
    const patch = {
      patchType: PATCH_TYPE.KEY_UPDATE,
      wordCount: 1,
      scoreDelta: 5000n,
      parentStateRoot: parentRoot,
      indices: [401],
      newWords: [12345n],
    };
    const patchBytes = encodePatch(patch);
    const patchHash = computePatchHash(patchBytes); // domain-prefixed (matches on-chain + replay/v4)
    patchBytes[patchBytes.length - 1] ^= 1;
    const logs = [
      {
        topics: [
          V4_EVENT_TOPICS.CoretexPatchBytes,
          topicUint(7),
          topicAddress('0x1111111111111111111111111111111111111111'),
          patchHash,
        ],
        data: '0x' + wordHex('0x' + '22'.repeat(32)) + bytesData(bytesToHex(patchBytes)).slice(2),
      },
      {
        topics: [V4_EVENT_TOPICS.CortexStateAdvanced, topicUint(7), topicUint(2)],
        data: '0x'
          + wordHex(bytesToHex(parentRoot))
          + wordHex('0x' + '44'.repeat(32))
          + wordHex(patchHash)
          + wordHex('0x' + '33'.repeat(32))
          + wordHex(1),
      },
    ];

    const result = replayV4TransitionFromLogs(parent, logs);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'PATCH_HASH_MISMATCH');
  });

  test('replays multiple state advances in log order', () => {
    const parent = cleanState();
    const parentRoot = merkleizeState(parent);
    const miner = '0x1111111111111111111111111111111111111111';
    const patchA = {
      patchType: PATCH_TYPE.KEY_UPDATE,
      wordCount: 1,
      scoreDelta: 5000n,
      parentStateRoot: parentRoot,
      indices: [401],
      newWords: [12345n],
    };
    const patchABytes = encodePatch(patchA);
    const patchAHash = computePatchHash(patchABytes);
    const appliedA = applyPatch(parent, patchA);
    assert.equal(appliedA.ok, true);
    const patchB = {
      patchType: PATCH_TYPE.KEY_UPDATE,
      wordCount: 1,
      scoreDelta: 6000n,
      parentStateRoot: merkleizeState(appliedA.state),
      indices: [402],
      newWords: [67890n],
    };
    const patchBBytes = encodePatch(patchB);
    const patchBHash = computePatchHash(patchBBytes);
    const appliedB = applyPatch(appliedA.state, patchB);
    assert.equal(appliedB.ok, true);

    const logs = [
      {
        topics: [V4_EVENT_TOPICS.CoretexPatchBytes, topicUint(7), topicAddress(miner), patchAHash],
        data: '0x' + wordHex('0x' + '22'.repeat(32)) + bytesData(bytesToHex(patchABytes)).slice(2),
      },
      {
        topics: [V4_EVENT_TOPICS.CortexStateAdvanced, topicUint(7), topicUint(2)],
        data: '0x'
          + wordHex(bytesToHex(parentRoot))
          + wordHex(bytesToHex(merkleizeState(appliedA.state)))
          + wordHex(patchAHash)
          + wordHex('0x' + '33'.repeat(32))
          + wordHex(1),
      },
      {
        topics: [V4_EVENT_TOPICS.CoretexPatchBytes, topicUint(7), topicAddress(miner), patchBHash],
        data: '0x' + wordHex('0x' + '44'.repeat(32)) + bytesData(bytesToHex(patchBBytes)).slice(2),
      },
      {
        topics: [V4_EVENT_TOPICS.CortexStateAdvanced, topicUint(7), topicUint(3)],
        data: '0x'
          + wordHex(bytesToHex(merkleizeState(appliedA.state)))
          + wordHex(bytesToHex(merkleizeState(appliedB.state)))
          + wordHex(patchBHash)
          + wordHex('0x' + '55'.repeat(32))
          + wordHex(1),
      },
    ];

    const result = replayV4TransitionsFromLogs(parent, logs);
    assert.equal(result.ok, true);
    assert.equal(result.transitionCount, 2);
    assert.equal(result.results[1].scoreDeltaPpm, '6000');
  });
});
