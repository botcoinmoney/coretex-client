/**
 * Unit tests for CoreTex v4 fundamental design issue fixes:
 *
 *   F1 — Epoch-seed salt for substrate hash functions (eventIdToKey128 / eventIdToMem128)
 *   F2 — localModelAgreementOverride replaces circular mean
 *   F3 — rerankerHitThreshold in EvaluatorProfile / buildBundleManifest
 *   R1 — replayV4TransitionsFromLogs sorts logs and rejects out-of-order transitionIndex
 *   R2 — replayV4TransitionFromLogs rejects multi-advance log sets
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

import { eventIdToKey128, eventIdToMem128, scoreProductionState } from '../../dist/eval/corpus.js';
import { buildBundleManifest, qwen3Reranker06BManifest } from '../../dist/bundle/index.js';
import {
  replayV4TransitionFromLogs,
  replayV4TransitionsFromLogs,
  V4_EVENT_TOPICS,
} from '../../dist/index.js';
import { encodePatch, applyPatch, merkleizeState, bytesToHex, keccak256, PATCH_TYPE } from '../../dist/index.js';

const repoRoot = fileURLToPath(new URL('../../../..', import.meta.url));

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeCleanState() {
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

function makeAdvanceLog(epochId, transitionIndex, parentRoot, newRoot, patchHash, blockNumber, logIndex) {
  return {
    topics: [
      V4_EVENT_TOPICS.CortexStateAdvanced,
      topicUint(epochId),
      topicUint(transitionIndex),
    ],
    data: '0x'
      + wordHex(typeof parentRoot === 'string' ? parentRoot : bytesToHex(parentRoot))
      + wordHex(typeof newRoot === 'string' ? newRoot : bytesToHex(newRoot))
      + wordHex(patchHash)
      + wordHex('0x' + '33'.repeat(32))
      + wordHex(1),
    blockNumber: blockNumber !== undefined ? '0x' + blockNumber.toString(16) : undefined,
    logIndex: logIndex !== undefined ? '0x' + logIndex.toString(16) : undefined,
  };
}

function makePatchLog(epochId, miner, patchHash, patchBytes, blockNumber, logIndex) {
  return {
    topics: [
      V4_EVENT_TOPICS.CoretexPatchBytes,
      topicUint(epochId),
      topicAddress(miner),
      patchHash,
    ],
    data: '0x' + wordHex('0x' + '22'.repeat(32)) + bytesData(bytesToHex(patchBytes)).slice(2),
    blockNumber: blockNumber !== undefined ? '0x' + blockNumber.toString(16) : undefined,
    logIndex: logIndex !== undefined ? '0x' + logIndex.toString(16) : undefined,
  };
}

/** Minimal synthetic corpus with events covering all components. */
function makeSyntheticCorpus() {
  return {
    corpusRoot: '0x' + '11'.repeat(32),
    sources: {},
    events: {
      near_collision: [{
        id: 'nc-seed-test',
        family: 'near_collision',
        taskType: 'near',
        isProtected: false,
        epochCommitted: 1,
        sourceRef: 'test',
        queryText: '',
        truthText: '',
        isStaleTruth: false,
        relevant: true,
      }],
      temporal: [
        {
          id: 'stale-seed-test',
          family: 'temporal',
          taskType: 'stale',
          isProtected: false,
          epochCommitted: 1,
          sourceRef: 'test',
          queryText: '',
          truthText: '',
          isStaleTruth: true,
          relevant: true,
        },
        {
          id: 'current-seed-test',
          family: 'temporal',
          taskType: 'current',
          isProtected: false,
          epochCommitted: 1,
          sourceRef: 'test',
          queryText: '',
          truthText: '',
          isStaleTruth: false,
          relevant: true,
        },
      ],
      long_horizon: [{
        id: 'lh-seed-test',
        family: 'long_horizon',
        taskType: 'long',
        isProtected: false,
        epochCommitted: 1,
        sourceRef: 'test',
        queryText: '',
        truthText: '',
        isStaleTruth: false,
        relevant: true,
      }],
    },
  };
}

// ─── F1: Epoch-seed salt ──────────────────────────────────────────────────────

describe('F1 — epoch-seed salt for substrate hash functions', () => {
  const SEED = '0x' + 'ab'.repeat(32);

  test('eventIdToKey128("foo") and eventIdToKey128("foo", seed) produce DIFFERENT bigints', () => {
    const noSeed = eventIdToKey128('foo');
    const withSeed = eventIdToKey128('foo', SEED);
    assert.equal(typeof noSeed, 'bigint');
    assert.equal(typeof withSeed, 'bigint');
    assert.notEqual(noSeed, withSeed, 'seeded hash must differ from unseeded hash');
  });

  test('eventIdToMem128("foo") and eventIdToMem128("foo", seed) produce DIFFERENT bigints', () => {
    const noSeed = eventIdToMem128('foo');
    const withSeed = eventIdToMem128('foo', SEED);
    assert.notEqual(noSeed, withSeed, 'seeded hash must differ from unseeded hash');
  });

  test('different seeds produce different hashes', () => {
    const seed1 = '0x' + '01'.repeat(32);
    const seed2 = '0x' + '02'.repeat(32);
    assert.notEqual(eventIdToKey128('foo', seed1), eventIdToKey128('foo', seed2));
    assert.notEqual(eventIdToMem128('foo', seed1), eventIdToMem128('foo', seed2));
  });

  test('same seed+eventId always produces same hash (deterministic)', () => {
    assert.equal(eventIdToKey128('bar', SEED), eventIdToKey128('bar', SEED));
    assert.equal(eventIdToMem128('bar', SEED), eventIdToMem128('bar', SEED));
  });

  test('scoreProductionState with epochSeed produces different scores than without (slot fills that scored under no-seed do not score under different seed)', () => {
    const corpus = makeSyntheticCorpus();
    const state = makeCleanState();
    const event = corpus.events.near_collision[0];

    // Fill slot 384 (retrieval key slot 0) using the NO-SEED hash
    const noSeedKeyId = eventIdToKey128(event.id);
    state.words[384] = (noSeedKeyId << 128n) | (1n << 80n);

    // Score without seed → should hit (slot has the no-seed hash)
    const scoreNoSeed = scoreProductionState(state, corpus, {
      shardId: '0x' + '00'.repeat(16),
      evalItemsPerFamily: 0,
    });

    // Score with seed → should NOT hit (slot has wrong hash for this seed)
    const scoreSeed = scoreProductionState(state, corpus, {
      shardId: '0x' + '00'.repeat(16),
      evalItemsPerFamily: 0,
      epochSeed: SEED,
    });

    assert.equal(scoreNoSeed.hits.near_collision, 1, 'no-seed path should hit the no-seed slot');
    assert.equal(scoreSeed.hits.near_collision, 0, 'seeded path should NOT hit the no-seed slot');
    assert.ok(scoreNoSeed.composite > scoreSeed.composite, 'no-seed composite must exceed seeded composite');
  });

  test('scoreProductionState with correct epochSeed scores correctly', () => {
    const corpus = makeSyntheticCorpus();
    const state = makeCleanState();
    const event = corpus.events.near_collision[0];

    // Fill slot 384 using the SEEDED hash
    const seededKeyId = eventIdToKey128(event.id, SEED);
    state.words[384] = (seededKeyId << 128n) | (1n << 80n);

    const scoreSeed = scoreProductionState(state, corpus, {
      shardId: '0x' + '00'.repeat(16),
      evalItemsPerFamily: 0,
      epochSeed: SEED,
    });

    assert.equal(scoreSeed.hits.near_collision, 1, 'seeded path should hit the seeded slot');
  });
});

// ─── F2: localModelAgreementOverride ─────────────────────────────────────────

describe('F2 — localModelAgreementOverride replaces circular mean', () => {
  /**
   * Build an all-hits state against the mini corpus (except localModel).
   * Fills: near_collision key, stale temporal (revoked), current temporal (active),
   * long_horizon (active), all 128 relations, all 48 codebook slots.
   * Result: nearCol=1, temporal=(0+1)/2 → wait, stale needs revoked flag (0x0002).
   * For temporalCurrentStale=1: staleRejection=1 (revoked) AND temporalCurrent=1.
   */
  function allHitsState() {
    const state = makeCleanState();
    // near_collision retrieval key (slot 384, flags bit 80 = active)
    state.words[384] = (eventIdToKey128('nc-seed-test') << 128n) | (1n << 80n);
    // temporal stale: must be revoked (flags 0x0003 = valid|revoked) → revokedMemIds
    state.words[32] = (eventIdToMem128('stale-seed-test') << 128n) | (3n << 64n);
    // temporal current: active (flags 0x0001 = valid)
    state.words[40] = (eventIdToMem128('current-seed-test') << 128n) | (1n << 64n);
    // long horizon: active
    state.words[48] = (eventIdToMem128('lh-seed-test') << 128n) | (1n << 64n);
    // relations — all 128 filled
    for (let i = 672; i <= 799; i++) state.words[i] = 1n << 192n;
    // codebook — all 48 active
    for (let slot = 0; slot < 48; slot++) {
      state.words[896 + slot * 2] = (BigInt(slot + 1) << 240n) | (1n << 224n) | (1n << 208n);
    }
    return state;
  }

  test('localModelAgreement defaults to 0 when no override provided', () => {
    const corpus = makeSyntheticCorpus();
    const state = allHitsState();
    const score = scoreProductionState(state, corpus, {
      shardId: '0x' + '00'.repeat(16),
      evalItemsPerFamily: 0,
    });
    assert.equal(score.components.localModelAgreement, 0);
  });

  test('localModelAgreementOverride: 1.0 increases composite by exactly 0.10 vs override: 0.0', () => {
    const corpus = makeSyntheticCorpus();
    const state = allHitsState();
    const opts = { shardId: '0x' + '00'.repeat(16), evalItemsPerFamily: 0 };

    const score0 = scoreProductionState(state, corpus, { ...opts, localModelAgreementOverride: 0.0 });
    const score1 = scoreProductionState(state, corpus, { ...opts, localModelAgreementOverride: 1.0 });

    assert.equal(score0.components.localModelAgreement, 0);
    assert.equal(score1.components.localModelAgreement, 1);
    // Delta must be exactly 0.10 (0.10 weight × 1.0 override)
    const delta = score1.composite - score0.composite;
    assert.ok(Math.abs(delta - 0.10) < 1e-10, `expected delta 0.10, got ${delta}`);
  });

  test('localModelAgreementOverride is clamped to [0, 1]', () => {
    const corpus = makeSyntheticCorpus();
    const state = makeCleanState();
    const opts = { shardId: '0x' + '00'.repeat(16), evalItemsPerFamily: 0 };

    const scoreOver = scoreProductionState(state, corpus, { ...opts, localModelAgreementOverride: 2.0 });
    const scoreUnder = scoreProductionState(state, corpus, { ...opts, localModelAgreementOverride: -1.0 });

    assert.equal(scoreOver.components.localModelAgreement, 1, 'override > 1 should clamp to 1');
    assert.equal(scoreUnder.components.localModelAgreement, 0, 'override < 0 should clamp to 0');
  });

  test('5 active components (no override) sum to 0.90 max composite weight', () => {
    const corpus = makeSyntheticCorpus();
    const state = allHitsState();
    const score = scoreProductionState(state, corpus, {
      shardId: '0x' + '00'.repeat(16),
      evalItemsPerFamily: 0,
    });
    // 5 active components each at 1.0: 0.20+0.20+0.20+0.20+0.10 = 0.90
    assert.ok(Math.abs(score.composite - 0.90) < 1e-10, `expected 0.90, got ${score.composite}`);
  });
});

// ─── F3: rerankerHitThreshold in bundle profile ───────────────────────────────

describe('F3 — rerankerHitThreshold in EvaluatorProfile', () => {
  const model = qwen3Reranker06BManifest('0123456789abcdef0123456789abcdef01234567', [
    { path: 'model.safetensors', sha256: 'a'.repeat(64), bytes: 1 },
  ]);

  function buildDefaultManifest() {
    return buildBundleManifest({
      repoRoot,
      corpusRoot: '0x' + '11'.repeat(32),
      corpusFiles: ['benchmark/fixtures/season1/coretex_season1_10000.json'],
      model,
    });
  }

  test('default bundle profile has rerankerHitThreshold = 0.002', () => {
    const manifest = buildDefaultManifest();
    assert.equal(manifest.evaluator.profile.rerankerHitThreshold, 0.002);
  });

  test('rerankerHitThreshold is part of the bundle hash (changing it invalidates the bundle)', () => {
    const manifest = buildDefaultManifest();
    const manifestCustom = buildBundleManifest({
      repoRoot,
      corpusRoot: '0x' + '11'.repeat(32),
      corpusFiles: ['benchmark/fixtures/season1/coretex_season1_10000.json'],
      model,
      evaluatorProfile: { rerankerHitThreshold: 0.005 },
    });
    assert.notEqual(manifest.bundleHash, manifestCustom.bundleHash,
      'changing rerankerHitThreshold must change bundleHash');
    assert.equal(manifestCustom.evaluator.profile.rerankerHitThreshold, 0.005);
  });

  test('custom rerankerHitThreshold overrides default', () => {
    const manifest = buildBundleManifest({
      repoRoot,
      corpusRoot: '0x' + '11'.repeat(32),
      corpusFiles: ['benchmark/fixtures/season1/coretex_season1_10000.json'],
      model,
      evaluatorProfile: { rerankerHitThreshold: 0.001 },
    });
    assert.equal(manifest.evaluator.profile.rerankerHitThreshold, 0.001);
  });
});

// ─── R1: replayV4TransitionsFromLogs — sort and monotone check ────────────────

describe('R1 — replayV4TransitionsFromLogs sorts out-of-order logs correctly', () => {
  function makeTwoTransitionLogs() {
    const parent = makeCleanState();
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
    const patchAHash = bytesToHex(keccak256(patchABytes));
    const appliedA = applyPatch(parent, patchA);
    assert.equal(appliedA.ok, true);
    const rootA = merkleizeState(appliedA.state);

    const patchB = {
      patchType: PATCH_TYPE.KEY_UPDATE,
      wordCount: 1,
      scoreDelta: 6000n,
      parentStateRoot: rootA,
      indices: [402],
      newWords: [67890n],
    };
    const patchBBytes = encodePatch(patchB);
    const patchBHash = bytesToHex(keccak256(patchBBytes));
    const appliedB = applyPatch(appliedA.state, patchB);
    assert.equal(appliedB.ok, true);
    const rootB = merkleizeState(appliedB.state);

    return { parent, parentRoot, miner, patchABytes, patchAHash, rootA, patchBBytes, patchBHash, rootB, appliedA, appliedB };
  }

  test('out-of-order logs (by blockNumber) are reordered and replayed correctly', () => {
    const { parent, parentRoot, miner, patchABytes, patchAHash, rootA, patchBBytes, patchBHash, rootB } = makeTwoTransitionLogs();

    // Deliver logs out of order: B before A (block 2 before block 1)
    const logs = [
      makePatchLog(7, miner, patchBHash, patchBBytes, /*block=*/2, /*logIndex=*/0),
      makeAdvanceLog(7, /*transitionIndex=*/3, rootA, rootB, patchBHash, /*block=*/2, /*logIndex=*/1),
      makePatchLog(7, miner, patchAHash, patchABytes, /*block=*/1, /*logIndex=*/0),
      makeAdvanceLog(7, /*transitionIndex=*/2, parentRoot, rootA, patchAHash, /*block=*/1, /*logIndex=*/1),
    ];

    const result = replayV4TransitionsFromLogs(parent, logs);
    assert.equal(result.ok, true, `expected ok=true, got: ${JSON.stringify(result)}`);
    assert.equal(result.transitionCount, 2);
    assert.equal(result.results[0].scoreDeltaPpm, '5000');
    assert.equal(result.results[1].scoreDeltaPpm, '6000');
  });

  test('out-of-order logs (by logIndex within same block) are reordered correctly', () => {
    const { parent, parentRoot, miner, patchABytes, patchAHash, rootA } = makeTwoTransitionLogs();

    // Only one transition but with logIndex reversed within same block
    const logs = [
      makeAdvanceLog(7, 2, parentRoot, rootA, patchAHash, /*block=*/5, /*logIndex=*/10),
      makePatchLog(7, miner, patchAHash, patchABytes, /*block=*/5, /*logIndex=*/1),
    ];

    const result = replayV4TransitionsFromLogs(parent, logs);
    assert.equal(result.ok, true, `expected ok=true, got: ${JSON.stringify(result)}`);
    assert.equal(result.transitionCount, 1);
  });

  test('non-monotone transitionIndex is rejected with OUT_OF_ORDER_LOGS', () => {
    const { parent, parentRoot, miner, patchABytes, patchAHash, rootA, patchBBytes, patchBHash, rootB } = makeTwoTransitionLogs();

    // Deliver logs with transitionIndex going BACKWARDS (3 then 2) at same blockNumber
    const logs = [
      makePatchLog(7, miner, patchBHash, patchBBytes, /*block=*/1, /*logIndex=*/0),
      makeAdvanceLog(7, /*transitionIndex=*/3, parentRoot, rootA, patchBHash, /*block=*/1, /*logIndex=*/1),
      makePatchLog(7, miner, patchAHash, patchABytes, /*block=*/1, /*logIndex=*/2),
      makeAdvanceLog(7, /*transitionIndex=*/2, rootA, rootB, patchAHash, /*block=*/1, /*logIndex=*/3),
    ];

    const result = replayV4TransitionsFromLogs(parent, logs);
    assert.equal(result.ok, false);
    assert.equal(result.error.code, 'OUT_OF_ORDER_LOGS');
  });
});

// ─── R2: replayV4TransitionFromLogs — rejects multi-advance log sets ──────────

describe('R2 — replayV4TransitionFromLogs rejects multi-advance log sets', () => {
  test('log set with 2 CortexStateAdvanced events returns MULTIPLE_ADVANCES error', () => {
    const parent = makeCleanState();
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
    const patchAHash = bytesToHex(keccak256(patchABytes));
    const appliedA = applyPatch(parent, patchA);
    assert.equal(appliedA.ok, true);
    const rootA = merkleizeState(appliedA.state);

    const patchB = {
      patchType: PATCH_TYPE.KEY_UPDATE,
      wordCount: 1,
      scoreDelta: 6000n,
      parentStateRoot: rootA,
      indices: [402],
      newWords: [67890n],
    };
    const patchBBytes = encodePatch(patchB);
    const patchBHash = bytesToHex(keccak256(patchBBytes));
    const appliedB = applyPatch(appliedA.state, patchB);
    assert.equal(appliedB.ok, true);
    const rootB = merkleizeState(appliedB.state);

    // Feed a multi-transition log set to the SINGULAR replay function
    const logs = [
      makePatchLog(7, miner, patchAHash, patchABytes),
      makeAdvanceLog(7, 2, parentRoot, rootA, patchAHash),
      makePatchLog(7, miner, patchBHash, patchBBytes),
      makeAdvanceLog(7, 3, rootA, rootB, patchBHash),
    ];

    const result = replayV4TransitionFromLogs(parent, logs);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'MULTIPLE_ADVANCES');
    assert.ok(result.message.includes('2'), `expected message to mention count 2: ${result.message}`);
  });

  test('log set with exactly one advance is still accepted by singular replay', () => {
    const parent = makeCleanState();
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
    const patchAHash = bytesToHex(keccak256(patchABytes));
    const appliedA = applyPatch(parent, patchA);
    assert.equal(appliedA.ok, true);
    const rootA = merkleizeState(appliedA.state);

    const logs = [
      makePatchLog(7, miner, patchAHash, patchABytes),
      makeAdvanceLog(7, 2, parentRoot, rootA, patchAHash),
    ];

    const result = replayV4TransitionFromLogs(parent, logs);
    assert.equal(result.ok, true, `expected ok=true: ${JSON.stringify(result)}`);
    assert.equal(result.transitionIndex, '2');
  });
});
