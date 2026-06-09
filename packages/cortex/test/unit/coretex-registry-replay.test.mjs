/**
 * Canonical CoreTexRegistry replay decoder test.
 *
 * Builds ABI-encoded logs (matching CoreTexRegistry.sol's event encoding) from the REAL committed
 * state-root vectors (genuine patch bytes + roots + patch hashes), then asserts: topic constants,
 * decode of state/finalize events, replay of one + multiple advances in order, and the failure cases
 * (wrong parent, wrong patch hash, wrong new root, missing bytes, coreVersion mismatch, out-of-order).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import {
  CORETEX_EVENT_TOPICS, decodeCoreTexStateAdvanced,
  decodeCoreTexEpochFinalized, decodeCoreTexEpochReverted,
  replayCoreTexFromLogs, coretexRangeLogs,
  CORETEX_DEFAULT_LOG_CHUNK_BLOCKS, CORETEX_DEFAULT_CONFIRMATION_DEPTH,
} from '../../dist/index.js';
import { applyPatch, encodePatch } from '../../dist/state/patch.js';
import { merkleizeState, bytesToHex } from '../../dist/state/merkle.js';
import { computePatchHash } from '../../dist/eval/seed-derivation.js';
import { RANGES, PATCH_TYPE } from '../../dist/state/types.js';

const here = dirname(fileURLToPath(import.meta.url));
const fx = JSON.parse(readFileSync(resolve(here, '../../../../release/calibration/fixtures/state-root-vectors.json'), 'utf8'));
const [genesis, temporalVec, mixedVec] = fx.vectors;

const BUNDLE = '0x474cd8851eebd097a7f1480818c1ccdb0dd473c5da08cd6909b071ac8c101715';
const CORPUS = '0x15bab3a8e0d6fdb8df4d525e49aa7e22c815e749c8d95301a89e54de933beb33';
const FRONTIER = '0x' + '00'.repeat(31) + '09';
const MINER = '0x00000000000000000000000000000000000000aa';

// canonical topics cross-checked against `cast sig-event` in the build step
const TOPIC = CORETEX_EVENT_TOPICS;
function pad32(hex) { return hex.replace(/^0x/, '').padStart(64, '0'); }
function num32(n) { return BigInt(n).toString(16).padStart(64, '0'); }

// ABI-encode a CoreTexStateAdvanced log (3 indexed topics + non-indexed data)
function advanceLog({ epoch, idx, miner, parent, child, patchHash, evalHash, cvh, corpus, frontier, credits, wordCount, patchHex }) {
  const bytes = patchHex.replace(/^0x/, '');
  const byteLen = bytes.length / 2;
  const padded = bytes.padEnd(Math.ceil(byteLen / 32) * 64, '0');
  const head = [pad32(parent), pad32(child), pad32(patchHash), pad32(evalHash), pad32(cvh), pad32(corpus), pad32(frontier), num32(credits), num32(wordCount), num32(320)].join('');
  const tail = num32(byteLen) + padded;
  return {
    topics: [TOPIC.CoreTexStateAdvanced, '0x' + num32(epoch), '0x' + num32(idx), '0x' + pad32(miner)],
    data: '0x' + head + tail,
  };
}
function epochFinalizedLog({ epoch, parent, finalRoot, cvh, corpus, frontier, patchSet, score, baseline }) {
  return { topics: [TOPIC.CoreTexEpochFinalized, '0x' + num32(epoch)], data: '0x' + [pad32(parent), pad32(finalRoot), pad32(cvh), pad32(corpus), pad32(frontier), pad32(patchSet), pad32(score), pad32(baseline)].join('') };
}
// CoreTexEpochReverted(uint64 indexed epoch, address indexed by) — both indexed, empty data.
function epochRevertedLog({ epoch, by }) {
  return { topics: [TOPIC.CoreTexEpochReverted, '0x' + num32(epoch), '0x' + pad32(by)], data: '0x' };
}

const adv0 = advanceLog({ epoch: 7, idx: 0, miner: MINER, parent: genesis.stateRoot, child: temporalVec.childStateRoot, patchHash: temporalVec.patchHash, evalHash: '0x' + '11'.repeat(32), cvh: BUNDLE, corpus: CORPUS, frontier: FRONTIER, credits: 30000, wordCount: temporalVec.patch.wordCount, patchHex: temporalVec.patchBytesHex });
const adv1 = advanceLog({ epoch: 7, idx: 1, miner: MINER, parent: temporalVec.childStateRoot, child: mixedVec.childStateRoot, patchHash: mixedVec.patchHash, evalHash: '0x' + '22'.repeat(32), cvh: BUNDLE, corpus: CORPUS, frontier: FRONTIER, credits: 40000, wordCount: mixedVec.patch.wordCount, patchHex: mixedVec.patchBytesHex });
const finalizedLog = epochFinalizedLog({ epoch: 7, parent: genesis.stateRoot, finalRoot: mixedVec.childStateRoot, cvh: BUNDLE, corpus: CORPUS, frontier: FRONTIER, patchSet: '0x' + '90'.repeat(32), score: '0x' + '91'.repeat(32), baseline: '0x' + 'ba'.repeat(32) });

const empty = { words: new Array(1024).fill(0n) };

describe('CoreTexRegistry canonical replay decoder', () => {
  test('topics match cast-computed signatures', () => {
    assert.equal(TOPIC.CoreTexStateAdvanced, '0x2f0a89894d44aa2294de109d294ac072f0e206dc834a0c35c6fbf1623ec02dd0');
    assert.equal(TOPIC.CoreTexEpochFinalized, '0x7c882e64d34d7e0b82f8004ec182f5b9e942388f7b7b1ea60233306c02821085');
    assert.equal(TOPIC.CoreTexEpochReverted, '0x42068f2b30d6ed5d2709ee5dc0f0036daee1f9eb097565606d3ac326f6b51f6b');
  });

  test('decode CoreTexEpochReverted (indexed epoch + by, empty data)', () => {
    const r = decodeCoreTexEpochReverted(epochRevertedLog({ epoch: 7, by: MINER }));
    assert.equal(r.epoch, 7n);
    assert.equal(r.by, MINER);
    assert.equal(decodeCoreTexEpochReverted(adv0), null);
  });

  test('decode CoreTexStateAdvanced (incl miner topic + compactPatchBytes)', () => {
    const a = decodeCoreTexStateAdvanced(adv0);
    assert.equal(a.epoch, 7n); assert.equal(a.transitionIndex, 0n);
    assert.equal(a.miner, MINER);
    assert.equal(a.parentStateRoot, genesis.stateRoot);
    assert.equal(a.newStateRoot, temporalVec.childStateRoot);
    assert.equal(a.patchHash, temporalVec.patchHash);
    assert.equal('0x' + Buffer.from(a.compactPatchBytes).toString('hex'), temporalVec.patchBytesHex);
    assert.equal(a.improvementCredits, 30000n);
    assert.equal(a.wordCount, temporalVec.patch.wordCount);
  });

  test('decode CoreTexEpochFinalized', () => {
    const f = decodeCoreTexEpochFinalized(finalizedLog);
    assert.equal(f.epoch, 7n);
    assert.equal(f.finalStateRoot, mixedVec.childStateRoot);
  });

  test('replay ONE advance reproduces the temporal child root', () => {
    const r = replayCoreTexFromLogs(empty, [adv0], { expectedBundleHash: BUNDLE });
    assert.equal(r.ok, true, r.message);
    assert.equal(r.transitions, 1);
    assert.equal(r.reproducedFinalRoot, temporalVec.childStateRoot);
  });

  test('replay MULTIPLE advances in order (+ finalize) reproduces final root', () => {
    const r = replayCoreTexFromLogs(empty, [adv0, adv1, finalizedLog], { expectedBundleHash: BUNDLE });
    assert.equal(r.ok, true, r.message);
    assert.equal(r.transitions, 2);
    assert.equal(r.reproducedFinalRoot, mixedVec.childStateRoot);
    assert.equal(r.onChainFinalRoot, mixedVec.childStateRoot);
  });

  test('unsorted chain logs are canonicalized by transitionIndex (sort-tolerant)', () => {
    const r = replayCoreTexFromLogs(empty, [adv1, adv0], { expectedBundleHash: BUNDLE });
    assert.equal(r.ok, true, r.message); // sorted to 0,1 → valid
    assert.equal(r.reproducedFinalRoot, mixedVec.childStateRoot);
  });

  test('transition GAP (missing index) rejected as OUT_OF_ORDER', () => {
    const adv2 = advanceLog({ epoch: 7, idx: 2, miner: MINER, parent: temporalVec.childStateRoot, child: mixedVec.childStateRoot, patchHash: mixedVec.patchHash, evalHash: '0x00', cvh: BUNDLE, corpus: CORPUS, frontier: FRONTIER, credits: 0, wordCount: mixedVec.patch.wordCount, patchHex: mixedVec.patchBytesHex });
    const r = replayCoreTexFromLogs(empty, [adv0, adv2], { expectedBundleHash: BUNDLE }); // 0 then 2, missing 1
    assert.equal(r.ok, false); assert.equal(r.code, 'OUT_OF_ORDER');
  });

  test('wrong parent root rejected', () => {
    const bad = advanceLog({ epoch: 7, idx: 0, miner: MINER, parent: '0x' + 'de'.repeat(32), child: temporalVec.childStateRoot, patchHash: temporalVec.patchHash, evalHash: '0x00', cvh: BUNDLE, corpus: CORPUS, frontier: FRONTIER, credits: 0, wordCount: temporalVec.patch.wordCount, patchHex: temporalVec.patchBytesHex });
    const r = replayCoreTexFromLogs(empty, [bad], { expectedBundleHash: BUNDLE });
    assert.equal(r.ok, false); assert.equal(r.code, 'STATE_PARENT_MISMATCH');
  });

  test('wrong patch hash rejected', () => {
    const tampered = advanceLog({ epoch: 7, idx: 0, miner: MINER, parent: genesis.stateRoot, child: temporalVec.childStateRoot, patchHash: '0x' + 'ff'.repeat(32), evalHash: '0x00', cvh: BUNDLE, corpus: CORPUS, frontier: FRONTIER, credits: 0, wordCount: 3, patchHex: temporalVec.patchBytesHex });
    const r = replayCoreTexFromLogs(empty, [tampered], { expectedBundleHash: BUNDLE });
    assert.equal(r.ok, false); assert.equal(r.code, 'PATCH_HASH_MISMATCH');
  });

  test('wrong new root rejected', () => {
    const tampered = advanceLog({ epoch: 7, idx: 0, miner: MINER, parent: genesis.stateRoot, child: '0x' + 'ab'.repeat(32), patchHash: temporalVec.patchHash, evalHash: '0x00', cvh: BUNDLE, corpus: CORPUS, frontier: FRONTIER, credits: 0, wordCount: 3, patchHex: temporalVec.patchBytesHex });
    const r = replayCoreTexFromLogs(empty, [tampered], { expectedBundleHash: BUNDLE });
    assert.equal(r.ok, false); assert.equal(r.code, 'NEW_ROOT_MISMATCH');
  });

  test('bundle/coreVersion mismatch rejected', () => {
    const r = replayCoreTexFromLogs(empty, [adv0], { expectedBundleHash: '0x' + 'cc'.repeat(32) });
    assert.equal(r.ok, false); assert.equal(r.code, 'CORE_VERSION_MISMATCH');
  });

  test('non-coreVersion registry pin mismatches are rejected', () => {
    assert.equal(
      replayCoreTexFromLogs(empty, [adv0], { expectedBundleHash: BUNDLE, expectedCorpusRoot: '0x' + 'c1'.repeat(32) }).code,
      'CORPUS_ROOT_MISMATCH',
    );
    assert.equal(
      replayCoreTexFromLogs(empty, [adv0], { expectedBundleHash: BUNDLE, expectedActiveFrontierRoot: '0x' + 'f1'.repeat(32) }).code,
      'ACTIVE_FRONTIER_ROOT_MISMATCH',
    );
    assert.equal(
      replayCoreTexFromLogs(empty, [adv0, finalizedLog], { expectedBundleHash: BUNDLE, expectedBaselineManifestHash: '0x' + 'b1'.repeat(32) }).code,
      'BASELINE_MANIFEST_HASH_MISMATCH',
    );
  });

  test('missing patch bytes rejected', () => {
    const empty0 = advanceLog({ epoch: 7, idx: 0, miner: MINER, parent: genesis.stateRoot, child: temporalVec.childStateRoot, patchHash: temporalVec.patchHash, evalHash: '0x00', cvh: BUNDLE, corpus: CORPUS, frontier: FRONTIER, credits: 0, wordCount: 0, patchHex: '0x' });
    const r = replayCoreTexFromLogs(empty, [empty0], { expectedBundleHash: BUNDLE });
    assert.equal(r.ok, false); assert.equal(r.code, 'NO_PATCH_BYTES');
  });
});

describe('CoreTexRegistry replay — r5 grammar enforcement (canonical replay == scoring)', () => {
  // A forged r5 advance: a patch writing nonzero into the reserved policy region (896). applyPatch WITHOUT
  // policyAtomsMode ACCEPTS it (r4 codebook mask = 0), so its child root is internally consistent.
  const forgedParent = merkleizeState(empty);
  const forgedPatch = { patchType: PATCH_TYPE.MIXED, wordCount: 1, scoreDelta: 1n, parentStateRoot: forgedParent, indices: [RANGES.CODEBOOK_START], newWords: [1n] };
  const forgedBytes = encodePatch(forgedPatch);
  const forgedHex = '0x' + Buffer.from(forgedBytes).toString('hex');
  const applied = applyPatch(empty, forgedPatch); // ok WITHOUT policyAtomsMode
  const forgedChildRoot = bytesToHex(merkleizeState(applied.state));
  const forgedPatchHash = computePatchHash(forgedBytes);
  const forgedAdv = advanceLog({ epoch: 7, idx: 0, miner: MINER, parent: genesis.stateRoot, child: forgedChildRoot, patchHash: forgedPatchHash, evalHash: '0x' + '11'.repeat(32), cvh: BUNDLE, corpus: CORPUS, frontier: FRONTIER, credits: 30000, wordCount: 1, patchHex: forgedHex });

  test('forged r5 advance (reserved-region nonzero) RECONSTRUCTS without the flag (the gap)', () => {
    const r = replayCoreTexFromLogs(empty, [forgedAdv], { expectedBundleHash: BUNDLE });
    assert.equal(r.ok, true, 'without policyAtomsMode, replay silently reconstructs the forged root');
  });

  test('forged r5 advance is REJECTED (APPLY_FAILED) under policyAtomsMode — canonical replay enforces the grammar', () => {
    const r = replayCoreTexFromLogs(empty, [forgedAdv], { expectedBundleHash: BUNDLE, policyAtomsMode: true });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'APPLY_FAILED');
  });

  test('a clean (non-forged) advance still replays under policyAtomsMode (no false rejection)', () => {
    const r = replayCoreTexFromLogs(empty, [adv0], { expectedBundleHash: BUNDLE, policyAtomsMode: true });
    assert.equal(r.ok, true);
  });
});

describe('CoreTexRegistry replay — per-epoch transitionIndex + epoch revert semantics', () => {
  // epoch 8 legitimately restarts transitionIndex at 0 (same continuity chain).
  const adv8idx0 = advanceLog({ epoch: 8, idx: 0, miner: MINER, parent: temporalVec.childStateRoot, child: mixedVec.childStateRoot, patchHash: mixedVec.patchHash, evalHash: '0x' + '22'.repeat(32), cvh: BUNDLE, corpus: CORPUS, frontier: FRONTIER, credits: 40000, wordCount: mixedVec.patch.wordCount, patchHex: mixedVec.patchBytesHex });
  // epoch 8 restarting from GENESIS (the post-revert continuation of a reverted epoch 7).
  const adv8fromGenesis = advanceLog({ epoch: 8, idx: 0, miner: MINER, parent: genesis.stateRoot, child: temporalVec.childStateRoot, patchHash: temporalVec.patchHash, evalHash: '0x' + '33'.repeat(32), cvh: BUNDLE, corpus: CORPUS, frontier: FRONTIER, credits: 30000, wordCount: temporalVec.patch.wordCount, patchHex: temporalVec.patchBytesHex });
  const revert7 = epochRevertedLog({ epoch: 7, by: MINER });

  test('second epoch restarting transitionIndex at 0 is NOT a false OUT_OF_ORDER', () => {
    const r = replayCoreTexFromLogs(empty, [adv0, adv8idx0], { expectedBundleHash: BUNDLE });
    assert.equal(r.ok, true, r.message);
    assert.equal(r.transitions, 2);
    assert.equal(r.reproducedFinalRoot, mixedVec.childStateRoot);
  });

  test('an index gap WITHIN an epoch is still OUT_OF_ORDER (per-epoch tracking)', () => {
    const adv8idx1 = advanceLog({ epoch: 8, idx: 1, miner: MINER, parent: temporalVec.childStateRoot, child: mixedVec.childStateRoot, patchHash: mixedVec.patchHash, evalHash: '0x00', cvh: BUNDLE, corpus: CORPUS, frontier: FRONTIER, credits: 0, wordCount: mixedVec.patch.wordCount, patchHex: mixedVec.patchBytesHex });
    const r = replayCoreTexFromLogs(empty, [adv0, adv8idx1], { expectedBundleHash: BUNDLE }); // epoch 8 starts at 1
    assert.equal(r.ok, false);
    assert.equal(r.code, 'OUT_OF_ORDER');
  });

  test('an unacknowledged CoreTexEpochReverted refuses to report clean', () => {
    const r = replayCoreTexFromLogs(empty, [adv0, adv1, finalizedLog, revert7], { expectedBundleHash: BUNDLE });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'EPOCH_REVERT_UNACKNOWLEDGED');
    assert.deepEqual(r.revertedEpochs, [7]);
  });

  test('an acknowledged revert unwinds the epoch: its advances + finalize are excluded', () => {
    const r = replayCoreTexFromLogs(empty, [adv0, adv1, finalizedLog, revert7], { expectedBundleHash: BUNDLE, acknowledgedRevertedEpochs: [7] });
    assert.equal(r.ok, true, r.message);
    assert.equal(r.transitions, 0);
    assert.equal(r.reproducedFinalRoot, genesis.stateRoot);
    assert.equal(r.onChainFinalRoot, undefined, 'reverted epoch finalize must not bind the final root');
    assert.deepEqual(r.revertedEpochs, [7]);
  });

  test('post-revert continuation: epoch 8 chains off the pre-revert root', () => {
    const r = replayCoreTexFromLogs(empty, [adv0, adv1, revert7, adv8fromGenesis], { expectedBundleHash: BUNDLE, acknowledgedRevertedEpochs: [7] });
    assert.equal(r.ok, true, r.message);
    assert.equal(r.transitions, 1);
    assert.equal(r.reproducedFinalRoot, temporalVec.childStateRoot);
  });

  test('acknowledging a revert that did not happen does not mask other epochs', () => {
    const r = replayCoreTexFromLogs(empty, [adv0, adv1, revert7], { expectedBundleHash: BUNDLE, acknowledgedRevertedEpochs: [9] });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'EPOCH_REVERT_UNACKNOWLEDGED');
  });
});

describe('coretexRangeLogs — pagination + confirmation-depth capping', () => {
  function withFetchMock(latestBlockNumber, fn) {
    const calls = [];
    const realFetch = globalThis.fetch;
    let blockNumberCalls = 0;
    globalThis.fetch = async (_url, init) => {
      const body = JSON.parse(init.body);
      if (body.method === 'eth_blockNumber') {
        blockNumberCalls++;
        return { ok: true, json: async () => ({ result: '0x' + latestBlockNumber.toString(16) }) };
      }
      if (body.method === 'eth_getLogs') {
        const p = body.params[0];
        calls.push({ fromBlock: BigInt(p.fromBlock), toBlock: BigInt(p.toBlock), topics: p.topics, address: p.address });
        return { ok: true, json: async () => ({ result: [] }) };
      }
      throw new Error(`unexpected RPC method ${body.method}`);
    };
    return Promise.resolve(fn(calls, () => blockNumberCalls)).finally(() => { globalThis.fetch = realFetch; });
  }

  test('chunks the range at chunkBlocks boundaries and caps toBlock at latest - confirmationDepth', () =>
    withFetchMock(200n, async (calls) => {
      const logs = await coretexRangeLogs('http://127.0.0.1:1', '0x' + '11'.repeat(20), '0x64', '0xc8', { chunkBlocks: 7, confirmationDepth: 50 });
      assert.deepEqual(logs, []);
      // latest=200, depth=50 → confirmed head 150; requested 100..200 → 100..150 in chunks of 7
      assert.equal(calls[0].fromBlock, 100n);
      assert.equal(calls[0].toBlock, 106n);
      assert.equal(calls.at(-1).toBlock, 150n);
      for (let i = 1; i < calls.length; i++) {
        assert.equal(calls[i].fromBlock, calls[i - 1].toBlock + 1n, 'chunks are contiguous, no gaps/overlaps');
      }
      assert.equal(calls.length, 8); // ceil(51 / 7)
      // every chunk carries the full canonical topic OR-set including the revert event
      assert.deepEqual(calls[0].topics, [[
        CORETEX_EVENT_TOPICS.CoreTexStateAdvanced,
        CORETEX_EVENT_TOPICS.CoreTexEpochFinalized,
        CORETEX_EVENT_TOPICS.CoreTexEpochReverted,
      ]]);
    }));

  test('range entirely beyond the confirmed head yields zero eth_getLogs calls', () =>
    withFetchMock(100n, async (calls) => {
      const logs = await coretexRangeLogs('http://127.0.0.1:1', undefined, '0x60', '0x64', { chunkBlocks: 10, confirmationDepth: 50 });
      assert.deepEqual(logs, []);
      assert.equal(calls.length, 0); // from=96 > confirmed head 50
    }));

  test('latestBlock option skips the eth_blockNumber round-trip', () =>
    withFetchMock(0n, async (calls, blockNumberCalls) => {
      await coretexRangeLogs('http://127.0.0.1:1', undefined, '0x0', '0x10', { chunkBlocks: 100, confirmationDepth: 0, latestBlock: 16n });
      assert.equal(blockNumberCalls(), 0);
      assert.equal(calls.length, 1);
      assert.equal(calls[0].fromBlock, 0n);
      assert.equal(calls[0].toBlock, 16n);
    }));

  test('defaults: 9500-block chunks, Base confirmation depth 15', () =>
    withFetchMock(100000n, async (calls) => {
      assert.equal(CORETEX_DEFAULT_LOG_CHUNK_BLOCKS, 9500);
      assert.equal(CORETEX_DEFAULT_CONFIRMATION_DEPTH, 15);
      await coretexRangeLogs('http://127.0.0.1:1', undefined, '0x0', '0x' + (100000).toString(16));
      // confirmed head 99985; 99986 blocks / 9500 → 11 chunks
      assert.equal(calls.length, 11);
      assert.equal(calls[0].toBlock, 9499n);
      assert.equal(calls.at(-1).toBlock, 99985n);
    }));

  test('rejects non-positive chunk size', async () => {
    await assert.rejects(
      () => coretexRangeLogs('http://127.0.0.1:1', undefined, '0x0', '0x10', { chunkBlocks: 0, latestBlock: 16n }),
      /chunkBlocks must be positive/,
    );
  });
});
