/**
 * Canonical CoreTexRegistry replay decoder test.
 *
 * Builds ABI-encoded logs (matching CoreTexRegistry.sol's event encoding) from the REAL committed
 * state-root vectors (genuine patch bytes + roots + patch hashes), then asserts: topic constants,
 * decode of all three events, replay of one + multiple advances in order, and the failure cases
 * (wrong parent, wrong patch hash, wrong new root, missing bytes, coreVersion mismatch, out-of-order).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import {
  CORETEX_EVENT_TOPICS, decodeCoreTexEpochStarted, decodeCoreTexStateAdvanced,
  decodeCoreTexEpochFinalized, replayCoreTexFromLogs,
} from '../../dist/index.js';

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
function epochStartedLog({ epoch, parent, cvh, corpus, frontier, baseline, seed }) {
  return { topics: [TOPIC.CoreTexEpochStarted, '0x' + num32(epoch)], data: '0x' + [pad32(parent), pad32(cvh), pad32(corpus), pad32(frontier), pad32(baseline), pad32(seed)].join('') };
}
function epochFinalizedLog({ epoch, parent, finalRoot, cvh, corpus, frontier, patchSet, score, baseline }) {
  return { topics: [TOPIC.CoreTexEpochFinalized, '0x' + num32(epoch)], data: '0x' + [pad32(parent), pad32(finalRoot), pad32(cvh), pad32(corpus), pad32(frontier), pad32(patchSet), pad32(score), pad32(baseline)].join('') };
}

const adv0 = advanceLog({ epoch: 7, idx: 0, miner: MINER, parent: genesis.stateRoot, child: temporalVec.childStateRoot, patchHash: temporalVec.patchHash, evalHash: '0x' + '11'.repeat(32), cvh: BUNDLE, corpus: CORPUS, frontier: FRONTIER, credits: 30000, wordCount: temporalVec.patch.wordCount, patchHex: temporalVec.patchBytesHex });
const adv1 = advanceLog({ epoch: 7, idx: 1, miner: MINER, parent: temporalVec.childStateRoot, child: mixedVec.childStateRoot, patchHash: mixedVec.patchHash, evalHash: '0x' + '22'.repeat(32), cvh: BUNDLE, corpus: CORPUS, frontier: FRONTIER, credits: 40000, wordCount: mixedVec.patch.wordCount, patchHex: mixedVec.patchBytesHex });
const startedLog = epochStartedLog({ epoch: 7, parent: genesis.stateRoot, cvh: BUNDLE, corpus: CORPUS, frontier: FRONTIER, baseline: '0x' + 'ba'.repeat(32), seed: '0x' + '5e'.repeat(32) });
const finalizedLog = epochFinalizedLog({ epoch: 7, parent: genesis.stateRoot, finalRoot: mixedVec.childStateRoot, cvh: BUNDLE, corpus: CORPUS, frontier: FRONTIER, patchSet: '0x' + '90'.repeat(32), score: '0x' + '91'.repeat(32), baseline: '0x' + 'ba'.repeat(32) });

const empty = { words: new Array(1024).fill(0n) };

describe('CoreTexRegistry canonical replay decoder', () => {
  test('topics match cast-computed signatures', () => {
    assert.equal(TOPIC.CoreTexStateAdvanced, '0x2f0a89894d44aa2294de109d294ac072f0e206dc834a0c35c6fbf1623ec02dd0');
    assert.equal(TOPIC.CoreTexEpochStarted, '0xfdd4b01921a2e9dac964ae9b6ebd4d0649cd934841331933c2cea94792e616f3');
    assert.equal(TOPIC.CoreTexEpochFinalized, '0x7c882e64d34d7e0b82f8004ec182f5b9e942388f7b7b1ea60233306c02821085');
  });

  test('decode CoreTexEpochStarted', () => {
    const e = decodeCoreTexEpochStarted(startedLog);
    assert.equal(e.epoch, 7n);
    assert.equal(e.parentStateRoot, genesis.stateRoot);
    assert.equal(e.coreVersionHash, BUNDLE);
    assert.equal(e.corpusRoot, CORPUS);
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

  test('replay MULTIPLE advances in order (+ start + finalize) reproduces final root', () => {
    const r = replayCoreTexFromLogs(empty, [startedLog, adv0, adv1, finalizedLog], { expectedBundleHash: BUNDLE });
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

  test('wrong parent root rejected (epochStarted parent != provided state)', () => {
    const bad = epochStartedLog({ epoch: 7, parent: '0x' + 'de'.repeat(32), cvh: BUNDLE, corpus: CORPUS, frontier: FRONTIER, baseline: '0x00', seed: '0x00' });
    const r = replayCoreTexFromLogs(empty, [bad, adv0], { expectedBundleHash: BUNDLE });
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

  test('missing patch bytes rejected', () => {
    const empty0 = advanceLog({ epoch: 7, idx: 0, miner: MINER, parent: genesis.stateRoot, child: temporalVec.childStateRoot, patchHash: temporalVec.patchHash, evalHash: '0x00', cvh: BUNDLE, corpus: CORPUS, frontier: FRONTIER, credits: 0, wordCount: 0, patchHex: '0x' });
    const r = replayCoreTexFromLogs(empty, [empty0], { expectedBundleHash: BUNDLE });
    assert.equal(r.ok, false); assert.equal(r.code, 'NO_PATCH_BYTES');
  });
});
