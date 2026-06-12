/**
 * §9/§7 pass tests for the v0 CoreTexCoordinatorCore concurrency + baseline lane.
 *
 * §9 (W02 race / FIFO signing queue):
 *  - concurrent same-miner and cross-miner submits are strictly serialized in
 *    arrival order; exactly one evaluation per unique submission; no
 *    double-spent solveIndex/prevReceiptHash (same-miner receipts chain on the
 *    signer-provided receiptHash reservation);
 *  - a signer that cannot provide receiptHash makes a follow-up same-miner
 *    submit reject MinerReceiptChainBusy instead of double-spending;
 *  - tick() cannot interleave with an in-flight submit (shared mutex);
 *  - pre-sign re-checks: mid-evaluation epoch rollover and freeze reject
 *    before the signer runs;
 *  - freeze => submits reject epoch_cutover_in_progress and tick is a no-op;
 *    unfreeze restores service;
 *  - reject envelopes carry NO deterministicDeltaPpm / requiredDeltaPpm.
 *
 * §7 (baseline runtime semantics, baselineRecompute='activeRootChanged'):
 *  - missing launch baseline prevents serving (boot hard-fails);
 *  - status threshold fields update after an accepted state advance (gate
 *    tracks the live baseline, not a static config value);
 *  - rotation to a root with no baseline flips status to
 *    awaiting_baseline_recompute and refuses submits until
 *    setRecomputedBaseline provides one; invalidateBaselines re-arms the gate.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  CoreTexCoordinatorCore,
} from '../../dist/coordinator/coretex-coordinator-core.js';
import { merkleizeState, bytesToHex, applyPatch, decodePatch, encodePatch, computePatchHash } from '../../dist/index.js';

// ── helpers (mirrors coretex-coordinator-core.test.mjs) ────────────────────
const GENESIS = { words: new Array(1024).fill(0n) };
const GENESIS_ROOT = bytesToHex(merkleizeState(GENESIS));
const CORE_V = '0x' + '0e'.repeat(32);
const CORPUS = '0x' + 'c0'.repeat(32);
const FRONTIER = '0x' + 'fe'.repeat(32);
const BASELINE = '0x' + 'ba'.repeat(32);
const SEED_COMMIT = '0x' + 'cc'.repeat(32);
const V4_ADDR = '0xf3' + '11'.repeat(19);
const REG_ADDR = '0xea' + '22'.repeat(19);
const SIGNER = '0x' + '33'.repeat(20);
const EPOCH = 106n;
const MINER_A = '0x' + 'aa'.repeat(20);
const MINER_B = '0x' + 'bb'.repeat(20);

// No static screenerThresholdPpm: the live threshold must derive from the
// baseline plus state-advance threshold (288438 + 2700ppm -> 1350ppm under
// the default policy).
const baseConfig = {
  epoch: EPOCH,
  expectedChainId: 8453n,
  v4Address: V4_ADDR,
  registryAddress: REG_ADDR,
  expectedCoordinatorSigner: SIGNER,
  expectedEpochPins: {
    parentStateRoot: GENESIS_ROOT,
    coreVersionHash: CORE_V,
    corpusRoot: CORPUS,
    activeFrontierRoot: FRONTIER,
    baselineManifestHash: BASELINE,
    hiddenSeedCommit: SEED_COMMIT,
  },
  confirmationDepth: 4,
  receiptTtlSec: 60,
  perMinerScreenerCap: 50,
  baselineParentScorePpm: 288438,
  minImprovementPpm: 2500,
  replayTolerancePpm: 200,
  targetBlockOffset: 30,
  patchWordBudget: 4,
  rulesVersion: 192,
  workPolicyHash: '0x' + '66'.repeat(32),
  allowedPatchTypes: [{ name: 'MEMORY_INDEX_UPDATE', byte: 255, wordIndexRange: [32, 383] }],
  activeSubstrateSurfaces: ['temporal_update', 'evidence_bundle'],
};

class MockChain {
  constructor(opts = {}) {
    this.head = opts.head ?? 1000;
    this.chainId = opts.chainId ?? 8453n;
    this.v4Epoch = opts.v4Epoch ?? EPOCH;
    this.epochCommit = opts.epochCommit ?? '0x' + '92'.repeat(32);
    this.signer = opts.signer ?? SIGNER;
    this.registryAddr = opts.registryAddr ?? REG_ADDR;
    this.pins = opts.pins ?? { ...baseConfig.expectedEpochPins };
    this.events = opts.events ?? [];
    this.blockHashes = opts.blockHashes ?? new Map();
    this.regEpoch = opts.regEpoch ?? { liveStateRoot: GENESIS_ROOT, transitionCount: 0 };
    this.minerCounters = opts.minerCounters ?? { screenersThisEpoch: 0, nextIndex: 0n, lastReceiptHash: '0x' + '00'.repeat(32) };
    // Per-miner counters (lowercased address -> counters); falls back to minerCounters.
    this.minerCountersByAddr = opts.minerCountersByAddr ?? new Map();
    this.qualified = opts.qualified ?? 0;
  }
  async getBlockNumber() { return this.head; }
  async getBlockHashAt(n) { return this.blockHashes.get(n) ?? null; }
  async getStateAdvancedEvents(from, to) {
    return this.events.filter((e) => Number(e.blockNumber) >= from && Number(e.blockNumber) <= to);
  }
  async getRegistryEpoch() { return this.regEpoch; }
  async getRegistryEpochPins() { return this.pins; }
  async getV4CurrentEpoch() { return this.v4Epoch; }
  async getV4EpochCommit() { return this.epochCommit; }
  async getV4CoordinatorSigner() { return this.signer; }
  async getV4CoreTexRegistry() { return this.registryAddr; }
  async getChainId() { return this.chainId; }
  async getMinerCoreTexCounters(_epoch, miner) {
    return this.minerCountersByAddr.get(miner.toLowerCase()) ?? this.minerCounters;
  }
  async getQualifiedScreenerPassesSinceLastStateAdvance() { return this.qualified; }
}
function loadGenesis() { return { words: [...GENESIS.words] }; }
function delay(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
function flushTasks() { return new Promise((resolve) => setImmediate(resolve)); }

function hexToBytes(h) {
  const s = h.replace(/^0x/, '');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Unique single-word MEMORY_INDEX_UPDATE patch against `rootHex`. */
function makePatchHex(rootHex, idx, valByte) {
  const valHex = valByte.toString(16).padStart(2, '0') + '00'.repeat(31);
  return `0xff010000000000000000${rootHex.replace(/^0x/, '')}${idx.toString(16).padStart(2, '0')}${valHex}`;
}

function rewritePatchScoreDelta(patchHex, deltaPpm) {
  const decoded = decodePatch(hexToBytes(patchHex));
  return bytesToHex(encodePatch({ ...decoded, scoreDelta: BigInt(deltaPpm) }));
}

class EventChain {
  constructor() {
    this.state = { words: [...GENESIS.words] };
    this.root = GENESIS_ROOT;
    this.transitionIndex = 0;
  }
  next({ blockNumber, blockHash, miner = MINER_A }) {
    const idx = 38 + this.transitionIndex;
    const patchHex = makePatchHex(this.root, idx, this.transitionIndex + 1);
    const buf = hexToBytes(patchHex);
    const decoded = decodePatch(buf);
    const next = applyPatch(this.state, decoded, true);
    if (!next.ok) throw new Error(`buildEvent: applyPatch failed ${next.code}`);
    const newRoot = bytesToHex(merkleizeState(next.state));
    const ev = {
      blockNumber: BigInt(blockNumber), blockHash, logIndex: 0n, epoch: EPOCH,
      transitionIndex: BigInt(this.transitionIndex), miner,
      parent: this.root, newRoot, patchHash: computePatchHash(buf), evalReportHash: '0x' + 'e1'.repeat(32),
      coreV: CORE_V, corpus: CORPUS, frontier: FRONTIER,
      credits: 1000n, wordCount: decoded.wordCount, compactPatchBytes: patchHex,
    };
    this.state = next.state;
    this.root = newRoot;
    this.transitionIndex += 1;
    return ev;
  }
}

function dualProofFor(patchHex, parentStateRoot = GENESIS_ROOT) {
  return {
    kind: 'coretex-dual-pack-v1',
    mode: 'future_blockhash_dual_pack',
    epochId: Number(EPOCH),
    receivedAtBlock: 1000,
    targetBlock: 1030,
    targetBlockOffset: 30,
    blockhash: '0x' + '77'.repeat(32),
    patchHash: computePatchHash(hexToBytes(patchHex)).toLowerCase(),
    parentStateRoot: parentStateRoot.toLowerCase(),
    corpusRoot: CORPUS,
    coreVersionHash: CORE_V,
    hiddenSeedCommit: SEED_COMMIT,
    epochSecretCommit: SEED_COMMIT,
    gate: { domain: 'gate', seedCommit: '0x' + '91'.repeat(32), accepted: true, scorePpm: 3100 },
    confirm: { domain: 'confirm', seedCommit: '0x' + '92'.repeat(32), accepted: true, scorePpm: 3090 },
  };
}

function screenerResult(patchHex, parentStateRoot, deltaPpm = 1500) {
  return {
    outcome: 'screener_pass',
    deterministicDeltaPpm: deltaPpm,
    evalReportHash: '0x' + 'e1'.repeat(32),
    artifactHash: '0x' + 'a1'.repeat(32),
    evaluationProof: dualProofFor(patchHex, parentStateRoot),
  };
}

/** Signer that derives a synthetic-but-unique bytes32 receiptHash so the core
 *  can chain a same-miner follow-up receipt on the un-landed reservation. */
function chainingSigner(record = []) {
  let n = 0;
  return {
    signCoreTexReceipt: ({ miner, receipt }) => {
      n += 1;
      const receiptHash = '0x' + n.toString(16).padStart(8, '0') + receipt.patchHash.slice(10);
      record.push({ miner, solveIndex: receipt.solveIndex, prevReceiptHash: receipt.prevReceiptHash, patchHash: receipt.patchHash, receiptHash });
      return {
        signature: '0x' + '5a'.repeat(65),
        transactionData: '0x' + receipt.patchHash.slice(2, 10),
        receiptHash,
      };
    },
  };
}

const plainSigner = {
  signCoreTexReceipt: ({ receipt }) => ({
    signature: '0x' + '5a'.repeat(65),
    transactionData: '0x' + receipt.patchHash.slice(2, 10),
  }),
};

function submitBody(patchHex, miner = MINER_A, parentStateRoot = GENESIS_ROOT) {
  return { patchBytesHex: patchHex, parentStateRoot, minerAddress: miner };
}

// ── §9: FIFO signing queue + reservations ───────────────────────────────────
describe('CoreTexCoordinatorCore §9 — FIFO signing queue', () => {
  test('concurrent same-miner + cross-miner submits: strict arrival order, one eval each, chained counters, no double-spend', async () => {
    const evalOrder = [];
    let active = 0;
    let maxActive = 0;
    const evaluator = {
      scorePatch: async (input) => {
        active += 1;
        maxActive = Math.max(maxActive, active);
        evalOrder.push(computePatchHash(hexToBytes(input.patchBytesHex)).toLowerCase());
        await delay(10);
        active -= 1;
        return screenerResult(input.patchBytesHex, input.parentStateRoot);
      },
    };
    const signedLog = [];
    const chain = new MockChain({
      head: 1000,
      minerCountersByAddr: new Map([
        [MINER_A, { screenersThisEpoch: 0, nextIndex: 0n, lastReceiptHash: '0x' + '00'.repeat(32) }],
        [MINER_B, { screenersThisEpoch: 0, nextIndex: 5n, lastReceiptHash: '0x' + '07'.repeat(32) }],
      ]),
    });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator, chainingSigner(signedLog));
    await coord.boot();

    const pA1 = makePatchHex(GENESIS_ROOT, 40, 1);
    const pB1 = makePatchHex(GENESIS_ROOT, 41, 2);
    const pA2 = makePatchHex(GENESIS_ROOT, 42, 3);
    const pB2 = makePatchHex(GENESIS_ROOT, 43, 4);
    // Fire all four WITHOUT awaiting in between.
    const results = await Promise.all([
      coord.submit(submitBody(pA1, MINER_A)),
      coord.submit(submitBody(pB1, MINER_B)),
      coord.submit(submitBody(pA2, MINER_A)),
      coord.submit(submitBody(pB2, MINER_B)),
    ]);
    for (const [i, out] of results.entries()) {
      assert.equal(out.status, 'accepted', `submit ${i} accepted: ${JSON.stringify(out)}`);
    }
    // Exactly one evaluation per unique submission, strictly in arrival order.
    assert.deepEqual(evalOrder, [pA1, pB1, pA2, pB2].map((p) => computePatchHash(hexToBytes(p)).toLowerCase()));
    assert.equal(maxActive, 1, 'never more than one evaluation in flight');
    // Same-miner solve chains: A gets 0 then 1 chained on A1's receiptHash;
    // B gets 5 then 6 chained on B1's receiptHash. No counter double-spend.
    const [a1, b1, a2, b2] = results;
    assert.equal(a1.receipt.solveIndex, '0');
    assert.equal(a2.receipt.solveIndex, '1');
    assert.equal(b1.receipt.solveIndex, '5');
    assert.equal(b2.receipt.solveIndex, '6');
    assert.equal(b1.receipt.prevReceiptHash, '0x' + '07'.repeat(32));
    const signedA1 = signedLog.find((s) => s.patchHash === a1.patchHash);
    const signedB1 = signedLog.find((s) => s.patchHash === b1.patchHash);
    assert.equal(a2.receipt.prevReceiptHash, signedA1.receiptHash);
    assert.equal(b2.receipt.prevReceiptHash, signedB1.receiptHash);
    const perMiner = new Map();
    for (const s of signedLog) {
      const seen = perMiner.get(s.miner) ?? new Set();
      assert.equal(seen.has(s.solveIndex), false, `solveIndex ${s.solveIndex} signed twice for ${s.miner}`);
      seen.add(s.solveIndex);
      perMiner.set(s.miner, seen);
    }
    assert.equal(coord.getState().minerReservationCount, 2);
  });

  test('signer without receiptHash: second same-miner submit rejects MinerReceiptChainBusy until the chain catches up', async () => {
    const evaluator = { scorePatch: (input) => screenerResult(input.patchBytesHex, input.parentStateRoot) };
    const chain = new MockChain({ head: 1000 });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator, plainSigner);
    await coord.boot();

    const first = await coord.submit(submitBody(makePatchHex(GENESIS_ROOT, 40, 1)));
    assert.equal(first.status, 'accepted');
    assert.equal(first.receipt.solveIndex, '0');

    const blocked = await coord.submit(submitBody(makePatchHex(GENESIS_ROOT, 41, 2)));
    assert.equal(blocked.status, 'rejected');
    assert.equal(blocked.code, 'MinerReceiptChainBusy');

    // Cross-miner submits are NOT blocked by miner A's reservation.
    const other = await coord.submit(submitBody(makePatchHex(GENESIS_ROOT, 42, 3), MINER_B));
    assert.equal(other.status, 'accepted');

    // Miner A's first receipt lands: chain counters advance, reservation clears.
    const landedHash = '0x' + '11'.repeat(32);
    chain.minerCountersByAddr.set(MINER_A, { screenersThisEpoch: 1, nextIndex: 1n, lastReceiptHash: landedHash });
    const after = await coord.submit(submitBody(makePatchHex(GENESIS_ROOT, 41, 2)));
    assert.equal(after.status, 'accepted');
    assert.equal(after.receipt.solveIndex, '1');
    assert.equal(after.receipt.prevReceiptHash, landedHash);
  });

  test('tick can advance during remote eval; submit rejects stale root before signing', async () => {
    const chainGen = new EventChain();
    const rootsDuringEval = [];
    let signerCalls = 0;
    let coord;
    const evaluator = {
      scorePatch: async (input) => {
        rootsDuringEval.push(coord.getState().liveRoot.toLowerCase());
        await delay(50);
        rootsDuringEval.push(coord.getState().liveRoot.toLowerCase());
        return screenerResult(input.patchBytesHex, input.parentStateRoot);
      },
    };
    const countingSigner = {
      signCoreTexReceipt: ({ receipt }) => {
        signerCalls += 1;
        return { signature: '0x' + '5a'.repeat(65), transactionData: '0x' + receipt.patchHash.slice(2, 10) };
      },
    };
    const chain = new MockChain({ head: 200, regEpoch: { liveStateRoot: GENESIS_ROOT, transitionCount: 0 } });
    coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator, countingSigner);
    await coord.boot();

    // A confirmed state advance is ready for the next tick.
    const ev0 = chainGen.next({ blockNumber: 300, blockHash: '0x' + '55'.repeat(32) });
    chain.events.push(ev0);
    chain.blockHashes.set(300, ev0.blockHash);
    chain.head = 400;
    chain.regEpoch = { liveStateRoot: ev0.newRoot, transitionCount: 1 };

    const submitP = coord.submit(submitBody(makePatchHex(GENESIS_ROOT, 40, 1)));
    await flushTasks(); // let the submit enter the mutex and start evaluating
    const tickP = coord.tick();
    const [out] = await Promise.all([submitP, tickP]);

    assert.equal(out.status, 'rejected');
    assert.equal(out.code, 'W02_STALE_PARENT_AT_SIGNING');
    assert.equal(signerCalls, 0);
    assert.equal(rootsDuringEval[0], GENESIS_ROOT.toLowerCase());
    assert.equal(rootsDuringEval[1], ev0.newRoot.toLowerCase());
    assert.equal(coord.getState().liveRoot.toLowerCase(), ev0.newRoot.toLowerCase());
  });

  test('pre-sign re-check: epoch rollover mid-evaluation rejects before the signer runs', async () => {
    let chain;
    const evaluator = {
      scorePatch: async (input) => {
        chain.v4Epoch = EPOCH + 1n; // rolls over while the evaluation is in flight
        return screenerResult(input.patchBytesHex, input.parentStateRoot);
      },
    };
    let signerCalls = 0;
    const countingSigner = {
      signCoreTexReceipt: ({ receipt }) => {
        signerCalls += 1;
        return { signature: '0x' + '5a'.repeat(65), transactionData: '0x' + receipt.patchHash.slice(2, 10) };
      },
    };
    chain = new MockChain({ head: 1000 });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator, countingSigner);
    await coord.boot();
    const out = await coord.submit(submitBody(makePatchHex(GENESIS_ROOT, 40, 1)));
    assert.equal(out.status, 'rejected');
    assert.equal(out.code, 'CoordEpochMismatch');
    assert.equal(signerCalls, 0, 'stale-epoch evaluation must never reach the signer');
  });

  test('freeze rejects submits with epoch_cutover_in_progress, quiesces tick, and unfreeze restores service', async () => {
    const chainGen = new EventChain();
    const evaluator = { scorePatch: (input) => screenerResult(input.patchBytesHex, input.parentStateRoot) };
    const chain = new MockChain({ head: 200, regEpoch: { liveStateRoot: GENESIS_ROOT, transitionCount: 0 } });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator, plainSigner);
    await coord.boot();

    await coord.freeze('epoch cutover drill');
    assert.equal(coord.isFrozen(), true);
    const rejected = await coord.submit(submitBody(makePatchHex(GENESIS_ROOT, 40, 1)));
    assert.equal(rejected.status, 'rejected');
    assert.equal(rejected.code, 'epoch_cutover_in_progress');

    // A confirmed event is ready, but a frozen tick must not mutate anything.
    const ev0 = chainGen.next({ blockNumber: 300, blockHash: '0x' + '55'.repeat(32) });
    chain.events.push(ev0);
    chain.blockHashes.set(300, ev0.blockHash);
    chain.head = 400;
    chain.regEpoch = { liveStateRoot: ev0.newRoot, transitionCount: 1 };
    await coord.tick();
    assert.equal(coord.getState().transitionCount, 0, 'frozen tick is a no-op');

    const status = await coord.getStatus();
    assert.equal(status.acceptingSubmissions, false);
    assert.equal(status.frozen, true);
    const health = await coord.health();
    assert.equal(health.frozen, true);
    assert.equal(health.acceptingSubmissions, false);

    coord.unfreeze();
    await coord.tick();
    assert.equal(coord.getState().transitionCount, 1, 'unfrozen tick applies the event');
    // New live root is a foreign advance (no signed pending) -> baseline gate
    // takes over; freeze itself no longer rejects.
    const next = await coord.submit(submitBody(makePatchHex(ev0.newRoot, 40, 1), MINER_A, ev0.newRoot));
    assert.notEqual(next.code, 'epoch_cutover_in_progress');
  });

  test('freeze flipped mid-evaluation rejects at the pre-sign re-check', async () => {
    let coord;
    let signerCalls = 0;
    const evaluator = {
      scorePatch: async (input) => {
        void coord.freeze('cutover started mid-flight'); // flag flips synchronously
        return screenerResult(input.patchBytesHex, input.parentStateRoot);
      },
    };
    const countingSigner = {
      signCoreTexReceipt: ({ receipt }) => {
        signerCalls += 1;
        return { signature: '0x' + '5a'.repeat(65), transactionData: '0x' + receipt.patchHash.slice(2, 10) };
      },
    };
    coord = new CoreTexCoordinatorCore(baseConfig, new MockChain({ head: 1000 }), loadGenesis, evaluator, countingSigner);
    await coord.boot();
    const out = await coord.submit(submitBody(makePatchHex(GENESIS_ROOT, 40, 1)));
    assert.equal(out.status, 'rejected');
    assert.equal(out.code, 'epoch_cutover_in_progress');
    assert.equal(signerCalls, 0);
    coord.unfreeze();
  });

  test('reject envelopes never carry deterministicDeltaPpm / requiredDeltaPpm', async () => {
    const evaluator = { scorePatch: (input) => screenerResult(input.patchBytesHex, input.parentStateRoot, 320) };
    const coord = new CoreTexCoordinatorCore(baseConfig, new MockChain({ head: 1000 }), loadGenesis, evaluator, plainSigner);
    await coord.boot();
    // baseline 288438 + state threshold 2700 -> live threshold 1350; delta
    // 320 is below it.
    const out = await coord.submit(submitBody(makePatchHex(GENESIS_ROOT, 40, 1)));
    assert.equal(out.status, 'rejected');
    assert.equal(out.code, 'W03_DETERMINISTIC_DELTA_TOO_LOW');
    assert.equal('deterministicDeltaPpm' in out, false, 'reject must not leak a score oracle');
    assert.equal('requiredDeltaPpm' in out, false, 'reject must not leak the live threshold');
  });
});

// ── §7: baseline runtime semantics ──────────────────────────────────────────
describe('CoreTexCoordinatorCore §7 — baseline runtime semantics', () => {
  test('missing launch baseline prevents serving (boot hard-fails)', async () => {
    const { baselineParentScorePpm: _omit, ...withoutBaseline } = baseConfig;
    const coord = new CoreTexCoordinatorCore(withoutBaseline, new MockChain({ head: 1000 }), loadGenesis,
      { scorePatch: () => ({ outcome: 'reject', code: 'noop', reason: 'noop' }) });
    await assert.rejects(() => coord.boot(), /launch baselineParentScorePpm/);
  });

  test('status threshold fields update after an accepted state advance and the gate tracks the live baseline', async () => {
    const advancePatch = makePatchHex(GENESIS_ROOT, 38, 1);
    const deltaPpm = 400000 - 288438;
    const rewritten = rewritePatchScoreDelta(advancePatch, deltaPpm);
    const signedHash = computePatchHash(hexToBytes(rewritten)).toLowerCase();
    let mode = 'screener';
    let screenerDelta = 320;
    const evaluator = {
      scorePatch: (input) => mode === 'screener'
        ? screenerResult(input.patchBytesHex, input.parentStateRoot, screenerDelta)
        : {
            outcome: 'state_advance',
            deterministicDeltaPpm: deltaPpm,
            evalReportHash: '0x' + 'e2'.repeat(32),
            artifactHash: '0x' + 'a2'.repeat(32),
            scoreBeforePpm: 288438,
            scoreAfterPpm: 400000,
            rewrittenPatchBytesHex: rewritten,
            evaluationProof: dualProofFor(input.patchBytesHex, input.parentStateRoot),
          },
    };
    const chain = new MockChain({ head: 1000 });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator, plainSigner);
    await coord.boot();

    // Launch context: baseline 288438 with a 2700ppm state threshold -> live
    // screener threshold 1350ppm.
    const status0 = await coord.getStatus();
    assert.equal(status0.baselineState, 'ready');
    assert.equal(status0.baselineParentScorePpm, 288438);
    assert.equal(status0.stateAdvanceThresholdPpm, 2700);
    assert.equal(status0.screenerThresholdPpm, 1350);
    assert.equal(status0.thresholds.screenerThresholdPpm, 1350);

    // A 320ppm screener is below the launch threshold.
    const before = await coord.submit(submitBody(makePatchHex(GENESIS_ROOT, 40, 1)));
    assert.equal(before.code, 'W03_DETERMINISTIC_DELTA_TOO_LOW');

    // Accepted state advance -> confirmed on chain -> baseline = scoreAfterPpm.
    mode = 'advance';
    const out = await coord.submit(submitBody(advancePatch));
    assert.equal(out.status, 'accepted');
    assert.equal(out.outcome, 'STATE_ADVANCE');
    const landed = {
      blockNumber: 1001n, blockHash: '0x' + '01'.repeat(32), logIndex: 0n, epoch: EPOCH,
      transitionIndex: 0n, miner: MINER_A, parent: GENESIS_ROOT, newRoot: out.newStateRoot,
      patchHash: signedHash, evalReportHash: '0x' + 'e2'.repeat(32),
      coreV: CORE_V, corpus: CORPUS, frontier: FRONTIER, credits: 1000n,
      wordCount: 1, compactPatchBytes: rewritten,
    };
    chain.events.push(landed);
    chain.blockHashes.set(1001, landed.blockHash);
    chain.head = 1010;
    chain.regEpoch = { liveStateRoot: out.newStateRoot, transitionCount: 1 };
    chain.minerCounters = { screenersThisEpoch: 0, nextIndex: 1n, lastReceiptHash: '0x' + '12'.repeat(32) };
    await coord.tick();

    const status1 = await coord.getStatus();
    assert.equal(status1.baselineState, 'ready');
    assert.equal(status1.baselineParentScorePpm, 400000);
    assert.equal(status1.screenerThresholdPpm, 1350, 'state-threshold floor dominates normal launch baselines');
    assert.equal(status1.thresholds.baselineParentScorePpm, 400000);

    // A 1400ppm screener clears the live gate.
    mode = 'screener';
    screenerDelta = 1400;
    const after = await coord.submit(submitBody(makePatchHex(out.newStateRoot, 40, 1), MINER_A, out.newStateRoot));
    assert.equal(after.status, 'accepted', `expected accept, got ${JSON.stringify(after)}`);
  });

  test('rotation to a baseline-less root flips to awaiting_baseline_recompute and refuses submits until recompute', async () => {
    const chainGen = new EventChain();
    const evaluator = { scorePatch: (input) => screenerResult(input.patchBytesHex, input.parentStateRoot) };
    const chain = new MockChain({ head: 200, regEpoch: { liveStateRoot: GENESIS_ROOT, transitionCount: 0 } });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator, plainSigner);
    await coord.boot();

    // A foreign state advance (no receipt signed here) rotates the active root.
    const ev0 = chainGen.next({ blockNumber: 300, blockHash: '0x' + '55'.repeat(32) });
    chain.events.push(ev0);
    chain.blockHashes.set(300, ev0.blockHash);
    chain.head = 400;
    chain.regEpoch = { liveStateRoot: ev0.newRoot, transitionCount: 1 };
    await coord.tick();
    assert.equal(coord.getState().liveRoot.toLowerCase(), ev0.newRoot.toLowerCase());

    const status = await coord.getStatus();
    assert.equal(status.baselineState, 'awaiting_baseline_recompute');
    assert.equal(status.baselineParentScorePpm, null);
    assert.equal(status.screenerThresholdPpm, null);
    assert.equal(status.acceptingSubmissions, false);
    const health = await coord.health();
    assert.equal(health.baselineState, 'awaiting_baseline_recompute');
    assert.equal(health.acceptingSubmissions, false);

    const refused = await coord.submit(submitBody(makePatchHex(ev0.newRoot, 40, 1), MINER_A, ev0.newRoot));
    assert.equal(refused.status, 'rejected');
    assert.equal(refused.code, 'awaiting_baseline_recompute');

    // Recomputed baseline for the new context re-arms the gate.
    coord.setRecomputedBaseline({ stateRoot: ev0.newRoot, baselineParentScorePpm: 300000 });
    const ready = await coord.getStatus();
    assert.equal(ready.baselineState, 'ready');
    assert.equal(ready.baselineParentScorePpm, 300000);
    assert.equal(ready.screenerThresholdPpm, 1350);
    const accepted = await coord.submit(submitBody(makePatchHex(ev0.newRoot, 40, 1), MINER_A, ev0.newRoot));
    assert.equal(accepted.status, 'accepted', `expected accept, got ${JSON.stringify(accepted)}`);

    // Orchestrator-driven invalidation (corpus/frontier rotation) re-enters
    // awaiting_baseline_recompute.
    coord.invalidateBaselines();
    const invalidated = await coord.submit(submitBody(makePatchHex(ev0.newRoot, 41, 1), MINER_A, ev0.newRoot));
    assert.equal(invalidated.code, 'awaiting_baseline_recompute');
    assert.equal((await coord.getStatus()).baselineState, 'awaiting_baseline_recompute');
  });
});
