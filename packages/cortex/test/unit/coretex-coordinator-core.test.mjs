/**
 * Deterministic unit tests for the v0 production CoreTexCoordinatorCore.
 *
 * Mocks ChainClient + ParentSubstrateLoader + RealEvaluator so every invariant
 * the auditor pinned can be asserted without touching real RPCs or
 * shellouts. The mainnet-coord-v16.mjs fixture proves the same semantics on
 * live Base; this file proves the production code path does the same.
 *
 * Coverage:
 *  - canonical route gate (via the endpoints.ts test)
 *  - no stale public routes (via the endpoints.ts test)
 *  - perMinerScreenerCap-only public naming (via the contract.test)
 *  - chain-confirmed-only root tracking — signed receipt does NOT move root
 *  - landed event moves root (deterministic injection)
 *  - reorg detection rolls back to canonical snapshot
 *  - reorg prunes substrate cache
 *  - parity mismatch disables signing
 *  - startup replay respects confirmation depth (lastScannedBlock = safeHead)
 *  - boot wiring gates: chainId / V4 epoch / signer / registry / pins
 *  - expired pending receipt releases submit dedup
 *  - originalPatchHash and signedPatchHash both retrievable
 *  - stale receipt lookup returns 409 + PendingReceiptStale + no transaction
 *  - acceptingSubmissions=false during reconciliation
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  CoreTexCoordinatorCore,
} from '../../dist/coordinator/coretex-coordinator-core.js';
import { merkleizeState, bytesToHex, applyPatch, decodePatch, encodePatch, computePatchHash } from '../../dist/index.js';

// ── helpers ───────────────────────────────────────────────────────────────
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
  // §7 launch baseline for the pinned (genesis) context. 288438 under the
  // default policy derives a live screener threshold of 355ppm.
  baselineParentScorePpm: 288438,
  screenerThresholdPpm: 355,
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
    this.blockHashes = opts.blockHashes ?? new Map(); // blockNumber -> hash
    this.regEpoch = opts.regEpoch ?? { liveStateRoot: GENESIS_ROOT, transitionCount: 0 };
    this.minerCounters = opts.minerCounters ?? { screenersThisEpoch: 0, nextIndex: 0n, lastReceiptHash: '0x' + '00'.repeat(32) };
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
  async getMinerCoreTexCounters() { return this.minerCounters; }
  async getQualifiedScreenerPassesSinceLastStateAdvance() { return this.qualified; }
}
function loadGenesis() { return { words: [...GENESIS.words] }; }
const evaluator = { scorePatch: () => ({ outcome: 'reject', code: 'noop', reason: 'no-op' }) };
const signer = {
  signCoreTexReceipt: ({ receipt }) => ({
    signature: '0x' + '5a'.repeat(65),
    transactionData: '0x' + receipt.patchHash.slice(2, 10),
  }),
};

// Stateful event chain builder. Maintains running state across events so each
// new event has parent = previous newRoot.
class EventChain {
  constructor() {
    this.state = { words: [...GENESIS.words] };
    this.root = GENESIS_ROOT;
    this.transitionIndex = 0;
  }
  next({ blockNumber, blockHash, miner = '0x' + 'aa'.repeat(20) }) {
    const idx = 38 + this.transitionIndex;
    const valHex = '01' + (this.transitionIndex + 1).toString(16).padStart(2, '0') + '00'.repeat(30);
    const patchHex = `0xff010000000000000000${this.root.replace(/^0x/, '')}${idx.toString(16).padStart(2, '0')}${valHex}`;
    const buf = new Uint8Array(patchHex.replace(/^0x/, '').length / 2);
    const h = patchHex.replace(/^0x/, '');
    for (let i = 0; i < buf.length; i++) buf[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
    const decoded = decodePatch(buf);
    const next = applyPatch(this.state, decoded, true);
    if (!next.ok) throw new Error(`buildEvent: applyPatch failed ${next.code}`);
    const newRoot = bytesToHex(merkleizeState(next.state));
    const patchHash = computePatchHash(buf);
    const ev = {
      blockNumber: BigInt(blockNumber), blockHash, logIndex: 0n, epoch: EPOCH,
      transitionIndex: BigInt(this.transitionIndex), miner,
      parent: this.root, newRoot, patchHash, evalReportHash: '0x' + 'e1'.repeat(32),
      coreV: CORE_V, corpus: CORPUS, frontier: FRONTIER,
      credits: 1000n, wordCount: decoded.wordCount, compactPatchBytes: patchHex,
    };
    this.state = next.state;
    this.root = newRoot;
    this.transitionIndex += 1;
    return ev;
  }
}
// Legacy stub for tests that only need one event from genesis.
function buildEvent({ transitionIndex = 0, parent = GENESIS_ROOT, blockNumber, blockHash, miner = '0x' + 'aa'.repeat(20) }) {
  const c = new EventChain();
  if (parent !== GENESIS_ROOT) throw new Error('buildEvent: use EventChain for non-genesis parent');
  for (let i = 0; i < transitionIndex; i++) c.next({ blockNumber: 0, blockHash: '0x' + 'aa'.repeat(32) });
  return c.next({ blockNumber, blockHash, miner });
}

function rewritePatchScoreDelta(patchHex, deltaPpm) {
  const decoded = decodePatch(hexToBytes(patchHex));
  return bytesToHex(encodePatch({ ...decoded, scoreDelta: BigInt(deltaPpm) }));
}

function hexToBytes(h) {
  const s = h.replace(/^0x/, '');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function dualProofFor(patchHex, parentStateRoot = GENESIS_ROOT, overrides = {}) {
  const patchHash = computePatchHash(hexToBytes(patchHex)).toLowerCase();
  return {
    kind: 'coretex-dual-pack-v1',
    mode: 'future_blockhash_dual_pack',
    epochId: Number(EPOCH),
    receivedAtBlock: 1000,
    targetBlock: 1030,
    targetBlockOffset: 30,
    blockhash: '0x' + '77'.repeat(32),
    patchHash,
    parentStateRoot: parentStateRoot.toLowerCase(),
    corpusRoot: CORPUS,
    coreVersionHash: CORE_V,
    hiddenSeedCommit: SEED_COMMIT,
    epochSecretCommit: SEED_COMMIT,
    gate: { domain: 'gate', seedCommit: '0x' + '91'.repeat(32), accepted: true, scorePpm: 3100 },
    confirm: { domain: 'confirm', seedCommit: '0x' + '92'.repeat(32), accepted: true, scorePpm: 3090 },
    ...overrides,
  };
}

describe('CoreTexCoordinatorCore — boot wiring gates', () => {
  test('rejects chainId mismatch', async () => {
    const chain = new MockChain({ chainId: 1n });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await assert.rejects(() => coord.boot(), /chainId/);
  });
  test('rejects V4 epoch mismatch', async () => {
    const chain = new MockChain({ v4Epoch: 999n });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await assert.rejects(() => coord.boot(), /V4\.currentEpoch/);
  });
  test('rejects missing V4 epoch commit', async () => {
    const chain = new MockChain({ epochCommit: '0x' + '00'.repeat(32) });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await assert.rejects(() => coord.boot(), /epochCommit.*is zero/);
  });
  test('rejects coordinator signer mismatch', async () => {
    const chain = new MockChain({ signer: '0xdeadbeef' + '00'.repeat(16) });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await assert.rejects(() => coord.boot(), /coordinatorSigner/);
  });
  test('rejects V4 -> registry mismatch', async () => {
    const chain = new MockChain({ registryAddr: '0xdeadbeef' + '00'.repeat(16) });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await assert.rejects(() => coord.boot(), /coreTexRegistry/);
  });
  test('rejects epoch pin mismatch (corpusRoot)', async () => {
    const chain = new MockChain({ pins: { ...baseConfig.expectedEpochPins, corpusRoot: '0x' + 'de'.repeat(32) } });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await assert.rejects(() => coord.boot(), /corpusRoot/);
  });
  test('rejects parent substrate merkle mismatch', async () => {
    const chain = new MockChain();
    const wrongParent = () => ({ words: new Array(1024).fill(1n) }); // merkles to something ≠ genesis
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, wrongParent, evaluator);
    await assert.rejects(() => coord.boot(), /parent substrate merkles/);
  });
});

describe('CoreTexCoordinatorCore — chain-confirmed-only semantics', () => {
  test('boot from clean chain — liveRoot = parent, signing enabled', async () => {
    const chain = new MockChain({ head: 1000 });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await coord.boot();
    const s = coord.getState();
    assert.equal(s.liveRoot.toLowerCase(), GENESIS_ROOT.toLowerCase());
    assert.equal(s.transitionCount, 0);
    assert.equal(s.signingEnabled, true);
    assert.equal(s.unhealthyReason, null);
  });

  test('mid-run epoch rollover disables signing with CoordEpochMismatch', async () => {
    const chain = new MockChain({ head: 1000 });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator, signer);
    await coord.boot();
    chain.v4Epoch = EPOCH + 1n;
    await coord.tick();
    const s = coord.getState();
    assert.equal(s.signingEnabled, false);
    assert.match(s.unhealthyReason, /CoordEpochMismatch/);
    const rejected = await coord.submit({
      patchBytesHex: buildEvent({ blockNumber: 500, blockHash: '0x' + '55'.repeat(32) }).compactPatchBytes,
      parentStateRoot: GENESIS_ROOT,
      minerAddress: '0x' + 'aa'.repeat(20),
    });
    assert.equal(rejected.code, 'CoordEpochMismatch');
    assert.equal(coord.getMetrics().epochMismatchCount >= 1, true);
  });

  test('startup replay applies events through safeHead, not latest', async () => {
    // head = 1000, depth = 4 → safeHead = 996
    // events at blocks 500 (safe), 998 (UNCONFIRMED, > safeHead)
    const chainGen = new EventChain();
    const ev0 = chainGen.next({ blockNumber: 500, blockHash: '0x' + '55'.repeat(32) });
    const ev1 = chainGen.next({ blockNumber: 998, blockHash: '0x' + '99'.repeat(32) });
    const chain = new MockChain({ head: 1000, events: [ev0, ev1], regEpoch: { liveStateRoot: ev1.newRoot, transitionCount: 2 } });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await coord.boot();
    const s = coord.getState();
    // Only ev0 should be applied; ev1 is past safeHead
    assert.equal(s.transitionCount, 1, 'only the safeHead-confirmed event applied');
    assert.equal(s.liveRoot.toLowerCase(), ev0.newRoot.toLowerCase());
    // lastScannedBlock starts at safeHead, not latest head
    assert.equal(s.lastScannedBlock, 996, `lastScannedBlock should be safeHead 996; got ${s.lastScannedBlock}`);
  });

  test('tick applies newly-finalized events', async () => {
    const chainGen = new EventChain();
    const ev0 = chainGen.next({ blockNumber: 500, blockHash: '0x' + '55'.repeat(32) });
    const chain = new MockChain({ head: 1000, events: [ev0], regEpoch: { liveStateRoot: ev0.newRoot, transitionCount: 1 } });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await coord.boot();
    // Now a new event lands at block 1001 and head advances to 1010 (1001 is still confirmed: 1010-4=1006 > 1001)
    const ev1 = chainGen.next({ blockNumber: 1001, blockHash: '0x' + '01'.repeat(32) });
    chain.events.push(ev1);
    chain.head = 1010;
    chain.regEpoch = { liveStateRoot: ev1.newRoot, transitionCount: 2 };
    await coord.tick();
    const s = coord.getState();
    assert.equal(s.transitionCount, 2);
    assert.equal(s.liveRoot.toLowerCase(), ev1.newRoot.toLowerCase());
    assert.equal(s.signingEnabled, true);
  });

  test('chain-ahead finality lag disables submissions until confirmed replay catches up', async () => {
    const chainGen = new EventChain();
    const ev0 = chainGen.next({ blockNumber: 998, blockHash: '0x' + '98'.repeat(32) });
    const chain = new MockChain({
      head: 1000,
      events: [ev0],
      regEpoch: { liveStateRoot: ev0.newRoot, transitionCount: 1 },
    });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator, signer);
    await coord.boot();
    let s = coord.getState();
    assert.equal(s.transitionCount, 0, 'unconfirmed event not applied at boot');
    assert.equal(s.signingEnabled, false, 'coord refuses to sign while chain root is ahead of confirmed root');
    assert.match(s.unhealthyReason, /CoordAwaitingFinality/);

    const rejected = await coord.submit({
      patchBytesHex: ev0.compactPatchBytes,
      parentStateRoot: GENESIS_ROOT,
      minerAddress: '0x' + 'aa'.repeat(20),
    });
    assert.equal(rejected.code, 'CoordAwaitingFinality');

    chain.head = 1005; // safeHead = 1001, ev0 is now confirmed
    chain.blockHashes.set(998, ev0.blockHash);
    await coord.tick();
    s = coord.getState();
    assert.equal(s.transitionCount, 1);
    assert.equal(s.signingEnabled, true);
    assert.equal(s.unhealthyReason, null);
  });
});

describe('CoreTexCoordinatorCore — event-context strict checks', () => {
  test('rejects event with wrong coreVersionHash', async () => {
    const ev = buildEvent({ transitionIndex: 0, parent: GENESIS_ROOT, blockNumber: 500, blockHash: '0x' + '55'.repeat(32) });
    const bad = { ...ev, coreV: '0x' + 'de'.repeat(32) };
    const chain = new MockChain({ head: 1000, events: [bad] });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await assert.rejects(() => coord.boot(), /event coreVersionHash.*≠ configured/);
  });
  test('rejects event with wrong corpusRoot', async () => {
    const ev = buildEvent({ transitionIndex: 0, parent: GENESIS_ROOT, blockNumber: 500, blockHash: '0x' + '55'.repeat(32) });
    const bad = { ...ev, corpus: '0x' + 'de'.repeat(32) };
    const chain = new MockChain({ head: 1000, events: [bad] });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await assert.rejects(() => coord.boot(), /corpusRoot.*≠ configured/);
  });
  test('rejects event with wrong wordCount', async () => {
    const ev = buildEvent({ transitionIndex: 0, parent: GENESIS_ROOT, blockNumber: 500, blockHash: '0x' + '55'.repeat(32) });
    const bad = { ...ev, wordCount: 5 };
    const chain = new MockChain({ head: 1000, events: [bad] });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await assert.rejects(() => coord.boot(), /wordCount.*≠ decoded patch wordCount/);
  });
  test('rejects non-contiguous transitionIndex', async () => {
    const ev = buildEvent({ transitionIndex: 5, parent: GENESIS_ROOT, blockNumber: 500, blockHash: '0x' + '55'.repeat(32) });
    const chain = new MockChain({ head: 1000, events: [ev] });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await assert.rejects(() => coord.boot(), /non-contiguous transitionIndex/);
  });
});

describe('CoreTexCoordinatorCore — reorg detection + rollback', () => {
  test('reorg detected via changed blockHash → rollback to last canonical snapshot', async () => {
    const chainGen = new EventChain();
    const ev0 = chainGen.next({ blockNumber: 500, blockHash: '0x' + '55'.repeat(32) });
    const ev1 = chainGen.next({ blockNumber: 600, blockHash: '0x' + '66'.repeat(32) });
    const chain = new MockChain({ head: 1000, events: [ev0, ev1], regEpoch: { liveStateRoot: ev1.newRoot, transitionCount: 2 },
      blockHashes: new Map([[500, ev0.blockHash], [600, ev1.blockHash]]) });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await coord.boot();
    const before = coord.getState();
    assert.equal(before.transitionCount, 2);
    assert.equal(before.snapshotCount, 2);
    assert.equal(before.stateByRootSize, 3, 'stateByRoot has parent + 2 advances');
    // Now simulate reorg: ev1's block hash changed on chain AND that branch lost
    // its CoreTexStateAdvanced log on the canonical chain (the reorg replaced it).
    chain.blockHashes.set(600, '0x' + 'ff'.repeat(32));
    chain.events = chain.events.filter((e) => e !== ev1);
    await coord.tick();
    const after = coord.getState();
    assert.equal(after.transitionCount, 1, 'rolled back to ev0');
    assert.equal(after.liveRoot.toLowerCase(), ev0.newRoot.toLowerCase());
    assert.equal(after.snapshotCount, 1);
    assert.equal(after.stateByRootSize, 2, 'reorged-branch substrate pruned');
  });

  test('reorg of first advance rolls back to epoch parent and unconfirms receipt', async () => {
    const ev = buildEvent({ blockNumber: 500, blockHash: '0x' + '55'.repeat(32) });
    const rewritten = rewritePatchScoreDelta(ev.compactPatchBytes, 3000);
    const signedHash = computePatchHash(hexToBytes(rewritten)).toLowerCase();
    const evalAdvance = {
      scorePatch: () => ({
        outcome: 'state_advance',
        deterministicDeltaPpm: 3000,
        evalReportHash: '0x' + 'e3'.repeat(32),
        artifactHash: '0x' + 'a3'.repeat(32),
        scoreBeforePpm: 100,
        scoreAfterPpm: 3100,
        rewrittenPatchBytesHex: rewritten,
        evaluationProof: dualProofFor(ev.compactPatchBytes),
      }),
    };
    const chain = new MockChain({
      head: 200,
      regEpoch: { liveStateRoot: GENESIS_ROOT, transitionCount: 0 },
      blockHashes: new Map(),
    });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evalAdvance, signer);
    await coord.boot();
    const out = await coord.submit({
      patchBytesHex: ev.compactPatchBytes,
      parentStateRoot: GENESIS_ROOT,
      minerAddress: '0x' + 'aa'.repeat(20),
    });

    const landed = { ...ev, blockNumber: 300n, blockHash: '0x' + '66'.repeat(32),
      patchHash: signedHash, compactPatchBytes: rewritten, newRoot: out.newStateRoot };
    chain.events.push(landed);
    chain.blockHashes.set(300, landed.blockHash);
    chain.head = 400;
    chain.regEpoch = { liveStateRoot: out.newStateRoot, transitionCount: 1 };
    await coord.tick();
    assert.equal(coord.getReceiptByHash(signedHash).body.confirmedOnChain, true);
    assert.ok(coord.getSubstrate(out.newStateRoot), 'advanced substrate is cached before reorg');

    chain.blockHashes.set(300, '0x' + 'ff'.repeat(32));
    chain.events = [];
    chain.regEpoch = { liveStateRoot: GENESIS_ROOT, transitionCount: 0 };
    await coord.tick();
    assert.equal(coord.getState().liveRoot.toLowerCase(), GENESIS_ROOT.toLowerCase());
    assert.equal(coord.getSubstrate(out.newStateRoot), null, 'reorged root pruned');
    const lookup = coord.getReceiptByHash(signedHash);
    assert.equal(lookup.status, 200);
    assert.equal(lookup.body.pendingState, 'pending');
    assert.equal(lookup.body.confirmedOnChain, false);
  });
});

describe('CoreTexCoordinatorCore — pending receipt lifecycle', () => {
  test('expired pending releases submitDedup', async () => {
    const chain = new MockChain({ head: 1000 });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await coord.boot();
    const now = Math.floor(Date.now() / 1000);
    const p = { originalPatchHash: '0x' + '11'.repeat(32), signedPatchHash: '0x' + '22'.repeat(32),
                parentRoot: GENESIS_ROOT, expectedNewRoot: '0x' + '33'.repeat(32),
                compactPatchBytes: '0xff01', miner: '0x' + 'aa'.repeat(20),
                issuedAt: now - 100, expiresAt: now - 1, state: 'pending' };
    const env = { status: 'accepted', outcome: 'STATE_ADVANCE', patchHash: p.signedPatchHash,
                  evalReportHash: '0x' + 'ef'.repeat(32), receipt: {},
                  transaction: { to: V4_ADDR, chainId: 8453, value: '0', data: '0xdeadbeef' } };
    coord.registerPending(p, env);
    await coord.tick(); // triggers gcPending
    const s = coord.getState();
    assert.equal(s.pendingCount, 0, 'expired pending record swept');
    // Receipt lookup for the now-expired record returns 404
    const lookup = coord.getReceiptByHash(p.signedPatchHash);
    assert.equal(lookup.status, 404);
    assert.match(lookup.body.reason, /expired/);
  });

  test('lookup works by BOTH original and signed patch hash', async () => {
    const chain = new MockChain({ head: 1000 });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await coord.boot();
    const now = Math.floor(Date.now() / 1000);
    const p = { originalPatchHash: '0x' + '11'.repeat(32), signedPatchHash: '0x' + '22'.repeat(32),
                parentRoot: GENESIS_ROOT, expectedNewRoot: '0x' + '33'.repeat(32),
                compactPatchBytes: '0xff01', miner: '0x' + 'aa'.repeat(20),
                issuedAt: now, expiresAt: now + 60, state: 'pending' };
    const env = { status: 'accepted', outcome: 'STATE_ADVANCE', patchHash: p.signedPatchHash,
                  evalReportHash: '0x' + 'ef'.repeat(32), receipt: {},
                  transaction: { to: V4_ADDR, chainId: 8453, value: '0', data: '0xdeadbeef' } };
    coord.registerPending(p, env);
    const bySigned = coord.getReceiptByHash(p.signedPatchHash);
    const byOriginal = coord.getReceiptByHash(p.originalPatchHash);
    assert.equal(bySigned.status, 200);
    assert.equal(byOriginal.status, 200);
    assert.equal(bySigned.body.patchHash, byOriginal.body.patchHash);
  });

  test('stale pending lookup returns 409 + PendingReceiptStale + no transaction', async () => {
    const chain = new MockChain({ head: 1000 });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await coord.boot();
    const now = Math.floor(Date.now() / 1000);
    const p = { originalPatchHash: '0x' + '11'.repeat(32), signedPatchHash: '0x' + '22'.repeat(32),
                parentRoot: GENESIS_ROOT, expectedNewRoot: '0x' + '33'.repeat(32),
                compactPatchBytes: '0xff01', miner: '0x' + 'aa'.repeat(20),
                issuedAt: now, expiresAt: now + 60, state: 'pending' };
    const env = { status: 'accepted', outcome: 'STATE_ADVANCE', patchHash: p.signedPatchHash,
                  evalReportHash: '0x' + 'ef'.repeat(32), receipt: {},
                  transaction: { to: V4_ADDR, chainId: 8453, value: '0', data: '0xdeadbeef' } };
    coord.registerPending(p, env);
    p.state = 'stale';
    const r = coord.getReceiptByHash(p.signedPatchHash);
    assert.equal(r.status, 409);
    assert.equal(r.body.code, 'PendingReceiptStale');
    assert.equal(r.body.transaction, undefined, 'no broadcastable transaction handed back');
  });

  test('screener receipt cache and dedup expire without lookup', async () => {
    const ev = buildEvent({ blockNumber: 500, blockHash: '0x' + '55'.repeat(32) });
    const evalOk = {
      scorePatch: () => ({
        outcome: 'screener_pass',
        deterministicDeltaPpm: 500,
        evalReportHash: '0x' + 'e1'.repeat(32),
        artifactHash: '0x' + 'a1'.repeat(32),
        evaluationProof: dualProofFor(ev.compactPatchBytes),
      }),
    };
    const chain = new MockChain({ head: 1000 });
    const coord = new CoreTexCoordinatorCore({ ...baseConfig, receiptTtlSec: 1 }, chain, loadGenesis, evalOk, signer);
    await coord.boot();
    const body = {
      patchBytesHex: ev.compactPatchBytes,
      parentStateRoot: GENESIS_ROOT,
      minerAddress: '0x' + 'aa'.repeat(20),
    };
    const first = await coord.submit(body);
    assert.equal(first.status, 'accepted');
    // While the receipt is still inside its TTL the (parentRoot, patchHash, outcome)
    // tuple must dedup — no second screener credit for the same patch.
    const duplicate = await coord.submit(body);
    assert.equal(duplicate.code, 'DuplicateCoreTexPatch');
    // Drive expiry deterministically. The core quantizes time to whole seconds via
    // Math.floor(Date.now()/1000), so a single fixed sleep races the second-boundary
    // under concurrent-runner load. Instead tick in a bounded poll loop until the
    // receipt cache + dedup actually expire — this exercises the real TTL path
    // (no injected clock) without any wall-clock margin flake. The cap is far above
    // the 1s TTL so a slow host cannot false-fail; expiry normally lands on the
    // first or second tick.
    const deadline = Date.now() + 15_000;
    while (coord.getReceiptByHash(first.patchHash).status !== 404) {
      assert.ok(Date.now() < deadline, 'screener receipt did not expire within 15s of its 1s TTL');
      await new Promise((resolve) => setTimeout(resolve, 250));
      await coord.tick();
    }
    // Expiry happened with NO prior getReceiptByHash success forcing it — the gc
    // sweep alone retired the cache entry and released the dedup key.
    assert.equal(coord.getReceiptByHash(first.patchHash).status, 404);
    assert.equal(coord.getMetrics().receiptExpiryCount >= 1, true);
    // Dedup released by the same sweep: the identical patch is creditable again.
    const second = await coord.submit(body);
    assert.equal(second.status, 'accepted');
  });
});

describe('CoreTexCoordinatorCore — production submit path', () => {
  test('submit runs evaluator + signer, caches screener receipt, and keeps live root unchanged', async () => {
    const ev = buildEvent({ blockNumber: 500, blockHash: '0x' + '55'.repeat(32) });
    const calls = [];
    const evalOk = {
      scorePatch: (input) => {
        calls.push(input);
        return {
          outcome: 'screener_pass',
          deterministicDeltaPpm: 500,
          evalReportHash: '0x' + 'e1'.repeat(32),
          artifactHash: '0x' + 'a1'.repeat(32),
          evaluationProof: dualProofFor(ev.compactPatchBytes),
        };
      },
    };
    const chain = new MockChain({ head: 1000, minerCounters: { screenersThisEpoch: 2, nextIndex: 9n, lastReceiptHash: '0x' + '09'.repeat(32) } });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evalOk, signer);
    await coord.boot();
    const out = await coord.submit({
      patchBytesHex: ev.compactPatchBytes,
      parentStateRoot: GENESIS_ROOT,
      minerAddress: '0x' + 'aa'.repeat(20),
    });
    assert.equal(out.status, 'accepted');
    assert.equal(out.outcome, 'SCREENER_PASS');
    assert.equal(out.deterministicDeltaPpm, undefined);
    assert.equal(out.receipt.scoreBeforePpm, undefined);
    assert.equal(out.receipt.scoreAfterPpm, undefined);
    assert.equal(out.transaction.to, V4_ADDR.toLowerCase());
    assert.equal(out.perMinerScreenerCount, 3);
    assert.equal(coord.getState().liveRoot.toLowerCase(), GENESIS_ROOT.toLowerCase());
    assert.equal(calls.length, 1);
    const lookup = coord.getReceiptByHash(out.patchHash);
    assert.equal(lookup.status, 200);
    assert.equal(lookup.body.confirmedOnChain, false);
  });

  test('accepted submit refuses missing or malformed dual-pack proof before signing', async () => {
    const ev = buildEvent({ blockNumber: 500, blockHash: '0x' + '55'.repeat(32) });
    const body = {
      patchBytesHex: ev.compactPatchBytes,
      parentStateRoot: GENESIS_ROOT,
      minerAddress: '0x' + 'aa'.repeat(20),
    };
    const acceptedWithoutProof = {
      scorePatch: () => ({
        outcome: 'screener_pass',
        deterministicDeltaPpm: 500,
        evalReportHash: '0x' + 'e1'.repeat(32),
        artifactHash: '0x' + 'a1'.repeat(32),
      }),
    };
    const coord = new CoreTexCoordinatorCore(baseConfig, new MockChain({ head: 1000 }), loadGenesis, acceptedWithoutProof, signer);
    await coord.boot();
    const missing = await coord.submit(body);
    assert.equal(missing.status, 'rejected');
    assert.equal(missing.code, 'DUAL_PACK_PROOF_INVALID');
    assert.match(missing.reason, /missing dual-pack proof/);

    const badProof = {
      scorePatch: () => ({
        outcome: 'screener_pass',
        deterministicDeltaPpm: 500,
        evalReportHash: '0x' + 'e1'.repeat(32),
        artifactHash: '0x' + 'a1'.repeat(32),
        evaluationProof: dualProofFor(ev.compactPatchBytes, GENESIS_ROOT, { blockhash: '0x' + '00'.repeat(32) }),
      }),
    };
    const coord2 = new CoreTexCoordinatorCore(baseConfig, new MockChain({ head: 1000 }), loadGenesis, badProof, signer);
    await coord2.boot();
    const malformed = await coord2.submit(body);
    assert.equal(malformed.status, 'rejected');
    assert.equal(malformed.code, 'DUAL_PACK_PROOF_INVALID');
    assert.match(malformed.reason, /blockhash invalid/);
  });

  test('state advance submit stores pending by original and signed hashes, then confirms from chain event', async () => {
    const ev = buildEvent({ blockNumber: 500, blockHash: '0x' + '55'.repeat(32) });
    const rewritten = rewritePatchScoreDelta(ev.compactPatchBytes, 3000);
    const signedHash = computePatchHash(hexToBytes(rewritten)).toLowerCase();
    const evalAdvance = {
      scorePatch: () => ({
        outcome: 'state_advance',
        deterministicDeltaPpm: 3000,
        evalReportHash: '0x' + 'e2'.repeat(32),
        artifactHash: '0x' + 'a2'.repeat(32),
        scoreBeforePpm: 100,
        scoreAfterPpm: 3100,
        rewrittenPatchBytesHex: rewritten,
        evaluationProof: dualProofFor(ev.compactPatchBytes),
      }),
    };
    const chain = new MockChain({ head: 1000, qualified: 25 });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evalAdvance, signer);
    await coord.boot();
    const out = await coord.submit({
      patchBytesHex: ev.compactPatchBytes,
      parentStateRoot: GENESIS_ROOT,
      minerAddress: '0x' + 'aa'.repeat(20),
    });
    assert.equal(out.status, 'accepted');
    assert.equal(out.outcome, 'STATE_ADVANCE');
    assert.equal(out.deterministicDeltaPpm, undefined);
    assert.equal(out.receipt.scoreBeforePpm, undefined);
    assert.equal(out.receipt.scoreAfterPpm, undefined);
    assert.equal(out.patchHash, signedHash);
    assert.notEqual(out.patchHash, ev.patchHash);
    assert.equal(coord.getState().liveRoot.toLowerCase(), GENESIS_ROOT.toLowerCase(), 'signing does not roll state forward');

    assert.equal(coord.getReceiptByHash(ev.patchHash).status, 200, 'original hash lookup works');
    assert.equal(coord.getReceiptByHash(signedHash).status, 200, 'signed hash lookup works');

    const landed = { ...ev, blockNumber: 1001n, blockHash: '0x' + '01'.repeat(32),
      patchHash: signedHash, compactPatchBytes: rewritten, newRoot: out.newStateRoot };
    chain.events.push(landed);
    chain.blockHashes.set(1001, landed.blockHash);
    chain.head = 1010;
    chain.regEpoch = { liveStateRoot: out.newStateRoot, transitionCount: 1 };
    await coord.tick();
    assert.equal(coord.getState().liveRoot.toLowerCase(), out.newStateRoot.toLowerCase());
    const status = await coord.getStatus();
    assert.equal(status.baselineParentScorePpm, 3100);
    assert.equal(status.baselineVarianceSource, 'unavailable');
    assert.equal(status.baselineVariancePpm, undefined);
    const confirmed = coord.getReceiptByHash(signedHash);
    assert.equal(confirmed.status, 200);
    assert.equal(confirmed.body.confirmedOnChain, true);
  });

  test('state advance submit rejects evaluator rewrite that changes patch semantics', async () => {
    const ev = buildEvent({ blockNumber: 500, blockHash: '0x' + '55'.repeat(32) });
    const decoded = decodePatch(hexToBytes(ev.compactPatchBytes));
    const malicious = encodePatch({
      ...decoded,
      scoreDelta: 3000n,
      indices: [decoded.indices[0] + 1],
      newWords: [decoded.newWords[0] + 1n],
    });
    const evalAdvance = {
      scorePatch: () => ({
        outcome: 'state_advance',
        deterministicDeltaPpm: 3000,
        evalReportHash: '0x' + 'e2'.repeat(32),
        artifactHash: '0x' + 'a2'.repeat(32),
        scoreBeforePpm: 100,
        scoreAfterPpm: 3100,
        rewrittenPatchBytesHex: bytesToHex(malicious),
        evaluationProof: dualProofFor(ev.compactPatchBytes),
      }),
    };
    const coord = new CoreTexCoordinatorCore(baseConfig, new MockChain({ head: 1000 }), loadGenesis, evalAdvance, signer);
    await coord.boot();
    const out = await coord.submit({
      patchBytesHex: ev.compactPatchBytes,
      parentStateRoot: GENESIS_ROOT,
      minerAddress: '0x' + 'aa'.repeat(20),
    });
    assert.equal(out.status, 'rejected');
    assert.equal(out.code, 'EVAL_REWRITE_INVALID');
  });

  test('submit rejects unknown body keys before evaluation', async () => {
    const ev = buildEvent({ blockNumber: 500, blockHash: '0x' + '55'.repeat(32) });
    const calls = [];
    const evalOk = { scorePatch: () => { calls.push('eval'); return { outcome: 'reject', code: 'noop', reason: 'noop' }; } };
    const chain = new MockChain({ head: 1000 });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evalOk, signer);
    await coord.boot();
    const out = await coord.submit({
      patchBytesHex: ev.compactPatchBytes,
      parentStateRoot: GENESIS_ROOT,
      minerAddress: '0x' + 'aa'.repeat(20),
      junk: 'x',
    });
    assert.equal(out.code, 'BODY_UNKNOWN_KEY');
    assert.deepEqual(calls, []);
  });

  test('evaluator exceptions and malformed accepted scores become structured rejections', async () => {
    const ev = buildEvent({ blockNumber: 500, blockHash: '0x' + '55'.repeat(32) });
    const body = {
      patchBytesHex: ev.compactPatchBytes,
      parentStateRoot: GENESIS_ROOT,
      minerAddress: '0x' + 'aa'.repeat(20),
    };
    const chain = new MockChain({ head: 1000 });
    const throwsEval = { scorePatch: () => { throw new Error('secret detail'); } };
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, throwsEval, signer);
    await coord.boot();
    const failed = await coord.submit(body);
    assert.equal(failed.code, 'EvalFailure');
    assert.equal(failed.reason, 'evaluator failed');
    assert.equal(coord.getMetrics().evalFailureCount, 1);

    const badDelta = {
      scorePatch: () => ({
        outcome: 'state_advance',
        deterministicDeltaPpm: 5000,
        evalReportHash: '0x' + 'e2'.repeat(32),
        artifactHash: '0x' + 'a2'.repeat(32),
        scoreBeforePpm: 5000,
        scoreAfterPpm: 4000,
        rewrittenPatchBytesHex: ev.compactPatchBytes,
      }),
    };
    const coord2 = new CoreTexCoordinatorCore(baseConfig, new MockChain({ head: 1000 }), loadGenesis, badDelta, signer);
    await coord2.boot();
    const malformed = await coord2.submit(body);
    assert.equal(malformed.code, 'EVAL_SCORE_INVALID');
  });

  test('signer exceptions become structured rejections', async () => {
    const ev = buildEvent({ blockNumber: 500, blockHash: '0x' + '55'.repeat(32) });
    const evalOk = {
      scorePatch: () => ({
        outcome: 'screener_pass',
        deterministicDeltaPpm: 500,
        evalReportHash: '0x' + 'e1'.repeat(32),
        artifactHash: '0x' + 'a1'.repeat(32),
        evaluationProof: dualProofFor(ev.compactPatchBytes),
      }),
    };
    const throwingSigner = { signCoreTexReceipt: () => { throw new Error('key failed'); } };
    const coord = new CoreTexCoordinatorCore(baseConfig, new MockChain({ head: 1000 }), loadGenesis, evalOk, throwingSigner);
    await coord.boot();
    const out = await coord.submit({
      patchBytesHex: ev.compactPatchBytes,
      parentStateRoot: GENESIS_ROOT,
      minerAddress: '0x' + 'aa'.repeat(20),
    });
    assert.equal(out.code, 'SignerFailure');
    assert.equal(out.reason, 'signer failed');
    assert.equal(coord.getMetrics().signerFailureCount, 1);
  });
});

describe('CoreTexCoordinatorCore — parity gate', () => {
  test('parity-mismatch when coord leads chain → signing disabled', async () => {
    // start with low head so the boot's safeHead doesn't lock lastScannedBlock past
    // the event we'll inject.
    const chain = new MockChain({ head: 200, regEpoch: { liveStateRoot: GENESIS_ROOT, transitionCount: 0 } });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await coord.boot();
    // Inject an event at block 300, advance head to 400 so 300 is safe-confirmed
    const chainGen = new EventChain();
    const ev = chainGen.next({ blockNumber: 300, blockHash: '0x' + '55'.repeat(32) });
    chain.events.push(ev);
    chain.head = 400; // safeHead = 396, ev at 300 confirmed
    // Mock chain returns transitionCount=0 even after the event lands (simulates a
    // chain-side state mutation we missed or RPC desync). Coord should detect parity drift.
    await coord.tick();
    const s = coord.getState();
    assert.equal(s.signingEnabled, false, `signingEnabled should be false; got ${s.signingEnabled}`);
    assert.match(s.unhealthyReason, /parity-mismatch.*coord transitionCount=1 > chain=0/);
  });
});

describe('CoreTexCoordinatorCore — /coretex/health shape', () => {
  test('exposes all six epoch pins + confirmationDepth + chain/confirmed roots + acceptingSubmissions', async () => {
    const chain = new MockChain({ head: 1000 });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await coord.boot();
    const h = await coord.health();
    assert.equal(h.epoch, 106);
    assert.equal(h.chainId, 8453);
    assert.equal(h.confirmationDepth, 4);
    assert.equal(h.acceptingSubmissions, true);
    assert.equal(h.confirmedLiveRoot.toLowerCase(), GENESIS_ROOT.toLowerCase());
    for (const k of ['parentStateRoot', 'coreVersionHash', 'corpusRoot', 'activeFrontierRoot',
                     'baselineManifestHash', 'hiddenSeedCommit']) {
      assert.ok(h.epochPins[k], `epochPins.${k} present`);
    }
  });

  test('after forceUnhealthy: acceptingSubmissions=false + reason exposed', async () => {
    const chain = new MockChain({ head: 1000 });
    const coord = new CoreTexCoordinatorCore(baseConfig, chain, loadGenesis, evaluator);
    await coord.boot();
    coord.forceUnhealthy('test-disabled');
    const h = await coord.health();
    assert.equal(h.acceptingSubmissions, false);
    assert.equal(h.reason, 'test-disabled');
    assert.equal(h.ok, false);
  });

  test('rotated epoch status uses configured live-root baseline and keeps fixed-pack repeatability separate', async () => {
    const chain = new MockChain({ head: 1000 });
    const coord = new CoreTexCoordinatorCore({
      ...baseConfig,
      baselineParentScorePpm: 4242,
      baselineVariancePpm: 0,
      baselineVarianceSource: 'unavailable',
      fixedPackRepeatabilityPpm: 0,
    }, chain, loadGenesis, evaluator);
    await coord.boot();
    const status = await coord.getStatus();
    assert.equal(status.baselineParentScorePpm, 4242);
    assert.equal(status.baselineVarianceSource, 'unavailable');
    assert.equal(status.baselineVariancePpm, undefined);
    assert.equal(status.fixedPackRepeatabilityPpm, 0);
  });
});
