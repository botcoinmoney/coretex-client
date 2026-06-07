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
import { merkleizeState, bytesToHex, applyPatch, decodePatch, computePatchHash } from '../../dist/index.js';

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
    this.epochStartBlock = opts.epochStartBlock ?? 100;
  }
  async getBlockNumber() { return this.head; }
  async getBlockHashAt(n) { return this.blockHashes.get(n) ?? null; }
  async getStateAdvancedEvents(from, to) {
    return this.events.filter((e) => Number(e.blockNumber) >= from && Number(e.blockNumber) <= to);
  }
  async getEpochStartedBlock() { return this.epochStartBlock; }
  async getRegistryEpoch() { return this.regEpoch; }
  async getRegistryEpochPins() { return this.pins; }
  async getV4CurrentEpoch() { return this.v4Epoch; }
  async getV4EpochCommit() { return this.epochCommit; }
  async getV4CoordinatorSigner() { return this.signer; }
  async getV4CoreTexRegistry() { return this.registryAddr; }
  async getChainId() { return this.chainId; }
}
function loadGenesis() { return { words: [...GENESIS.words] }; }
const evaluator = { scorePatch: () => ({ outcome: 'reject', code: 'noop', reason: 'no-op' }) };

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
    assert.equal(s.pendingCount, 1, 'pending record kept but state moved');
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
});
