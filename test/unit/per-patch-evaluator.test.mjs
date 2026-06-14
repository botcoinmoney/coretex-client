/**
 * Per-patch evaluation orchestrator tests. All deps are injected
 * fakes — no I/O, no models.
 *
 * The orchestrator's job is to compose seed-derivation + blockhash
 * binding + admission + dual-pack scoring + receipt construction.
 * Tests below lock in each branch of that composition.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { dualPackProofFromPerPatchReceipt, runPerPatchEvaluation } from '../../dist/index.js';

const PARENT_ROOT = `0x${'aa'.repeat(32)}`;
const MINER = `0x${'10'.repeat(20)}`;
const EPOCH_SECRET = `0x${'01'.repeat(32)}`;
const CORPUS_ROOT = `0x${'cc'.repeat(32)}`;
const BUNDLE_HASH = `0x${'dd'.repeat(32)}`;
const BLOCKHASH = `0x${'02'.repeat(32)}`;

function makeRequest(over = {}) {
  return {
    normalizedPatchBytes: new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]),
    parentRoot: PARENT_ROOT,
    minerAddress: MINER,
    epochId: 7,
    structurallyValid: true,
    ...over,
  };
}

function makeRpcClient(blockhash = BLOCKHASH, head = 1000) {
  return {
    async getLatestBlockNumber() { return head; },
    async getBlockHash() { return blockhash; },
    async waitForBlock(blockNumber) {
      return { number: blockNumber, blockhash, timestamp: 1700000000 };
    },
  };
}

function makeScorer(scoresBySeed, { accepted = true } = {}) {
  // Floors-aware scorer contract: returns { scorePpm, accepted }. The fake reports accepted:true
  // (floors pass) by default so gating reduces to score>=threshold; pass {accepted:false} to
  // exercise the structural/protected/family acceptance-floor rejection path.
  return async ({ evalSeed, which }) => {
    const scorePpm = typeof scoresBySeed === 'function' ? scoresBySeed(evalSeed, which) : (scoresBySeed.get(which) ?? 0);
    return { scorePpm, accepted };
  };
}

function makeDeps(over = {}) {
  return {
    rpcClient: makeRpcClient(),
    scorer: makeScorer(new Map([['gate', 50_000], ['confirm', 50_000]])),
    targetBlockOffset: 30,
    thresholdPpm: 1_000,
    perMinerCap: 5,
    epochSecret: EPOCH_SECRET,
    corpusRoot: CORPUS_ROOT,
    bundleHash: BUNDLE_HASH,
    dedupCache: new Map(),
    minerAdmissions: new Map(),
    ...over,
  };
}

describe('runPerPatchEvaluation — happy path', () => {
  test('both packs clear threshold → accepted receipt with all witness fields', async () => {
    const r = await runPerPatchEvaluation(makeRequest(), makeDeps());
    assert.equal(r.accepted, true);
    assert.equal(r.gateScorePpm, 50_000);
    assert.equal(r.confirmScorePpm, 50_000);
    assert.equal(r.receivedAtBlock, 1000);
    assert.equal(r.targetBlock, 1030);
    assert.equal(r.blockhash, BLOCKHASH);
    assert.match(r.patchHash, /^0x[0-9a-f]{64}$/);
    assert.match(r.dedupKey, /^0x[0-9a-f]{64}$/);
    assert.match(r.gateSeed, /^0x[0-9a-f]{64}$/);
    assert.match(r.confirmSeed, /^0x[0-9a-f]{64}$/);
    // The two seeds MUST differ — that's the whole point of dual-pack.
    assert.notEqual(r.gateSeed, r.confirmSeed);
    assert.equal(r.rejectionReason, undefined);
  });

  test('accepted receipt builds coordinator dual-pack proof without raw seed disclosure', async () => {
    const r = await runPerPatchEvaluation(makeRequest(), makeDeps());
    const proof = dualPackProofFromPerPatchReceipt(r, {
      corpusRoot: CORPUS_ROOT,
      coreVersionHash: BUNDLE_HASH,
      hiddenSeedCommit: `0x${'99'.repeat(32)}`,
      targetBlockOffset: 30,
    });
    assert.equal(proof.kind, 'coretex-dual-pack-v1');
    assert.equal(proof.mode, 'future_blockhash_dual_pack');
    assert.equal(proof.targetBlock, proof.receivedAtBlock + proof.targetBlockOffset);
    assert.equal(proof.patchHash, r.patchHash);
    assert.equal(proof.parentStateRoot, r.parentRoot);
    assert.equal(proof.corpusRoot, CORPUS_ROOT);
    assert.equal(proof.coreVersionHash, BUNDLE_HASH);
    assert.match(proof.gate.seedCommit, /^0x[0-9a-f]{64}$/);
    assert.match(proof.confirm.seedCommit, /^0x[0-9a-f]{64}$/);
    assert.notEqual(proof.gate.seedCommit, proof.confirm.seedCommit);
    assert.equal(JSON.stringify(proof).includes(r.gateSeed), false);
    assert.equal(JSON.stringify(proof).includes(r.confirmSeed), false);
  });

  test('determinism — same request + deps → byte-identical receipt', async () => {
    // (Two independent runs must agree. The blockhash is the only
    // input that production picks live; in tests we fix it.)
    const a = await runPerPatchEvaluation(makeRequest(), makeDeps());
    const b = await runPerPatchEvaluation(makeRequest(), makeDeps());
    assert.deepEqual(a, b);
  });
});

describe('runPerPatchEvaluation — dual-pack rejection branches', () => {
  test('gate below threshold → confirm scorer is NOT called', async () => {
    let confirmCalled = false;
    const scorer = async ({ which }) => {
      if (which === 'confirm') confirmCalled = true;
      return { scorePpm: which === 'gate' ? 500 : 99_999, accepted: true };
    };
    const r = await runPerPatchEvaluation(makeRequest(), makeDeps({ scorer }));
    assert.equal(r.accepted, false);
    assert.equal(r.rejectionReason, 'gate-below-threshold');
    assert.equal(r.gateScorePpm, 500);
    assert.equal(r.confirmScorePpm, 0);
    assert.equal(confirmCalled, false, 'short-circuit: never pay the confirm-pack CPU cost on gate-fail');
  });

  test('gate passes but confirm fails → not accepted (pack-luck filter)', async () => {
    const scorer = makeScorer(new Map([['gate', 50_000], ['confirm', 500]]));
    const r = await runPerPatchEvaluation(makeRequest(), makeDeps({ scorer }));
    assert.equal(r.accepted, false);
    assert.equal(r.rejectionReason, 'confirm-below-threshold');
    assert.equal(r.gateScorePpm, 50_000);
    assert.equal(r.confirmScorePpm, 500);
  });

  test('both fail → gate-below-threshold (first rejection wins)', async () => {
    const scorer = makeScorer(new Map([['gate', 500], ['confirm', 500]]));
    const r = await runPerPatchEvaluation(makeRequest(), makeDeps({ scorer }));
    assert.equal(r.rejectionReason, 'gate-below-threshold');
  });

  test('exact threshold passes', async () => {
    const scorer = makeScorer(new Map([['gate', 1_000], ['confirm', 1_000]]));
    const r = await runPerPatchEvaluation(makeRequest(), makeDeps({ scorer, thresholdPpm: 1_000 }));
    assert.equal(r.accepted, true);
  });

  test('high score but acceptance floors FAIL → rejected (floors cannot be bypassed by score)', async () => {
    // gate pack scores well above threshold but the canonical scorer reports accepted:false
    // (e.g. structural/protected/family floor violation). Must NOT be accepted.
    const scorer = makeScorer(new Map([['gate', 99_000], ['confirm', 99_000]]), { accepted: false });
    const r = await runPerPatchEvaluation(makeRequest(), makeDeps({ scorer, thresholdPpm: 1_000 }));
    assert.equal(r.accepted, false);
    assert.equal(r.rejectionReason, 'gate-acceptance-floor');
    assert.equal(r.gateScorePpm, 99_000, 'score is recorded even though floors rejected it');
  });
});

describe('runPerPatchEvaluation — admission gate', () => {
  test('structurally invalid → rejected before RPC call', async () => {
    let rpcCalled = false;
    const rpcClient = {
      async getLatestBlockNumber() { rpcCalled = true; return 1000; },
      async getBlockHash() { return BLOCKHASH; },
      async waitForBlock(n) { return { number: n, blockhash: BLOCKHASH, timestamp: 0 }; },
    };
    const r = await runPerPatchEvaluation(
      makeRequest({ structurallyValid: false }),
      makeDeps({ rpcClient }),
    );
    assert.equal(r.accepted, false);
    assert.equal(r.rejectionReason, 'structurally-invalid');
    assert.equal(rpcCalled, false, 'admission must fail-fast before paying the blockhash wait');
  });

  test('duplicate dedup-key → rejected with collapse reason', async () => {
    const req = makeRequest();
    // First call to compute the dedupKey, then use it to seed the cache.
    const first = await runPerPatchEvaluation(req, makeDeps());
    // Seed the cache so the second call hits the cached branch.
    const cache = new Map([[first.dedupKey, first]]);
    const second = await runPerPatchEvaluation(req, makeDeps({ dedupCache: cache }));
    assert.equal(second.rejectionReason, 'cached');
    assert.equal(second.accepted, first.accepted);
    assert.equal(second.patchHash, first.patchHash);
  });

  test('per-miner cap reached → rejected', async () => {
    const adm = new Map([[MINER.toLowerCase(), 5]]);
    const r = await runPerPatchEvaluation(makeRequest(), makeDeps({ perMinerCap: 5, minerAdmissions: adm }));
    assert.equal(r.accepted, false);
    assert.equal(r.rejectionReason, 'per-miner-cap-reached');
  });
});

describe('runPerPatchEvaluation — anti-pre-testing properties', () => {
  test('targetBlock = receivedAtBlock + targetBlockOffset', async () => {
    const r = await runPerPatchEvaluation(makeRequest(), makeDeps({
      rpcClient: makeRpcClient(BLOCKHASH, 4242),
      targetBlockOffset: 30,
    }));
    assert.equal(r.receivedAtBlock, 4242);
    assert.equal(r.targetBlock, 4272);
  });

  test('two patches with the same parentRoot get DIFFERENT seeds (patchHash differs)', async () => {
    const a = await runPerPatchEvaluation(
      makeRequest({ normalizedPatchBytes: new Uint8Array([1, 2, 3]) }),
      makeDeps(),
    );
    const b = await runPerPatchEvaluation(
      makeRequest({ normalizedPatchBytes: new Uint8Array([1, 2, 4]) }),
      makeDeps(),
    );
    assert.notEqual(a.gateSeed, b.gateSeed);
    assert.notEqual(a.confirmSeed, b.confirmSeed);
    assert.notEqual(a.patchHash, b.patchHash);
  });

  test('two miners submitting the same patch get the SAME seed (dedup-cache contract)', async () => {
    // First-submitter wins on the (parentRoot, patchBytes) dedup
    // cache, so the eval seed MUST NOT depend on minerAddress —
    // otherwise the two miners would compute different seeds but
    // share a cached verdict, creating ambiguity. Sybil rerolls are
    // prevented by the dedup cache, not by per-miner seed entropy.
    const a = await runPerPatchEvaluation(
      makeRequest({ minerAddress: `0x${'10'.repeat(20)}` }),
      makeDeps(),
    );
    const b = await runPerPatchEvaluation(
      makeRequest({ minerAddress: `0x${'20'.repeat(20)}` }),
      makeDeps(),
    );
    assert.equal(a.gateSeed, b.gateSeed);
    assert.equal(a.confirmSeed, b.confirmSeed);
    assert.equal(a.patchHash, b.patchHash);
    assert.equal(a.dedupKey, b.dedupKey);
  });

  test('different blockhash → different seeds (replay-watcher must agree byte-for-byte)', async () => {
    const a = await runPerPatchEvaluation(
      makeRequest(),
      makeDeps({ rpcClient: makeRpcClient(`0x${'11'.repeat(32)}`) }),
    );
    const b = await runPerPatchEvaluation(
      makeRequest(),
      makeDeps({ rpcClient: makeRpcClient(`0x${'22'.repeat(32)}`) }),
    );
    assert.notEqual(a.gateSeed, b.gateSeed);
    assert.notEqual(a.blockhash, b.blockhash);
  });
});

describe('runPerPatchEvaluation — §8 injected seed context (seam)', () => {
  test('injecting a seedContext SKIPS the RPC draw and pins the receipt to it', async () => {
    let rpcCalled = false;
    const rpcClient = {
      async getLatestBlockNumber() { rpcCalled = true; return 99_999; },
      async getBlockHash() { return `0x${'ee'.repeat(32)}`; },
      async waitForBlock(n) { rpcCalled = true; return { number: n, blockhash: `0x${'ee'.repeat(32)}`, timestamp: 0 }; },
    };
    const seedContext = { receivedAtBlock: 7_000_000, targetBlock: 7_000_030, blockhash: `0x${'77'.repeat(32)}` };
    const r = await runPerPatchEvaluation(makeRequest(), makeDeps({ rpcClient, seedContext }));
    assert.equal(rpcCalled, false, 'a pinned seedContext means the orchestrator never touches the chain');
    assert.equal(r.receivedAtBlock, 7_000_000);
    assert.equal(r.targetBlock, 7_000_030);
    assert.equal(r.blockhash, `0x${'77'.repeat(32)}`);
    assert.equal(r.accepted, true);
  });

  test('PARITY: an injected seed produces the SAME receipt as deriving that seed fresh', async () => {
    // A fresh-draw run whose RPC returns blockhash X at head H.
    const fresh = await runPerPatchEvaluation(makeRequest(), makeDeps({
      rpcClient: makeRpcClient(`0x${'5a'.repeat(32)}`, 4_242),
      targetBlockOffset: 30,
    }));
    // An injection run with the SAME (receivedAtBlock, targetBlock, blockhash)
    // and a chain client that would draw something DIFFERENT — proving the
    // pinned seed (not the chain) drove the seeds.
    const injected = await runPerPatchEvaluation(makeRequest(), makeDeps({
      rpcClient: makeRpcClient(`0x${'ff'.repeat(32)}`, 1),
      targetBlockOffset: 30,
      seedContext: { receivedAtBlock: 4_242, targetBlock: 4_272, blockhash: `0x${'5a'.repeat(32)}` },
    }));
    assert.deepEqual(injected, fresh, 'injection parity: byte-identical receipt incl. gate/confirm seeds');
  });

  test('onSeedDerived fires AFTER the seed is derived and BEFORE any scoring', async () => {
    const order = [];
    const scorer = async ({ which }) => { order.push(`score:${which}`); return { scorePpm: 50_000, accepted: true }; };
    const onSeedDerived = (seedContext) => { order.push(`seed:${seedContext.blockhash}`); };
    const r = await runPerPatchEvaluation(makeRequest(), makeDeps({ scorer, onSeedDerived }));
    assert.equal(r.accepted, true);
    assert.equal(order[0], `seed:${BLOCKHASH}`, 'onSeedDerived runs before the first scorer call');
    assert.deepEqual(order, [`seed:${BLOCKHASH}`, 'score:gate', 'score:confirm']);
  });

  test('onSeedDerived receives the SAME seed context that lands in the receipt', async () => {
    let captured;
    const onSeedDerived = (seedContext) => { captured = seedContext; };
    const r = await runPerPatchEvaluation(makeRequest(), makeDeps({
      rpcClient: makeRpcClient(BLOCKHASH, 8_080),
      onSeedDerived,
    }));
    assert.deepEqual(captured, { receivedAtBlock: 8_080, targetBlock: 8_110, blockhash: BLOCKHASH });
    assert.equal(r.receivedAtBlock, captured.receivedAtBlock);
    assert.equal(r.blockhash, captured.blockhash);
  });

  test('onSeedDerived is NOT called on an admission rejection (no seed drawn)', async () => {
    let called = false;
    const onSeedDerived = () => { called = true; };
    const r = await runPerPatchEvaluation(makeRequest({ structurallyValid: false }), makeDeps({ onSeedDerived }));
    assert.equal(r.accepted, false);
    assert.equal(called, false, 'no seed is drawn for a rejected admission → no record');
  });

  test('an onSeedDerived throw aborts BEFORE any scoring (durable-record failure fails closed)', async () => {
    let scored = false;
    const scorer = async () => { scored = true; return { scorePpm: 50_000, accepted: true }; };
    const onSeedDerived = () => { throw new Error('durable record failed'); };
    await assert.rejects(
      runPerPatchEvaluation(makeRequest(), makeDeps({ scorer, onSeedDerived })),
      /durable record failed/,
    );
    assert.equal(scored, false, 'no pack may be scored if the seed could not be durably recorded');
  });
});

describe('runPerPatchEvaluation — RPC failure modes', () => {
  test('waitForBlock timeout propagates as throw', async () => {
    const rpcClient = {
      async getLatestBlockNumber() { return 1000; },
      async getBlockHash() { return BLOCKHASH; },
      async waitForBlock() { throw new Error('timed out'); },
    };
    await assert.rejects(
      runPerPatchEvaluation(makeRequest(), makeDeps({ rpcClient })),
      /timed out/,
    );
  });

  test('getLatestBlockNumber failure propagates', async () => {
    const rpcClient = {
      async getLatestBlockNumber() { throw new Error('rpc down'); },
      async getBlockHash() { return BLOCKHASH; },
      async waitForBlock(n) { return { number: n, blockhash: BLOCKHASH, timestamp: 0 }; },
    };
    await assert.rejects(
      runPerPatchEvaluation(makeRequest(), makeDeps({ rpcClient })),
      /rpc down/,
    );
  });
});
