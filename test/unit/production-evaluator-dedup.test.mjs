/**
 * §8 grinding dedup + envelope strip, and §3 canonical artifact wiring,
 * exercised through `createCoreTexEvaluatorCore` with counting fakes.
 *
 * Seeds include receivedAtBlock, so resubmitting identical patch bytes
 * would draw FRESH gate/confirm packs — retry-until-lucky. The persistent
 * CoreTexEvalDedupStore must short-circuit duplicates WITHOUT any scorer
 * run or pack draw, and per-miner admission counts must survive across
 * evaluator instances (coordinator restarts).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  PATCH_TYPE,
  QWEN_RERANKER_DEFAULT_INSTRUCTION,
  buildCoordinatorBootAttestation,
  bytesToHex,
  createCoreTexEvaluatorCore,
  createInMemoryDedupStore,
  encodePatch,
  qwenRerankerPromptTemplateHash,
  verifyPostRevealEvalReportArtifact,
} from '../../dist/index.js';
import { computePatchHash } from '../../dist/eval/seed-derivation.js';

const PARENT_ROOT = `0x${'aa'.repeat(32)}`;
const PARENT_ROOT_B = `0x${'ab'.repeat(32)}`;
const MINER = `0x${'10'.repeat(20)}`;
const MINER_B = `0x${'20'.repeat(20)}`;
const EPOCH_SECRET = `0x${'01'.repeat(32)}`;
const CORPUS_ROOT = `0x${'cc'.repeat(32)}`;
const BUNDLE_HASH = `0x${'dd'.repeat(32)}`;
const BLOCKHASH = `0x${'02'.repeat(32)}`;

function patchBytesHex(word = 0x1234n) {
  return bytesToHex(encodePatch({
    patchType: PATCH_TYPE.KEY_UPDATE,
    wordCount: 1,
    scoreDelta: 0n,
    parentStateRoot: new Uint8Array(32).fill(0xaa),
    indices: [401],
    newWords: [word],
  }));
}

function hexToBytes(hex) {
  return Uint8Array.from(Buffer.from(hex.replace(/^0x/i, ''), 'hex'));
}

function makeRpcClient(counters = { calls: 0 }, head = 1000) {
  return {
    async getLatestBlockNumber() { counters.calls += 1; return head; },
    async getBlockHash() { return BLOCKHASH; },
    async waitForBlock(n) { return { number: n, blockhash: BLOCKHASH, timestamp: 1700000000 }; },
  };
}

function makeSeedScorer(counters = { calls: 0 }, { deltaPpm = 50_000, accepted = true, reason } = {}) {
  return async () => {
    counters.calls += 1;
    return {
      accepted,
      ...(reason ? { reason } : {}),
      before: { composite: 0.4 },
      after: { composite: 0.4 + deltaPpm / 1_000_000 },
      deltaPpm,
      perFamilyDelta: {},
    };
  };
}

function bootAttestation() {
  return buildCoordinatorBootAttestation({
    bundleHash: BUNDLE_HASH,
    rerankerModelId: 'Qwen/Qwen3-Reranker-0.6B',
    rerankerRevision: 'e61197ed45024b0ed8a2d74b80b4d909f1255473',
    rerankerMode: 'qwen3-per-batch',
    rerankerInstruction: QWEN_RERANKER_DEFAULT_INSTRUCTION,
    promptTemplateHash: qwenRerankerPromptTemplateHash(QWEN_RERANKER_DEFAULT_INSTRUCTION),
    memoryIRMode: 'off',
  });
}

function makeCore(over = {}) {
  const counters = { scorer: { calls: 0 }, rpc: { calls: 0 } };
  const artifacts = [];
  const core = createCoreTexEvaluatorCore({
    epochId: 7,
    epochSecret: EPOCH_SECRET,
    corpusRoot: CORPUS_ROOT,
    bundleHash: BUNDLE_HASH,
    stateThresholdPpm: 10_000,
    screenerThresholdPpm: 1_000,
    replayTolerancePpm: 250,
    targetBlockOffset: 30,
    perMinerCap: 5,
    rpcClient: makeRpcClient(counters.rpc),
    dedupStore: createInMemoryDedupStore(),
    bootAttestation: bootAttestation(),
    parentStateLoader: () => ({ fake: 'parent-state' }),
    seedScorer: makeSeedScorer(counters.scorer),
    publishArtifact: (artifact) => { artifacts.push(artifact); },
    ...over,
  });
  return { core, counters, artifacts };
}

describe('createCoreTexEvaluatorCore — grinding dedup (§8)', () => {
  test('duplicate (epochId, parentStateRoot, patchHash) short-circuits without scorer or pack draw', async () => {
    const { core, counters } = makeCore();
    const first = await core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER });
    assert.equal(first.outcome, 'state_advance');
    const scorerCallsAfterFirst = counters.scorer.calls;
    const rpcCallsAfterFirst = counters.rpc.calls;
    assert.ok(scorerCallsAfterFirst >= 2, 'dual-pack must have scored gate + confirm');

    const second = await core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER });
    assert.equal(second.outcome, 'reject');
    assert.equal(second.code, 'duplicate_submission');
    assert.match(second.reason, /state_advance/, 'rejection documents the prior outcome');
    assert.equal(counters.scorer.calls, scorerCallsAfterFirst, 'duplicate must NOT invoke the scorer');
    assert.equal(counters.rpc.calls, rpcCallsAfterFirst, 'duplicate must NOT draw a fresh pack (no new blockhash binding)');
  });

  test('a rejected-below-threshold patch is ALSO deduped (no retry-until-lucky on fresh packs)', async () => {
    const { core, counters } = makeCore({ seedScorer: makeSeedScorer({ calls: 0 }, { deltaPpm: 10 }) });
    const first = await core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER });
    assert.equal(first.outcome, 'reject');
    assert.equal(first.code, 'gate-below-threshold');
    const second = await core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER });
    assert.equal(second.code, 'duplicate_submission');
    assert.equal(counters.rpc.calls, 1, 'only the first submission may bind a blockhash');
  });

  test('same patch bytes at a NEW parentStateRoot is a distinct evaluation', async () => {
    const { core, counters } = makeCore();
    const a = await core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER });
    const callsAfterA = counters.scorer.calls;
    const b = await core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT_B, miner: MINER });
    assert.equal(a.outcome, 'state_advance');
    assert.equal(b.outcome, 'state_advance');
    assert.ok(counters.scorer.calls > callsAfterA, 'new parent root must re-evaluate');
  });

  test('duplicates survive evaluator restarts through the SAME store', async () => {
    const store = createInMemoryDedupStore();
    const a = makeCore({ dedupStore: store });
    await a.core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER });
    const b = makeCore({ dedupStore: store });
    const result = await b.core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER });
    assert.equal(result.code, 'duplicate_submission');
    assert.equal(b.counters.scorer.calls, 0);
  });
});

describe('createCoreTexEvaluatorCore — per-miner cap through the store', () => {
  test('cap is enforced across calls and across evaluator instances', async () => {
    const store = createInMemoryDedupStore();
    const a = makeCore({ dedupStore: store, perMinerCap: 2 });
    const r1 = await a.core.scorePatch({ patchBytesHex: patchBytesHex(1n), parentStateRoot: PARENT_ROOT, miner: MINER });
    const r2 = await a.core.scorePatch({ patchBytesHex: patchBytesHex(2n), parentStateRoot: PARENT_ROOT, miner: MINER });
    assert.equal(r1.outcome, 'state_advance');
    assert.equal(r2.outcome, 'state_advance');
    const scorerCalls = a.counters.scorer.calls;

    const r3 = await a.core.scorePatch({ patchBytesHex: patchBytesHex(3n), parentStateRoot: PARENT_ROOT, miner: MINER });
    assert.equal(r3.outcome, 'reject');
    assert.equal(r3.code, 'per-miner-cap-reached');
    assert.equal(a.counters.scorer.calls, scorerCalls, 'capped miner must not reach the scorer');

    // Restart: same store, new core — the count persists.
    const b = makeCore({ dedupStore: store, perMinerCap: 2 });
    const r4 = await b.core.scorePatch({ patchBytesHex: patchBytesHex(4n), parentStateRoot: PARENT_ROOT, miner: MINER });
    assert.equal(r4.code, 'per-miner-cap-reached');
    assert.equal(b.counters.scorer.calls, 0);

    // A different miner is not affected.
    const r5 = await b.core.scorePatch({ patchBytesHex: patchBytesHex(5n), parentStateRoot: PARENT_ROOT, miner: MINER_B });
    assert.equal(r5.outcome, 'state_advance');
  });

  test('construction requires a finite perMinerCap and a store', () => {
    assert.throws(() => makeCore({ perMinerCap: Number.MAX_SAFE_INTEGER }), /perMinerCap/);
    assert.throws(() => makeCore({ perMinerCap: undefined }), /perMinerCap/);
    assert.throws(() => makeCore({ dedupStore: undefined }), /CoreTexEvalDedupStore/);
  });
});

describe('createInMemoryDedupStore — §8 atomic seed-pin + admission-charge', () => {
  const KEY = { epochId: 7, parentStateRoot: PARENT_ROOT, patchHash: `0x${'33'.repeat(32)}` };
  const SEED = { receivedAtBlock: 1000, targetBlock: 1030, blockhash: `0x${'B2'.repeat(32)}` };

  test('records the seed + charges the admission at draw, reused on getAttempt (lowercased)', () => {
    const store = createInMemoryDedupStore();
    assert.equal(store.getAttempt(KEY), null, 'no attempt before any draw');
    assert.equal(store.minerAdmissions(7, MINER), 0, 'no admission before any draw');
    store.recordSeedDrawnAndAdmission(KEY, SEED, MINER);
    const a = store.getAttempt(KEY);
    assert.equal(a.state, 'drawn');
    assert.equal(a.seedContext.receivedAtBlock, 1000);
    assert.equal(a.seedContext.targetBlock, 1030);
    assert.equal(a.seedContext.blockhash, `0x${'b2'.repeat(32)}`, 'blockhash normalized lowercase');
    assert.equal(a.minerAddress, MINER.toLowerCase());
    assert.equal(a.admissionCharged, true);
    assert.equal(a.outcome, undefined, 'drawn attempt has no outcome yet');
    // The admission is DERIVED from the atomic row — charged in the SAME call.
    assert.equal(store.minerAdmissions(7, MINER), 1, 'admission charged atomically with the seed');
  });

  test('recordSeedDrawnAndAdmission is idempotent — never overwrites a pinned seed nor re-charges', () => {
    const store = createInMemoryDedupStore();
    store.recordSeedDrawnAndAdmission(KEY, SEED, MINER);
    // A second draw with a DIFFERENT blockhash must NOT replace the pinned one
    // NOR charge the admission again (exactly-once on the key).
    store.recordSeedDrawnAndAdmission(KEY, { receivedAtBlock: 9999, targetBlock: 10029, blockhash: `0x${'ff'.repeat(32)}` }, MINER);
    assert.equal(store.getAttempt(KEY).seedContext.blockhash, `0x${'b2'.repeat(32)}`, 'first pinned seed survives');
    assert.equal(store.getAttempt(KEY).seedContext.receivedAtBlock, 1000);
    assert.equal(store.minerAdmissions(7, MINER), 1, 'admission NOT double-charged on a re-draw');
  });

  test('recordAttemptOutcome upgrades state but preserves the pinned seed + charged admission', () => {
    const store = createInMemoryDedupStore();
    store.recordSeedDrawnAndAdmission(KEY, SEED, MINER);
    store.recordAttemptOutcome(KEY, 'accepted', 'state_advance');
    const a = store.getAttempt(KEY);
    assert.equal(a.state, 'accepted');
    assert.equal(a.outcome, 'state_advance');
    assert.equal(a.seedContext.blockhash, `0x${'b2'.repeat(32)}`, 'seed preserved through the upgrade');
    assert.equal(a.admissionCharged, true, 'admission preserved through the upgrade');
    assert.equal(store.minerAdmissions(7, MINER), 1, 'admission still counted after the terminal upgrade');
  });

  test('recordAttemptOutcome before recordSeedDrawnAndAdmission throws (invariant)', () => {
    const store = createInMemoryDedupStore();
    assert.throws(() => store.recordAttemptOutcome(KEY, 'rejected', 'reject', 'x'), /recordSeedDrawnAndAdmission/);
  });
});

describe('createCoreTexEvaluatorCore — §8 seed-redraw closure (crash-then-retry)', () => {
  // A store that swallows the FIRST recordAttemptOutcome (simulating a crash
  // after the seed is durably drawn but before the outcome lands), then behaves
  // normally. The seed-draw record persists; the dedup record does NOT.
  function crashAfterDrawStore() {
    const inner = createInMemoryDedupStore();
    let crashed = false;
    return {
      ...inner,
      get: (k) => inner.get(k),
      put: (r) => { if (!crashed) { crashed = true; throw new Error('simulated crash after draw, before outcome'); } return inner.put(r); },
      getAttempt: (k) => inner.getAttempt(k),
      recordSeedDrawnAndAdmission: (k, s, m) => inner.recordSeedDrawnAndAdmission(k, s, m),
      recordAttemptOutcome: (k, st, o, c) => inner.recordAttemptOutcome(k, st, o, c),
      minerAdmissions: (e, m) => inner.minerAdmissions(e, m),
    };
  }

  test('a crash after the draw leaves a pinned seed; the retry REUSES it (no fresh blockhash draw)', async () => {
    const store = crashAfterDrawStore();
    // First attempt: draws a fresh blockhash, records the seed, then crashes on
    // put() (no dedup record written).
    const a = makeCore({ dedupStore: store });
    await assert.rejects(
      a.core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER }),
      /simulated crash/,
    );
    assert.ok(a.counters.rpc.calls >= 1, 'first attempt drew a fresh blockhash');
    // Retry through a NEW core over the SAME durable store (no dedup record, so
    // no short-circuit): it must REUSE the pinned seed, NOT draw a fresh one.
    const b = makeCore({ dedupStore: store });
    const retry = await b.core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER });
    assert.equal(b.counters.rpc.calls, 0, 'the retry must NOT draw a fresh blockhash (seed reused from the pinned attempt)');
    assert.equal(retry.outcome, 'state_advance');
  });

  test('the reused seed produces the SAME packs as the pinned draw (injection parity)', async () => {
    // Capture the seeds derived on the (crashing) first attempt, then assert the
    // retry derives byte-identical gate/confirm seeds (so the same hidden packs
    // are scored). We capture via the seedScorer's evalSeed arguments.
    const firstSeeds = [];
    const retrySeeds = [];
    const store = crashAfterDrawStore();
    const a = makeCore({
      dedupStore: store,
      seedScorer: async ({ evalSeed }) => { firstSeeds.push(evalSeed.toLowerCase()); return { accepted: true, before: { composite: 0.4 }, after: { composite: 0.45 }, deltaPpm: 50_000, perFamilyDelta: {} }; },
    });
    await assert.rejects(a.core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER }), /simulated crash/);

    const b = makeCore({
      dedupStore: store,
      seedScorer: async ({ evalSeed }) => { retrySeeds.push(evalSeed.toLowerCase()); return { accepted: true, before: { composite: 0.4 }, after: { composite: 0.45 }, deltaPpm: 50_000, perFamilyDelta: {} }; },
    });
    await b.core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER });
    assert.ok(firstSeeds.length >= 1 && retrySeeds.length >= 1, 'both attempts scored at least one pack');
    assert.deepEqual(retrySeeds, firstSeeds, 'retry derived byte-identical seeds → same hidden packs (no redraw)');
  });

  test('admission is charged EXACTLY ONCE across a crash + retry (not 0, not 2)', async () => {
    const store = crashAfterDrawStore();
    const a = makeCore({ dedupStore: store, perMinerCap: 1 });
    await assert.rejects(a.core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER }), /simulated crash/);
    // The seed pin AND the admission charge were ONE atomic write before the
    // crash, so the admission is already present (=1) for the drawn-but-not-
    // completed attempt — the gap where it could stay UNCHARGED (=0) is closed.
    assert.equal(store.minerAdmissions(7, MINER), 1, 'admission charged atomically with the seed, present after the crash');
    // Retry consumes the SAME admission the first (crashed) draw recorded — the
    // miner is not charged twice — so the cap-1 retry still succeeds.
    const b = makeCore({ dedupStore: store, perMinerCap: 1 });
    const retry = await b.core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER });
    assert.equal(retry.outcome, 'state_advance', 'retry not blocked by a double-charged admission cap');
    assert.equal(store.minerAdmissions(7, MINER), 1, 'admission stays EXACTLY ONCE across the crash + retry');
  });
});

describe('createCoreTexEvaluatorCore — §8 pending-window cross-miner dedup', () => {
  // Same crash-after-draw store as above: it leaves a real 'drawn' attempt
  // (pinned seed + charged admission) keyed (epoch, parentRoot, patchHash),
  // owned by the FIRST miner, with NO dedup outcome recorded.
  function crashAfterDrawStore() {
    const inner = createInMemoryDedupStore();
    let crashed = false;
    return {
      ...inner,
      get: (k) => inner.get(k),
      put: (r) => { if (!crashed) { crashed = true; throw new Error('simulated crash after draw, before outcome'); } return inner.put(r); },
      getAttempt: (k) => inner.getAttempt(k),
      recordSeedDrawnAndAdmission: (k, s, m) => inner.recordSeedDrawnAndAdmission(k, s, m),
      recordAttemptOutcome: (k, st, o, c) => inner.recordAttemptOutcome(k, st, o, c),
      minerAdmissions: (e, m) => inner.minerAdmissions(e, m),
    };
  }

  // Helper: leave a real drawn-not-completed attempt for MINER on the store.
  async function leaveDrawnAttemptForMinerA(store) {
    const a = makeCore({ dedupStore: store });
    await assert.rejects(
      a.core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER }),
      /simulated crash/,
    );
    // The real (epoch, parentRoot, patchHash) attempt is now 'drawn' and owned by
    // MINER, with its admission charged exactly once (no dedup outcome recorded).
    assert.equal(store.minerAdmissions(7, MINER), 1, 'miner A holds exactly one drawn admission');
  }

  test('a DIFFERENT miner submitting the same (epoch,parentRoot,patchHash) is REJECTED in-flight — no score, no draw, no charge', async () => {
    const store = crashAfterDrawStore();
    await leaveDrawnAttemptForMinerA(store);

    // Miner B submits the identical patch bytes at the same parent during miner
    // A's drawn-not-completed window. B must NOT free-ride on A's pinned seed.
    const b = makeCore({ dedupStore: store });
    const result = await b.core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER_B });
    assert.equal(result.outcome, 'reject');
    assert.equal(result.code, 'duplicate_in_flight', 'cross-miner in-flight duplicate gets a distinct rejection code');
    assert.equal(b.counters.scorer.calls, 0, 'B must NOT be scored (no free-ride on the pinned seed)');
    assert.equal(b.counters.rpc.calls, 0, 'B must NOT draw a fresh pack');
    assert.equal(store.minerAdmissions(7, MINER_B), 0, "B's admission stays uncharged");
    assert.equal(store.minerAdmissions(7, MINER), 1, "miner A's admission is NOT re-charged (stays exactly 1)");
    // The reject must carry NO score oracle.
    assert.equal('deterministicDeltaPpm' in result, false);
    assert.equal('requiredDeltaPpm' in result, false);
  });

  test('the SAME miner crash-retrying its own drawn attempt is UNCHANGED (reuses seed, drains, no extra charge)', async () => {
    const store = crashAfterDrawStore();
    await leaveDrawnAttemptForMinerA(store);

    // Miner A retries its OWN attempt: the legitimate self crash-retry path is
    // preserved — reuse the pinned seed (no fresh blockhash), no re-charge.
    const a2 = makeCore({ dedupStore: store });
    const retry = await a2.core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER });
    assert.equal(retry.outcome, 'state_advance', 'self retry still scores + advances');
    assert.equal(a2.counters.rpc.calls, 0, 'self retry reuses the pinned seed (no fresh blockhash draw)');
    assert.equal(store.minerAdmissions(7, MINER), 1, "miner A's admission stays exactly once across the self retry");
  });

  test('cross-miner in-flight reject does NOT consume the slot — miner A can still complete its own retry afterward', async () => {
    const store = crashAfterDrawStore();
    await leaveDrawnAttemptForMinerA(store);

    // B is rejected in-flight (no state change to the attempt) ...
    const b = makeCore({ dedupStore: store });
    const rb = await b.core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER_B });
    assert.equal(rb.code, 'duplicate_in_flight');
    // ... so miner A's subsequent retry still owns + completes the evaluation.
    const a2 = makeCore({ dedupStore: store });
    const retry = await a2.core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER });
    assert.equal(retry.outcome, 'state_advance', "B's in-flight reject left A's attempt intact");
  });

  test('once miner A COMPLETES, a resubmission (any miner) deduplicates as before (completed path unchanged)', async () => {
    // No crash: miner A completes cleanly, writing a dedup outcome record.
    const store = createInMemoryDedupStore();
    const a = makeCore({ dedupStore: store });
    const first = await a.core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER });
    assert.equal(first.outcome, 'state_advance');
    // A completed eval short-circuits with the COMPLETED dedup code, NOT the
    // in-flight code — the pending-window branch only triggers before completion.
    const dupSame = await a.core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER });
    assert.equal(dupSame.code, 'duplicate_submission', 'completed self-resubmit still dedups as before');
    const b = makeCore({ dedupStore: store });
    const dupOther = await b.core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER_B });
    assert.equal(dupOther.code, 'duplicate_submission', 'completed cross-miner resubmit dedups via the completed path');
    assert.equal(b.counters.scorer.calls, 0, 'completed dedup never reaches the scorer');
  });
});

describe('createCoreTexEvaluatorCore — §8 coordinator-pinned seed (remote path)', () => {
  test('input.seedContext is injected verbatim — the scorer never draws its own blockhash', async () => {
    const seenSeeds = [];
    const { core, counters } = makeCore({
      seedScorer: async ({ evalSeed }) => { seenSeeds.push(evalSeed.toLowerCase()); return { accepted: true, before: { composite: 0.4 }, after: { composite: 0.45 }, deltaPpm: 50_000, perFamilyDelta: {} }; },
    });
    const PINNED = { receivedAtBlock: 5_000_000, targetBlock: 5_000_030, blockhash: `0x${'7c'.repeat(32)}` };
    const result = await core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER, seedContext: PINNED });
    assert.equal(result.outcome, 'state_advance');
    assert.equal(counters.rpc.calls, 0, 'a coordinator-pinned seed means NO RPC blockhash draw on the scorer');
    // The artifact's seed derivation must echo the pinned seed.
    assert.equal(result.evalReportHash, result.artifactHash);
  });

  test('the pinned seed flows into the committed artifact seedDerivation', async () => {
    const { core, artifacts } = makeCore();
    const PINNED = { receivedAtBlock: 5_000_000, targetBlock: 5_000_030, blockhash: `0x${'7c'.repeat(32)}` };
    await core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER, seedContext: PINNED });
    assert.equal(artifacts.length, 1);
    assert.equal(artifacts[0].seedDerivation.receivedAtBlock, 5_000_000);
    assert.equal(artifacts[0].seedDerivation.targetBlock, 5_000_030);
    assert.equal(artifacts[0].seedDerivation.blockhash, `0x${'7c'.repeat(32)}`);
  });

  test('keyless scorer does not apply scorer-local duplicate_submission to coordinator-pinned retries', async () => {
    const store = createInMemoryDedupStore();
    const scorerCalls = { calls: 0 };
    const patchHex = patchBytesHex();
    const patchHash = computePatchHash(hexToBytes(patchHex)).toLowerCase();
    const { core, counters } = makeCore({
      dedupStore: store,
      seedScorer: makeSeedScorer(scorerCalls, { accepted: false, reason: 'gate-acceptance-floor' }),
    });
    const PINNED = { receivedAtBlock: 5_000_000, targetBlock: 5_000_030, blockhash: `0x${'7c'.repeat(32)}` };
    const injectedSeeds = { gateSeed: `0x${'8a'.repeat(32)}`, confirmSeed: `0x${'8b'.repeat(32)}` };

    const first = await core.scorePatch({
      patchBytesHex: patchHex,
      parentStateRoot: PARENT_ROOT,
      miner: MINER,
      seedContext: PINNED,
      injectedSeeds,
    });
    const second = await core.scorePatch({
      patchBytesHex: patchHex,
      parentStateRoot: PARENT_ROOT,
      miner: MINER_B,
      seedContext: PINNED,
      injectedSeeds,
    });

    assert.equal(first.outcome, 'reject');
    assert.equal(first.code, 'gate-acceptance-floor');
    assert.equal(second.outcome, 'reject');
    assert.equal(second.code, 'gate-acceptance-floor');
    assert.equal(scorerCalls.calls, 2, 'both coordinator-pinned gate packs must score; no scorer-local duplicate short-circuit');
    assert.equal(counters.rpc.calls, 0, 'keyless scorer never draws its own blockhash');
    assert.equal(store.get({ epochId: 7, parentStateRoot: PARENT_ROOT, patchHash }), null, 'remote scorer host does not persist authoritative dedup outcomes');
    assert.equal(store.minerAdmissions(7, MINER), 0, 'remote scorer host does not charge authoritative admissions');
    assert.equal(store.minerAdmissions(7, MINER_B), 0, 'remote scorer host does not charge cross-miner admissions');
  });
});

describe('createCoreTexEvaluatorCore — envelope strip (§8)', () => {
  test('reject results carry NO deterministicDeltaPpm / requiredDeltaPpm', async () => {
    const { core } = makeCore({ seedScorer: makeSeedScorer({ calls: 0 }, { deltaPpm: 10 }) });
    const below = await core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER });
    assert.equal(below.outcome, 'reject');
    assert.equal('deterministicDeltaPpm' in below, false, 'reject must not leak a score oracle');
    assert.equal('requiredDeltaPpm' in below, false, 'reject must not leak the threshold');

    const dup = await core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER });
    assert.equal(dup.code, 'duplicate_submission');
    assert.equal('deterministicDeltaPpm' in dup, false);
    assert.equal('requiredDeltaPpm' in dup, false);
  });
});

describe('createCoreTexEvaluatorCore — canonical artifact + attestation (§2/§3)', () => {
  test('exposes the hash-bound boot attestation', () => {
    const { core } = makeCore();
    assert.equal(core.bootAttestation.rerankerModelId, 'Qwen/Qwen3-Reranker-0.6B');
    assert.match(core.bootAttestation.attestationHash, /^0x[0-9a-f]{64}$/);
    assert.match(core.bootAttestation.promptTemplateHash, /^0x[0-9a-f]{64}$/);
  });

  test('accepted result commits ONE hash (evalReportHash == artifactHash) and publishes a verifiable artifact', async () => {
    const { core, artifacts } = makeCore();
    const result = await core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER });
    assert.equal(result.outcome, 'state_advance');
    assert.equal(result.evalReportHash, result.artifactHash);
    assert.equal(artifacts.length, 1);
    const artifact = artifacts[0];
    assert.equal(artifact.artifactHash, result.artifactHash, 'on-chain hash must be THE published artifact hash');
    assert.equal(artifact.evalReportHash, result.evalReportHash);
    assert.equal(artifact.outcome, 'STATE_ADVANCE');
    assert.equal(artifact.seedDerivation.mode, 'future_blockhash_dual_pack');
    assert.equal(artifact.seedDerivation.receivedAtBlock, artifact.receipt.receivedAtBlock);
    assert.equal(artifact.seedDerivation.targetBlockOffset, 30);
    assert.equal(artifact.thresholdPpm, 1_000);

    // A validator replays the published artifact end-to-end.
    const verified = await verifyPostRevealEvalReportArtifact(JSON.parse(JSON.stringify(artifact)), {
      rpcClient: { async getBlockHash() { return BLOCKHASH; } },
      scorer: async () => ({ scorePpm: 50_000, accepted: true }),
      epochSecret: EPOCH_SECRET,
    });
    assert.equal(verified.ok, true, JSON.stringify(verified));
  });

  test('screener_pass (below state threshold) also carries the single artifact hash', async () => {
    const { core, artifacts } = makeCore({ stateThresholdPpm: 60_000 });
    const result = await core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER });
    assert.equal(result.outcome, 'screener_pass');
    assert.equal(result.evalReportHash, result.artifactHash);
    assert.equal(artifacts[0].outcome, 'SCREENER_PASS');
    assert.equal(artifacts[0].artifactHash, result.artifactHash);
  });

  test('publish failure fails the evaluation (no unpublished commitment)', async () => {
    const { core } = makeCore({ publishArtifact: () => { throw new Error('s3 down'); } });
    await assert.rejects(
      core.scorePatch({ patchBytesHex: patchBytesHex(), parentStateRoot: PARENT_ROOT, miner: MINER }),
      /s3 down/,
    );
  });
});
