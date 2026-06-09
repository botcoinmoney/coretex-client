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
