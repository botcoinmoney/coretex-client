/**
 * Per-patch receipt replay verification tests.
 *
 * The verifier's job is to reproduce every coordinator-side decision
 * from public chain data + the post-epoch epochSecret reveal. The
 * tests below lock in each failure mode and the happy path.
 *
 * All deps are injected fakes — no I/O, no models. Production wires
 * `evaluateRetrievalBenchmarkPatch` as the scorer in task #38.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  runPerPatchEvaluation,
  verifyPerPatchReceipt,
} from '../../dist/index.js';

const PARENT_ROOT = `0x${'aa'.repeat(32)}`;
const MINER = `0x${'10'.repeat(20)}`;
const EPOCH_SECRET = `0x${'01'.repeat(32)}`;
const CORPUS_ROOT = `0x${'cc'.repeat(32)}`;
const BUNDLE_HASH = `0x${'dd'.repeat(32)}`;
const BLOCKHASH = `0x${'02'.repeat(32)}`;
const PATCH_BYTES = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);

function makeRpcClient(blockhashByBlock = new Map(), head = 1000) {
  return {
    async getLatestBlockNumber() { return head; },
    async getBlockHash(n) {
      const h = blockhashByBlock.get(n);
      if (!h) throw new Error(`block ${n} not found`);
      return h;
    },
    async waitForBlock(n) {
      const h = blockhashByBlock.get(n);
      if (!h) throw new Error(`block ${n} not found`);
      return { number: n, blockhash: h, timestamp: 1700000000 };
    },
  };
}

async function buildAcceptedReceipt(overrideScorer) {
  // Run the orchestrator with a deterministic scorer to produce a
  // signed-shape receipt that the verifier should accept.
  const targetBlock = 1030;
  const rpcClient = makeRpcClient(new Map([[targetBlock, BLOCKHASH]]));
  const scorer = overrideScorer ?? (async () => ({ scorePpm: 50_000, accepted: true }));
  return runPerPatchEvaluation(
    {
      normalizedPatchBytes: PATCH_BYTES,
      parentRoot: PARENT_ROOT,
      minerAddress: MINER,
      epochId: 7,
      structurallyValid: true,
    },
    {
      rpcClient,
      scorer,
      targetBlockOffset: 30,
      thresholdPpm: 1_000,
      perMinerCap: 5,
      epochSecret: EPOCH_SECRET,
      corpusRoot: CORPUS_ROOT,
      bundleHash: BUNDLE_HASH,
      dedupCache: new Map(),
      minerAdmissions: new Map(),
    },
  );
}

describe('verifyPerPatchReceipt — happy path', () => {
  test('an honest receipt verifies (scores match within tolerance)', async () => {
    const receipt = await buildAcceptedReceipt();
    const rpcClient = makeRpcClient(new Map([[receipt.targetBlock, BLOCKHASH]]));
    const r = await verifyPerPatchReceipt(receipt, {
      rpcClient,
      replayTolerancePpm: 250,
      scorer: async () => ({ scorePpm: 50_000, accepted: true }),  // replay reproduces exactly
      epochSecret: EPOCH_SECRET,
      corpusRoot: CORPUS_ROOT,
      bundleHash: BUNDLE_HASH,
      normalizedPatchBytes: PATCH_BYTES,
    });
    assert.equal(r.ok, true);
    if (r.ok) {
      assert.equal(r.gateDeltaPpm, 0);
      assert.equal(r.confirmDeltaPpm, 0);
    }
  });

  test('replay within tolerance band passes (e.g., 200ppm off, tolerance 250)', async () => {
    const receipt = await buildAcceptedReceipt();
    const rpcClient = makeRpcClient(new Map([[receipt.targetBlock, BLOCKHASH]]));
    const r = await verifyPerPatchReceipt(receipt, {
      rpcClient,
      replayTolerancePpm: 250,
      scorer: async () => ({ scorePpm: 50_200, accepted: true }),  // 200 ppm above coordinator
      epochSecret: EPOCH_SECRET,
      corpusRoot: CORPUS_ROOT,
      bundleHash: BUNDLE_HASH,
      normalizedPatchBytes: PATCH_BYTES,
    });
    assert.equal(r.ok, true);
    if (r.ok) {
      assert.equal(r.gateDeltaPpm, 200);
      assert.equal(r.confirmDeltaPpm, 200);
    }
  });
});

describe('verifyPerPatchReceipt — anti-forgery failures', () => {
  test('blockhash mismatch — chain returns a different hash than receipt claims', async () => {
    const receipt = await buildAcceptedReceipt();
    const wrongHash = `0x${'ff'.repeat(32)}`;
    const rpcClient = makeRpcClient(new Map([[receipt.targetBlock, wrongHash]]));
    const r = await verifyPerPatchReceipt(receipt, {
      rpcClient,
      replayTolerancePpm: 250,
      scorer: async () => ({ scorePpm: 50_000, accepted: true }),
      epochSecret: EPOCH_SECRET,
      corpusRoot: CORPUS_ROOT,
      bundleHash: BUNDLE_HASH,
      normalizedPatchBytes: PATCH_BYTES,
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.code, 'BLOCKHASH_MISMATCH');
  });

  test('patchHash mismatch — replay gets different patch bytes than what was hashed', async () => {
    const receipt = await buildAcceptedReceipt();
    const rpcClient = makeRpcClient(new Map([[receipt.targetBlock, BLOCKHASH]]));
    const r = await verifyPerPatchReceipt(receipt, {
      rpcClient,
      replayTolerancePpm: 250,
      scorer: async () => ({ scorePpm: 50_000, accepted: true }),
      epochSecret: EPOCH_SECRET,
      corpusRoot: CORPUS_ROOT,
      bundleHash: BUNDLE_HASH,
      normalizedPatchBytes: new Uint8Array([9, 9, 9]),  // different bytes
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.code, 'PATCH_HASH_MISMATCH');
  });

  test('gate seed mismatch — wrong epochSecret used', async () => {
    const receipt = await buildAcceptedReceipt();
    const rpcClient = makeRpcClient(new Map([[receipt.targetBlock, BLOCKHASH]]));
    const r = await verifyPerPatchReceipt(receipt, {
      rpcClient,
      replayTolerancePpm: 250,
      scorer: async () => ({ scorePpm: 50_000, accepted: true }),
      epochSecret: `0x${'ee'.repeat(32)}`,  // WRONG epoch secret
      corpusRoot: CORPUS_ROOT,
      bundleHash: BUNDLE_HASH,
      normalizedPatchBytes: PATCH_BYTES,
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.code, 'GATE_SEED_MISMATCH');
  });

  test('gate score beyond tolerance — coordinator scored 50000 but replay says 60000', async () => {
    const receipt = await buildAcceptedReceipt();
    const rpcClient = makeRpcClient(new Map([[receipt.targetBlock, BLOCKHASH]]));
    const r = await verifyPerPatchReceipt(receipt, {
      rpcClient,
      replayTolerancePpm: 250,
      scorer: async () => ({ scorePpm: 60_000, accepted: true }),  // 10000 ppm above — way beyond tolerance
      epochSecret: EPOCH_SECRET,
      corpusRoot: CORPUS_ROOT,
      bundleHash: BUNDLE_HASH,
      normalizedPatchBytes: PATCH_BYTES,
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.code, 'GATE_SCORE_BEYOND_TOLERANCE');
  });

  test('confirm score beyond tolerance — gate passes, confirm fails', async () => {
    const receipt = await buildAcceptedReceipt();
    const rpcClient = makeRpcClient(new Map([[receipt.targetBlock, BLOCKHASH]]));
    const r = await verifyPerPatchReceipt(receipt, {
      rpcClient,
      replayTolerancePpm: 250,
      scorer: async ({ which }) => ({ scorePpm: which === "gate" ? 50_000 : 60_000, accepted: true }),
      epochSecret: EPOCH_SECRET,
      corpusRoot: CORPUS_ROOT,
      bundleHash: BUNDLE_HASH,
      normalizedPatchBytes: PATCH_BYTES,
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.code, 'CONFIRM_SCORE_BEYOND_TOLERANCE');
  });

  test('RPC error surfaces as RPC_ERROR with detail', async () => {
    const receipt = await buildAcceptedReceipt();
    const rpcClient = {
      async getLatestBlockNumber() { return 0; },
      async getBlockHash() { throw new Error('archive node behind by 5 blocks'); },
      async waitForBlock() { throw new Error('archive node behind'); },
    };
    const r = await verifyPerPatchReceipt(receipt, {
      rpcClient,
      replayTolerancePpm: 250,
      scorer: async () => ({ scorePpm: 0, accepted: true }),
      epochSecret: EPOCH_SECRET,
      corpusRoot: CORPUS_ROOT,
      bundleHash: BUNDLE_HASH,
      normalizedPatchBytes: PATCH_BYTES,
    });
    assert.equal(r.ok, false);
    if (!r.ok) {
      assert.equal(r.code, 'RPC_ERROR');
      assert.match(r.detail, /archive node/);
    }
  });
});

describe('verifyPerPatchReceipt — pre-RPC rejection receipts', () => {
  test('admission-rejection receipts (receivedAtBlock=0) verify with zero score deltas', async () => {
    // A receipt where the patch was rejected at the admission gate
    // before any RPC call. These receipts have no blockhash, seed, or
    // scores — but patchHash + dedupKey still must reproduce.
    const dedupCache = new Map();
    // Force the admission to fail via a cached dedup key.
    const first = await buildAcceptedReceipt();
    dedupCache.set(first.dedupKey, first);
    const targetBlock = 1030;
    const rpcClient = makeRpcClient(new Map([[targetBlock, BLOCKHASH]]));
    const cached = await runPerPatchEvaluation(
      {
        normalizedPatchBytes: PATCH_BYTES,
        parentRoot: PARENT_ROOT,
        minerAddress: MINER,
        epochId: 7,
        structurallyValid: true,
      },
      {
        rpcClient,
        scorer: async () => ({ scorePpm: 50_000, accepted: true }),
        targetBlockOffset: 30,
        thresholdPpm: 1_000,
        perMinerCap: 5,
        epochSecret: EPOCH_SECRET,
        corpusRoot: CORPUS_ROOT,
        bundleHash: BUNDLE_HASH,
        dedupCache,
        minerAdmissions: new Map(),
      },
    );
    assert.equal(cached.rejectionReason, 'cached');

    // Now exercise a structurally-invalid path which has receivedAtBlock=0.
    const structurallyBad = await runPerPatchEvaluation(
      {
        normalizedPatchBytes: PATCH_BYTES,
        parentRoot: PARENT_ROOT,
        minerAddress: MINER,
        epochId: 7,
        structurallyValid: false,
      },
      {
        rpcClient,
        scorer: async () => ({ scorePpm: 50_000, accepted: true }),
        targetBlockOffset: 30,
        thresholdPpm: 1_000,
        perMinerCap: 5,
        epochSecret: EPOCH_SECRET,
        corpusRoot: CORPUS_ROOT,
        bundleHash: BUNDLE_HASH,
        dedupCache: new Map(),
        minerAdmissions: new Map(),
      },
    );
    assert.equal(structurallyBad.receivedAtBlock, 0);

    // Verify — the patchHash + dedupKey still must reproduce; no score check.
    const r = await verifyPerPatchReceipt(structurallyBad, {
      rpcClient,
      replayTolerancePpm: 250,
      scorer: async () => ({ scorePpm: 50_000, accepted: true }),
      epochSecret: EPOCH_SECRET,
      corpusRoot: CORPUS_ROOT,
      bundleHash: BUNDLE_HASH,
      normalizedPatchBytes: PATCH_BYTES,
    });
    assert.equal(r.ok, true);
  });
});
