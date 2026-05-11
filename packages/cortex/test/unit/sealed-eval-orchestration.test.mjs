/**
 * Tests for sealed-eval gate/confirm/batch-settlement orchestration
 * (Phase S3 + S4 scaffolding). All test scorers are deterministic
 * fakes — no model work, no I/O. Production wires
 * evaluateRetrievalBenchmarkPatch into the same shape after the
 * launch corpus completes.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  runGateEvaluation,
  runConfirmEvaluation,
  selectBatchWinners,
  sortFinalists,
  patchesConflict,
} from '../../dist/index.js';

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const MINER_A = `0x${'aa'.repeat(20)}`;
const MINER_B = `0x${'bb'.repeat(20)}`;
const MINER_C = `0x${'cc'.repeat(20)}`;
const HASH_A = `0x${'01'.repeat(32)}`;
const HASH_B = `0x${'02'.repeat(32)}`;
const HASH_C = `0x${'03'.repeat(32)}`;
const HASH_D = `0x${'04'.repeat(32)}`;

function dummyState() {
  // Minimal CortexState shape — orchestrator never inspects words; only
  // the injected scorer + applyPatch see the inside.
  return { words: new Array(1024).fill(0n) };
}

function makePatch(indices) {
  return {
    patchType: 1,
    wordCount: indices.length,
    scoreDelta: 0n,
    parentStateRoot: new Uint8Array(32),
    indices,
    newWords: indices.map(() => 0n),
  };
}

function admitted(commitmentHash, minerAddress, indices, sizeBytes = 64) {
  const patch = makePatch(indices);
  const patchBytes = new Uint8Array(sizeBytes);
  return { commitmentHash, minerAddress, patch, patchBytes };
}

// ─── runGateEvaluation ────────────────────────────────────────────────────────

describe('runGateEvaluation', () => {
  test('marks every admitted reveal with isFinalist based on threshold', async () => {
    const admittedReveals = [
      admitted(HASH_A, MINER_A, [10]),
      admitted(HASH_B, MINER_B, [20]),
      admitted(HASH_C, MINER_C, [30]),
    ];
    // Deterministic fake scorer: A → 5000ppm, B → 1500ppm, C → 4000ppm
    const scores = new Map([
      [HASH_A, 5000],
      [HASH_B, 1500],
      [HASH_C, 4000],
    ]);
    const scorer = async (_parent, patch) => {
      const found = admittedReveals.find((r) => r.patch === patch);
      return scores.get(found.commitmentHash);
    };

    const outcomes = await runGateEvaluation({
      admittedReveals,
      parentSubstrate: dummyState(),
      gateSeedHex: `0x${'11'.repeat(32)}`,
      thresholdPpm: 2500,
      scorer,
    });

    assert.equal(outcomes.length, 3);
    assert.equal(outcomes[0].commitmentHash, HASH_A);
    assert.equal(outcomes[0].gateDeltaPpm, 5000);
    assert.equal(outcomes[0].isFinalist, true);
    assert.equal(outcomes[1].commitmentHash, HASH_B);
    assert.equal(outcomes[1].gateDeltaPpm, 1500);
    assert.equal(outcomes[1].isFinalist, false);
    assert.equal(outcomes[2].commitmentHash, HASH_C);
    assert.equal(outcomes[2].isFinalist, true);
  });

  test('preserves input order in the output (deterministic)', async () => {
    const admittedReveals = [admitted(HASH_C, MINER_C, [30]), admitted(HASH_A, MINER_A, [10])];
    let i = 0;
    const scorer = async () => { i++; return 9999; };
    const outcomes = await runGateEvaluation({
      admittedReveals,
      parentSubstrate: dummyState(),
      gateSeedHex: `0x${'11'.repeat(32)}`,
      thresholdPpm: 2500,
      scorer,
    });
    assert.equal(outcomes[0].commitmentHash, HASH_C);
    assert.equal(outcomes[1].commitmentHash, HASH_A);
    assert.equal(i, 2);
  });
});

// ─── runConfirmEvaluation ─────────────────────────────────────────────────────

describe('runConfirmEvaluation', () => {
  test('only scores finalists from the gate phase', async () => {
    const reveals = [
      admitted(HASH_A, MINER_A, [10]),
      admitted(HASH_B, MINER_B, [20]),
      admitted(HASH_C, MINER_C, [30]),
    ];
    const finalists = [
      { commitmentHash: HASH_A, minerAddress: MINER_A, gateDeltaPpm: 5000, isFinalist: true },
      { commitmentHash: HASH_B, minerAddress: MINER_B, gateDeltaPpm: 1500, isFinalist: false },
      { commitmentHash: HASH_C, minerAddress: MINER_C, gateDeltaPpm: 4000, isFinalist: true },
    ];
    const calls = [];
    const scorer = async (_p, _patch, seedHex) => {
      calls.push(seedHex);
      return 3000;
    };

    const outcomes = await runConfirmEvaluation({
      finalists,
      admittedRevealsByHash: new Map(reveals.map((r) => [r.commitmentHash, r])),
      parentSubstrate: dummyState(),
      confirmSeedHex: `0x${'22'.repeat(32)}`,
      thresholdPpm: 2500,
      scorer,
    });

    // Only A and C are finalists; B should not have been scored.
    assert.equal(outcomes.length, 2);
    assert.equal(outcomes[0].commitmentHash, HASH_A);
    assert.equal(outcomes[1].commitmentHash, HASH_C);
    assert.equal(calls.length, 2);
    assert.equal(calls[0], `0x${'22'.repeat(32)}`);
  });

  test('missing admitted reveal yields zero-delta clearsConfirm:false (defensive)', async () => {
    const finalists = [
      { commitmentHash: HASH_D, minerAddress: MINER_A, gateDeltaPpm: 5000, isFinalist: true },
    ];
    const outcomes = await runConfirmEvaluation({
      finalists,
      admittedRevealsByHash: new Map(), // empty — bookkeeping bug
      parentSubstrate: dummyState(),
      confirmSeedHex: `0x${'22'.repeat(32)}`,
      thresholdPpm: 2500,
      scorer: async () => 9999, // would clear if it ran
    });
    assert.equal(outcomes.length, 1);
    assert.equal(outcomes[0].confirmDeltaPpm, 0);
    assert.equal(outcomes[0].clearsConfirm, false);
  });
});

// ─── sortFinalists ────────────────────────────────────────────────────────────

describe('sortFinalists', () => {
  test('sorts by confirmDeltaPpm desc, then patch size asc, then hash asc', () => {
    const finalists = [
      { commitmentHash: HASH_A, minerAddress: MINER_A, confirmDeltaPpm: 1000, clearsConfirm: true },
      { commitmentHash: HASH_B, minerAddress: MINER_B, confirmDeltaPpm: 5000, clearsConfirm: true },
      { commitmentHash: HASH_C, minerAddress: MINER_C, confirmDeltaPpm: 5000, clearsConfirm: true },
      { commitmentHash: HASH_D, minerAddress: MINER_A, confirmDeltaPpm: 3000, clearsConfirm: true },
    ];
    const sizes = new Map([
      [HASH_A, 100],
      [HASH_B, 200],  // tied with C on score but bigger patch → second
      [HASH_C, 50],   // smallest patch among score-5000 → first
      [HASH_D, 100],
    ]);
    const sorted = sortFinalists(finalists, sizes);
    assert.deepEqual(
      sorted.map((f) => f.commitmentHash),
      [HASH_C, HASH_B, HASH_D, HASH_A],
    );
  });

  test('falls back to hash ascending when score + size are tied', () => {
    const finalists = [
      { commitmentHash: HASH_B, minerAddress: MINER_B, confirmDeltaPpm: 3000, clearsConfirm: true },
      { commitmentHash: HASH_A, minerAddress: MINER_A, confirmDeltaPpm: 3000, clearsConfirm: true },
    ];
    const sizes = new Map([[HASH_A, 100], [HASH_B, 100]]);
    const sorted = sortFinalists(finalists, sizes);
    assert.equal(sorted[0].commitmentHash, HASH_A);
  });
});

// ─── patchesConflict ──────────────────────────────────────────────────────────

describe('patchesConflict', () => {
  test('detects shared word index', () => {
    assert.equal(patchesConflict(makePatch([10, 20]), makePatch([20, 30])), true);
    assert.equal(patchesConflict(makePatch([10]), makePatch([10])), true);
  });
  test('false when no overlap', () => {
    assert.equal(patchesConflict(makePatch([10, 20]), makePatch([30, 40])), false);
  });
});

// ─── selectBatchWinners ───────────────────────────────────────────────────────

describe('selectBatchWinners', () => {
  // Apply-patch fake: returns a new "state" whose words are a tag of
  // which patch was last applied. The orchestrator only cares that
  // applyPatch produces a distinct object passed back into the
  // marginal scorer.
  let stateCounter = 0;
  function applyPatch(state, _patch) {
    return { words: state.words, tag: ++stateCounter };
  }

  function makeMarginalScorer(perCommitmentMarginal) {
    return async (current, patch) => {
      // Look up which commitment this patch belongs to by indices[0]
      // (per our fixture, each patch has a unique first index).
      const idx = patch.indices[0];
      return perCommitmentMarginal.get(idx) ?? 0;
    };
  }

  test('selects the highest-marginal winners deterministically', async () => {
    const reveals = [
      admitted(HASH_A, MINER_A, [10]),
      admitted(HASH_B, MINER_B, [20]),
      admitted(HASH_C, MINER_C, [30]),
    ];
    const finalists = [
      { commitmentHash: HASH_A, minerAddress: MINER_A, confirmDeltaPpm: 4000, clearsConfirm: true },
      { commitmentHash: HASH_B, minerAddress: MINER_B, confirmDeltaPpm: 5000, clearsConfirm: true },
      { commitmentHash: HASH_C, minerAddress: MINER_C, confirmDeltaPpm: 3000, clearsConfirm: true },
    ];
    const marginalByIdx = new Map([[10, 4000], [20, 5000], [30, 3000]]);

    const result = await selectBatchWinners({
      epochParentSubstrate: dummyState(),
      finalists,
      admittedReveals: reveals,
      maxAdvancesPerEpoch: 5,
      thresholdPpm: 2500,
      marginalScorer: makeMarginalScorer(marginalByIdx),
      applyPatch,
    });

    assert.equal(result.winners.length, 3);
    // Sorted by confirmDelta desc: B, A, C
    assert.equal(result.winners[0].commitmentHash, HASH_B);
    assert.equal(result.winners[1].commitmentHash, HASH_A);
    assert.equal(result.winners[2].commitmentHash, HASH_C);
    assert.equal(result.rejectedConflicts.length, 0);
    assert.equal(result.rejectedBelowThreshold.length, 0);
    assert.equal(result.rejectedCapReached.length, 0);
  });

  test('skips conflicting patches in favor of the higher-confirmDelta winner', async () => {
    const reveals = [
      admitted(HASH_A, MINER_A, [10, 20]),
      admitted(HASH_B, MINER_B, [20]),  // conflicts with A on index 20
      admitted(HASH_C, MINER_C, [30]),
    ];
    const finalists = [
      { commitmentHash: HASH_A, minerAddress: MINER_A, confirmDeltaPpm: 5000, clearsConfirm: true },
      { commitmentHash: HASH_B, minerAddress: MINER_B, confirmDeltaPpm: 4000, clearsConfirm: true },
      { commitmentHash: HASH_C, minerAddress: MINER_C, confirmDeltaPpm: 3000, clearsConfirm: true },
    ];
    const marginalByIdx = new Map([[10, 5000], [20, 4000], [30, 3000]]);

    const result = await selectBatchWinners({
      epochParentSubstrate: dummyState(),
      finalists,
      admittedReveals: reveals,
      maxAdvancesPerEpoch: 5,
      thresholdPpm: 2500,
      marginalScorer: makeMarginalScorer(marginalByIdx),
      applyPatch,
    });
    assert.deepEqual(result.winners.map((w) => w.commitmentHash), [HASH_A, HASH_C]);
    assert.deepEqual(result.rejectedConflicts, [HASH_B]);
  });

  test('respects maxAdvancesPerEpoch cap', async () => {
    const reveals = [
      admitted(HASH_A, MINER_A, [10]),
      admitted(HASH_B, MINER_B, [20]),
      admitted(HASH_C, MINER_C, [30]),
    ];
    const finalists = [
      { commitmentHash: HASH_A, minerAddress: MINER_A, confirmDeltaPpm: 5000, clearsConfirm: true },
      { commitmentHash: HASH_B, minerAddress: MINER_B, confirmDeltaPpm: 4000, clearsConfirm: true },
      { commitmentHash: HASH_C, minerAddress: MINER_C, confirmDeltaPpm: 3000, clearsConfirm: true },
    ];
    const marginalByIdx = new Map([[10, 5000], [20, 4000], [30, 3000]]);

    const result = await selectBatchWinners({
      epochParentSubstrate: dummyState(),
      finalists,
      admittedReveals: reveals,
      maxAdvancesPerEpoch: 2,
      thresholdPpm: 2500,
      marginalScorer: makeMarginalScorer(marginalByIdx),
      applyPatch,
    });
    assert.equal(result.winners.length, 2);
    assert.deepEqual(result.winners.map((w) => w.commitmentHash), [HASH_A, HASH_B]);
    assert.deepEqual(result.rejectedCapReached, [HASH_C]);
  });

  test('same miner cannot win twice in one epoch', async () => {
    const reveals = [
      admitted(HASH_A, MINER_A, [10]),
      admitted(HASH_B, MINER_A, [20]), // same miner!
      admitted(HASH_C, MINER_B, [30]),
    ];
    const finalists = [
      { commitmentHash: HASH_A, minerAddress: MINER_A, confirmDeltaPpm: 5000, clearsConfirm: true },
      { commitmentHash: HASH_B, minerAddress: MINER_A, confirmDeltaPpm: 4000, clearsConfirm: true },
      { commitmentHash: HASH_C, minerAddress: MINER_B, confirmDeltaPpm: 3000, clearsConfirm: true },
    ];
    const marginalByIdx = new Map([[10, 5000], [20, 4000], [30, 3000]]);

    const result = await selectBatchWinners({
      epochParentSubstrate: dummyState(),
      finalists,
      admittedReveals: reveals,
      maxAdvancesPerEpoch: 5,
      thresholdPpm: 2500,
      marginalScorer: makeMarginalScorer(marginalByIdx),
      applyPatch,
    });
    // A wins; B (same miner) is rejected; C wins (different miner).
    assert.deepEqual(result.winners.map((w) => w.commitmentHash), [HASH_A, HASH_C]);
    assert.deepEqual(result.rejectedCapReached, [HASH_B]);
  });

  test('marginal re-evaluation filters out pack-luck advances', async () => {
    const reveals = [
      admitted(HASH_A, MINER_A, [10]),
      admitted(HASH_B, MINER_B, [20]),
    ];
    const finalists = [
      { commitmentHash: HASH_A, minerAddress: MINER_A, confirmDeltaPpm: 5000, clearsConfirm: true },
      { commitmentHash: HASH_B, minerAddress: MINER_B, confirmDeltaPpm: 4000, clearsConfirm: true },
    ];
    // B's confirm delta was 4000 (cleared threshold) but its marginal
    // on the post-A substrate drops below threshold. Filter it out.
    const marginalByIdx = new Map([[10, 5000], [20, 100]]);

    const result = await selectBatchWinners({
      epochParentSubstrate: dummyState(),
      finalists,
      admittedReveals: reveals,
      maxAdvancesPerEpoch: 5,
      thresholdPpm: 2500,
      marginalScorer: makeMarginalScorer(marginalByIdx),
      applyPatch,
    });
    assert.deepEqual(result.winners.map((w) => w.commitmentHash), [HASH_A]);
    assert.deepEqual(result.rejectedBelowThreshold, [HASH_B]);
  });
});
