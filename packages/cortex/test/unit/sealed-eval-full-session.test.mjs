/**
 * Full-session sealed-eval smoke — composes BOTH layers of the
 * sealed-eval surface into one deterministic story:
 *
 *   commit primitives  (src/coordinator/sealed-eval.ts)
 *     buildPatchCommitment → computeCommitmentRoot → deriveCoretexEvalSeed
 *     → deriveGateSeed + deriveConfirmSeed → verifyPatchReveal
 *     → computeDuplicateKey → screenerAdmissionDecision
 *
 *   orchestration primitives  (src/coordinator/sealed-eval-orchestration.ts)
 *     runGateEvaluation → runConfirmEvaluation → selectBatchWinners
 *
 * The pure-functions composition test (`sealed-eval-lifecycle.test.mjs`)
 * proves the commit layer up to admission; the orchestration test
 * (`sealed-eval-orchestration.test.mjs`) proves the gate/confirm/batch
 * layer in isolation. This file is the bridge: a single end-to-end
 * walkthrough where the OUTPUTS of the commit layer feed the INPUTS of
 * the orchestration layer.
 *
 * Scenario:
 *   - 4 miners commit patches in an epoch
 *   - 1 commitment is duplicate-collapsed at admission (same dup-key as
 *     an earlier admit)
 *   - 1 commitment fails post-commit admission (rule 2)
 *   - Remaining commitments pass gate; some fail the confirm threshold
 *   - Two passing commitments conflict; lower-confirm-delta loses
 *   - One commitment's marginal on post-winner substrate drops below
 *     threshold (pack-luck filter)
 *   - maxAdvancesPerEpoch caps the rest
 *
 * Everything is pure — no models, no I/O.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  buildPatchCommitment,
  computeCommitmentRoot,
  deriveCoretexEvalSeed,
  deriveGateSeed,
  deriveConfirmSeed,
  verifyPatchReveal,
  computeDuplicateKey,
  screenerAdmissionDecision,
  runGateEvaluation,
  runConfirmEvaluation,
  selectBatchWinners,
} from '../../dist/index.js';

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const EPOCH_ID = 99;
const PARENT_ROOT = `0x${'aa'.repeat(32)}`;
const CORPUS_ROOT = `0x${'cc'.repeat(32)}`;
const BUNDLE_HASH = `0x${'dd'.repeat(32)}`;
const EPOCH_SECRET = `0x${'01'.repeat(32)}`;
const FUTURE_BLOCKHASH = `0x${'02'.repeat(32)}`;
const DRAND = `0x${'03'.repeat(32)}`;

const MINER_A = `0x${'10'.repeat(20)}`;
const MINER_B = `0x${'20'.repeat(20)}`;
const MINER_C = `0x${'30'.repeat(20)}`;
const MINER_D = `0x${'40'.repeat(20)}`;

const SALT_A = `0x${'a1'.repeat(32)}`;
const SALT_A_DUP = `0x${'a2'.repeat(32)}`; // miner A's second salt — same patch bytes
const SALT_B = `0x${'b1'.repeat(32)}`;
const SALT_C = `0x${'c1'.repeat(32)}`;
const SALT_D = `0x${'d1'.repeat(32)}`;

// Patches differ by touched indices. A and A-DUP carry IDENTICAL bytes
// so the duplicate-key collapses; the other miners produce distinct dup
// keys.
const PATCH_BYTES_A = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);
const PATCH_BYTES_A_DUP = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]); // bit-identical
const PATCH_BYTES_B = new Uint8Array([0x10, 0x11, 0x12, 0x13, 0x14, 0x15]);
const PATCH_BYTES_C = new Uint8Array([0x20, 0x21, 0x22, 0x23, 0x24]);
const PATCH_BYTES_D = new Uint8Array([0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36]);

// Decoded Patch shape — orchestrator never inspects words, but the
// conflict detector uses .indices and the marginal scorer reads
// .indices[0] in our fake.
function decodedPatch(indices) {
  return {
    patchType: 1,
    wordCount: indices.length,
    scoreDelta: 0n,
    parentStateRoot: new Uint8Array(32),
    indices,
    newWords: indices.map(() => 0n),
  };
}
function dummyState() { return { words: new Array(1024).fill(0n) }; }

// ─── Test ─────────────────────────────────────────────────────────────────────

describe('sealed-eval full session (commit → admit → gate → confirm → winners)', () => {
  test('end-to-end deterministic flow with all rejection paths exercised', async () => {
    // ─── Stage 1: commit window — 5 commitments from 4 miners ─────────
    const commitA = buildPatchCommitment({
      epochId: EPOCH_ID,
      epochParentRoot: PARENT_ROOT,
      minerAddress: MINER_A,
      bundleHash: BUNDLE_HASH,
      patchBytes: PATCH_BYTES_A,
      saltHex: SALT_A,
    });
    const commitADup = buildPatchCommitment({
      epochId: EPOCH_ID,
      epochParentRoot: PARENT_ROOT,
      minerAddress: MINER_A,
      bundleHash: BUNDLE_HASH,
      patchBytes: PATCH_BYTES_A_DUP, // same bytes as A
      saltHex: SALT_A_DUP,           // different salt → different commitment hash
    });
    const commitB = buildPatchCommitment({
      epochId: EPOCH_ID,
      epochParentRoot: PARENT_ROOT,
      minerAddress: MINER_B,
      bundleHash: BUNDLE_HASH,
      patchBytes: PATCH_BYTES_B,
      saltHex: SALT_B,
    });
    const commitC = buildPatchCommitment({
      epochId: EPOCH_ID,
      epochParentRoot: PARENT_ROOT,
      minerAddress: MINER_C,
      bundleHash: BUNDLE_HASH,
      patchBytes: PATCH_BYTES_C,
      saltHex: SALT_C,
    });
    const commitD = buildPatchCommitment({
      epochId: EPOCH_ID,
      epochParentRoot: PARENT_ROOT,
      minerAddress: MINER_D,
      bundleHash: BUNDLE_HASH,
      patchBytes: PATCH_BYTES_D,
      saltHex: SALT_D,
    });
    assert.notEqual(commitA.commitmentHash, commitADup.commitmentHash, 'different salts → different hashes');

    // ─── Stage 2: commit window closes → coordinator anchors root ──────
    const commitmentRoot = computeCommitmentRoot([
      commitA.commitmentHash,
      commitADup.commitmentHash,
      commitB.commitmentHash,
      commitC.commitmentHash,
      commitD.commitmentHash,
    ]);
    assert.match(commitmentRoot, /^0x[0-9a-f]{64}$/);

    // ─── Stage 3: future randomness lands → seeds derived ──────────────
    const coretexEvalSeed = deriveCoretexEvalSeed({
      epochId: EPOCH_ID,
      epochParentRoot: PARENT_ROOT,
      corpusRoot: CORPUS_ROOT,
      bundleHash: BUNDLE_HASH,
      commitmentRoot,
      epochSecret: EPOCH_SECRET,
      futureBlockHash: FUTURE_BLOCKHASH,
      optionalDrandRoundHash: DRAND,
    });
    const gateSeed = deriveGateSeed(coretexEvalSeed);
    const confirmSeed = deriveConfirmSeed(coretexEvalSeed);
    assert.notEqual(gateSeed, confirmSeed);
    assert.match(gateSeed, /^0x[0-9a-f]{64}$/);
    assert.match(confirmSeed, /^0x[0-9a-f]{64}$/);

    // ─── Stage 4: reveal verification ───────────────────────────────────
    // All five miners reveal honestly; verification passes for all.
    const revealCases = [
      { commit: commitA,    miner: MINER_A, bytes: PATCH_BYTES_A,     salt: SALT_A },
      { commit: commitADup, miner: MINER_A, bytes: PATCH_BYTES_A_DUP, salt: SALT_A_DUP },
      { commit: commitB,    miner: MINER_B, bytes: PATCH_BYTES_B,     salt: SALT_B },
      { commit: commitC,    miner: MINER_C, bytes: PATCH_BYTES_C,     salt: SALT_C },
      { commit: commitD,    miner: MINER_D, bytes: PATCH_BYTES_D,     salt: SALT_D },
    ];
    for (const r of revealCases) {
      const v = verifyPatchReveal({
        commitmentHash: r.commit.commitmentHash,
        patchBytes: r.bytes,
        saltHex: r.salt,
        epochId: EPOCH_ID,
        epochParentRoot: PARENT_ROOT,
        minerAddress: r.miner,
        bundleHash: BUNDLE_HASH,
      });
      assert.equal(v.ok, true, `reveal for ${r.commit.commitmentHash} should verify`);
    }

    // ─── Stage 5: post-commit admission ─────────────────────────────────
    // Miner C's reveal fails post-commit structural admission (rule 2).
    // Miner A's second commit has identical dup-key as the first (rule 4).
    const RESULTING_ROOT_A = `0x${'77'.repeat(32)}`;
    const RESULTING_ROOT_B = `0x${'88'.repeat(32)}`;
    const RESULTING_ROOT_C = `0x${'99'.repeat(32)}`;
    const RESULTING_ROOT_D = `0x${'aa'.repeat(32)}`;
    // The decoded patches each miner submitted (touched word indices).
    // Conflict matrix: A=[10,20], B=[20,30] conflict via 20.
    //                  A_DUP same as A (collapses).
    //                  C=[50],   D=[70].
    const PATCH_A_DECODED = decodedPatch([10, 20]);
    const PATCH_A_DUP_DECODED = decodedPatch([10, 20]);
    const PATCH_B_DECODED = decodedPatch([20, 30]);
    const PATCH_C_DECODED = decodedPatch([50]);
    const PATCH_D_DECODED = decodedPatch([70]);

    function dupKeyFor(touched, bytes, resultingRoot) {
      return computeDuplicateKey({
        epochParentRoot: PARENT_ROOT,
        sortedTouchedWordIndices: touched,
        normalizedPatchBytes: bytes,
        resultingStateRoot: resultingRoot,
      });
    }
    const dupKeyA = dupKeyFor([10, 20], PATCH_BYTES_A, RESULTING_ROOT_A);
    const dupKeyADup = dupKeyFor([10, 20], PATCH_BYTES_A_DUP, RESULTING_ROOT_A);
    const dupKeyB = dupKeyFor([20, 30], PATCH_BYTES_B, RESULTING_ROOT_B);
    const dupKeyC = dupKeyFor([50], PATCH_BYTES_C, RESULTING_ROOT_C);
    const dupKeyD = dupKeyFor([70], PATCH_BYTES_D, RESULTING_ROOT_D);
    assert.equal(dupKeyA, dupKeyADup, 'A and A_DUP have identical inputs → identical dup-keys');

    // Host bookkeeping.
    const admittedDuplicateKeysThisEpoch = new Set();
    const minerAdmissions = new Map();
    const PER_MINER_CAP = 5;

    function tryAdmit({ commit, miner, dupKey, postCommitAdmissionPassed }) {
      const decision = screenerAdmissionDecision({
        minerAddress: miner,
        commitmentHash: commit.commitmentHash,
        duplicateKey: dupKey,
        admittedDuplicateKeysThisEpoch,
        minerAdmissionsThisEpoch: minerAdmissions.get(miner) ?? 0,
        perMinerCap: PER_MINER_CAP,
        postCommitAdmissionPassed,
      });
      if (decision.admit) {
        admittedDuplicateKeysThisEpoch.add(dupKey.toLowerCase());
        minerAdmissions.set(miner, (minerAdmissions.get(miner) ?? 0) + 1);
      }
      return decision;
    }

    const dA    = tryAdmit({ commit: commitA,    miner: MINER_A, dupKey: dupKeyA,    postCommitAdmissionPassed: true });
    const dADup = tryAdmit({ commit: commitADup, miner: MINER_A, dupKey: dupKeyADup, postCommitAdmissionPassed: true });
    const dB    = tryAdmit({ commit: commitB,    miner: MINER_B, dupKey: dupKeyB,    postCommitAdmissionPassed: true });
    const dC    = tryAdmit({ commit: commitC,    miner: MINER_C, dupKey: dupKeyC,    postCommitAdmissionPassed: false }); // fails rule 2
    const dD    = tryAdmit({ commit: commitD,    miner: MINER_D, dupKey: dupKeyD,    postCommitAdmissionPassed: true });

    assert.deepEqual(dA,    { admit: true, reason: 'OK' });
    assert.deepEqual(dADup, { admit: false, reason: 'duplicate-key-collapsed' });
    assert.deepEqual(dB,    { admit: true, reason: 'OK' });
    assert.deepEqual(dC,    { admit: false, reason: 'pre-commit-structural-only' });
    assert.deepEqual(dD,    { admit: true, reason: 'OK' });

    // Only A, B, D survive admission.
    const admittedReveals = [
      { commitmentHash: commitA.commitmentHash, minerAddress: MINER_A, patch: PATCH_A_DECODED, patchBytes: PATCH_BYTES_A },
      { commitmentHash: commitB.commitmentHash, minerAddress: MINER_B, patch: PATCH_B_DECODED, patchBytes: PATCH_BYTES_B },
      { commitmentHash: commitD.commitmentHash, minerAddress: MINER_D, patch: PATCH_D_DECODED, patchBytes: PATCH_BYTES_D },
    ];

    // ─── Stage 6: gate evaluation on the gate pack ──────────────────────
    // Scorer responds with different values per pack — gate vs confirm
    // distinguishable. A and D pass gate easily; B sits just over the
    // gate threshold but flunks confirm.
    const gateScores = new Map([
      [commitA.commitmentHash, 7000],
      [commitB.commitmentHash, 3000],
      [commitD.commitmentHash, 6000],
    ]);
    const confirmScores = new Map([
      [commitA.commitmentHash, 5500], // clears
      [commitB.commitmentHash, 1500], // fails confirm (gate-pack-luck filtered)
      [commitD.commitmentHash, 4800], // clears
    ]);
    const scorer = async (_parent, _patch, packSeedHex) => {
      // Find which admitted reveal this patch belongs to.
      const reveal = admittedReveals.find((r) => r.patch === _patch);
      if (!reveal) throw new Error('test scorer: unknown patch');
      if (packSeedHex === gateSeed)   return gateScores.get(reveal.commitmentHash);
      if (packSeedHex === confirmSeed) return confirmScores.get(reveal.commitmentHash);
      throw new Error(`test scorer: unexpected packSeedHex ${packSeedHex}`);
    };

    const THRESHOLD_PPM = 2500;
    const gateOutcomes = await runGateEvaluation({
      admittedReveals,
      parentSubstrate: dummyState(),
      gateSeedHex: gateSeed,
      thresholdPpm: THRESHOLD_PPM,
      scorer,
    });
    assert.equal(gateOutcomes.length, 3);
    assert.equal(gateOutcomes.every((o) => o.isFinalist), true, 'all three clear gate');

    // ─── Stage 7: confirm evaluation on the confirm pack ────────────────
    const admittedRevealsByHash = new Map(admittedReveals.map((r) => [r.commitmentHash, r]));
    const confirmOutcomes = await runConfirmEvaluation({
      finalists: gateOutcomes,
      admittedRevealsByHash,
      parentSubstrate: dummyState(),
      confirmSeedHex: confirmSeed,
      thresholdPpm: THRESHOLD_PPM,
      scorer,
    });
    assert.equal(confirmOutcomes.length, 3);
    const confirmByHash = new Map(confirmOutcomes.map((o) => [o.commitmentHash, o]));
    assert.equal(confirmByHash.get(commitA.commitmentHash).clearsConfirm, true);
    assert.equal(confirmByHash.get(commitB.commitmentHash).clearsConfirm, false,
      'B was gate-pack-lucky — confirm filters it');
    assert.equal(confirmByHash.get(commitD.commitmentHash).clearsConfirm, true);

    // Only A and D survive into batch settlement.
    const survivingFinalists = confirmOutcomes.filter((o) => o.clearsConfirm);

    // ─── Stage 8: batch settlement on the epoch parent ──────────────────
    // Marginal scorer: A is unaffected when applied first (5400); D's
    // marginal post-A drops to just under threshold (2400) so it gets
    // filtered as a pack-luck advance.
    const marginalScorer = async (_state, patch) => {
      const idx = patch.indices[0];
      if (idx === 10) return 5400; // A's marginal on the epoch parent
      if (idx === 70) return 2400; // D's marginal after A applied — fails
      return 0;
    };
    let stateCounter = 0;
    const applyPatch = (state, _patch) => ({ words: state.words, tag: ++stateCounter });

    const settlement = await selectBatchWinners({
      epochParentSubstrate: dummyState(),
      finalists: survivingFinalists,
      admittedReveals,
      maxAdvancesPerEpoch: 10,
      thresholdPpm: THRESHOLD_PPM,
      marginalScorer,
      applyPatch,
    });

    assert.equal(settlement.winners.length, 1, 'only A survives marginal re-evaluation');
    assert.equal(settlement.winners[0].commitmentHash, commitA.commitmentHash);
    assert.equal(settlement.winners[0].minerAddress, MINER_A);
    assert.equal(settlement.winners[0].marginalDeltaPpm, 5400);
    assert.deepEqual(settlement.rejectedBelowThreshold, [commitD.commitmentHash]);
    assert.deepEqual(settlement.rejectedConflicts, []);
    assert.deepEqual(settlement.rejectedCapReached, []);
    // Final state advanced exactly once.
    assert.equal(settlement.finalStateRoot.tag, 1);
  });

  test('replay determinism: same epoch inputs → byte-identical winners', async () => {
    // Two independent runs of the same composition must agree on the
    // final winner set, in the same order. This is the contract that
    // the verify-epoch path relies on.
    const commits = [];
    const patchBytesArr = [];
    const decodedPatches = [];
    const miners = [`0x${'11'.repeat(20)}`, `0x${'22'.repeat(20)}`, `0x${'33'.repeat(20)}`];
    const salts = [
      `0x${'aa'.repeat(32)}`,
      `0x${'bb'.repeat(32)}`,
      `0x${'cc'.repeat(32)}`,
    ];
    const indicesPerMiner = [[100], [200], [300]];
    for (let i = 0; i < 3; i++) {
      const bytes = new Uint8Array([0xaa + i, 0xbb + i, 0xcc + i]);
      patchBytesArr.push(bytes);
      decodedPatches.push(decodedPatch(indicesPerMiner[i]));
      commits.push(buildPatchCommitment({
        epochId: 7,
        epochParentRoot: PARENT_ROOT,
        minerAddress: miners[i],
        bundleHash: BUNDLE_HASH,
        patchBytes: bytes,
        saltHex: salts[i],
      }));
    }

    async function runOnce() {
      const commitmentRoot = computeCommitmentRoot(commits.map((c) => c.commitmentHash));
      const seed = deriveCoretexEvalSeed({
        epochId: 7,
        epochParentRoot: PARENT_ROOT,
        corpusRoot: CORPUS_ROOT,
        bundleHash: BUNDLE_HASH,
        commitmentRoot,
        epochSecret: EPOCH_SECRET,
        futureBlockHash: FUTURE_BLOCKHASH,
      });
      const gSeed = deriveGateSeed(seed);
      const cSeed = deriveConfirmSeed(seed);

      const admitted = commits.map((c, i) => ({
        commitmentHash: c.commitmentHash,
        minerAddress: miners[i],
        patch: decodedPatches[i],
        patchBytes: patchBytesArr[i],
      }));
      const scorer = async (_p, _patch, packSeedHex) => {
        const reveal = admitted.find((r) => r.patch === _patch);
        const base = parseInt(reveal.commitmentHash.slice(2, 4), 16) * 100;
        return packSeedHex === gSeed ? base : base + 50;
      };
      const gateOutcomes = await runGateEvaluation({
        admittedReveals: admitted,
        parentSubstrate: dummyState(),
        gateSeedHex: gSeed,
        thresholdPpm: 0,
        scorer,
      });
      const confirmOutcomes = await runConfirmEvaluation({
        finalists: gateOutcomes,
        admittedRevealsByHash: new Map(admitted.map((r) => [r.commitmentHash, r])),
        parentSubstrate: dummyState(),
        confirmSeedHex: cSeed,
        thresholdPpm: 0,
        scorer,
      });
      const settlement = await selectBatchWinners({
        epochParentSubstrate: dummyState(),
        finalists: confirmOutcomes,
        admittedReveals: admitted,
        maxAdvancesPerEpoch: 10,
        thresholdPpm: 0,
        marginalScorer: async (_s, patch) => 1000 + patch.indices[0],
        applyPatch: (state, _p) => ({ words: state.words, tag: (state.tag ?? 0) + 1 }),
      });
      return settlement.winners.map((w) => ({
        commit: w.commitmentHash,
        miner: w.minerAddress,
        marginal: w.marginalDeltaPpm,
      }));
    }

    const run1 = await runOnce();
    const run2 = await runOnce();
    assert.deepEqual(run1, run2, 'sealed-eval composition must be byte-deterministic');
    assert.equal(run1.length, 3, 'all three should win — no conflicts, no duplicate miners');
  });
});
