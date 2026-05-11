/**
 * End-to-end composition smoke for the sealed-eval lifecycle, using
 * only the pure functions in packages/cortex/src/coordinator/sealed-eval.ts.
 *
 * Walks through:
 *
 *   commit (miner A) ─┐
 *   commit (miner B) ─┼─→ commitmentRoot
 *   commit (miner A) ─┘    (duplicate of A's first — collapses)
 *
 *                    commitmentRoot
 *                    epochSecret  (revealed AFTER root anchored)
 *                    futureBlockHash  (observed AFTER commit close)
 *                    optionalDrandRoundHash
 *                                ↓
 *                       coretexEvalSeed
 *                            ↓
 *               ┌──── deriveGateSeed
 *               └──── deriveConfirmSeed
 *
 *   reveal (miner A first commit)  → ok
 *   reveal (miner A wrong-salt)    → reject
 *   reveal (miner B's commit re-targeted at A) → reject
 *
 *   screenerAdmissionDecision per admitted reveal,
 *   exercising rule 2 (post-commit), rule 3 (per-miner cap),
 *   rule 4 (duplicate-key collapse).
 *
 * The whole flow is deterministic; no I/O, no models.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  buildPatchCommitment,
  computePatchCommitmentHash,
  verifyPatchReveal,
  computeDuplicateKey,
  computeCommitmentRoot,
  deriveCoretexEvalSeed,
  deriveGateSeed,
  deriveConfirmSeed,
  screenerAdmissionDecision,
} from '../../dist/index.js';

const EPOCH_ID = 1234;
const PARENT_ROOT = `0x${'aa'.repeat(32)}`;
const CORPUS_ROOT = `0x${'cc'.repeat(32)}`;
const BUNDLE_HASH = `0x${'dd'.repeat(32)}`;
const EPOCH_SECRET = `0x${'01'.repeat(32)}`;
const FUTURE_BLOCKHASH = `0x${'02'.repeat(32)}`;
const DRAND = `0x${'03'.repeat(32)}`;

const MINER_A = `0x${'10'.repeat(20)}`;
const MINER_B = `0x${'20'.repeat(20)}`;

const SALT_A1 = `0x${'a1'.repeat(32)}`;
const SALT_A2 = `0x${'a2'.repeat(32)}`;
const SALT_B  = `0x${'b1'.repeat(32)}`;

const PATCH_A = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
const PATCH_B = new Uint8Array([0x05, 0x06, 0x07, 0x08]);
// PATCH_A_DUP is bit-identical to PATCH_A; the resulting state root and
// touched indices will be identical too, so duplicateKey collapses.
const PATCH_A_DUP = new Uint8Array([0x01, 0x02, 0x03, 0x04]);

describe('sealed-eval lifecycle composition (pure)', () => {
  test('full commit → root → seed → reveal → admission flow', () => {
    // ─── Stage 1: commit window ────────────────────────────────────────
    const commitA1 = buildPatchCommitment({
      epochId: EPOCH_ID,
      epochParentRoot: PARENT_ROOT,
      minerAddress: MINER_A,
      bundleHash: BUNDLE_HASH,
      patchBytes: PATCH_A,
      saltHex: SALT_A1,
    });
    const commitB = buildPatchCommitment({
      epochId: EPOCH_ID,
      epochParentRoot: PARENT_ROOT,
      minerAddress: MINER_B,
      bundleHash: BUNDLE_HASH,
      patchBytes: PATCH_B,
      saltHex: SALT_B,
    });
    // Miner A commits a different-salt commitment with the same patch
    // bytes. Different commitment hash (salt differs) but same
    // duplicateKey downstream (same patch bytes, same parent root, same
    // resulting state root).
    const commitA2 = buildPatchCommitment({
      epochId: EPOCH_ID,
      epochParentRoot: PARENT_ROOT,
      minerAddress: MINER_A,
      bundleHash: BUNDLE_HASH,
      patchBytes: PATCH_A_DUP,
      saltHex: SALT_A2,
    });
    assert.notEqual(commitA1.commitmentHash, commitA2.commitmentHash, 'salts differ → hashes differ');
    assert.notEqual(commitA1.commitmentHash, commitB.commitmentHash);

    // ─── Stage 2: commit close → commitmentRoot ────────────────────────
    const commitmentRoot = computeCommitmentRoot([
      commitA1.commitmentHash,
      commitB.commitmentHash,
      commitA2.commitmentHash,
    ]);
    assert.match(commitmentRoot, /^0x[0-9a-f]{64}$/);
    // Order independence: re-anchor with permuted set yields same root.
    assert.equal(
      commitmentRoot,
      computeCommitmentRoot([commitB.commitmentHash, commitA2.commitmentHash, commitA1.commitmentHash]),
    );

    // ─── Stage 3: seed derivation (after commitmentRoot anchored) ──────
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
    assert.match(coretexEvalSeed, /^0x[0-9a-f]{64}$/);
    const gateSeed = deriveGateSeed(coretexEvalSeed);
    const confirmSeed = deriveConfirmSeed(coretexEvalSeed);
    assert.notEqual(gateSeed, confirmSeed);
    assert.notEqual(gateSeed, coretexEvalSeed);

    // ─── Stage 4: reveal verification ───────────────────────────────────
    // Honest reveal of A's first commitment.
    const revealOK = verifyPatchReveal({
      commitmentHash: commitA1.commitmentHash,
      patchBytes: PATCH_A,
      saltHex: SALT_A1,
      epochId: EPOCH_ID,
      epochParentRoot: PARENT_ROOT,
      minerAddress: MINER_A,
      bundleHash: BUNDLE_HASH,
    });
    assert.equal(revealOK.ok, true);

    // Honest reveal of A's second commitment (the dup).
    const revealDupOK = verifyPatchReveal({
      commitmentHash: commitA2.commitmentHash,
      patchBytes: PATCH_A_DUP,
      saltHex: SALT_A2,
      epochId: EPOCH_ID,
      epochParentRoot: PARENT_ROOT,
      minerAddress: MINER_A,
      bundleHash: BUNDLE_HASH,
    });
    assert.equal(revealDupOK.ok, true);

    // Adversarial: A tries to open A1 with the wrong salt. Reject.
    const revealWrongSalt = verifyPatchReveal({
      commitmentHash: commitA1.commitmentHash,
      patchBytes: PATCH_A,
      saltHex: SALT_A2, // wrong salt
      epochId: EPOCH_ID,
      epochParentRoot: PARENT_ROOT,
      minerAddress: MINER_A,
      bundleHash: BUNDLE_HASH,
    });
    assert.equal(revealWrongSalt.ok, false);

    // Adversarial: A tries to claim B's commitment. Re-targeted reveal
    // computes a different commitment hash, so the recomputed hash
    // doesn't match B's stored commitmentHash → reject.
    const revealStolen = verifyPatchReveal({
      commitmentHash: commitB.commitmentHash,
      patchBytes: PATCH_B,
      saltHex: SALT_B,
      epochId: EPOCH_ID,
      epochParentRoot: PARENT_ROOT,
      minerAddress: MINER_A, // wrong miner — was MINER_B
      bundleHash: BUNDLE_HASH,
    });
    assert.equal(revealStolen.ok, false);
    if (!revealStolen.ok) assert.equal(revealStolen.reason, 'commitment-hash-mismatch');

    // ─── Stage 5: post-commit admission decision ───────────────────────
    // We assume the host has already run structural / visible-split
    // checks and decided whether each reveal passed admission.
    const RESULTING_STATE_ROOT_A = `0x${'77'.repeat(32)}`;
    const RESULTING_STATE_ROOT_B = `0x${'88'.repeat(32)}`;
    const TOUCHED = [384];
    const dupKeyA = computeDuplicateKey({
      epochParentRoot: PARENT_ROOT,
      sortedTouchedWordIndices: TOUCHED,
      normalizedPatchBytes: PATCH_A,
      resultingStateRoot: RESULTING_STATE_ROOT_A,
    });
    const dupKeyADup = computeDuplicateKey({
      epochParentRoot: PARENT_ROOT,
      sortedTouchedWordIndices: TOUCHED,
      normalizedPatchBytes: PATCH_A_DUP,
      resultingStateRoot: RESULTING_STATE_ROOT_A,
    });
    const dupKeyB = computeDuplicateKey({
      epochParentRoot: PARENT_ROOT,
      sortedTouchedWordIndices: TOUCHED,
      normalizedPatchBytes: PATCH_B,
      resultingStateRoot: RESULTING_STATE_ROOT_B,
    });
    assert.equal(dupKeyA, dupKeyADup, 'dup-key collapses identical patches');
    assert.notEqual(dupKeyA, dupKeyB);

    // Host bookkeeping (would be a Map in production):
    const admittedDuplicateKeysThisEpoch = new Set();
    const minerAdmissions = new Map();
    const PER_MINER_CAP = 5;

    function admit(minerAddress, dupKey, postCommitAdmissionPassed) {
      const decision = screenerAdmissionDecision({
        minerAddress,
        commitmentHash: `0x${'00'.repeat(32)}`, // not used for the bookkeeping in the helper
        duplicateKey: dupKey,
        admittedDuplicateKeysThisEpoch,
        minerAdmissionsThisEpoch: minerAdmissions.get(minerAddress) ?? 0,
        perMinerCap: PER_MINER_CAP,
        postCommitAdmissionPassed,
      });
      if (decision.admit) {
        admittedDuplicateKeysThisEpoch.add(dupKey.toLowerCase());
        minerAdmissions.set(minerAddress, (minerAdmissions.get(minerAddress) ?? 0) + 1);
      }
      return decision;
    }

    // A's first reveal admits.
    const admitA1 = admit(MINER_A, dupKeyA, true);
    assert.deepEqual(admitA1, { admit: true, reason: 'OK' });

    // A's second reveal — same patch bytes, same dup-key — collapses.
    const admitA2 = admit(MINER_A, dupKeyADup, true);
    assert.deepEqual(admitA2, { admit: false, reason: 'duplicate-key-collapsed' });

    // B's reveal admits — different dup-key, fresh budget.
    const admitB = admit(MINER_B, dupKeyB, true);
    assert.deepEqual(admitB, { admit: true, reason: 'OK' });

    // Final state: 2 admitted dup-keys (A and B); A has 1 admission, B has 1.
    assert.equal(admittedDuplicateKeysThisEpoch.size, 2);
    assert.equal(minerAdmissions.get(MINER_A), 1);
    assert.equal(minerAdmissions.get(MINER_B), 1);

    // ─── Stage 6: pre-commit-only structural reveal earns nothing ──────
    const dupKeyC = `0x${'cc'.repeat(32)}`;
    const admitStructuralOnly = admit(MINER_A, dupKeyC, /* admissionPassed */ false);
    assert.deepEqual(admitStructuralOnly, { admit: false, reason: 'pre-commit-structural-only' });
    // No bookkeeping side-effect for refused admission.
    assert.equal(admittedDuplicateKeysThisEpoch.size, 2);
    assert.equal(minerAdmissions.get(MINER_A), 1);
  });

  test('per-miner cap fires once miner A reaches 5 admissions, B unaffected', () => {
    const admittedDuplicateKeysThisEpoch = new Set();
    const minerAdmissions = new Map();
    const PER_MINER_CAP = 5;

    function makeDupKey(seed) {
      return computeDuplicateKey({
        epochParentRoot: PARENT_ROOT,
        sortedTouchedWordIndices: [seed],
        normalizedPatchBytes: new Uint8Array([seed & 0xff, (seed >> 8) & 0xff]),
        resultingStateRoot: `0x${seed.toString(16).padStart(64, '0')}`,
      });
    }

    // Miner A admits 5 times (different dup keys), then 6th hits the cap.
    for (let i = 0; i < 5; i++) {
      const dk = makeDupKey(i + 1);
      const d = screenerAdmissionDecision({
        minerAddress: MINER_A,
        commitmentHash: `0x${'00'.repeat(32)}`,
        duplicateKey: dk,
        admittedDuplicateKeysThisEpoch,
        minerAdmissionsThisEpoch: minerAdmissions.get(MINER_A) ?? 0,
        perMinerCap: PER_MINER_CAP,
        postCommitAdmissionPassed: true,
      });
      assert.equal(d.admit, true, `admission ${i + 1} should pass`);
      admittedDuplicateKeysThisEpoch.add(dk.toLowerCase());
      minerAdmissions.set(MINER_A, (minerAdmissions.get(MINER_A) ?? 0) + 1);
    }
    const sixthAttempt = screenerAdmissionDecision({
      minerAddress: MINER_A,
      commitmentHash: `0x${'00'.repeat(32)}`,
      duplicateKey: makeDupKey(99),
      admittedDuplicateKeysThisEpoch,
      minerAdmissionsThisEpoch: minerAdmissions.get(MINER_A) ?? 0,
      perMinerCap: PER_MINER_CAP,
      postCommitAdmissionPassed: true,
    });
    assert.deepEqual(sixthAttempt, { admit: false, reason: 'per-miner-cap-reached' });

    // Miner B: fresh budget, admits.
    const dB = screenerAdmissionDecision({
      minerAddress: MINER_B,
      commitmentHash: `0x${'00'.repeat(32)}`,
      duplicateKey: makeDupKey(100),
      admittedDuplicateKeysThisEpoch,
      minerAdmissionsThisEpoch: 0,
      perMinerCap: PER_MINER_CAP,
      postCommitAdmissionPassed: true,
    });
    assert.deepEqual(dB, { admit: true, reason: 'OK' });
  });

  test('deterministic reproduction: same inputs → same downstream artifacts', () => {
    const inputs = {
      epochId: 7,
      epochParentRoot: PARENT_ROOT,
      corpusRoot: CORPUS_ROOT,
      bundleHash: BUNDLE_HASH,
      commitmentRoot: computeCommitmentRoot([
        computePatchCommitmentHash({
          epochId: 7,
          epochParentRoot: PARENT_ROOT,
          minerAddress: MINER_A,
          bundleHash: BUNDLE_HASH,
          patchBytes: PATCH_A,
          saltHex: SALT_A1,
        }),
      ]),
      epochSecret: EPOCH_SECRET,
      futureBlockHash: FUTURE_BLOCKHASH,
    };
    const seed1 = deriveCoretexEvalSeed(inputs);
    const seed2 = deriveCoretexEvalSeed(inputs);
    assert.equal(seed1, seed2);
    assert.equal(deriveGateSeed(seed1), deriveGateSeed(seed2));
    assert.equal(deriveConfirmSeed(seed1), deriveConfirmSeed(seed2));
  });
});
