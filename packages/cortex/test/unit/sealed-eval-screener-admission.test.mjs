/**
 * Phase S5 of CORETEX_SEALED_EPOCH_EVAL_HARDENING_PLAN.md.
 *
 * Tests screenerAdmissionDecision — pure helper, no I/O.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { screenerAdmissionDecision } from '../../dist/index.js';

const MINER_A = `0x${'aa'.repeat(20)}`;
const MINER_B = `0x${'bb'.repeat(20)}`;
const COMMIT_HASH = `0x${'11'.repeat(32)}`;
const DUP_KEY_A = `0x${'22'.repeat(32)}`;
const DUP_KEY_B = `0x${'33'.repeat(32)}`;

function input(over = {}) {
  return {
    minerAddress: MINER_A,
    commitmentHash: COMMIT_HASH,
    duplicateKey: DUP_KEY_A,
    admittedDuplicateKeysThisEpoch: new Set(),
    minerAdmissionsThisEpoch: 0,
    perMinerCap: 5,
    postCommitAdmissionPassed: true,
    ...over,
  };
}

describe('screenerAdmissionDecision', () => {
  test('admits a fresh commitment under the cap', () => {
    const d = screenerAdmissionDecision(input());
    assert.deepEqual(d, { admit: true, reason: 'OK' });
  });

  test('refuses pre-commit structural-only reveals (rule 2)', () => {
    const d = screenerAdmissionDecision(input({ postCommitAdmissionPassed: false }));
    assert.deepEqual(d, { admit: false, reason: 'pre-commit-structural-only' });
  });

  test('refuses when duplicateKey is already admitted this epoch (rule 4)', () => {
    const already = new Set([DUP_KEY_A.toLowerCase()]);
    const d = screenerAdmissionDecision(input({ admittedDuplicateKeysThisEpoch: already }));
    assert.deepEqual(d, { admit: false, reason: 'duplicate-key-collapsed' });
  });

  test('duplicate-key collapse is case-insensitive', () => {
    const upperDupKey = '0x' + 'AB'.repeat(32);
    const already = new Set([upperDupKey.toLowerCase()]);
    const d = screenerAdmissionDecision(input({ duplicateKey: upperDupKey, admittedDuplicateKeysThisEpoch: already }));
    assert.equal(d.admit, false);
    assert.equal(d.reason, 'duplicate-key-collapsed');
  });

  test('different duplicateKey on the same epoch still admissible', () => {
    const already = new Set([DUP_KEY_A.toLowerCase()]);
    const d = screenerAdmissionDecision(input({
      duplicateKey: DUP_KEY_B,
      admittedDuplicateKeysThisEpoch: already,
    }));
    assert.deepEqual(d, { admit: true, reason: 'OK' });
  });

  test('refuses when per-miner cap is reached (rule 3)', () => {
    const d = screenerAdmissionDecision(input({ minerAdmissionsThisEpoch: 5, perMinerCap: 5 }));
    assert.deepEqual(d, { admit: false, reason: 'per-miner-cap-reached' });
  });

  test('admits while strictly under cap', () => {
    const d = screenerAdmissionDecision(input({ minerAdmissionsThisEpoch: 4, perMinerCap: 5 }));
    assert.deepEqual(d, { admit: true, reason: 'OK' });
  });

  test('cap is per-miner, not per-epoch — second miner unaffected', () => {
    // MINER_A has hit the cap; MINER_B has fresh budget.
    const dA = screenerAdmissionDecision(input({ minerAdmissionsThisEpoch: 5, perMinerCap: 5 }));
    const dB = screenerAdmissionDecision(input({
      minerAddress: MINER_B,
      minerAdmissionsThisEpoch: 0,
      perMinerCap: 5,
    }));
    assert.equal(dA.admit, false);
    assert.equal(dB.admit, true);
  });

  test('precedence: structural failure > dup collapse > per-miner cap', () => {
    // All three negative conditions true at once. Structural is most
    // specific (the patch isn't admissible at all), so it wins.
    const d = screenerAdmissionDecision(input({
      postCommitAdmissionPassed: false,
      admittedDuplicateKeysThisEpoch: new Set([DUP_KEY_A.toLowerCase()]),
      minerAdmissionsThisEpoch: 99,
      perMinerCap: 5,
    }));
    assert.equal(d.reason, 'pre-commit-structural-only');

    // Structural pass, dup AND cap fail. Dup wins (the patch is already
    // credited — no point counting it again, regardless of cap).
    const d2 = screenerAdmissionDecision(input({
      postCommitAdmissionPassed: true,
      admittedDuplicateKeysThisEpoch: new Set([DUP_KEY_A.toLowerCase()]),
      minerAdmissionsThisEpoch: 99,
      perMinerCap: 5,
    }));
    assert.equal(d2.reason, 'duplicate-key-collapsed');
  });

  test('malformed inputs fail closed', () => {
    assert.equal(screenerAdmissionDecision(input({ minerAddress: 'not-an-address' })).reason, 'malformed-input');
    assert.equal(screenerAdmissionDecision(input({ commitmentHash: '0x12' })).reason, 'malformed-input');
    assert.equal(screenerAdmissionDecision(input({ duplicateKey: 'too-short' })).reason, 'malformed-input');
    assert.equal(screenerAdmissionDecision(input({ minerAdmissionsThisEpoch: -1 })).reason, 'malformed-input');
    assert.equal(screenerAdmissionDecision(input({ minerAdmissionsThisEpoch: 1.5 })).reason, 'malformed-input');
    assert.equal(screenerAdmissionDecision(input({ perMinerCap: 0 })).reason, 'malformed-input');
    assert.equal(screenerAdmissionDecision(input({ perMinerCap: -3 })).reason, 'malformed-input');
    assert.equal(screenerAdmissionDecision(input({ postCommitAdmissionPassed: 'yes' })).reason, 'malformed-input');
  });

  test('does not mutate the input set', () => {
    const before = new Set([DUP_KEY_B.toLowerCase()]);
    const snapshot = new Set(before);
    screenerAdmissionDecision(input({ admittedDuplicateKeysThisEpoch: before }));
    assert.deepEqual(before, snapshot, 'helper must be pure — host owns set mutation');
  });
});
