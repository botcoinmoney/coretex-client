/**
 * Live-eval admission decision — pure helper, no I/O.
 *
 * Three rules, ordered by precedence:
 *   1. structurally-invalid
 *   2. duplicate-key-collapsed
 *   3. per-miner-cap-reached
 *
 * This is the surviving piece of the sealed-eval design after the rip
 * (see docs/CORETEX_V4_ONCHAIN_RANDOMNESS_PLAN.md §"What Survives"). The
 * tests below are adapted from the prior sealed-eval-screener-admission
 * tests with the new field names and live-eval context.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { liveEvalAdmissionDecision } from '../../dist/index.js';

const MINER_A = `0x${'aa'.repeat(20)}`;
const MINER_B = `0x${'bb'.repeat(20)}`;
const PATCH_HASH = `0x${'11'.repeat(32)}`;
const DUP_KEY_A = `0x${'22'.repeat(32)}`;
const DUP_KEY_B = `0x${'33'.repeat(32)}`;

function input(over = {}) {
  return {
    minerAddress: MINER_A,
    patchHash: PATCH_HASH,
    dedupKey: DUP_KEY_A,
    dedupedKeysThisEpoch: new Set(),
    minerAdmissionsThisEpoch: 0,
    perMinerCap: 5,
    structurallyValid: true,
    ...over,
  };
}

describe('liveEvalAdmissionDecision', () => {
  test('admits a fresh patch under the cap', () => {
    const d = liveEvalAdmissionDecision(input());
    assert.deepEqual(d, { admit: true, reason: 'OK' });
  });

  test('refuses structurally-invalid patches (rule 1)', () => {
    const d = liveEvalAdmissionDecision(input({ structurallyValid: false }));
    assert.deepEqual(d, { admit: false, reason: 'structurally-invalid' });
  });

  test('refuses when dedupKey already evaluated this epoch (rule 2)', () => {
    const already = new Set([DUP_KEY_A.toLowerCase()]);
    const d = liveEvalAdmissionDecision(input({ dedupedKeysThisEpoch: already }));
    assert.deepEqual(d, { admit: false, reason: 'duplicate-key-collapsed' });
  });

  test('dedup is case-insensitive', () => {
    const upperKey = '0x' + 'AB'.repeat(32);
    const already = new Set([upperKey.toLowerCase()]);
    const d = liveEvalAdmissionDecision(input({ dedupKey: upperKey, dedupedKeysThisEpoch: already }));
    assert.equal(d.admit, false);
    assert.equal(d.reason, 'duplicate-key-collapsed');
  });

  test('different dedupKey on same epoch still admissible', () => {
    const already = new Set([DUP_KEY_A.toLowerCase()]);
    const d = liveEvalAdmissionDecision(input({
      dedupKey: DUP_KEY_B,
      dedupedKeysThisEpoch: already,
    }));
    assert.deepEqual(d, { admit: true, reason: 'OK' });
  });

  test('refuses when per-miner cap reached (rule 3)', () => {
    const d = liveEvalAdmissionDecision(input({ minerAdmissionsThisEpoch: 5, perMinerCap: 5 }));
    assert.deepEqual(d, { admit: false, reason: 'per-miner-cap-reached' });
  });

  test('admits while strictly under cap', () => {
    const d = liveEvalAdmissionDecision(input({ minerAdmissionsThisEpoch: 4, perMinerCap: 5 }));
    assert.deepEqual(d, { admit: true, reason: 'OK' });
  });

  test('cap is per-miner — different miner unaffected', () => {
    const dA = liveEvalAdmissionDecision(input({ minerAdmissionsThisEpoch: 5, perMinerCap: 5 }));
    const dB = liveEvalAdmissionDecision(input({
      minerAddress: MINER_B,
      minerAdmissionsThisEpoch: 0,
      perMinerCap: 5,
    }));
    assert.equal(dA.admit, false);
    assert.equal(dB.admit, true);
  });

  test('precedence: structural > dedup > cap', () => {
    // All three negative conditions hit at once — structural wins.
    const d = liveEvalAdmissionDecision(input({
      structurallyValid: false,
      dedupedKeysThisEpoch: new Set([DUP_KEY_A.toLowerCase()]),
      minerAdmissionsThisEpoch: 99,
      perMinerCap: 5,
    }));
    assert.equal(d.reason, 'structurally-invalid');

    // Structural pass, dedup AND cap fail — dedup wins.
    const d2 = liveEvalAdmissionDecision(input({
      structurallyValid: true,
      dedupedKeysThisEpoch: new Set([DUP_KEY_A.toLowerCase()]),
      minerAdmissionsThisEpoch: 99,
      perMinerCap: 5,
    }));
    assert.equal(d2.reason, 'duplicate-key-collapsed');
  });

  test('malformed inputs fail closed', () => {
    assert.equal(liveEvalAdmissionDecision(input({ minerAddress: 'not-an-address' })).reason, 'malformed-input');
    assert.equal(liveEvalAdmissionDecision(input({ patchHash: '0x12' })).reason, 'malformed-input');
    assert.equal(liveEvalAdmissionDecision(input({ dedupKey: 'too-short' })).reason, 'malformed-input');
    assert.equal(liveEvalAdmissionDecision(input({ minerAdmissionsThisEpoch: -1 })).reason, 'malformed-input');
    assert.equal(liveEvalAdmissionDecision(input({ minerAdmissionsThisEpoch: 1.5 })).reason, 'malformed-input');
    assert.equal(liveEvalAdmissionDecision(input({ perMinerCap: 0 })).reason, 'malformed-input');
    assert.equal(liveEvalAdmissionDecision(input({ structurallyValid: 'yes' })).reason, 'malformed-input');
    assert.equal(liveEvalAdmissionDecision(input({ dedupedKeysThisEpoch: ['not', 'a', 'set'] })).reason, 'malformed-input');
  });

  test('does not mutate the dedup set', () => {
    const before = new Set([DUP_KEY_B.toLowerCase()]);
    const snapshot = new Set(before);
    liveEvalAdmissionDecision(input({ dedupedKeysThisEpoch: before }));
    assert.deepEqual(before, snapshot, 'helper must be pure — host owns set mutation');
  });
});
