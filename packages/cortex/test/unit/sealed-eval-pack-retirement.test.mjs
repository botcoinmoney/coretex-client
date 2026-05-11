/**
 * Phase S6 of CORETEX_SEALED_EPOCH_EVAL_HARDENING_PLAN.md — pure
 * scaffolding for marking gate/confirm packs spent after reveal.
 *
 * These helpers do not touch storage or future-pack derivation; the
 * host wires them in once persistence lands. Goal: make the
 * sealed-eval surface expose the two contracts a host needs to
 * implement S6 correctly — derive a stable pack ID from each seed,
 * and check membership of the host's retired-set.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  computeGatePackId,
  computeConfirmPackId,
  isPackRetired,
  deriveGateSeed,
  deriveConfirmSeed,
  deriveCoretexEvalSeed,
  GATE_PACK_ID_DOMAIN_PREFIX,
  CONFIRM_PACK_ID_DOMAIN_PREFIX,
} from '../../dist/index.js';

const SEED_A = `0x${'11'.repeat(32)}`;
const SEED_B = `0x${'22'.repeat(32)}`;

describe('computeGatePackId / computeConfirmPackId', () => {
  test('returns a 32-byte hex string', () => {
    const id = computeGatePackId(SEED_A);
    assert.match(id, /^0x[0-9a-f]{64}$/);
    const cid = computeConfirmPackId(SEED_A);
    assert.match(cid, /^0x[0-9a-f]{64}$/);
  });

  test('domain separation: gate and confirm IDs differ even with the same seed bytes', () => {
    // The same 32 bytes fed to both helpers must produce DIFFERENT
    // IDs — otherwise a malicious caller could substitute one pack for
    // the other in the host's retired-set.
    const gid = computeGatePackId(SEED_A);
    const cid = computeConfirmPackId(SEED_A);
    assert.notEqual(gid, cid, 'distinct domain prefixes must produce distinct IDs');
  });

  test('deterministic: same seed → same ID byte-for-byte', () => {
    assert.equal(computeGatePackId(SEED_A), computeGatePackId(SEED_A));
    assert.equal(computeConfirmPackId(SEED_B), computeConfirmPackId(SEED_B));
  });

  test('different seeds → different IDs', () => {
    assert.notEqual(computeGatePackId(SEED_A), computeGatePackId(SEED_B));
    assert.notEqual(computeConfirmPackId(SEED_A), computeConfirmPackId(SEED_B));
  });

  test('gate-pack-ID does NOT equal the underlying gate seed', () => {
    // If pack-id were just the seed itself, the host's retired-set
    // would alias with any other downstream use of the seed bytes.
    // The domain-separated prefix prevents that.
    assert.notEqual(computeGatePackId(SEED_A), SEED_A);
    assert.notEqual(computeConfirmPackId(SEED_A), SEED_A);
  });

  test('rejects non-bytes32 input', () => {
    assert.throws(() => computeGatePackId('0x1234'), /gateSeedHex/);
    assert.throws(() => computeConfirmPackId('not-hex'), /confirmSeedHex/);
  });

  test('domain prefixes are exported as constants for cross-checking', () => {
    assert.equal(GATE_PACK_ID_DOMAIN_PREFIX, 'botcoin-coretex-gate-pack-id-v1');
    assert.equal(CONFIRM_PACK_ID_DOMAIN_PREFIX, 'botcoin-coretex-confirm-pack-id-v1');
    assert.notEqual(GATE_PACK_ID_DOMAIN_PREFIX, CONFIRM_PACK_ID_DOMAIN_PREFIX);
  });
});

describe('isPackRetired', () => {
  test('returns true iff packId is in the retired set', () => {
    const id = computeGatePackId(SEED_A);
    const retired = new Set([id.toLowerCase()]);
    assert.equal(isPackRetired(id, retired), true);
    const fresh = computeGatePackId(SEED_B);
    assert.equal(isPackRetired(fresh, retired), false);
  });

  test('case-insensitive — host stores lower-case but caller may pass mixed case', () => {
    const id = computeConfirmPackId(SEED_A);
    const upper = '0x' + id.slice(2).toUpperCase();
    const retired = new Set([id.toLowerCase()]);
    assert.equal(isPackRetired(upper, retired), true);
  });

  test('rejects malformed pack-id input', () => {
    assert.throws(() => isPackRetired('0xnope', new Set()), /packId/);
    assert.throws(() => isPackRetired('0x' + '11'.repeat(31), new Set()), /packId/);
  });

  test('empty retired-set: every fresh ID is unspent', () => {
    assert.equal(isPackRetired(computeGatePackId(SEED_A), new Set()), false);
  });
});

describe('S6 composition: derived seeds → pack IDs → retirement check', () => {
  test('full path from epoch inputs to retired-set lookup', () => {
    const evalSeed = deriveCoretexEvalSeed({
      epochId: 42,
      epochParentRoot: `0x${'aa'.repeat(32)}`,
      corpusRoot: `0x${'cc'.repeat(32)}`,
      bundleHash: `0x${'dd'.repeat(32)}`,
      commitmentRoot: `0x${'ee'.repeat(32)}`,
      epochSecret: `0x${'01'.repeat(32)}`,
      futureBlockHash: `0x${'02'.repeat(32)}`,
    });
    const gateSeed = deriveGateSeed(evalSeed);
    const confirmSeed = deriveConfirmSeed(evalSeed);
    const gateId = computeGatePackId(gateSeed);
    const confirmId = computeConfirmPackId(confirmSeed);

    // Host retires both after settlement.
    const retired = new Set([gateId.toLowerCase(), confirmId.toLowerCase()]);

    assert.equal(isPackRetired(gateId, retired), true);
    assert.equal(isPackRetired(confirmId, retired), true);
    // A fresh epoch's gate pack is not in the retired set yet.
    const otherEvalSeed = deriveCoretexEvalSeed({
      epochId: 43, // next epoch
      epochParentRoot: `0x${'aa'.repeat(32)}`,
      corpusRoot: `0x${'cc'.repeat(32)}`,
      bundleHash: `0x${'dd'.repeat(32)}`,
      commitmentRoot: `0x${'ff'.repeat(32)}`,
      epochSecret: `0x${'01'.repeat(32)}`,
      futureBlockHash: `0x${'02'.repeat(32)}`,
    });
    const otherGateId = computeGatePackId(deriveGateSeed(otherEvalSeed));
    assert.equal(isPackRetired(otherGateId, retired), false);
  });
});
