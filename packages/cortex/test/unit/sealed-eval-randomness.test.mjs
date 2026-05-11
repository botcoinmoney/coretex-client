/**
 * Phase S2 of CORETEX_SEALED_EPOCH_EVAL_HARDENING_PLAN.md.
 *
 * Tests deriveCoretexEvalSeed + deriveGateSeed + deriveConfirmSeed
 * randomness binding. Pure functions, no I/O, no model work.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  deriveCoretexEvalSeed,
  deriveGateSeed,
  deriveConfirmSeed,
  SEALED_EVAL_SEED_DOMAIN_PREFIX,
  GATE_SEED_DOMAIN_TAG,
  CONFIRM_SEED_DOMAIN_TAG,
} from '../../dist/index.js';

const ROOT_A = `0x${'aa'.repeat(32)}`;
const ROOT_B = `0x${'bb'.repeat(32)}`;
const CORPUS_A = `0x${'cc'.repeat(32)}`;
const BUNDLE_A = `0x${'dd'.repeat(32)}`;
const COMMIT_ROOT = `0x${'ee'.repeat(32)}`;
const SECRET = `0x${'01'.repeat(32)}`;
const BLOCKHASH = `0x${'02'.repeat(32)}`;
const DRAND = `0x${'03'.repeat(32)}`;

function seed(over = {}) {
  return {
    epochId: 78,
    epochParentRoot: ROOT_A,
    corpusRoot: CORPUS_A,
    bundleHash: BUNDLE_A,
    commitmentRoot: COMMIT_ROOT,
    epochSecret: SECRET,
    futureBlockHash: BLOCKHASH,
    ...over,
  };
}

describe('deriveCoretexEvalSeed', () => {
  test('domain prefix constants are stable', () => {
    assert.equal(SEALED_EVAL_SEED_DOMAIN_PREFIX, 'botcoin-coretex-sealed-eval-v1');
    assert.equal(GATE_SEED_DOMAIN_TAG, 'gate');
    assert.equal(CONFIRM_SEED_DOMAIN_TAG, 'confirm');
  });

  test('deterministic for the same inputs', () => {
    assert.equal(deriveCoretexEvalSeed(seed()), deriveCoretexEvalSeed(seed()));
    assert.match(deriveCoretexEvalSeed(seed()), /^0x[0-9a-f]{64}$/);
  });

  test('changes when ANY binding changes', () => {
    const base = deriveCoretexEvalSeed(seed());
    assert.notEqual(base, deriveCoretexEvalSeed(seed({ epochId: 79 })));
    assert.notEqual(base, deriveCoretexEvalSeed(seed({ epochParentRoot: ROOT_B })));
    assert.notEqual(base, deriveCoretexEvalSeed(seed({ corpusRoot: `0x${'55'.repeat(32)}` })));
    assert.notEqual(base, deriveCoretexEvalSeed(seed({ bundleHash: `0x${'66'.repeat(32)}` })));
    assert.notEqual(base, deriveCoretexEvalSeed(seed({ commitmentRoot: `0x${'77'.repeat(32)}` })));
    assert.notEqual(base, deriveCoretexEvalSeed(seed({ epochSecret: `0x${'88'.repeat(32)}` })));
    assert.notEqual(base, deriveCoretexEvalSeed(seed({ futureBlockHash: `0x${'99'.repeat(32)}` })));
  });

  test('drand mix-in changes the seed', () => {
    const noDrand = deriveCoretexEvalSeed(seed());
    const withDrand = deriveCoretexEvalSeed(seed({ optionalDrandRoundHash: DRAND }));
    assert.notEqual(noDrand, withDrand);
    // And drand alone is deterministic
    assert.equal(
      deriveCoretexEvalSeed(seed({ optionalDrandRoundHash: DRAND })),
      deriveCoretexEvalSeed(seed({ optionalDrandRoundHash: DRAND })),
    );
  });

  test('explicit undefined drand equals omitted drand', () => {
    assert.equal(
      deriveCoretexEvalSeed(seed({ optionalDrandRoundHash: undefined })),
      deriveCoretexEvalSeed(seed()),
    );
  });

  test('rejects zero futureBlockHash (would collapse to coordinator-only randomness)', () => {
    assert.throws(
      () => deriveCoretexEvalSeed(seed({ futureBlockHash: `0x${'00'.repeat(32)}` })),
      /futureBlockHash: cannot be zero/,
    );
  });

  test('rejects zero epochSecret', () => {
    assert.throws(
      () => deriveCoretexEvalSeed(seed({ epochSecret: `0x${'00'.repeat(32)}` })),
      /epochSecret: cannot be zero/,
    );
  });

  test('rejects malformed hex on any binding', () => {
    assert.throws(() => deriveCoretexEvalSeed(seed({ epochParentRoot: 'not-hex' })), /epochParentRoot/);
    assert.throws(() => deriveCoretexEvalSeed(seed({ corpusRoot: '0x12' })), /corpusRoot/);
    assert.throws(() => deriveCoretexEvalSeed(seed({ bundleHash: 'too-short' })), /bundleHash/);
    assert.throws(() => deriveCoretexEvalSeed(seed({ commitmentRoot: '' })), /commitmentRoot/);
    assert.throws(() => deriveCoretexEvalSeed(seed({ futureBlockHash: '0x' + 'gg'.repeat(32) })), /futureBlockHash/);
  });

  test('rejects malformed drand hex when provided', () => {
    assert.throws(
      () => deriveCoretexEvalSeed(seed({ optionalDrandRoundHash: 'too-short' })),
      /optionalDrandRoundHash/,
    );
  });

  test('seed bound to commitmentRoot — adversary cannot precompute pre-commit-close', () => {
    // Two different commitmentRoots produce two different seeds even when
    // every other binding is identical. This is the core sealed-eval
    // property: until commitments are locked + commitmentRoot computed,
    // the seed is unknowable.
    const seedA = deriveCoretexEvalSeed(seed({ commitmentRoot: `0x${'aa'.repeat(32)}` }));
    const seedB = deriveCoretexEvalSeed(seed({ commitmentRoot: `0x${'bb'.repeat(32)}` }));
    assert.notEqual(seedA, seedB);
  });
});

describe('deriveGateSeed / deriveConfirmSeed', () => {
  const baseSeed = deriveCoretexEvalSeed(seed());

  test('gate seed deterministic and 32-byte hex', () => {
    assert.equal(deriveGateSeed(baseSeed), deriveGateSeed(baseSeed));
    assert.match(deriveGateSeed(baseSeed), /^0x[0-9a-f]{64}$/);
  });

  test('confirm seed deterministic and 32-byte hex', () => {
    assert.equal(deriveConfirmSeed(baseSeed), deriveConfirmSeed(baseSeed));
    assert.match(deriveConfirmSeed(baseSeed), /^0x[0-9a-f]{64}$/);
  });

  test('gate seed != confirm seed (distinct domain tags)', () => {
    assert.notEqual(deriveGateSeed(baseSeed), deriveConfirmSeed(baseSeed));
  });

  test('gate seed != coretex eval seed (not a passthrough)', () => {
    assert.notEqual(deriveGateSeed(baseSeed), baseSeed);
    assert.notEqual(deriveConfirmSeed(baseSeed), baseSeed);
  });

  test('different coretex eval seeds → different gate / confirm seeds', () => {
    const alt = deriveCoretexEvalSeed(seed({ epochId: 99 }));
    assert.notEqual(deriveGateSeed(baseSeed), deriveGateSeed(alt));
    assert.notEqual(deriveConfirmSeed(baseSeed), deriveConfirmSeed(alt));
  });

  test('rejects malformed coretex eval seed input', () => {
    assert.throws(() => deriveGateSeed('not-hex'), /coretexEvalSeed/);
    assert.throws(() => deriveConfirmSeed('0x12'), /coretexEvalSeed/);
  });
});
