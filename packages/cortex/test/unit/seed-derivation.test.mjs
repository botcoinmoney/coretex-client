/**
 * Per-patch eval-seed derivation — pure hashing, no I/O.
 *
 * Spec source: docs/CORETEX_V4_ONCHAIN_RANDOMNESS_PLAN.md §Seed Formula.
 *
 * Two domain-separated seeds are derived per patch: gate + confirm.
 * A patch must clear threshold on both to be accepted. The tests
 * below lock in:
 *   - byte-determinism (same inputs → same output across calls)
 *   - domain separation (gate ≠ confirm for identical inputs)
 *   - sensitivity to every input field (changing one byte changes the seed)
 *   - input validation (refuse zero blockhash, malformed hex)
 *   - patchHash + dedupKey domain-separated correctly
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  deriveGateEvalSeed,
  deriveConfirmEvalSeed,
  computePatchHash,
  computeDedupKey,
  EVAL_SEED_GATE_DOMAIN_PREFIX,
  EVAL_SEED_CONFIRM_DOMAIN_PREFIX,
  DEDUP_KEY_DOMAIN_PREFIX,
  PATCH_HASH_DOMAIN_PREFIX,
} from '../../dist/index.js';

const BASE_INPUT = {
  epochSecret: `0x${'11'.repeat(32)}`,
  blockhash:   `0x${'22'.repeat(32)}`,
  epochId:     42,
  patchHash:   `0x${'33'.repeat(32)}`,
  parentRoot:  `0x${'44'.repeat(32)}`,
  corpusRoot:  `0x${'66'.repeat(32)}`,
  bundleHash:  `0x${'77'.repeat(32)}`,
};

describe('deriveGateEvalSeed / deriveConfirmEvalSeed', () => {
  test('returns bytes32 hex', () => {
    const g = deriveGateEvalSeed(BASE_INPUT);
    const c = deriveConfirmEvalSeed(BASE_INPUT);
    assert.match(g, /^0x[0-9a-f]{64}$/);
    assert.match(c, /^0x[0-9a-f]{64}$/);
  });

  test('deterministic — same inputs → same output', () => {
    assert.equal(deriveGateEvalSeed(BASE_INPUT), deriveGateEvalSeed(BASE_INPUT));
    assert.equal(deriveConfirmEvalSeed(BASE_INPUT), deriveConfirmEvalSeed(BASE_INPUT));
  });

  test('domain separation — gate and confirm produce DIFFERENT seeds for identical input', () => {
    // This is the whole point of dual-pack: two statistically
    // independent pack draws from a single blockhash.
    assert.notEqual(deriveGateEvalSeed(BASE_INPUT), deriveConfirmEvalSeed(BASE_INPUT));
  });

  test('sensitive to every input field', () => {
    const baseG = deriveGateEvalSeed(BASE_INPUT);
    const variants = [
      { ...BASE_INPUT, epochSecret: `0x${'aa'.repeat(32)}` },
      { ...BASE_INPUT, blockhash:   `0x${'aa'.repeat(32)}` },
      { ...BASE_INPUT, epochId: 43 },
      { ...BASE_INPUT, patchHash:   `0x${'aa'.repeat(32)}` },
      { ...BASE_INPUT, parentRoot:  `0x${'aa'.repeat(32)}` },
      { ...BASE_INPUT, corpusRoot:  `0x${'aa'.repeat(32)}` },
      { ...BASE_INPUT, bundleHash:  `0x${'aa'.repeat(32)}` },
    ];
    for (const v of variants) {
      assert.notEqual(deriveGateEvalSeed(v), baseG, `flipping a field should change the seed`);
    }
  });

  test('miner identity is NOT part of the seed (first-submitter-wins dedup contract)', () => {
    // Two miners submitting the same (parentRoot, patchBytes) hash to
    // the same dedupKey and resolve to the same cached verdict. The
    // seed therefore MUST NOT depend on minerAddress — otherwise the
    // two miners would compute different "true" seeds but share a
    // single cached verdict, creating ambiguity. Including
    // minerAddress would not prevent sybil rerolls (the dedup cache
    // already does that) — it would only break replay reproducibility.
    const seedA = deriveGateEvalSeed(BASE_INPUT);
    const seedB = deriveGateEvalSeed({ ...BASE_INPUT });
    assert.equal(seedA, seedB);
  });

  test('refuses zero blockhash — anti-pre-testing invariant', () => {
    // Zero blockhash means "block not observed yet". Deriving with a
    // zero blockhash would let the coordinator forge eval seeds with
    // only the inputs they pick. Refuse fast.
    const zero = `0x${'00'.repeat(32)}`;
    assert.throws(() => deriveGateEvalSeed({ ...BASE_INPUT, blockhash: zero }), /blockhash is zero/);
    assert.throws(() => deriveConfirmEvalSeed({ ...BASE_INPUT, blockhash: zero }), /blockhash is zero/);
  });

  test('rejects malformed input', () => {
    assert.throws(() => deriveGateEvalSeed({ ...BASE_INPUT, epochSecret: '0x1234' }), /epochSecret/);
    assert.throws(() => deriveGateEvalSeed({ ...BASE_INPUT, patchHash: '0xnope' }), /patchHash/);
    assert.throws(() => deriveGateEvalSeed({ ...BASE_INPUT, bundleHash: '' }), /bundleHash/);
  });

  test('domain prefixes are exported constants and distinct', () => {
    assert.equal(EVAL_SEED_GATE_DOMAIN_PREFIX,    'coretex-eval-v1-gate');
    assert.equal(EVAL_SEED_CONFIRM_DOMAIN_PREFIX, 'coretex-eval-v1-confirm');
    assert.notEqual(EVAL_SEED_GATE_DOMAIN_PREFIX, EVAL_SEED_CONFIRM_DOMAIN_PREFIX);
  });

  test('accepts bigint epochId equivalent to a number epochId', () => {
    const a = deriveGateEvalSeed({ ...BASE_INPUT, epochId: 42 });
    const b = deriveGateEvalSeed({ ...BASE_INPUT, epochId: 42n });
    assert.equal(a, b);
  });

  test('case-insensitive on input hex; output is always lowercase', () => {
    const upper = {
      ...BASE_INPUT,
      epochSecret: '0x' + 'AA'.repeat(32),
      blockhash:   '0x' + 'AA'.repeat(32),
    };
    const lower = {
      ...BASE_INPUT,
      epochSecret: '0x' + 'aa'.repeat(32),
      blockhash:   '0x' + 'aa'.repeat(32),
    };
    assert.equal(deriveGateEvalSeed(upper), deriveGateEvalSeed(lower));
    assert.match(deriveGateEvalSeed(upper), /^0x[0-9a-f]{64}$/);
  });
});

describe('computePatchHash', () => {
  test('returns bytes32 hex, deterministic', () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    const h1 = computePatchHash(bytes);
    const h2 = computePatchHash(bytes);
    assert.match(h1, /^0x[0-9a-f]{64}$/);
    assert.equal(h1, h2);
  });

  test('different bytes → different hash', () => {
    const a = computePatchHash(new Uint8Array([1, 2, 3]));
    const b = computePatchHash(new Uint8Array([1, 2, 4]));
    assert.notEqual(a, b);
  });

  test('domain-separated from raw keccak — prefix changes the result', () => {
    // The domain prefix means computePatchHash(bytes) ≠ keccak256(bytes).
    // This is verified indirectly: same bytes through a different domain
    // (dedupKey, which has its own prefix) must NOT equal patchHash.
    const bytes = new Uint8Array([9, 9, 9, 9]);
    const patchH = computePatchHash(bytes);
    const dedupH = computeDedupKey(`0x${'00'.repeat(32)}`, bytes);
    assert.notEqual(patchH, dedupH);
  });

  test('rejects non-Uint8Array input', () => {
    assert.throws(() => computePatchHash('abc'), /Uint8Array/);
    assert.throws(() => computePatchHash([1, 2, 3]), /Uint8Array/);
    assert.throws(() => computePatchHash(null), /Uint8Array/);
  });

  test('empty bytes hashes successfully (domain prefix only)', () => {
    const h = computePatchHash(new Uint8Array(0));
    assert.match(h, /^0x[0-9a-f]{64}$/);
  });

  test('PATCH_HASH_DOMAIN_PREFIX is exported', () => {
    assert.equal(PATCH_HASH_DOMAIN_PREFIX, 'coretex-patch-hash-v1');
  });
});

describe('computeDedupKey', () => {
  const PARENT = `0x${'aa'.repeat(32)}`;
  const PATCH = new Uint8Array([0x01, 0x02, 0x03]);

  test('returns bytes32 hex, deterministic', () => {
    const k1 = computeDedupKey(PARENT, PATCH);
    const k2 = computeDedupKey(PARENT, PATCH);
    assert.match(k1, /^0x[0-9a-f]{64}$/);
    assert.equal(k1, k2);
  });

  test('different parentRoot → different key (same patch bytes)', () => {
    const a = computeDedupKey(`0x${'aa'.repeat(32)}`, PATCH);
    const b = computeDedupKey(`0x${'bb'.repeat(32)}`, PATCH);
    assert.notEqual(a, b);
  });

  test('different patch bytes → different key (same parent)', () => {
    const a = computeDedupKey(PARENT, new Uint8Array([1, 2, 3]));
    const b = computeDedupKey(PARENT, new Uint8Array([1, 2, 4]));
    assert.notEqual(a, b);
  });

  test('rejects malformed parentRoot', () => {
    assert.throws(() => computeDedupKey('0xnope', PATCH), /parentRoot/);
    assert.throws(() => computeDedupKey('', PATCH), /parentRoot/);
  });

  test('rejects non-Uint8Array patch bytes', () => {
    assert.throws(() => computeDedupKey(PARENT, [1, 2, 3]), /Uint8Array/);
    assert.throws(() => computeDedupKey(PARENT, 'patch'), /Uint8Array/);
  });

  test('DEDUP_KEY_DOMAIN_PREFIX is exported', () => {
    assert.equal(DEDUP_KEY_DOMAIN_PREFIX, 'coretex-dedup-key-v1');
  });
});

describe('cross-helper domain separation', () => {
  test('all four hashing helpers produce distinct outputs for similar inputs', () => {
    // The same conceptual "input" — 32 bytes of patch material — must
    // produce four DIFFERENT hash outputs across the four domains
    // (gate seed, confirm seed, patch hash, dedup key). If two
    // overlapped, an attacker could substitute one for the other.
    const bytes = new Uint8Array(32).fill(0xab);
    const parentRoot = `0x${'cd'.repeat(32)}`;

    const patchH = computePatchHash(bytes);
    const dedupK = computeDedupKey(parentRoot, bytes);
    const gateS  = deriveGateEvalSeed({ ...BASE_INPUT, patchHash: patchH });
    const conS   = deriveConfirmEvalSeed({ ...BASE_INPUT, patchHash: patchH });

    const all = new Set([patchH, dedupK, gateS, conS]);
    assert.equal(all.size, 4, 'all four outputs must be distinct');
  });
});
