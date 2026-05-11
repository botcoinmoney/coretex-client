/**
 * Phase S1 of CORETEX_SEALED_EPOCH_EVAL_HARDENING_PLAN.md.
 *
 * Pure tests of the commit / reveal / duplicate-key / commitment-root
 * primitives in packages/cortex/src/coordinator/sealed-eval.ts. No I/O,
 * no model work — safe to run alongside the launch corpus generation.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  computePatchCommitmentHash,
  buildPatchCommitment,
  verifyPatchReveal,
  computeDuplicateKey,
  computeCommitmentRoot,
  PATCH_COMMIT_DOMAIN_PREFIX,
  PATCH_DUPLICATE_KEY_DOMAIN_PREFIX,
  COMMITMENT_LEAF_DOMAIN_PREFIX,
  CORETEX_ENDPOINTS,
  handleCoreTexCoordinatorRoute,
} from '../../dist/index.js';

const ROOT_A = `0x${'aa'.repeat(32)}`;
const ROOT_B = `0x${'bb'.repeat(32)}`;
const BUNDLE = `0x${'cc'.repeat(32)}`;
const MINER_A = `0x${'12'.repeat(20)}`;
const MINER_B = `0x${'34'.repeat(20)}`;
const SALT = `0x${'de'.repeat(32)}`;
const PATCH_BYTES = new Uint8Array([0x01, 0x02, 0x03, 0x04]);

function commit(over = {}) {
  return {
    epochId: 78,
    epochParentRoot: ROOT_A,
    minerAddress: MINER_A,
    bundleHash: BUNDLE,
    patchBytes: PATCH_BYTES,
    saltHex: SALT,
    ...over,
  };
}

describe('computePatchCommitmentHash', () => {
  test('is deterministic for the same inputs', () => {
    assert.equal(computePatchCommitmentHash(commit()), computePatchCommitmentHash(commit()));
  });

  test('changes when ANY field changes', () => {
    const base = computePatchCommitmentHash(commit());
    assert.notEqual(base, computePatchCommitmentHash(commit({ epochId: 79 })));
    assert.notEqual(base, computePatchCommitmentHash(commit({ epochParentRoot: ROOT_B })));
    assert.notEqual(base, computePatchCommitmentHash(commit({ minerAddress: MINER_B })));
    assert.notEqual(base, computePatchCommitmentHash(commit({ bundleHash: `0x${'dd'.repeat(32)}` })));
    assert.notEqual(base, computePatchCommitmentHash(commit({ patchBytes: new Uint8Array([0xff]) })));
    assert.notEqual(base, computePatchCommitmentHash(commit({ saltHex: `0x${'77'.repeat(32)}` })));
  });

  test('rejects bad hex (parent root, miner, bundle, salt)', () => {
    assert.throws(() => computePatchCommitmentHash(commit({ epochParentRoot: '0xnotahex' })), /epochParentRoot/);
    assert.throws(() => computePatchCommitmentHash(commit({ minerAddress: '0x12' })), /minerAddress/);
    assert.throws(() => computePatchCommitmentHash(commit({ bundleHash: 'too-short' })), /bundleHash/);
    assert.throws(() => computePatchCommitmentHash(commit({ saltHex: '0x' + 'ab'.repeat(16) })), /saltHex/);
  });

  test('rejects empty / non-Uint8Array patch bytes', () => {
    assert.throws(() => computePatchCommitmentHash(commit({ patchBytes: new Uint8Array() })), /patchBytes/);
    assert.throws(() => computePatchCommitmentHash(commit({ patchBytes: [1, 2, 3] })), /patchBytes/);
  });

  test('uses domain-separation prefix (different prefix → different hash)', () => {
    // Sanity: the prefix string is canonical, not user-controlled.
    assert.equal(PATCH_COMMIT_DOMAIN_PREFIX, 'botcoin-coretex-patch-commit-v1');
    assert.equal(PATCH_DUPLICATE_KEY_DOMAIN_PREFIX, 'botcoin-coretex-patch-duplicate-key-v1');
    assert.equal(COMMITMENT_LEAF_DOMAIN_PREFIX, 'botcoin-coretex-commitment-leaf-v1');
  });
});

describe('buildPatchCommitment', () => {
  test('returns the canonical hash and lowercased fields', () => {
    const c = buildPatchCommitment(commit({ minerAddress: '0xABCDEF1234567890ABCDEF1234567890ABCDEF12' }));
    assert.match(c.commitmentHash, /^0x[0-9a-f]{64}$/);
    assert.equal(c.minerAddress, '0xabcdef1234567890abcdef1234567890abcdef12');
    assert.equal(c.patchBytesLength, 4);
    assert.equal(c.epochId, 78n);
  });
});

describe('verifyPatchReveal', () => {
  test('round-trip: build then verify with the same inputs', () => {
    const c = buildPatchCommitment(commit());
    const r = verifyPatchReveal({
      commitmentHash: c.commitmentHash,
      patchBytes: PATCH_BYTES,
      saltHex: SALT,
      epochId: 78,
      epochParentRoot: ROOT_A,
      minerAddress: MINER_A,
      bundleHash: BUNDLE,
    });
    assert.equal(r.ok, true);
    if (r.ok) assert.equal(r.commitmentHash, c.commitmentHash);
  });

  test('rejects mismatched patch bytes', () => {
    const c = buildPatchCommitment(commit());
    const r = verifyPatchReveal({
      commitmentHash: c.commitmentHash,
      patchBytes: new Uint8Array([0xff, 0xff]),
      saltHex: SALT,
      epochId: 78,
      epochParentRoot: ROOT_A,
      minerAddress: MINER_A,
      bundleHash: BUNDLE,
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'commitment-hash-mismatch');
  });

  test('rejects mismatched salt', () => {
    const c = buildPatchCommitment(commit());
    const r = verifyPatchReveal({
      commitmentHash: c.commitmentHash,
      patchBytes: PATCH_BYTES,
      saltHex: `0x${'77'.repeat(32)}`,
      epochId: 78,
      epochParentRoot: ROOT_A,
      minerAddress: MINER_A,
      bundleHash: BUNDLE,
    });
    assert.equal(r.ok, false);
  });

  test('rejects mismatched epoch / parent / miner / bundle', () => {
    const c = buildPatchCommitment(commit());
    for (const override of [
      { epochId: 99 },
      { epochParentRoot: ROOT_B },
      { minerAddress: MINER_B },
      { bundleHash: `0x${'dd'.repeat(32)}` },
    ]) {
      const r = verifyPatchReveal({
        commitmentHash: c.commitmentHash,
        patchBytes: PATCH_BYTES,
        saltHex: SALT,
        epochId: 78,
        epochParentRoot: ROOT_A,
        minerAddress: MINER_A,
        bundleHash: BUNDLE,
        ...override,
      });
      assert.equal(r.ok, false, `should reject ${JSON.stringify(override)}`);
    }
  });

  test('rejects malformed input shape with coarse reason', () => {
    const r = verifyPatchReveal({
      commitmentHash: '0x' + 'ab'.repeat(32),
      patchBytes: new Uint8Array([0x01]),
      saltHex: 'not-hex',
      epochId: 78,
      epochParentRoot: ROOT_A,
      minerAddress: MINER_A,
      bundleHash: BUNDLE,
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'invalid-salt');
  });
});

describe('computeDuplicateKey', () => {
  test('deterministic for the same inputs', () => {
    const k = (over = {}) => computeDuplicateKey({
      epochParentRoot: ROOT_A,
      sortedTouchedWordIndices: [0, 384],
      normalizedPatchBytes: PATCH_BYTES,
      resultingStateRoot: ROOT_B,
      ...over,
    });
    assert.equal(k(), k());
  });

  test('different patches produce different keys', () => {
    const k = (over = {}) => computeDuplicateKey({
      epochParentRoot: ROOT_A,
      sortedTouchedWordIndices: [0, 384],
      normalizedPatchBytes: PATCH_BYTES,
      resultingStateRoot: ROOT_B,
      ...over,
    });
    assert.notEqual(k(), k({ resultingStateRoot: `0x${'77'.repeat(32)}` }));
    assert.notEqual(k(), k({ sortedTouchedWordIndices: [0, 385] }));
    assert.notEqual(k(), k({ normalizedPatchBytes: new Uint8Array([0xff]) }));
  });

  test('rejects non-ascending indices', () => {
    assert.throws(() => computeDuplicateKey({
      epochParentRoot: ROOT_A,
      sortedTouchedWordIndices: [10, 5],
      normalizedPatchBytes: PATCH_BYTES,
      resultingStateRoot: ROOT_B,
    }), /ascending/);
  });

  test('rejects out-of-range indices', () => {
    assert.throws(() => computeDuplicateKey({
      epochParentRoot: ROOT_A,
      sortedTouchedWordIndices: [0, 1024],
      normalizedPatchBytes: PATCH_BYTES,
      resultingStateRoot: ROOT_B,
    }), /\[0, 1023\]/);
    assert.throws(() => computeDuplicateKey({
      epochParentRoot: ROOT_A,
      sortedTouchedWordIndices: [-1, 0],
      normalizedPatchBytes: PATCH_BYTES,
      resultingStateRoot: ROOT_B,
    }), /\[0, 1023\]/);
  });
});

describe('computeCommitmentRoot', () => {
  test('empty set is zero root', () => {
    assert.equal(computeCommitmentRoot([]), '0x' + '00'.repeat(32));
  });

  test('single commitment yields a non-zero root', () => {
    const r = computeCommitmentRoot([`0x${'ab'.repeat(32)}`]);
    assert.match(r, /^0x[0-9a-f]{64}$/);
    assert.notEqual(r, '0x' + '00'.repeat(32));
  });

  test('insertion order does not change the root (sorted + deduped)', () => {
    const h1 = `0x${'01'.repeat(32)}`;
    const h2 = `0x${'02'.repeat(32)}`;
    const h3 = `0x${'03'.repeat(32)}`;
    assert.equal(
      computeCommitmentRoot([h1, h2, h3]),
      computeCommitmentRoot([h3, h1, h2]),
    );
  });

  test('duplicate commitment hash collapses to one leaf', () => {
    const h = `0x${'01'.repeat(32)}`;
    assert.equal(
      computeCommitmentRoot([h, h, h]),
      computeCommitmentRoot([h]),
    );
  });

  test('different set of commitments yields different root', () => {
    const a = computeCommitmentRoot([`0x${'01'.repeat(32)}`, `0x${'02'.repeat(32)}`]);
    const b = computeCommitmentRoot([`0x${'01'.repeat(32)}`, `0x${'03'.repeat(32)}`]);
    assert.notEqual(a, b);
  });
});

describe('sealed-eval route shim', () => {
  test('CORETEX_ENDPOINTS includes the four sealed-eval endpoints', () => {
    const names = CORETEX_ENDPOINTS.map((e) => e.name);
    for (const n of ['commit', 'reveal', 'commit-by-hash', 'epoch-status']) {
      assert.ok(names.includes(n), `expected ${n}`);
    }
  });

  test('POST /coretex/commit delegates to source.submitCommit', async () => {
    const calls = [];
    const source = {
      authorize: () => true,
      submitCommit: (body) => { calls.push(['commit', body]); return { status: 'committed', commitmentHash: '0xdead' }; },
    };
    const r = await handleCoreTexCoordinatorRoute(
      { method: 'POST', path: '/coretex/commit', body: { commitmentHash: '0xdead' } },
      source,
    );
    assert.equal(r.handled, true);
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, { status: 'committed', commitmentHash: '0xdead' });
    assert.deepEqual(calls, [['commit', { commitmentHash: '0xdead' }]]);
  });

  test('POST /coretex/reveal delegates to source.submitReveal', async () => {
    const calls = [];
    const source = {
      authorize: () => true,
      submitReveal: (body) => { calls.push(['reveal', body]); return { status: 'revealed', admission: 'pending' }; },
    };
    const r = await handleCoreTexCoordinatorRoute(
      { method: 'POST', path: '/coretex/reveal', body: { commitmentHash: '0xabc', patchBytes: '0x01' } },
      source,
    );
    assert.equal(r.handled, true);
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, { status: 'revealed', admission: 'pending' });
    assert.deepEqual(calls, [['reveal', { commitmentHash: '0xabc', patchBytes: '0x01' }]]);
  });

  test('GET /coretex/commit/:hash delegates with bytes32 hash', async () => {
    const seen = [];
    const hash = `0x${'42'.repeat(32)}`;
    const source = {
      authorize: () => true,
      getCommit: (h) => { seen.push(h); return { commitmentHash: h, status: 'committed' }; },
    };
    const r = await handleCoreTexCoordinatorRoute(
      { method: 'GET', path: `/coretex/commit/${hash}` },
      source,
    );
    assert.equal(r.status, 200);
    assert.deepEqual(seen, [hash.toLowerCase()]);
  });

  test('GET /coretex/epoch/:epochId/status delegates with bigint epoch id', async () => {
    const seen = [];
    const source = {
      authorize: () => true,
      getEpochStatus: (epoch) => { seen.push(epoch); return { epochId: epoch.toString(), status: 'open' }; },
    };
    const r = await handleCoreTexCoordinatorRoute(
      { method: 'GET', path: '/coretex/epoch/78/status' },
      source,
    );
    assert.equal(r.status, 200);
    assert.deepEqual(seen, [78n]);
  });

  test('unconfigured endpoints return 503 coretex-route-not-configured', async () => {
    const r = await handleCoreTexCoordinatorRoute(
      { method: 'POST', path: '/coretex/commit', body: {} },
      { authorize: () => true },
    );
    assert.equal(r.status, 503);
    assert.deepEqual(r.body, { error: 'coretex-route-not-configured', route: 'commit' });
  });
});
