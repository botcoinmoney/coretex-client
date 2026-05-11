/**
 * PatchReceivedNotice tests. Pure helper — no I/O, no models.
 *
 * The notice closes the only remaining anti-pre-testing gap in the
 * per-patch on-chain randomness design: `receivedAtBlock` is the one
 * seed input the coordinator picks unilaterally. A signed notice
 * published at HTTP ingress, before any eval scheduling, anchors
 * `receivedAtBlock` to a public log. Watchers cross-check every
 * receipt against the notice for that patchHash.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  canonicalNoticeBytes,
  computePatchReceivedNoticeHash,
  verifyPatchReceivedNotice,
  PATCH_RECEIVED_NOTICE_DOMAIN_PREFIX,
} from '../../dist/index.js';

const PATCH_HASH = `0x${'aa'.repeat(32)}`;
const COORD = `0x${'10'.repeat(20)}`;

function notice(over = {}) {
  return {
    patchHash: PATCH_HASH,
    receivedAtBlock: 4242,
    receivedAtTimestamp: 1_700_000_000,
    coordinatorAddress: COORD,
    ...over,
  };
}

describe('canonicalNoticeBytes', () => {
  test('returns Uint8Array with the domain prefix at the start', () => {
    const bytes = canonicalNoticeBytes(notice());
    assert.ok(bytes instanceof Uint8Array);
    const prefix = new TextEncoder().encode(PATCH_RECEIVED_NOTICE_DOMAIN_PREFIX);
    for (let i = 0; i < prefix.length; i++) {
      assert.equal(bytes[i], prefix[i], `byte ${i} should match domain prefix`);
    }
  });

  test('deterministic — same input → same bytes', () => {
    const a = canonicalNoticeBytes(notice());
    const b = canonicalNoticeBytes(notice());
    assert.deepEqual(a, b);
  });

  test('changes when any field changes (sensitivity)', () => {
    const base = canonicalNoticeBytes(notice());
    const variants = [
      notice({ patchHash: `0x${'bb'.repeat(32)}` }),
      notice({ receivedAtBlock: 4243 }),
      notice({ receivedAtTimestamp: 1_700_000_001 }),
      notice({ coordinatorAddress: `0x${'20'.repeat(20)}` }),
    ];
    for (const v of variants) {
      assert.notDeepEqual(canonicalNoticeBytes(v), base);
    }
  });

  test('rejects malformed input', () => {
    assert.throws(() => canonicalNoticeBytes(notice({ patchHash: '0xnope' })), /patchHash/);
    assert.throws(() => canonicalNoticeBytes(notice({ coordinatorAddress: 'not-an-address' })), /coordinatorAddress/);
    assert.throws(() => canonicalNoticeBytes(notice({ receivedAtBlock: -1 })), /receivedAtBlock/);
    assert.throws(() => canonicalNoticeBytes(notice({ receivedAtBlock: 1.5 })), /receivedAtBlock/);
    assert.throws(() => canonicalNoticeBytes(notice({ receivedAtTimestamp: -1 })), /receivedAtTimestamp/);
  });
});

describe('computePatchReceivedNoticeHash', () => {
  test('returns bytes32 hex', () => {
    const h = computePatchReceivedNoticeHash(notice());
    assert.match(h, /^0x[0-9a-f]{64}$/);
  });

  test('deterministic + sensitive to every field', () => {
    const h0 = computePatchReceivedNoticeHash(notice());
    assert.equal(h0, computePatchReceivedNoticeHash(notice()));
    assert.notEqual(h0, computePatchReceivedNoticeHash(notice({ receivedAtBlock: 4243 })));
    assert.notEqual(h0, computePatchReceivedNoticeHash(notice({ patchHash: `0x${'bb'.repeat(32)}` })));
  });
});

describe('verifyPatchReceivedNotice', () => {
  test('happy path — notice matches receipt + stored hash', () => {
    const n = notice();
    const r = verifyPatchReceivedNotice({
      notice: n,
      storedNoticeHash: computePatchReceivedNoticeHash(n),
      receiptPatchHash: n.patchHash,
      receiptReceivedAtBlock: n.receivedAtBlock,
    });
    assert.deepEqual(r, { ok: true });
  });

  test('missing notice → NOTICE_MISSING', () => {
    const r = verifyPatchReceivedNotice({
      notice: null,
      storedNoticeHash: `0x${'00'.repeat(32)}`,
      receiptPatchHash: PATCH_HASH,
      receiptReceivedAtBlock: 4242,
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.code, 'NOTICE_MISSING');
  });

  test('patchHash mismatch — coordinator forged the notice patchHash', () => {
    const n = notice();
    const r = verifyPatchReceivedNotice({
      notice: n,
      storedNoticeHash: computePatchReceivedNoticeHash(n),
      receiptPatchHash: `0x${'ff'.repeat(32)}`,
      receiptReceivedAtBlock: n.receivedAtBlock,
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.code, 'PATCH_HASH_MISMATCH');
  });

  test('receivedAtBlock mismatch — coordinator stamped a different block than the notice', () => {
    const n = notice();
    const r = verifyPatchReceivedNotice({
      notice: n,
      storedNoticeHash: computePatchReceivedNoticeHash(n),
      receiptPatchHash: n.patchHash,
      receiptReceivedAtBlock: 9999,        // different from notice.receivedAtBlock=4242
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.code, 'RECEIVED_AT_BLOCK_MISMATCH');
  });

  test('notice hash mismatch — host log was tampered with', () => {
    const n = notice();
    const r = verifyPatchReceivedNotice({
      notice: n,
      storedNoticeHash: `0x${'de'.repeat(32)}`,   // tampered
      receiptPatchHash: n.patchHash,
      receiptReceivedAtBlock: n.receivedAtBlock,
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.code, 'NOTICE_HASH_MISMATCH');
  });

  test('domain prefix is exported', () => {
    assert.equal(PATCH_RECEIVED_NOTICE_DOMAIN_PREFIX, 'coretex-patch-received-notice-v1');
  });
});
