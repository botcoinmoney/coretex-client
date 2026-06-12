import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  CORETEX_ENDPOINTS,
  createCoreTexCoordinatorRouteHandler,
  handleCoreTexCoordinatorRoute,
} from '../../dist/index.js';

describe('CoreTex v0 canonical endpoint surface', () => {
  test('declares EXACTLY the 5 launch endpoints', () => {
    assert.deepEqual(CORETEX_ENDPOINTS.map((route) => `${route.method} ${route.path}`), [
      'GET /coretex/health',
      'GET /coretex/status',
      'GET /coretex/substrate/:stateRoot',
      'POST /coretex/submit',
      'GET /coretex/receipt/:hash',
    ]);
  });

  test('routes the 5 canonical endpoints', async () => {
    const calls = [];
    const source = {
      health: () => ({ ok: true, version: 'v0' }),
      getStatus: (query) => { calls.push(['status', query]); return { lane: 'coretex', epochId: 7, miner: query.miner ?? null }; },
      getSubstrate: (root) => { calls.push(['substrate', root]); return { stateRoot: root, packedBytes: 32768 }; },
      submit: (body) => { calls.push(['submit', body]); return { status: 'accepted', patchHash: '0xdeadbeef' }; },
      getReceipt: (hash) => { calls.push(['receipt', hash]); return { status: 200, body: { status: 'accepted', patchHash: hash } }; },
    };
    const handle = createCoreTexCoordinatorRouteHandler(source);

    assert.deepEqual(await handle({ method: 'GET', path: '/coretex/health' }),
      { handled: true, status: 200, body: { ok: true, version: 'v0' } });

    assert.deepEqual(await handle({ method: 'GET', path: '/coretex/status', query: { miner: '0xabc' } }),
      { handled: true, status: 200, body: { lane: 'coretex', epochId: 7, miner: '0xabc' } });

    const root = '0x' + '11'.repeat(32);
    assert.deepEqual(await handle({ method: 'GET', path: `/coretex/substrate/${root}` }),
      { handled: true, status: 200, body: { stateRoot: root, packedBytes: 32768 } });

    assert.deepEqual(await handle({ method: 'POST', path: '/coretex/submit', body: { patch: '0x1234' } }),
      { handled: true, status: 200, body: { status: 'accepted', patchHash: '0xdeadbeef' } });

    const hash = '0x' + 'cd'.repeat(32);
    assert.deepEqual(await handle({ method: 'GET', path: `/coretex/receipt/${hash}` }),
      { handled: true, status: 200, body: { status: 'accepted', patchHash: hash } });
  });

  test('rejects removed v0 routes with 404 (no /coretex/challenge, /coretex/patch, etc.)', async () => {
    const source = { getStatus: () => ({}), submit: () => ({}) };
    for (const stale of [
      '/coretex/challenge',
      '/coretex/patch/0x' + 'ab'.repeat(32),
      '/coretex/patch-received/0x' + 'ab'.repeat(32),
      '/coretex/eval-report/0x' + 'ab'.repeat(32),
      '/coretex/corpus-delta/0',
      '/coretex/bundle/0x' + 'ab'.repeat(32),
      '/coretex/bundle/by-core-version/0x' + 'ab'.repeat(32),
    ]) {
      const r = await handleCoreTexCoordinatorRoute({ method: 'GET', path: stale }, source);
      assert.equal(r.handled, true, `${stale} should be handled (router owns /coretex/* namespace)`);
      assert.equal(r.status, 404, `${stale} should 404`);
      assert.deepEqual(r.body, { error: 'coretex-not-found' });
    }
  });

  test('returns 503 + structured error for not-configured routes', async () => {
    const source = {};
    const r = await handleCoreTexCoordinatorRoute({ method: 'GET', path: '/coretex/status' }, source);
    assert.equal(r.status, 503);
    assert.deepEqual(r.body, { error: 'coretex-route-not-configured', route: 'status' });
  });

  test('receipt-by-hash returns 404 when data source returns null/undefined', async () => {
    const source = { getReceipt: () => null };
    const hash = '0x' + 'de'.repeat(32);
    const r = await handleCoreTexCoordinatorRoute({ method: 'GET', path: `/coretex/receipt/${hash}` }, source);
    assert.equal(r.status, 404);
    assert.deepEqual(r.body, { status: 'rejected', reason: 'unknown patchHash (not signed by this coordinator)' });
  });

  test('substrate-by-root returns 404 when data source has no confirmed root', async () => {
    const source = { getSubstrate: () => null };
    const root = '0x' + '12'.repeat(32);
    const r = await handleCoreTexCoordinatorRoute({ method: 'GET', path: `/coretex/substrate/${root}` }, source);
    assert.equal(r.status, 404);
    assert.deepEqual(r.body, { error: 'coretex-substrate-not-found', stateRoot: root });
  });

  test('substrate-by-root returns non-200 when data source fails closed on malformed substrate', async () => {
    const source = { getSubstrate: () => ({ error: 'coretex-substrate-malformed' }) };
    const root = '0x' + '12'.repeat(32);
    const r = await handleCoreTexCoordinatorRoute({ method: 'GET', path: `/coretex/substrate/${root}` }, source);
    assert.equal(r.status, 502);
    assert.deepEqual(r.body, { error: 'coretex-substrate-malformed' });
  });

  test('receipt-by-hash propagates 409 stale + body from data source', async () => {
    const source = { getReceipt: () => ({ status: 409, body: { status: 'rejected', code: 'PendingReceiptStale', reason: 'competing advance landed' } }) };
    const hash = '0x' + 'de'.repeat(32);
    const r = await handleCoreTexCoordinatorRoute({ method: 'GET', path: `/coretex/receipt/${hash}` }, source);
    assert.equal(r.status, 409);
    assert.deepEqual(r.body, { status: 'rejected', code: 'PendingReceiptStale', reason: 'competing advance landed' });
  });

  test('guard rejects unauthorized status with 401', async () => {
    const source = {
      authorize: () => false,
      getStatus: () => ({ should: 'not-be-called' }),
    };
    const r = await handleCoreTexCoordinatorRoute({ method: 'GET', path: '/coretex/status' }, source);
    assert.equal(r.status, 401);
    assert.deepEqual(r.body, { error: 'coretex-unauthorized' });
  });

  test('guard rate-limits submit with 429', async () => {
    const source = {
      rateLimit: (ctx) => ctx.endpoint === 'submit' ? false : true,
      submit: () => ({ should: 'not-be-called' }),
    };
    const r = await handleCoreTexCoordinatorRoute({ method: 'POST', path: '/coretex/submit', body: {} }, source);
    assert.equal(r.status, 429);
    assert.deepEqual(r.body, { error: 'coretex-rate-limited' });
  });

  test('returns false handled for non-/coretex paths', async () => {
    const source = {};
    const r = await handleCoreTexCoordinatorRoute({ method: 'GET', path: '/v1/challenge' }, source);
    assert.equal(r.handled, false);
  });
});

// ── Submit HTTP status semantics + disconnect-signal threading ──────────────
import { submitHttpStatusFor } from '../../dist/index.js';

describe('submit HTTP status semantics', () => {
  test('infra-unavailable rejection codes map to 503', () => {
    for (const code of [
      'EvalFailure', 'SignerFailure', 'CoordSignerUnavailable', 'CoordUnhealthy',
      'CoordEpochMismatch', 'CoordAwaitingFinality', 'awaiting_baseline_recompute',
      'epoch_cutover_in_progress', 'epoch_cutover_unavailable', 'QueueFull',
    ]) {
      assert.equal(submitHttpStatusFor({ status: 'rejected', code }), 503, code);
    }
  });

  test('malformed-request codes map to 400; stale-root race (E01) stays 200', () => {
    for (const code of ['BODY', 'DECODE', 'E02', 'E03', 'E04', 'E05']) {
      assert.equal(submitHttpStatusFor({ status: 'rejected', code }), 400, code);
    }
    assert.equal(submitHttpStatusFor({ status: 'rejected', code: 'E01' }), 200);
  });

  test('semantic rejections and accepted envelopes stay 200 (bodies pass through verbatim)', () => {
    for (const code of ['duplicate_submission', 'DuplicateCoreTexPatch', 'CoreTexScreenerCapExceeded', 'MinerReceiptChainBusy', 'MinerQueueFull', 'ClientDisconnected', 'W03_DETERMINISTIC_DELTA_TOO_LOW']) {
      assert.equal(submitHttpStatusFor({ status: 'rejected', code }), 200, code);
    }
    assert.equal(submitHttpStatusFor({ status: 'accepted', outcome: 'screener_pass' }), 200);
    assert.equal(submitHttpStatusFor(null), 200);
    assert.equal(submitHttpStatusFor('weird'), 200);
  });

  test('the route applies the mapping and passes the envelope body through verbatim', async () => {
    const envelope = { status: 'rejected', code: 'EvalFailure', reason: 'evaluator failed' };
    const r = await handleCoreTexCoordinatorRoute(
      { method: 'POST', path: '/coretex/submit', body: { x: 1 } },
      { submit: () => envelope },
    );
    assert.equal(r.status, 503);
    assert.deepEqual(r.body, envelope);
    const bad = await handleCoreTexCoordinatorRoute(
      { method: 'POST', path: '/coretex/submit', body: {} },
      { submit: () => ({ status: 'rejected', code: 'BODY', reason: 'malformed body' }) },
    );
    assert.equal(bad.status, 400);
  });

  test('the client-disconnect signal is threaded to the submit handler', async () => {
    const ctl = new AbortController();
    let seen;
    await handleCoreTexCoordinatorRoute(
      { method: 'POST', path: '/coretex/submit', body: {}, signal: ctl.signal },
      { submit: (_body, opts) => { seen = opts?.signal; return { status: 'rejected', code: 'BODY' }; } },
    );
    assert.equal(seen, ctl.signal);
    // No signal on the request → no opts fabricated.
    let seenOpts = 'unset';
    await handleCoreTexCoordinatorRoute(
      { method: 'POST', path: '/coretex/submit', body: {} },
      { submit: (_body, opts) => { seenOpts = opts; return { status: 'rejected', code: 'BODY' }; } },
    );
    assert.equal(seenOpts, undefined);
  });
});
