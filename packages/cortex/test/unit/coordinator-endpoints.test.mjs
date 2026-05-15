import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  CORETEX_ENDPOINTS,
  createCoreTexCoordinatorRouteHandler,
  handleCoreTexCoordinatorRoute,
} from '../../dist/index.js';

describe('CoreTex coordinator endpoint contract', () => {
  test('declares the production /coretex surface', () => {
    assert.deepEqual(CORETEX_ENDPOINTS.map((route) => `${route.method} ${route.path}`), [
      'GET /coretex/challenge',
      'POST /coretex/submit',
      'GET /coretex/status',
      'GET /coretex/substrate/:stateRoot',
      'GET /coretex/patch/:hash',
      'GET /coretex/patch-received/:hash',
      'GET /coretex/eval-report/:hash',
      'GET /coretex/corpus-delta/:epoch',
      'GET /coretex/bundle/by-core-version/:coreVersionHash',
      'GET /coretex/bundle/:bundleHash',
      'GET /coretex/health',
    ]);
  });

  test('routes challenge/submit/status', async () => {
    const source = {
      getChallenge: () => ({ lane: 'coretex', challengeId: '0xabc' }),
      submit: (body) => ({ submitted: true, body }),
      getStatus: () => ({ lane: 'coretex', epochId: 7 }),
    };
    assert.deepEqual(await handleCoreTexCoordinatorRoute({
      method: 'GET',
      path: '/coretex/challenge',
    }, source), { handled: true, status: 200, body: { lane: 'coretex', challengeId: '0xabc' } });
    assert.deepEqual(await handleCoreTexCoordinatorRoute({
      method: 'POST',
      path: '/coretex/submit',
      body: { patch: '0x1234' },
    }, source), { handled: true, status: 200, body: { submitted: true, body: { patch: '0x1234' } } });
    assert.deepEqual(await handleCoreTexCoordinatorRoute({
      method: 'GET',
      path: '/coretex/status',
    }, source), { handled: true, status: 200, body: { lane: 'coretex', epochId: 7 } });
  });

  test('routes bytes32 and epoch lookups', async () => {
    const hash = `0x${'ab'.repeat(32)}`;
    const calls = [];
    const source = {
      getSubstrate: (stateRoot) => {
        calls.push(['substrate', stateRoot]);
        return { stateRoot };
      },
      getPatch: (patchHash) => {
        calls.push(['patch', patchHash]);
        return { patchHash };
      },
      getPatchReceivedNotice: (patchHash) => {
        calls.push(['patch-received', patchHash]);
        return { patchHash, receivedAtBlock: 123 };
      },
      getEvalReport: (evalReportHash) => {
        calls.push(['eval-report', evalReportHash]);
        return { evalReportHash };
      },
      getCorpusDelta: (epoch) => {
        calls.push(['corpus-delta', epoch.toString()]);
        return { epoch: epoch.toString() };
      },
      getBundle: (bundleHash) => {
        calls.push(['bundle', bundleHash]);
        return { bundleHash };
      },
      getBundleByCoreVersionHash: (coreVersionHash) => {
        calls.push(['bundle-by-core-version', coreVersionHash]);
        return { coreVersionHash };
      },
    };

    assert.deepEqual(await handleCoreTexCoordinatorRoute({
      method: 'GET',
      path: `/coretex/substrate/0x${'AB'.repeat(32)}`,
    }, source), { handled: true, status: 200, body: { stateRoot: hash } });

    await handleCoreTexCoordinatorRoute({ method: 'GET', path: `/coretex/patch/${hash}` }, source);
    await handleCoreTexCoordinatorRoute({ method: 'GET', path: `/coretex/patch-received/${hash}` }, source);
    await handleCoreTexCoordinatorRoute({ method: 'GET', path: `/coretex/eval-report/${hash}` }, source);
    await handleCoreTexCoordinatorRoute({ method: 'GET', path: '/coretex/corpus-delta/9' }, source);
    await handleCoreTexCoordinatorRoute({ method: 'GET', path: `/coretex/bundle/by-core-version/${hash}` }, source);
    await handleCoreTexCoordinatorRoute({ method: 'GET', path: `/coretex/bundle/${hash}` }, source);
    assert.deepEqual(calls, [
      ['substrate', hash],
      ['patch', hash],
      ['patch-received', hash],
      ['eval-report', hash],
      ['corpus-delta', '9'],
      ['bundle-by-core-version', hash],
      ['bundle', hash],
    ]);
  });

  test('createCoreTexCoordinatorRouteHandler binds a single async handler', async () => {
    const handle = createCoreTexCoordinatorRouteHandler({
      getChallenge: () => ({ lane: 'coretex', challengeId: '0xfeed' }),
    });
    const r = await handle({ method: 'GET', path: '/coretex/challenge' });
    assert.equal(r.handled, true);
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, { lane: 'coretex', challengeId: '0xfeed' });
  });

  test('rate-limit hook denial returns 429 and does not invoke route handler', async () => {
    let invoked = false;
    const response = await handleCoreTexCoordinatorRoute({
      method: 'POST',
      path: '/coretex/submit',
      body: { miner: '0xabc' },
      remoteAddress: '203.0.113.10',
    }, {
      rateLimit: (context) => ({
        ok: false,
        status: 429,
        body: { error: 'too-many-coretex-requests', endpoint: context.endpoint },
      }),
      submit: () => {
        invoked = true;
        return { ok: true };
      },
    });

    assert.equal(invoked, false);
    assert.deepEqual(response, {
      handled: true,
      status: 429,
      body: { error: 'too-many-coretex-requests', endpoint: 'submit' },
    });
  });

  test('authorization hook receives matched endpoint and request metadata', async () => {
    const seen = [];
    const hash = `0x${'ab'.repeat(32)}`;
    const response = await handleCoreTexCoordinatorRoute({
      method: 'GET',
      path: `/coretex/patch/${hash}`,
      headers: { authorization: 'Bearer test' },
      remoteAddress: '198.51.100.4',
    }, {
      authorize: (context) => {
        seen.push(context);
        return true;
      },
      getPatch: (patchHash) => ({ patchHash }),
    });

    assert.equal(response.status, 200);
    assert.equal(seen.length, 1);
    assert.deepEqual(seen[0], {
      endpoint: 'patch-by-hash',
      method: 'GET',
      path: `/coretex/patch/${hash}`,
      headers: { authorization: 'Bearer test' },
      remoteAddress: '198.51.100.4',
    });
  });

  test('ignores non-CoreTex routes and fails closed for missing handlers', async () => {
    assert.deepEqual(await handleCoreTexCoordinatorRoute({
      method: 'GET',
      path: '/v1/challenge',
    }, {}), { handled: false, status: 404, body: null });

    assert.deepEqual(await handleCoreTexCoordinatorRoute({
      method: 'GET',
      path: `/coretex/eval-report/0x${'11'.repeat(32)}`,
    }, {}), {
      handled: true,
      status: 503,
      body: { error: 'coretex-route-not-configured', route: 'eval-report-by-hash' },
    });

    assert.deepEqual(await handleCoreTexCoordinatorRoute({
      method: 'POST',
      path: '/coretex/screen',
      body: {},
    }, {}), {
      handled: true,
      status: 404,
      body: { error: 'coretex-not-found' },
    });
  });
});
