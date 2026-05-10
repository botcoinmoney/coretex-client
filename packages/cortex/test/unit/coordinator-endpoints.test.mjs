import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  CORETEX_ENDPOINTS,
  handleCoreTexCoordinatorRoute,
} from '../../dist/index.js';

describe('CoreTex coordinator endpoint contract', () => {
  test('declares the production /coretex surface', () => {
    assert.deepEqual(CORETEX_ENDPOINTS.map((route) => `${route.method} ${route.path}`), [
      'POST /coretex/screen',
      'POST /coretex/evaluate',
      'GET /coretex/substrate/current',
      'GET /coretex/substrate/:stateRoot',
      'GET /coretex/patch/:hash',
      'GET /coretex/eval-report/:hash',
      'GET /coretex/challenge-book/:epoch',
      'GET /coretex/corpus-delta/:epoch',
      'GET /coretex/client-bundle/:coreVersionHash',
      'GET /coretex/bundle/:bundleHash',
      'GET /coretex/corpus/:recordId',
      'GET /coretex/corpus/:recordId/embedding',
      'GET /coretex/coverage-hints',
      'GET /coretex/health',
    ]);
  });

  test('routes current substrate and bytes32 lookups additively', async () => {
    const hash = `0x${'ab'.repeat(32)}`;
    const calls = [];
    const source = {
      getCurrentSubstrate: () => ({ stateRoot: hash }),
      getSubstrate: (stateRoot) => {
        calls.push(['substrate', stateRoot]);
        return { stateRoot };
      },
      getPatch: (patchHash) => {
        calls.push(['patch', patchHash]);
        return { patchHash };
      },
    };

    assert.deepEqual(await handleCoreTexCoordinatorRoute({
      method: 'GET',
      path: '/coretex/substrate/current',
    }, source), { handled: true, status: 200, body: { stateRoot: hash } });

    assert.deepEqual(await handleCoreTexCoordinatorRoute({
      method: 'GET',
      path: `/coretex/substrate/0x${'AB'.repeat(32)}`,
    }, source), { handled: true, status: 200, body: { stateRoot: hash } });

    await handleCoreTexCoordinatorRoute({ method: 'GET', path: `/coretex/patch/${hash}` }, source);
    assert.deepEqual(calls, [['substrate', hash], ['patch', hash]]);
  });

  test('routes screen and evaluate POST bodies', async () => {
    const source = {
      screen: (body) => ({ lane: 'screen', body }),
      evaluate: (body) => ({ lane: 'evaluate', body }),
    };
    assert.deepEqual(await handleCoreTexCoordinatorRoute({
      method: 'POST',
      path: '/coretex/screen',
      body: { miner: '0xabc' },
    }, source), { handled: true, status: 200, body: { lane: 'screen', body: { miner: '0xabc' } } });
    assert.deepEqual(await handleCoreTexCoordinatorRoute({
      method: 'POST',
      path: '/coretex/evaluate',
      body: { patch: '0x1234' },
    }, source), { handled: true, status: 200, body: { lane: 'evaluate', body: { patch: '0x1234' } } });
  });

  test('rate-limit hook denial returns 429 and does not invoke route handler', async () => {
    let invoked = false;
    const response = await handleCoreTexCoordinatorRoute({
      method: 'POST',
      path: '/coretex/screen',
      body: { miner: '0xabc' },
      remoteAddress: '203.0.113.10',
    }, {
      rateLimit: (context) => ({
        ok: false,
        status: 429,
        body: { error: 'too-many-coretex-requests', endpoint: context.endpoint },
      }),
      screen: () => {
        invoked = true;
        return { ok: true };
      },
    });

    assert.equal(invoked, false);
    assert.deepEqual(response, {
      handled: true,
      status: 429,
      body: { error: 'too-many-coretex-requests', endpoint: 'screen' },
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
  });
});
