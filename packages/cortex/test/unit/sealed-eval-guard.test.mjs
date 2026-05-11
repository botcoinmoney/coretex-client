/**
 * Phase S0 of CORETEX_SEALED_EPOCH_EVAL_HARDENING_PLAN.md.
 *
 * The launch invariant: `POST /coretex/evaluate` must not return active
 * hidden-pack scores to public callers. createRetrievalDataSource defaults
 * to sealed mode (sealedHiddenEval !== false), wraps any host-provided
 * authorize so the evaluate endpoint short-circuits to 403 at the route
 * shim, and never lets a miner-authenticated request reach the host's
 * underlying evaluate callback.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  createRetrievalDataSource,
  handleCoreTexCoordinatorRoute,
} from '../../dist/index.js';

const BUNDLE_HASH = `0x${'ab'.repeat(32)}`;
const RETRIEVAL_KEY_LAYOUT = { dim: 243, quantization: 'int8', headerBytes: 9 };

function fixtureCorpus() {
  const events = [];
  return { events, byId: new Map(), corpusRoot: `0x${'11'.repeat(32)}`, corpusEpoch: 0,
    biEncoderRevision: '0123456789abcdef0123456789abcdef01234567',
    biEncoderModelId: 'BAAI/bge-m3',
    biEncoderRetrievalKeyLayout: RETRIEVAL_KEY_LAYOUT,
    labelingModelRevision: 'fedcba9876543210fedcba9876543210fedcba98',
    labelingModelId: 'memreranker/4B' };
}

function makeOpts(overrides = {}) {
  return {
    corpus: fixtureCorpus(),
    bundleManifest: { bundleHash: BUNDLE_HASH },
    bundleHash: BUNDLE_HASH,
    screen: () => ({ ok: 'screen' }),
    evaluate: () => ({ ok: 'evaluate-WOULD-HAVE-RAN' }),
    ...overrides,
  };
}

describe('sealed-eval guard (Phase S0)', () => {
  test('default ds is sealed: route shim returns 403 on POST /coretex/evaluate', async () => {
    const ds = createRetrievalDataSource(makeOpts());
    const r = await handleCoreTexCoordinatorRoute(
      { method: 'POST', path: '/coretex/evaluate', body: { miner: '0xabc' } },
      ds,
    );
    assert.deepEqual(r, {
      handled: true,
      status: 403,
      body: { error: 'coretex-hidden-eval-sealed', endpoint: 'evaluate' },
    });
  });

  test('default ds: evaluate host callback never invoked through the route shim', async () => {
    let invoked = false;
    const ds = createRetrievalDataSource(makeOpts({
      evaluate: () => { invoked = true; return { ok: 'should-not-see-this' }; },
    }));
    await handleCoreTexCoordinatorRoute(
      { method: 'POST', path: '/coretex/evaluate', body: { miner: '0xabc' } },
      ds,
    );
    assert.equal(invoked, false, 'evaluate must not run when sealed');
  });

  test('non-evaluate endpoints still pass through host authorize / handler', async () => {
    const seenAuth = [];
    const ds = createRetrievalDataSource(makeOpts({
      authorize: (ctx) => { seenAuth.push(ctx.endpoint); return true; },
      screen: (body) => ({ lane: 'screen', body }),
    }));
    const r = await handleCoreTexCoordinatorRoute(
      { method: 'POST', path: '/coretex/screen', body: { miner: '0xabc' } },
      ds,
    );
    assert.equal(r.handled, true);
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, { lane: 'screen', body: { miner: '0xabc' } });
    assert.deepEqual(seenAuth, ['screen'], 'host authorize ran for screen');
  });

  test('sealed mode does NOT consult host authorize for evaluate (short-circuits before host check)', async () => {
    let hostAuthCalledForEvaluate = false;
    const ds = createRetrievalDataSource(makeOpts({
      authorize: (ctx) => {
        if (ctx.endpoint === 'evaluate') hostAuthCalledForEvaluate = true;
        return true;
      },
    }));
    await handleCoreTexCoordinatorRoute(
      { method: 'POST', path: '/coretex/evaluate', body: {} },
      ds,
    );
    assert.equal(hostAuthCalledForEvaluate, false,
      'sealed guard must fire before host authorize touches the request');
  });

  test('sealedHiddenEval:false (explicit) restores legacy interactive evaluate', async () => {
    const ds = createRetrievalDataSource(makeOpts({
      sealedHiddenEval: false,
      authorize: () => true,
    }));
    const r = await handleCoreTexCoordinatorRoute(
      { method: 'POST', path: '/coretex/evaluate', body: { miner: '0xabc' } },
      ds,
    );
    assert.equal(r.handled, true);
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, { ok: 'evaluate-WOULD-HAVE-RAN' });
  });

  test('sealedHiddenEval:false still routes the host authorize for non-evaluate endpoints', async () => {
    let calls = 0;
    const ds = createRetrievalDataSource(makeOpts({
      sealedHiddenEval: false,
      authorize: () => { calls++; return true; },
    }));
    await handleCoreTexCoordinatorRoute(
      { method: 'POST', path: '/coretex/screen', body: {} },
      ds,
    );
    await handleCoreTexCoordinatorRoute(
      { method: 'POST', path: '/coretex/evaluate', body: {} },
      ds,
    );
    assert.equal(calls, 2, 'host authorize ran for both screen and evaluate when sealed=false');
  });

  test('omitting sealedHiddenEval is identical to sealedHiddenEval:true (sealed by default)', async () => {
    const dsDefault = createRetrievalDataSource(makeOpts());
    const dsExplicit = createRetrievalDataSource(makeOpts({ sealedHiddenEval: true }));
    const rDefault = await handleCoreTexCoordinatorRoute(
      { method: 'POST', path: '/coretex/evaluate', body: {} },
      dsDefault,
    );
    const rExplicit = await handleCoreTexCoordinatorRoute(
      { method: 'POST', path: '/coretex/evaluate', body: {} },
      dsExplicit,
    );
    assert.deepEqual(rDefault, rExplicit);
    assert.equal(rDefault.status, 403);
  });
});
