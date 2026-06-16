import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { makeInstrumentedReranker } from '../../scripts/lib/instrumented-reranker.mjs';

describe('instrumented reranker batching', () => {
  test('backend chunking preserves score order and cache semantics', async () => {
    const calls = [];
    const inner = {
      model: 'test/reranker',
      async score(pairs) {
        calls.push(pairs.map((p) => p.document));
        return pairs.map((p) => Number(p.document.replace('d', '')));
      },
    };
    const reranker = makeInstrumentedReranker({
      reranker: inner,
      modelId: 'test/reranker',
      revision: 'rev',
      profileHash: '0xprofile',
      substrateMode: 'test',
      memoryIRVersion: 'raw',
      mode: 'unit',
      batchSize: 2,
    });

    const pairs = [1, 2, 3, 4, 5].map((i) => ({ query: `q${i}`, document: `d${i}` }));
    assert.deepEqual(await reranker.score(pairs), [1, 2, 3, 4, 5]);
    assert.deepEqual(calls, [['d1', 'd2'], ['d3', 'd4'], ['d5']]);

    assert.deepEqual(await reranker.score(pairs), [1, 2, 3, 4, 5]);
    assert.equal(calls.length, 3, 'second identical request should be fully cached');

    const telemetry = reranker.telemetrySnapshot();
    assert.equal(telemetry.backendCalls, 3);
    assert.equal(telemetry.backendPairs, 5);
    assert.equal(telemetry.cacheHits, 5);
  });
});
