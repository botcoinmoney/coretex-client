/**
 * Reranker cache telemetry regression — getRerankerCacheStats must
 * return live hits/misses for the EXACT reranker object the caller
 * passes around.
 *
 * Earlier bug: createStreamingQwen3Reranker wrapped its score function
 * with withRerankerCache, then returned a NEW object
 * (`{ model, score, close }`) instead of the cached wrapper itself.
 * The cache itself worked but `getRerankerCacheStats` looked up by the
 * outer object and missed the WeakMap entry — telemetry always
 * returned undefined, producing `cache_hits=0 cache_misses=0` in
 * calibration artifacts even when the cache had served thousands of
 * pairs.
 *
 * This test pins the contract: passing the returned reranker to
 * `getRerankerCacheStats` must yield a non-null stats object whose
 * counters update after `.score()` calls.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  withRerankerCache,
  getRerankerCacheStats,
} from '../../dist/index.js';

describe('reranker cache telemetry', () => {
  test('getRerankerCacheStats returns live stats for the wrapped reranker', async () => {
    let underlyingCalls = 0;
    const inner = {
      model: 'test/inner',
      async score(pairs) {
        underlyingCalls++;
        return pairs.map(() => 0.5);
      },
    };
    const wrapped = withRerankerCache(inner, 1024);
    const stats0 = getRerankerCacheStats(wrapped);
    assert.ok(stats0, 'getRerankerCacheStats must resolve for a withRerankerCache wrap');
    assert.equal(stats0.hits, 0);
    assert.equal(stats0.misses, 0);

    // First call: all 3 pairs are misses.
    await wrapped.score([
      { query: 'q1', document: 'd1' },
      { query: 'q1', document: 'd2' },
      { query: 'q2', document: 'd1' },
    ]);
    assert.equal(stats0.hits, 0);
    assert.equal(stats0.misses, 3);
    assert.equal(underlyingCalls, 1);

    // Second call: same pairs → all 3 hits, no underlying call.
    await wrapped.score([
      { query: 'q1', document: 'd1' },
      { query: 'q1', document: 'd2' },
      { query: 'q2', document: 'd1' },
    ]);
    assert.equal(stats0.hits, 3);
    assert.equal(stats0.misses, 3);
    assert.equal(underlyingCalls, 1, 'no new underlying score() call when cache fully hits');

    // Mixed call: 2 cached + 1 new = 2 hits, 1 miss.
    await wrapped.score([
      { query: 'q1', document: 'd1' },
      { query: 'q2', document: 'd2' },
      { query: 'q2', document: 'd1' },
    ]);
    assert.equal(stats0.hits, 5);
    assert.equal(stats0.misses, 4);
  });

  test('wrappers that add fields via Object.assign preserve telemetry', async () => {
    // Streaming Qwen3 reranker has a close() method on top of the cached
    // wrapper. The wrapper is constructed via Object.assign so the
    // returned object is the SAME identity as what withRerankerCache
    // registered in cacheStatsByReranker. This test guards against a
    // regression where the streaming code returned a fresh object
    // wrapping the cached.score reference, silently disconnecting
    // telemetry from the operational reranker.
    const inner = { model: 'test/streaming', async score(pairs) { return pairs.map(() => 0.5); } };
    const cached = withRerankerCache(inner, 1024);
    const close = async () => {};
    const streaming = Object.assign(cached, { close });
    const stats = getRerankerCacheStats(streaming);
    assert.ok(stats, 'streaming reranker (Object.assign onto cached) must keep live stats');
    await streaming.score([{ query: 'q', document: 'd' }]);
    assert.equal(stats.misses, 1);
    await streaming.score([{ query: 'q', document: 'd' }]);
    assert.equal(stats.hits, 1);
  });
});
