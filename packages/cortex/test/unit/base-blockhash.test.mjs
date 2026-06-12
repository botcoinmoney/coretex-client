/**
 * Base JSON-RPC client tests with an injected fetch mock. The mock
 * server returns deterministic blockhashes for a controlled block
 * schedule, exercising all three methods:
 *
 *   - getLatestBlockNumber → eth_blockNumber
 *   - getBlockHash         → eth_getBlockByNumber
 *   - waitForBlock         → polling loop until head reaches target
 *
 * No network I/O. The mock fetch shows up as `opts.fetchImpl` to the
 * client constructor.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { createBaseRpcClient } from '../../dist/index.js';

function makeMockFetch(handler) {
  return async (url, init) => {
    const body = JSON.parse(init.body);
    const result = await handler(body);
    return {
      ok: true,
      status: 200,
      async json() { return { jsonrpc: '2.0', id: body.id, result }; },
    };
  };
}

function makeErrorFetch(error) {
  return async (url, init) => {
    const body = JSON.parse(init.body);
    return {
      ok: true,
      status: 200,
      async json() { return { jsonrpc: '2.0', id: body.id, error }; },
    };
  };
}

describe('createBaseRpcClient', () => {
  test('rejects empty rpcUrl at construction', () => {
    assert.throws(() => createBaseRpcClient(''), /rpcUrl is required/);
    assert.throws(() => createBaseRpcClient(null), /rpcUrl is required/);
  });

  test('getLatestBlockNumber decodes hex result', async () => {
    const mockFetch = makeMockFetch(async (body) => {
      assert.equal(body.method, 'eth_blockNumber');
      assert.deepEqual(body.params, []);
      return '0x1234'; // 4660
    });
    const client = createBaseRpcClient('http://test', { fetchImpl: mockFetch });
    assert.equal(await client.getLatestBlockNumber(), 4660);
  });

  test('credentialed RPC URLs are normalized before fetch', async () => {
    const mockFetch = async (url, init) => {
      assert.equal(url, 'https://rpc.example.com/v3/key');
      assert.doesNotThrow(() => new Request(url));
      assert.match(init.headers.authorization, /^Basic /);
      assert.equal(
        Buffer.from(init.headers.authorization.slice('Basic '.length), 'base64').toString('utf8'),
        'user:p/ss+word',
      );
      const body = JSON.parse(init.body);
      return {
        ok: true,
        status: 200,
        async json() { return { jsonrpc: '2.0', id: body.id, result: '0x1234' }; },
      };
    };
    const client = createBaseRpcClient('https://user:p%2Fss%2Bword@rpc.example.com/v3/key', { fetchImpl: mockFetch });
    assert.equal(await client.getLatestBlockNumber(), 4660);
  });

  test('getBlockHash returns lowercased hash', async () => {
    const mockFetch = makeMockFetch(async (body) => {
      assert.equal(body.method, 'eth_getBlockByNumber');
      assert.deepEqual(body.params, ['0x64', false]); // 100
      return { hash: '0xABCDEF' + 'aa'.repeat(29), timestamp: '0x10' };
    });
    const client = createBaseRpcClient('http://test', { fetchImpl: mockFetch });
    const h = await client.getBlockHash(100);
    assert.equal(h, '0xabcdef' + 'aa'.repeat(29));
  });

  test('getBlockHash rejects invalid block number', async () => {
    const client = createBaseRpcClient('http://test', { fetchImpl: makeMockFetch(async () => null) });
    await assert.rejects(() => client.getBlockHash(-1), /invalid block number/);
    await assert.rejects(() => client.getBlockHash(1.5), /invalid block number/);
  });

  test('getBlockHash throws when RPC returns null block', async () => {
    const mockFetch = makeMockFetch(async () => null);
    const client = createBaseRpcClient('http://test', { fetchImpl: mockFetch });
    await assert.rejects(() => client.getBlockHash(100), /block 100 not found/);
  });

  test('waitForBlock returns when chain head reaches target', async () => {
    let blockNumber = 90;
    const mockFetch = makeMockFetch(async (body) => {
      if (body.method === 'eth_blockNumber') {
        // Advance the chain by 5 blocks per poll.
        blockNumber += 5;
        return `0x${blockNumber.toString(16)}`;
      }
      // eth_getBlockByNumber for the target
      return { hash: `0x${'11'.repeat(32)}`, timestamp: `0x${(1700000000).toString(16)}` };
    });
    const client = createBaseRpcClient('http://test', {
      fetchImpl: mockFetch,
      pollIntervalMs: 1, // fast polling for tests
    });
    const block = await client.waitForBlock(100, 5000);
    assert.equal(block.number, 100);
    assert.equal(block.blockhash, `0x${'11'.repeat(32)}`);
    assert.equal(block.timestamp, 1700000000);
  });

  test('waitForBlock returns immediately if head already past target', async () => {
    const mockFetch = makeMockFetch(async (body) => {
      if (body.method === 'eth_blockNumber') return '0xff'; // 255
      return { hash: `0x${'22'.repeat(32)}`, timestamp: '0x100' };
    });
    const client = createBaseRpcClient('http://test', { fetchImpl: mockFetch, pollIntervalMs: 1 });
    const start = Date.now();
    const block = await client.waitForBlock(100, 5000);
    assert.equal(block.number, 100);
    assert.ok(Date.now() - start < 100, 'should not poll if head already past target');
  });

  test('waitForBlock times out if head never reaches target', async () => {
    const mockFetch = makeMockFetch(async () => '0x0a'); // stuck at 10
    const client = createBaseRpcClient('http://test', { fetchImpl: mockFetch, pollIntervalMs: 1 });
    await assert.rejects(() => client.waitForBlock(100, 50), /timed out/);
  });

  test('rpc errors surface as JS errors', async () => {
    const errFetch = makeErrorFetch({ code: -32000, message: 'execution reverted' });
    const client = createBaseRpcClient('http://test', { fetchImpl: errFetch });
    await assert.rejects(() => client.getLatestBlockNumber(), /-32000 execution reverted/);
  });

  test('HTTP non-200 surfaces as JS error', async () => {
    const httpErrFetch = async () => ({ ok: false, status: 503, async json() { return {}; } });
    const client = createBaseRpcClient('http://test', { fetchImpl: httpErrFetch });
    await assert.rejects(() => client.getLatestBlockNumber(), /HTTP 503/);
  });

  test('coordinator + replay watcher use the SAME client → same blockhash for same block', async () => {
    // Critical invariant for verifiability: any two callers querying
    // the same block number against the same RPC must receive the
    // identical blockhash. The client itself just relays — the RPC is
    // the source of truth.
    const fixedHash = `0x${'77'.repeat(32)}`;
    const mockFetch = makeMockFetch(async (body) => {
      if (body.method === 'eth_blockNumber') return '0x100';
      return { hash: fixedHash, timestamp: '0x10' };
    });
    const coord  = createBaseRpcClient('http://test', { fetchImpl: mockFetch });
    const replay = createBaseRpcClient('http://test', { fetchImpl: mockFetch });
    const a = await coord.getBlockHash(100);
    const b = await replay.getBlockHash(100);
    assert.equal(a, b);
    assert.equal(a, fixedHash);
  });
});
