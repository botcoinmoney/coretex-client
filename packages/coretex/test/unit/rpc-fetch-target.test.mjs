/**
 * rpcFetchTarget — credentialed JSON-RPC URL normalization.
 *
 * Node's fetch (undici) hard-rejects URLs with embedded basic-auth userinfo
 * ("Request cannot be constructed from a URL that includes credentials").
 * Observed live on Base mainnet (2026-06-09 e2e): every production per-patch
 * eval failed with EvalFailure because the production evaluator's rpcCall
 * passed the credentialed BASE_RPC_URL straight to fetch. rpcFetchTarget is
 * the single shared normalizer: userinfo must be stripped from the URL and
 * carried as an Authorization: Basic header instead.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { rpcFetchTarget } from '../../dist/replay/v4.js';

describe('rpcFetchTarget', () => {
  test('plain URL passes through with JSON content-type and no auth header', () => {
    const { url, headers } = rpcFetchTarget('https://mainnet.base.org/');
    assert.equal(url, 'https://mainnet.base.org/');
    assert.equal(headers['content-type'], 'application/json');
    assert.equal(headers.authorization, undefined);
  });

  test('embedded userinfo moves to Authorization: Basic and leaves the URL credential-free', () => {
    const { url, headers } = rpcFetchTarget('https://user:p%2Fss%2Bword@rpc.example.com/v3/key');
    assert.equal(url, 'https://rpc.example.com/v3/key');
    assert.match(headers.authorization, /^Basic /);
    const decoded = Buffer.from(headers.authorization.slice('Basic '.length), 'base64').toString('utf8');
    assert.equal(decoded, 'user:p/ss+word'); // percent-decoded before encoding
    // the normalized URL must be constructible by undici's Request
    assert.doesNotThrow(() => new Request(url));
  });

  test('password-only userinfo (https://:secret@host) is also normalized', () => {
    const { url, headers } = rpcFetchTarget('https://:secret@rpc.example.com/');
    assert.equal(url, 'https://rpc.example.com/');
    const decoded = Buffer.from(headers.authorization.slice('Basic '.length), 'base64').toString('utf8');
    assert.equal(decoded, ':secret');
  });
});
