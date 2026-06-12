/**
 * Thin Base JSON-RPC client. Used by both the coordinator and replay
 * watchers — same code path on both sides so the blockhash a receipt
 * was signed against is the same blockhash the watcher fetches at
 * verify time.
 *
 * Only three methods are exposed because that is all the per-patch
 * randomness flow needs: latest block number (for receivedAtBlock),
 * blockhash by number (for replay), and a polling wait that returns
 * when the target block is finalized.
 *
 * The client is intentionally minimal — no batching, no websocket, no
 * retry strategy beyond the polling loop in `waitForBlock`. The
 * coordinator wraps this with its HTTP timeout / circuit-breaker
 * policy.
 *
 * No I/O at import time. Construct via `createBaseRpcClient(rpcUrl)`.
 */

import { rpcFetchTarget } from '../replay/v4.js';

export interface BaseBlockResponse {
  /** Block number as a plain JS number (safe up to ~2^53, Base block
   * heights stay well under that for decades). */
  readonly number: number;
  /** Block hash. bytes32 hex, 0x-prefixed lowercase. */
  readonly blockhash: string;
  /** Unix seconds timestamp from the block header. */
  readonly timestamp: number;
}

export interface BaseRpcClient {
  /** Returns the chain head's block number. */
  getLatestBlockNumber(): Promise<number>;
  /** Returns the blockhash of `blockNumber`. Throws if the block does
   * not exist yet OR if the RPC's history depth doesn't reach back to
   * it (the watcher should configure an archive-capable RPC). */
  getBlockHash(blockNumber: number): Promise<string>;
  /** Polls until `blockNumber` is at or below the chain head, then
   * fetches and returns its hash + timestamp. Throws on timeout.
   *
   * Polling interval is 1 second (Base block time is 2s, so 1 s gives
   * sub-block precision without spamming the RPC). */
  waitForBlock(blockNumber: number, timeoutMs: number): Promise<BaseBlockResponse>;
}

export interface CreateBaseRpcClientOptions {
  /** Per-request HTTP timeout. Defaults to 10 s. */
  readonly requestTimeoutMs?: number;
  /** Polling interval for `waitForBlock`. Defaults to 1000 ms. */
  readonly pollIntervalMs?: number;
  /** fetch implementation override (test injection). Defaults to
   * the global fetch. */
  readonly fetchImpl?: typeof fetch;
}

/** Construct a Base JSON-RPC client bound to `rpcUrl`. The URL is
 * captured at construction; callers wanting to rotate the RPC create
 * a new client. */
export function createBaseRpcClient(
  rpcUrl: string,
  opts: CreateBaseRpcClientOptions = {},
): BaseRpcClient {
  if (typeof rpcUrl !== 'string' || rpcUrl.length === 0) {
    throw new Error('createBaseRpcClient: rpcUrl is required');
  }
  const requestTimeoutMs = opts.requestTimeoutMs ?? 10_000;
  const pollIntervalMs = opts.pollIntervalMs ?? 1000;
  const doFetch = opts.fetchImpl ?? fetch;

  async function rpc<T>(method: string, params: readonly unknown[]): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), requestTimeoutMs);
    try {
      const { url, headers } = rpcFetchTarget(rpcUrl);
      const res = await doFetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`base-rpc: ${method} HTTP ${res.status}`);
      const json = await res.json() as { result?: T; error?: { code: number; message: string } };
      if (json.error) throw new Error(`base-rpc: ${method} ${json.error.code} ${json.error.message}`);
      if (json.result === undefined) throw new Error(`base-rpc: ${method} returned no result`);
      return json.result;
    } finally {
      clearTimeout(timer);
    }
  }

  function parseHexNumber(hex: string): number {
    if (typeof hex !== 'string' || !hex.startsWith('0x')) {
      throw new Error(`base-rpc: expected hex string, got ${typeof hex}`);
    }
    return parseInt(hex.slice(2), 16);
  }

  return {
    async getLatestBlockNumber(): Promise<number> {
      const hex = await rpc<string>('eth_blockNumber', []);
      return parseHexNumber(hex);
    },
    async getBlockHash(blockNumber: number): Promise<string> {
      if (!Number.isInteger(blockNumber) || blockNumber < 0) {
        throw new Error(`getBlockHash: invalid block number ${blockNumber}`);
      }
      const block = await rpc<{ hash?: string } | null>(
        'eth_getBlockByNumber',
        [`0x${blockNumber.toString(16)}`, false],
      );
      if (!block || typeof block.hash !== 'string') {
        throw new Error(`getBlockHash: block ${blockNumber} not found`);
      }
      return block.hash.toLowerCase();
    },
    async waitForBlock(blockNumber: number, timeoutMs: number): Promise<BaseBlockResponse> {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        const head = await this.getLatestBlockNumber();
        if (head >= blockNumber) {
          const block = await rpc<{ hash?: string; timestamp?: string } | null>(
            'eth_getBlockByNumber',
            [`0x${blockNumber.toString(16)}`, false],
          );
          if (!block || typeof block.hash !== 'string' || typeof block.timestamp !== 'string') {
            throw new Error(`waitForBlock: block ${blockNumber} not found after head reached it`);
          }
          return {
            number: blockNumber,
            blockhash: block.hash.toLowerCase(),
            timestamp: parseHexNumber(block.timestamp),
          };
        }
        await new Promise((res) => setTimeout(res, pollIntervalMs));
      }
      throw new Error(`waitForBlock: timed out after ${timeoutMs}ms waiting for block ${blockNumber}`);
    },
  };
}
