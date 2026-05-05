/**
 * Phase 3 — Worker thread script for the evaluator pool.
 *
 * This module is loaded by worker_threads.Worker.
 * It receives EvalWorkerRequest messages, runs evalPatch, and posts back
 * EvalWorkerResponse or EvalWorkerError.
 *
 * Cache: decoded state is cached per parentStateRoot (hex) to avoid
 * redundant keccak256/merkleize on repeated parent within a worker.
 */

import { isMainThread, parentPort } from 'node:worker_threads';
import { unpack } from '../state/codec.js';
import { decodePatch } from '../state/patch.js';
import { evalPatch, StubCorpusLoader } from '../eval/index.js';
import type { EvalWorkerRequest, EvalWorkerMessage } from './pool.js';

if (isMainThread) {
  throw new Error('worker.ts must run inside a Worker thread, not on the main thread.');
}

if (!parentPort) {
  throw new Error('worker.ts: parentPort is null');
}

// ─── Per-worker state root cache ──────────────────────────────────────────────
// Avoids re-decoding the same state repeatedly within a worker.
// Capacity: 16 entries (LRU eviction — simple, no external dep).

const CACHE_CAPACITY = 16;
const decodeCache = new Map<string, ReturnType<typeof unpack>>();

function cacheGet(key: string): ReturnType<typeof unpack> | undefined {
  const val = decodeCache.get(key);
  if (val !== undefined) {
    // LRU: refresh by delete+set
    decodeCache.delete(key);
    decodeCache.set(key, val);
  }
  return val;
}

function cacheSet(key: string, val: ReturnType<typeof unpack>): void {
  if (decodeCache.size >= CACHE_CAPACITY) {
    // Evict oldest
    const oldest = decodeCache.keys().next().value;
    if (oldest !== undefined) decodeCache.delete(oldest);
  }
  decodeCache.set(key, val);
}

// ─── Message handler ──────────────────────────────────────────────────────────

parentPort.on('message', (req: EvalWorkerRequest) => {
  try {
    // Use cached state if available (keyed by first 8 bytes of stateBytes as hex)
    // We use patchWireBytes parent root for cache key (first 32 bytes after offset 10)
    // Actually simpler: key = hex of stateBytes slice 0:8 (enough to distinguish)
    const cacheKey = bufToHex(req.stateBytes.subarray(0, 8));
    let state = cacheGet(cacheKey);
    if (!state) {
      state = unpack(req.stateBytes);
      cacheSet(cacheKey, state);
    }

    const patch = decodePatch(req.patchWireBytes);
    const loader = new StubCorpusLoader(req.corpusRoot);

    const report = evalPatch(state, patch, {
      loader,
      shardId: req.shardId,
      patchWireBytes: req.patchWireBytes,
    });

    // Serialize bigints as strings with "n" suffix for round-trip
    const reportJson = JSON.stringify(report, (_k, v: unknown) =>
      typeof v === 'bigint' ? v.toString() + 'n' : v
    );

    const response: EvalWorkerMessage = { id: req.id, ok: true, reportJson };
    parentPort!.postMessage(response);
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : String(err);
    const response: EvalWorkerMessage = { id: req.id, ok: false, error: errMsg };
    parentPort!.postMessage(response);
  }
});

function bufToHex(buf: Uint8Array): string {
  let h = '';
  for (const b of buf) {
    h += b.toString(16).padStart(2, '0');
  }
  return h;
}
