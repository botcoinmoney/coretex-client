/**
 * Phase 3 — Worker thread script for the evaluator pool.
 *
 * This module is loaded by worker_threads.Worker.
 * It receives EvalWorkerRequest messages, runs evalPatch, and posts back
 * EvalWorkerResponse or EvalWorkerError.
 *
 * Cache: decoded state + Merkle tree are cached per parentStateRoot (hex) to
 * avoid redundant unpack/keccak work on repeated parent within a worker.
 */

import { isMainThread, parentPort } from 'node:worker_threads';
import { unpack } from '../state/codec.js';
import { decodePatch } from '../state/patch.js';
import { buildMerkleCache, bytesToHex } from '../state/merkle.js';
import { evalPatch, StubCorpusLoader } from '../eval/index.js';
import type { EvalWorkerRequest, EvalWorkerMessage } from './pool.js';

if (isMainThread) {
  throw new Error('worker.ts must run inside a Worker thread, not on the main thread.');
}

if (!parentPort) {
  throw new Error('worker.ts: parentPort is null');
}

// ─── Per-worker state root cache ──────────────────────────────────────────────
// Avoids re-decoding and re-merkleizing the same state repeatedly within a worker.
// Capacity: 16 entries (LRU eviction — simple, no external dep).

const CACHE_CAPACITY = 16;
type CachedParent = {
  readonly state: ReturnType<typeof unpack>;
  readonly merkleCache: ReturnType<typeof buildMerkleCache>;
};
const parentCache = new Map<string, CachedParent>();

function cacheGet(key: string): CachedParent | undefined {
  const val = parentCache.get(key);
  if (val !== undefined) {
    // LRU: refresh by delete+set
    parentCache.delete(key);
    parentCache.set(key, val);
  }
  return val;
}

function cacheSet(key: string, val: CachedParent): void {
  if (parentCache.size >= CACHE_CAPACITY) {
    // Evict oldest
    const oldest = parentCache.keys().next().value;
    if (oldest !== undefined) parentCache.delete(oldest);
  }
  parentCache.set(key, val);
}

// ─── Message handler ──────────────────────────────────────────────────────────

parentPort.on('message', (req: EvalWorkerRequest) => {
  try {
    const patch = decodePatch(req.patchWireBytes);
    const cacheKey = bytesToHex(patch.parentStateRoot).toLowerCase();
    let cached = cacheGet(cacheKey);
    if (!cached) {
      const state = unpack(req.stateBytes);
      const merkleCache = buildMerkleCache(state);
      if (bytesToHex(merkleCache.root).toLowerCase() === cacheKey) {
        cached = { state, merkleCache };
        cacheSet(cacheKey, cached);
      } else {
        // Do not cache mismatched inputs; evalPatch will return E01.
        cached = { state, merkleCache };
      }
    }

    const loader = new StubCorpusLoader(req.corpusRoot);

    const report = evalPatch(cached.state, patch, {
      loader,
      shardId: req.shardId,
      patchWireBytes: req.patchWireBytes,
      merkleCache: cached.merkleCache,
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
