/**
 * Unit tests: worker pool wrapper.
 * These tests verify WorkerPool plumbing with a mock worker script.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { Worker } from 'node:worker_threads';
import { WorkerPool, defaultPoolSize } from '../../dist/workers/pool.js';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
import * as path from 'node:path';

// ─── defaultPoolSize ──────────────────────────────────────────────────────────

describe('defaultPoolSize', () => {
  test('clamps to [1, 8]', () => {
    const size = defaultPoolSize();
    assert.ok(size >= 1 && size <= 8, `Expected 1-8, got ${size}`);
  });

  test('matches the small-host reserve policy', () => {
    const cpus = os.cpus().length;
    const expected = cpus <= 4 ? 1 : Math.max(1, Math.min(8, cpus - 2));
    assert.equal(defaultPoolSize(), expected);
  });
});

// ─── WorkerPool construction ──────────────────────────────────────────────────
// We can only test this if the compiled worker.js exists.
// Skip gracefully if not available.

describe('WorkerPool — plumbing', () => {
  const workerPath = fileURLToPath(new URL('../../dist/workers/worker.js', import.meta.url));

  test('WorkerPool reports correct size', async () => {
    let pool;
    try {
      pool = new WorkerPool(workerPath, 2);
      assert.equal(pool.size, 2);
    } catch (err) {
      // If dist not available, skip
      if (String(err).includes('Cannot find') || String(err).includes('MODULE_NOT_FOUND')) {
        return; // skip
      }
      throw err;
    } finally {
      if (pool) await pool.close();
    }
  });

  test('WorkerPool rejects after close', async () => {
    let pool;
    try {
      pool = new WorkerPool(workerPath, 1);
      await pool.close();
      await assert.rejects(
        () => pool.eval({
          stateBytes: new Uint8Array(32768),
          patchWireBytes: new Uint8Array(0),
          shardId: new Uint8Array(32),
          corpusRoot: '0x' + '00'.repeat(32),
        }),
        /closed/,
      );
    } catch (err) {
      if (String(err).includes('Cannot find') || String(err).includes('MODULE_NOT_FOUND')) {
        return; // skip — dist not compiled
      }
      throw err;
    }
  });

  test('WorkerPool enforces bounded queue backpressure', async () => {
    const pool = new WorkerPool('/tmp/nonexistent-worker.js', 0, { maxQueueSize: 1 });
    try {
      const req = {
        stateBytes: new Uint8Array(32768),
        patchWireBytes: new Uint8Array(0),
        shardId: new Uint8Array(32),
        corpusRoot: '0x' + '00'.repeat(32),
      };
      // First request is queued because the pool has no idle workers.
      pool.eval(req).catch(() => {});
      assert.equal(pool.queueDepth, 1);
      assert.equal(pool.inFlight, 0);

      // Second request is rejected immediately instead of growing an
      // unbounded coordinator eval queue.
      await assert.rejects(
        () => pool.eval(req),
        /queue is saturated/,
      );
      assert.equal(pool.queueDepth, 1);
    } finally {
      await pool.close();
    }
  });

  test('WorkerPool validates maxQueueSize option', () => {
    assert.throws(
      () => new WorkerPool('/tmp/nonexistent-worker.js', 0, { maxQueueSize: -1 }),
      /maxQueueSize/,
    );
    assert.throws(
      () => new WorkerPool('/tmp/nonexistent-worker.js', 0, { maxQueueSize: 1.5 }),
      /maxQueueSize/,
    );
  });
});
