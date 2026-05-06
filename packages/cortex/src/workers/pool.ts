/**
 * Phase 3 — Worker-pool wrapper around the evaluator.
 *
 * Pool size: 1 worker on small hosts; otherwise os.cpus().length - 2,
 * clamped to [1, 8]. Operators may override with an explicit size.
 * Eval is NEVER run on the main (HTTP request) thread.
 *
 * Architecture:
 *   - A fixed pool of Worker threads is spawned at pool creation.
 *   - Requests are enqueued; free workers pick them up.
 *   - The worker script is workerScript.mjs (compiled separately, or inlined).
 *   - Message protocol: EvalWorkerRequest / EvalWorkerMessage.
 */

import { Worker } from 'node:worker_threads';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';

// ─── Pool size ────────────────────────────────────────────────────────────────

export function defaultPoolSize(): number {
  const cpus = os.cpus().length;
  if (cpus <= 4) return 1;
  return Math.max(1, Math.min(8, cpus - 2));
}

// ─── Message types ────────────────────────────────────────────────────────────

export interface EvalWorkerRequest {
  readonly id: number;
  /** Packed CortexState (32768 bytes). */
  readonly stateBytes: Uint8Array;
  /** Encoded patch wire bytes. */
  readonly patchWireBytes: Uint8Array;
  /** Shard ID (32 bytes). */
  readonly shardId: Uint8Array;
  /** Corpus root (0x-prefixed hex). */
  readonly corpusRoot: string;
}

export interface EvalWorkerResponse {
  readonly id: number;
  readonly ok: true;
  /** Serialized EvalReport JSON. */
  readonly reportJson: string;
}

export interface EvalWorkerError {
  readonly id: number;
  readonly ok: false;
  readonly error: string;
}

export type EvalWorkerMessage = EvalWorkerResponse | EvalWorkerError;

// ─── Worker Pool ──────────────────────────────────────────────────────────────

type PendingEntry = {
  resolve: (value: string) => void;
  reject: (reason: Error) => void;
};

export class WorkerPool {
  private readonly workers: Worker[] = [];
  private readonly idle: Worker[] = [];
  private readonly queue: Array<{ req: EvalWorkerRequest; entry: PendingEntry }> = [];
  private readonly pending = new Map<Worker, Map<number, PendingEntry>>();
  private nextId = 0;
  private closed = false;

  constructor(workerScriptPath: string, size: number = defaultPoolSize()) {
    for (let i = 0; i < size; i++) {
      this._spawnWorker(workerScriptPath);
    }
    this._workerScriptPath = workerScriptPath;
  }

  private readonly _workerScriptPath: string;

  private _spawnWorker(scriptPath: string): Worker {
    const worker = new Worker(scriptPath);
    this.pending.set(worker, new Map());
    worker.on('message', (msg: EvalWorkerMessage) => this._onMessage(worker, msg));
    worker.on('error', (err: Error) => this._onWorkerError(worker, err));
    this.workers.push(worker);
    this.idle.push(worker);
    return worker;
  }

  /**
   * Submit an eval request to the worker pool.
   * Returns a promise resolving to reportJson string.
   */
  eval(req: Omit<EvalWorkerRequest, 'id'>): Promise<string> {
    if (this.closed) {
      return Promise.reject(new Error('WorkerPool: pool is closed'));
    }
    return new Promise<string>((resolve, reject) => {
      const id = this.nextId++;
      const fullReq: EvalWorkerRequest = { ...req, id };
      const entry: PendingEntry = { resolve, reject };
      const worker = this.idle.pop();
      if (worker !== undefined) {
        this._dispatch(worker, fullReq, entry);
      } else {
        this.queue.push({ req: fullReq, entry });
      }
    });
  }

  private _dispatch(worker: Worker, req: EvalWorkerRequest, entry: PendingEntry): void {
    const pendingMap = this.pending.get(worker);
    if (!pendingMap) return;
    pendingMap.set(req.id, entry);
    worker.postMessage(req);
  }

  private _onMessage(worker: Worker, msg: EvalWorkerMessage): void {
    const pendingMap = this.pending.get(worker);
    if (!pendingMap) return;
    const entry = pendingMap.get(msg.id);
    if (!entry) return;
    pendingMap.delete(msg.id);

    if (msg.ok) {
      entry.resolve(msg.reportJson);
    } else {
      entry.reject(new Error(msg.error));
    }

    // Drain queue or return worker to idle
    const next = this.queue.shift();
    if (next !== undefined) {
      this._dispatch(worker, next.req, next.entry);
    } else {
      this.idle.push(worker);
    }
  }

  private _onWorkerError(worker: Worker, err: Error): void {
    const pendingMap = this.pending.get(worker);
    if (pendingMap) {
      for (const entry of pendingMap.values()) {
        entry.reject(err);
      }
      pendingMap.clear();
    }

    // Remove from pool and respawn
    const idx = this.workers.indexOf(worker);
    if (idx >= 0) {
      this.workers.splice(idx, 1);
      this.pending.delete(worker);
      const idleIdx = this.idle.indexOf(worker);
      if (idleIdx >= 0) this.idle.splice(idleIdx, 1);
      // Respawn
      this._spawnWorker(this._workerScriptPath);
    }
  }

  /** Terminate all workers. */
  async close(): Promise<void> {
    this.closed = true;
    await Promise.all(this.workers.map((w) => w.terminate()));
  }

  get size(): number {
    return this.workers.length;
  }
}

/**
 * Resolve the default worker script path (dist/workers/worker.js).
 * Call from main thread only.
 */
export function defaultWorkerScriptPath(): string {
  return fileURLToPath(new URL('./worker.js', import.meta.url));
}
