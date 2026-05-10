/**
 * Cross-encoder reranker implementations for CoreTex v4 reward-law evaluation.
 *
 * Supported backends:
 *   - Qwen3-Reranker-0.6B  (generative model, logit-difference scoring)
 *   - Xenova/ms-marco-MiniLM-L-6-v2  (text-classification cross-encoder)
 *   - Deterministic hashing stub (no model load — for offline/CI tests)
 *
 * §8 plan: production uses Qwen3-Reranker-0.6B; coordinator runs this
 * cross-encoder on elevated candidates to verify state-advance patches.
 */

import { createHash } from 'node:crypto';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createInterface } from 'node:readline';
import { QWEN3_RERANKER_DEFAULT_REVISION } from '../bundle/index.js';

// ─── Public interface ─────────────────────────────────────────────────────────

export interface CrossEncoderReranker {
  /** HuggingFace model id or a descriptive identifier for the deterministic stub. */
  readonly model: string;
  /**
   * Score a batch of (query, document) pairs.
   *
   * Returns one relevance score per pair in [0, 1].
   * Higher is more relevant.
   */
  score(pairs: ReadonlyArray<{ query: string; document: string }>): Promise<number[]>;
}

const GPU_ENV_VARS = ['CORETEX_USE_GPU', 'PYTORCH_USE_MPS'] as const;

function refuseGpuForReranker(): void {
  for (const envVar of GPU_ENV_VARS) {
    const v = process.env[envVar];
    if (v && v !== '0') throw new Error(`reranker refuses to run with ${envVar}=${v} set (CPU-only contract)`);
  }
  if (process.env['CUDA_VISIBLE_DEVICES'] && process.env['CUDA_VISIBLE_DEVICES'] !== '') {
    throw new Error('reranker refuses to run with CUDA_VISIBLE_DEVICES set (CPU-only contract)');
  }
}

// ─── Qwen3-Reranker-0.6B (generative logit-difference path) ──────────────────

export interface Qwen3RerankerOptions {
  /** HuggingFace model id. Default: 'Qwen/Qwen3-Reranker-0.6B'. */
  model?: string | undefined;
  /** Pinned revision tag or commit hash. */
  revision?: string | undefined;
  /** Local cache directory for model weights. */
  cacheDir?: string | undefined;
  /** Python executable for the production Hugging Face runner. Default: python3. */
  pythonBin?: string | undefined;
  /**
   * When true, disable remote model fetching — require the model to be
   * pre-cached locally.  Useful in air-gapped / CI environments where the
   * weights are pre-installed.
   */
  localOnly?: boolean | undefined;
  /**
   * Number of (query, document) pairs to process per forward pass.
   * Default: 4 (0.6B is heavier than an embedder; keep batches small).
   */
  batchSize?: number | undefined;
}

/**
 * Build a Qwen3-Reranker cross-encoder that uses the generative
 * chat-template + logit-difference scoring path described in §8.
 *
 * Inference path for one pair:
 *   1. Format as:
 *        <|im_start|>system\nYou are a relevance judge.\n<|im_end|>\n
 *        <|im_start|>user\nQuery: {query}\nDocument: {doc}\n
 *        Is the document relevant? Answer yes or no.<|im_end|>\n
 *        <|im_start|>assistant\n
 *   2. Tokenise and run a single forward pass (no generation).
 *   3. Grab logits at the last position.
 *   4. relevance_score = sigmoid(logit[yes_token_id] - logit[no_token_id])
 */
export async function createQwen3Reranker(
  opts?: Qwen3RerankerOptions,
): Promise<CrossEncoderReranker> {
  refuseGpuForReranker();
  const modelId = opts?.model ?? 'Qwen/Qwen3-Reranker-0.6B';
  const revision = opts?.revision ?? QWEN3_RERANKER_DEFAULT_REVISION;
  const batchSize = opts?.batchSize ?? 4;
  const pythonBin = opts?.pythonBin ?? process.env['CORETEX_RERANKER_PYTHON'] ?? 'python3';
  const cacheDir = opts?.cacheDir;
  const localOnly = opts?.localOnly === true;

  return withRerankerCache({
    model: `${modelId}@${revision}`,
    async score(pairs) {
      const scores: number[] = [];
      for (let i = 0; i < pairs.length; i += batchSize) {
        const batch = pairs.slice(i, i + batchSize);
        const batchScores = await scoreBatchQwen3Python(batch, {
          modelId,
          revision,
          pythonBin,
          cacheDir,
          localOnly,
        });
        scores.push(...batchScores);
      }
      return scores;
    },
  });
}

function buildQwen3Prompt(query: string, doc: string): string {
  return (
    '<|im_start|>system\nYou are a relevance judge.\n<|im_end|>\n' +
    '<|im_start|>user\n' +
    `Query: ${query}\nDocument: ${doc}\n` +
    'Is the document relevant? Answer yes or no.' +
    '<|im_end|>\n' +
    '<|im_start|>assistant\n'
  );
}

interface Qwen3PythonOptions {
  readonly modelId: string;
  readonly revision: string;
  readonly pythonBin: string;
  readonly cacheDir?: string | undefined;
  readonly localOnly: boolean;
}

async function scoreBatchQwen3Python(
  batch: ReadonlyArray<{ query: string; document: string }>,
  opts: Qwen3PythonOptions,
): Promise<number[]> {
  if (batch.length === 0) return [];
  const env = { ...process.env };
  if (opts.cacheDir) env['HF_HOME'] = opts.cacheDir;
  if (opts.localOnly) env['HF_HUB_OFFLINE'] = '1';
  const input = JSON.stringify({
    model: opts.modelId,
    revision: opts.revision,
    pairs: batch.map((pair) => ({
      query: pair.query,
      document: pair.document,
      prompt: buildQwen3Prompt(pair.query, pair.document),
    })),
  });
  const script = String.raw`
import json, math, sys
try:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
except Exception as exc:
    raise SystemExit("missing Python dependencies for Qwen3 reranker: install torch and transformers; " + str(exc))

payload = json.load(sys.stdin)
model_id = payload["model"]
revision = payload["revision"]
tokenizer = AutoTokenizer.from_pretrained(model_id, revision=revision, trust_remote_code=True)
model = AutoModelForCausalLM.from_pretrained(
    model_id,
    revision=revision,
    trust_remote_code=True,
    torch_dtype=torch.float32,
)
model.to("cpu")
model.eval()
yes_ids = tokenizer.encode("yes", add_special_tokens=False)
no_ids = tokenizer.encode("no", add_special_tokens=False)
if not yes_ids or not no_ids:
    raise SystemExit("could not resolve yes/no token ids")
yes_id = yes_ids[-1]
no_id = no_ids[-1]
scores = []
with torch.no_grad():
    for pair in payload["pairs"]:
        encoded = tokenizer(pair["prompt"], return_tensors="pt", truncation=True, max_length=2048)
        encoded = {k: v.to("cpu") for k, v in encoded.items()}
        logits = model(**encoded).logits[0, -1]
        diff = float((logits[yes_id] - logits[no_id]).detach().cpu())
        scores.append(1.0 / (1.0 + math.exp(-diff)))
print(json.dumps({"scores": scores}))
`;
  const result = await runPythonJson(opts.pythonBin, ['-c', script], input, env);
  if (!Array.isArray(result['scores']) || result['scores'].length !== batch.length) {
    throw new Error('Qwen3 reranker returned an invalid scores payload');
  }
  return result['scores'].map((score) => {
    if (typeof score !== 'number' || !Number.isFinite(score)) throw new Error(`invalid Qwen3 score: ${score}`);
    return Math.max(0, Math.min(1, score));
  });
}

function runPythonJson(
  pythonBin: string,
  args: string[],
  input: string,
  env: NodeJS.ProcessEnv,
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const child = spawn(pythonBin, args, { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Qwen3 Python reranker exited ${code}: ${stderr.trim() || stdout.trim()}`));
        return;
      }
      try {
        resolve(JSON.parse(stdout) as Record<string, unknown>);
      } catch (err) {
        reject(new Error(`Qwen3 Python reranker returned non-JSON output: ${(err as Error).message}; stderr=${stderr.trim()}`));
      }
    });
    child.stdin.end(input);
  });
}

function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
}

// ─── Streaming Qwen3 / chat-template reranker (persistent subprocess) ────────

export interface StreamingQwen3RerankerOptions {
  readonly model: string;
  readonly revision: string;
  readonly pythonBin?: string;
  readonly scriptPath?: string;
  readonly cacheDir?: string;
  readonly localOnly?: boolean;
  readonly batchSize?: number;
  readonly numThreads?: number;
}

/**
 * Persistent-subprocess reranker. Spawns one Python child that loads the
 * pinned chat-template reranker (Qwen3 family — including MemReranker-4B,
 * which uses the same logit(yes)-logit(no) scoring path) exactly once and
 * services NDJSON requests over stdin/stdout. This is the only reranker
 * implementation that can sustain launch-scale corpus labeling; the per-batch
 * spawn variant pays the multi-gigabyte model-load cost on every score()
 * call and is unusable past a few hundred pairs on a CPU host.
 */
export function createStreamingQwen3Reranker(
  opts: StreamingQwen3RerankerOptions,
): CrossEncoderReranker & { close: () => Promise<void> } {
  refuseGpuForReranker();
  const pythonBin = opts.pythonBin ?? process.env['CORETEX_RERANKER_PYTHON'] ?? 'python3';
  const scriptPath =
    opts.scriptPath ??
    process.env['CORETEX_RERANKER_SCRIPT'] ??
    new URL('../../../../scripts/reranker_runner.py', import.meta.url).pathname;
  const batchSize = opts.batchSize ?? 4;

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    CORETEX_RERANKER_STREAM_MODEL_ID: opts.model,
    CORETEX_RERANKER_STREAM_REVISION: opts.revision,
  };
  if (opts.cacheDir) env['HF_HOME'] = opts.cacheDir;
  if (opts.localOnly) env['HF_HUB_OFFLINE'] = '1';
  if (opts.numThreads) env['RERANKER_NUM_THREADS'] = String(opts.numThreads);

  const child: ChildProcessWithoutNullStreams = spawn(pythonBin, [scriptPath, '--stream'], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env,
  });

  const stderrChunks: string[] = [];
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk: string) => stderrChunks.push(chunk));

  const responses = new Map<number, { resolve: (scores: number[]) => void; reject: (err: Error) => void }>();
  let nextId = 1;
  let readyResolve: () => void = () => {};
  let readyReject: (err: Error) => void = () => {};
  const ready = new Promise<void>((resolve, reject) => {
    readyResolve = resolve;
    readyReject = reject;
  });
  let exited = false;

  const rl = createInterface({ input: child.stdout });
  rl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      return;
    }
    if (parsed && typeof parsed === 'object' && 'ready' in parsed) {
      readyResolve();
      return;
    }
    if (parsed && typeof parsed === 'object' && 'id' in parsed) {
      const id = (parsed as { id: number }).id;
      const pending = responses.get(id);
      if (!pending) return;
      responses.delete(id);
      if ('error' in parsed) {
        pending.reject(new Error(`reranker stream error: ${(parsed as { error: string }).error}`));
        return;
      }
      const scores = (parsed as { scores?: number[] }).scores ?? [];
      pending.resolve(scores);
    }
  });

  child.on('exit', (code, signal) => {
    exited = true;
    const stderr = stderrChunks.join('');
    const err = new Error(
      `reranker stream child exited (code=${code}, signal=${signal}): ${stderr.slice(-500)}`,
    );
    readyReject(err);
    for (const pending of responses.values()) pending.reject(err);
    responses.clear();
  });

  child.on('error', (e) => {
    exited = true;
    readyReject(e);
    for (const pending of responses.values()) pending.reject(e);
    responses.clear();
  });

  async function scoreBatch(batch: ReadonlyArray<{ query: string; document: string }>): Promise<number[]> {
    if (exited) throw new Error('reranker stream child is no longer running');
    await ready;
    if (batch.length === 0) return [];
    const id = nextId++;
    const payload = JSON.stringify({
      id,
      pairs: batch.map((p) => ({ query: p.query, document: p.document })),
    }) + '\n';
    return new Promise<number[]>((resolve, reject) => {
      responses.set(id, { resolve, reject });
      child.stdin.write(payload, (writeErr) => {
        if (writeErr) {
          responses.delete(id);
          reject(writeErr);
        }
      });
    });
  }

  async function score(pairs: ReadonlyArray<{ query: string; document: string }>): Promise<number[]> {
    if (pairs.length === 0) return [];
    const out: number[] = [];
    for (let i = 0; i < pairs.length; i += batchSize) {
      const batch = pairs.slice(i, i + batchSize);
      const batchScores = await scoreBatch(batch);
      out.push(...batchScores.map((s) => Math.max(0, Math.min(1, s))));
    }
    return out;
  }

  async function close(): Promise<void> {
    if (exited) return;
    try {
      child.stdin.end();
    } catch {
      /* noop */
    }
    await new Promise<void>((resolve) => {
      if (exited) return resolve();
      child.once('exit', () => resolve());
    });
  }

  return { model: `${opts.model}@${opts.revision}`, score, close };
}

// ─── MiniLM cross-encoder (text-classification pipeline) ─────────────────────

export interface MiniLMRerankerOptions {
  /** HuggingFace model id. Default: 'Xenova/ms-marco-MiniLM-L-6-v2'. */
  model?: string | undefined;
  /** Local cache directory. */
  cacheDir?: string | undefined;
  /** Disable remote model fetching. */
  localOnly?: boolean | undefined;
}

/**
 * Build a cross-encoder using the `text-classification` pipeline.
 *
 * The Xenova/ms-marco-MiniLM-L-6-v2 model is a true BERT-based cross-encoder
 * that directly outputs a relevance score for each (query, passage) pair.
 * It is much lighter-weight than Qwen3 and suitable for unit/integration tests
 * that need a real model load.
 */
export async function createMiniLMReranker(
  opts?: MiniLMRerankerOptions,
): Promise<CrossEncoderReranker> {
  const modelId = opts?.model ?? 'Xenova/ms-marco-MiniLM-L-6-v2';

  let transformers: typeof import('@huggingface/transformers');
  try {
    transformers = await import('@huggingface/transformers');
  } catch (err) {
    throw new Error(
      'MiniLM reranker requires optional dependency @huggingface/transformers. ' +
        `Original error: ${(err as Error)?.message ?? String(err)}`,
    );
  }

  const { pipeline, env } = transformers as unknown as {
    pipeline(
      task: string,
      model: string,
      opts?: Record<string, unknown>,
    ): Promise<(input: Array<{ text: string; text_pair: string }>, opts?: Record<string, unknown>) => Promise<ClassificationOutput[]>>;
    env: { cacheDir?: string; allowLocalModels?: boolean; allowRemoteModels?: boolean } | undefined;
  };

  if (env) {
    if (opts?.cacheDir) env.cacheDir = opts.cacheDir;
    if (opts?.localOnly) {
      env.allowLocalModels = true;
      env.allowRemoteModels = false;
    }
  }

  const classifier = await pipeline('text-classification', modelId);

  return withRerankerCache({
    model: modelId,
    async score(pairs) {
      if (pairs.length === 0) return [];
      const inputs = pairs.map((p) => ({ text: p.query, text_pair: p.document }));
      const outputs = await classifier(inputs, { topk: 1 });
      return outputs.map((out) => {
        const item = Array.isArray(out) ? out[0]! : out;
        // ms-marco models return a single logit as score; apply sigmoid to
        // map to [0, 1] if the label is 'LABEL_0' (raw logit).
        if (item.label === 'LABEL_0') return sigmoid(item.score);
        return Math.max(0, Math.min(1, item.score));
      });
    },
  });
}

interface ClassificationOutput {
  label: string;
  score: number;
}

// ─── Deterministic hashing-based stub (no model load) ────────────────────────

export interface DeterministicRerankerOptions {
  /** Embedding dimension for hashing vectors. Default: 256. */
  dims?: number | undefined;
}

/**
 * Build a deterministic reranker backed by hashing vectors.
 *
 * No model is loaded. Scores are computed as:
 *   score = (tanh(dot(hashvec(query), hashvec(doc))) + 1) / 2
 *
 * This maps the dot product (which can be negative) into [0, 1].
 * Identical pairs always return the same score; different content
 * returns meaningfully different scores.
 *
 * Intended for offline/CI unit tests only.
 */
export async function createDeterministicReranker(
  opts?: DeterministicRerankerOptions,
): Promise<CrossEncoderReranker> {
  const dims = opts?.dims ?? 256;
  return {
    model: `deterministic-reranker-${dims}`,
    async score(pairs) {
      return pairs.map((pair) => {
        const q = hashVector(pair.query, dims);
        const d = hashVector(pair.document, dims);
        const dotProduct = dot(q, d);
        // tanh maps (-inf, +inf) to (-1, 1); shift to [0, 1]
        return (Math.tanh(dotProduct) + 1) / 2;
      });
    },
  };
}

// ─── Environment-based factory ────────────────────────────────────────────────

/**
 * Select and create a reranker based on the `CORETEX_RERANKER` environment
 * variable:
 *
 *   CORETEX_RERANKER=qwen3         → createQwen3Reranker()
 *   CORETEX_RERANKER=minilm        → createMiniLMReranker()
 *   CORETEX_RERANKER=deterministic → createDeterministicReranker()
 *   (unset / any other value)      → createDeterministicReranker() unless production mode is enabled.
 */
export async function rerankerFromEnv(): Promise<CrossEncoderReranker> {
  const rawSelector = process.env['CORETEX_RERANKER'];
  const productionMode = process.env['CORTEX_REAL_EVAL'] === '1' || process.env['CORETEX_RERANKER_PRODUCTION'] === '1';
  if (!rawSelector && productionMode) {
    throw new Error('CORETEX_RERANKER must be set in production mode (expected qwen3)');
  }
  const selector = (rawSelector ?? 'deterministic').toLowerCase();
  // Streaming mode keeps a single Python child for the entire process lifetime;
  // required for any caller that scores more than a few dozen pairs (e.g. the
  // determinism harness, calibration sweep, Phase 13 e2e on real corpus).
  const streaming = process.env['CORETEX_RERANKER_MODE'] === 'streaming';
  const revision = process.env['CORETEX_RERANKER_REVISION'] ?? QWEN3_RERANKER_DEFAULT_REVISION;
  const modelId = process.env['CORETEX_RERANKER_MODEL_ID'] ?? 'Qwen/Qwen3-Reranker-0.6B';
  switch (selector) {
    case 'qwen3':
      if (streaming) {
        return createStreamingQwen3Reranker({
          model: modelId,
          revision,
          cacheDir: process.env['CORTEX_LOCAL_MODEL_CACHE'],
          localOnly: process.env['CORTEX_LOCAL_MODEL_LOCAL_ONLY'] === '1',
          batchSize: Number(process.env['CORETEX_RERANKER_BATCH_SIZE'] ?? '8'),
          numThreads: Number(process.env['RERANKER_NUM_THREADS'] ?? '0') || undefined,
        });
      }
      return createQwen3Reranker({
        revision,
        cacheDir: process.env['CORTEX_LOCAL_MODEL_CACHE'],
        localOnly: process.env['CORTEX_LOCAL_MODEL_LOCAL_ONLY'] === '1',
      });
    case 'minilm':
      return createMiniLMReranker({
        cacheDir: process.env['CORTEX_LOCAL_MODEL_CACHE'],
        localOnly: process.env['CORTEX_LOCAL_MODEL_LOCAL_ONLY'] === '1',
      });
    case 'deterministic':
      if (productionMode && process.env['CORETEX_ALLOW_DETERMINISTIC_RERANKER'] !== '1') {
        throw new Error('deterministic reranker is not allowed in production mode');
      }
      return createDeterministicReranker();
    default:
      if (productionMode) {
        throw new Error(`unsupported CORETEX_RERANKER=${selector} in production mode`);
      }
      return createDeterministicReranker();
  }
}

// ─── LRU memoization wrapper ──────────────────────────────────────────────────

const DEFAULT_LRU_SIZE = 2048;

/**
 * Wrap a CrossEncoderReranker with an LRU score cache.
 *
 * Cache key: `${query}\x00${document}` (zero byte separator is safe because
 * it cannot appear in valid UTF-8 query/document strings in practice).
 *
 * This is useful when the same (query, corpus) pairs are re-scored across
 * multiple patch evaluations for the same parent state.
 */
export function withRerankerCache(
  reranker: CrossEncoderReranker,
  maxSize: number = DEFAULT_LRU_SIZE,
): CrossEncoderReranker {
  const cache = new LRUCache<string, number>(maxSize);

  return {
    model: reranker.model,
    async score(pairs) {
      const results = new Array<number>(pairs.length);
      const missingIndices: number[] = [];

      for (let i = 0; i < pairs.length; i++) {
        const key = cacheKey(pairs[i]!);
        const cached = cache.get(key);
        if (cached !== undefined) {
          results[i] = cached;
        } else {
          missingIndices.push(i);
        }
      }

      if (missingIndices.length > 0) {
        const missingPairs = missingIndices.map((i) => pairs[i]!);
        const computed = await reranker.score(missingPairs);
        for (let j = 0; j < missingIndices.length; j++) {
          const i = missingIndices[j]!;
          const score = computed[j]!;
          results[i] = score;
          cache.set(cacheKey(pairs[i]!), score);
        }
      }

      return results;
    },
  };
}

function cacheKey(pair: { query: string; document: string }): string {
  return `${pair.query}\x00${pair.document}`;
}

// ─── Minimal LRU cache ────────────────────────────────────────────────────────
// Implemented with a Map (insertion-order) and manual eviction.

class LRUCache<K, V> {
  private readonly map = new Map<K, V>();

  constructor(private readonly maxSize: number) {}

  get(key: K): V | undefined {
    if (!this.map.has(key)) return undefined;
    // Refresh: delete and re-insert to move to end
    const value = this.map.get(key)!;
    this.map.delete(key);
    this.map.set(key, value);
    return value;
  }

  set(key: K, value: V): void {
    if (this.map.has(key)) this.map.delete(key);
    this.map.set(key, value);
    if (this.map.size > this.maxSize) {
      // Evict oldest (first inserted)
      const first = this.map.keys().next().value;
      if (first !== undefined) this.map.delete(first);
    }
  }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

function hashVector(text: string, dims: number): number[] {
  const v = new Array<number>(dims).fill(0);
  const tokens = String(text).toLowerCase().match(/[a-z0-9$]+/g) ?? [];
  for (let i = 0; i < tokens.length; i++) {
    addTokenToVector(v, tokens[i]!, 1);
    if (i + 1 < tokens.length) addTokenToVector(v, `${tokens[i]} ${tokens[i + 1]}`, 0.5);
  }
  return v;
}

function addTokenToVector(v: number[], token: string, weight: number): void {
  const h = createHash('sha256').update(token).digest();
  const idx = h.readUInt32BE(0) % v.length;
  const sign = (h[4]! & 1) === 0 ? 1 : -1;
  if (idx < v.length) v[idx] = (v[idx] ?? 0) + sign * weight;
}

function dot(a: number[], b: number[]): number {
  const n = Math.min(a.length, b.length);
  let s = 0;
  for (let i = 0; i < n; i++) s += a[i]! * b[i]!;
  return s;
}
