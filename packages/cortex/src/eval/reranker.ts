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

// ─── Qwen3-Reranker-0.6B (generative logit-difference path) ──────────────────

export interface Qwen3RerankerOptions {
  /** HuggingFace model id. Default: 'Qwen/Qwen3-Reranker-0.6B'. */
  model?: string | undefined;
  /** Pinned revision tag or commit hash. */
  revision?: string | undefined;
  /** Local cache directory for model weights. */
  cacheDir?: string | undefined;
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
  const modelId = opts?.model ?? 'Qwen/Qwen3-Reranker-0.6B';
  const batchSize = opts?.batchSize ?? 4;

  // Dynamic import: @huggingface/transformers is an optional peer dependency.
  let transformers: typeof import('@huggingface/transformers');
  try {
    transformers = await import('@huggingface/transformers');
  } catch (err) {
    throw new Error(
      'Qwen3 reranker requires optional dependency @huggingface/transformers. ' +
        'Install it or use createDeterministicReranker() for offline tests. ' +
        `Original error: ${(err as Error)?.message ?? String(err)}`,
    );
  }

  const { AutoTokenizer, AutoModelForCausalLM, env } = transformers as unknown as {
    AutoTokenizer: { from_pretrained(id: string, opts: Record<string, unknown>): Promise<Tokenizer> };
    AutoModelForCausalLM: { from_pretrained(id: string, opts: Record<string, unknown>): Promise<CausalLM> };
    env: { cacheDir?: string; allowLocalModels?: boolean; allowRemoteModels?: boolean } | undefined;
  };

  if (env) {
    if (opts?.cacheDir) env.cacheDir = opts.cacheDir;
    if (opts?.localOnly) {
      env.allowLocalModels = true;
      env.allowRemoteModels = false;
    }
  }

  const loadOpts: Record<string, unknown> = {};
  if (opts?.revision) loadOpts['revision'] = opts.revision;

  const [tokenizer, model] = await Promise.all([
    AutoTokenizer.from_pretrained(modelId, loadOpts),
    AutoModelForCausalLM.from_pretrained(modelId, loadOpts),
  ]);

  // Resolve the yes/no token ids for the final logit probe.
  const yesTokenId = await resolveTokenId(tokenizer, 'yes');
  const noTokenId = await resolveTokenId(tokenizer, 'no');

  return withRerankerCache({
    model: modelId,
    async score(pairs) {
      const scores: number[] = [];
      for (let i = 0; i < pairs.length; i += batchSize) {
        const batch = pairs.slice(i, i + batchSize);
        const batchScores = await scoreBatchQwen3(
          batch,
          tokenizer,
          model,
          yesTokenId,
          noTokenId,
        );
        scores.push(...batchScores);
      }
      return scores;
    },
  });
}

// ─── Minimal shape types for Transformers.js objects ─────────────────────────
// We avoid importing the full type declarations here because they are not
// guaranteed to be present in all install configurations.

interface Tokenizer {
  // Tokenise a text string (or array of strings).
  // Returns an object with at least an `input_ids` tensor.
  (
    text: string | string[],
    opts?: Record<string, unknown>,
  ): Promise<Record<string, unknown>> | Record<string, unknown>;
  // Some models expose convert_tokens_to_ids or encode
  convert_tokens_to_ids?: (tokens: string[]) => number[];
  encode?: (text: string) => number[];
}

interface CausalLM {
  // Run a forward pass and return logits.
  ({ input_ids }: { input_ids: unknown }): Promise<{ logits: Tensor }> | { logits: Tensor };
}

interface Tensor {
  // Last logit row: shape [batchSize, seqLen, vocabSize]
  // We use tolist() or data/dims to extract values.
  tolist?: () => number[][][];
  data?: Float32Array | number[];
  dims?: number[];
}

async function resolveTokenId(tokenizer: Tokenizer, word: string): Promise<number> {
  if (typeof tokenizer.convert_tokens_to_ids === 'function') {
    const ids = tokenizer.convert_tokens_to_ids([word]);
    if (Array.isArray(ids) && typeof ids[0] === 'number' && ids[0] >= 0) return ids[0];
  }
  if (typeof tokenizer.encode === 'function') {
    const ids = tokenizer.encode(word);
    if (Array.isArray(ids) && ids.length > 0) {
      // encode usually includes BOS/EOS; take the last real content token
      return ids[ids.length - 1]!;
    }
  }
  // Fallback: tokenise the word and grab the first token id.
  const out = await Promise.resolve(tokenizer(word));
  const input_ids = (out as Record<string, { data?: number[] }>)['input_ids'];
  if (input_ids?.data && input_ids.data.length > 0) {
    return input_ids.data[input_ids.data.length - 1]!;
  }
  throw new Error(`resolveTokenId: cannot find token id for "${word}"`);
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

async function scoreBatchQwen3(
  batch: ReadonlyArray<{ query: string; document: string }>,
  tokenizer: Tokenizer,
  model: CausalLM,
  yesTokenId: number,
  noTokenId: number,
): Promise<number[]> {
  const scores: number[] = [];
  for (const pair of batch) {
    const prompt = buildQwen3Prompt(pair.query, pair.document);
    const encoded = await Promise.resolve(tokenizer(prompt, { return_tensors: 'pt' }));
    const output = await Promise.resolve(model({ input_ids: (encoded as Record<string, unknown>)['input_ids'] }));
    const logits = output.logits;
    const logitRow = extractLastPositionLogits(logits);
    const yesLogit = logitRow[yesTokenId] ?? 0;
    const noLogit = logitRow[noTokenId] ?? 0;
    scores.push(sigmoid(yesLogit - noLogit));
  }
  return scores;
}

function extractLastPositionLogits(logits: Tensor): number[] {
  if (typeof logits.tolist === 'function') {
    const arr = logits.tolist();
    // shape [batch, seq, vocab] — take batch 0, last seq position
    return arr[0]![arr[0]!.length - 1]!;
  }
  if (logits.data && logits.dims) {
    const [_batch, _seq, vocab] = logits.dims as [number, number, number];
    const data = Array.from(logits.data as Float32Array);
    // Last position is the last `vocab`-sized chunk
    return data.slice(data.length - vocab);
  }
  throw new Error('extractLastPositionLogits: unsupported Tensor shape');
}

function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
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
  switch (selector) {
    case 'qwen3':
      return createQwen3Reranker({
        revision: process.env['CORETEX_RERANKER_REVISION'] ?? QWEN3_RERANKER_DEFAULT_REVISION,
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
