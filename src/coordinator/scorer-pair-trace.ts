/**
 * Full scored-pair trace (input-identity proof) for the keyless GPU scorer.
 *
 * This is the SAME ordered-chain trace mechanism the CPU parity harness uses
 * (scripts/lib/instrumented-reranker.mjs): for every (query, document) the
 * reranker is asked to score, in CALL ORDER, we fold
 *   - the pair's `promptHash` (sha256 of the canonical JSON {query, document}
 *     the backend receives) into one chain, and
 *   - the pair's canonicalized raw score (toPrecision(17), -0 normalized to
 *     '0') into a second chain.
 * The two snapshot digests are
 *   pairTraceHash  = sha256 over the ordered "<index> <promptHash>\n" stream,
 *   scoreArrayHash = sha256 over the ordered "<index> <canonScore>\n" stream.
 *
 * The literals (`canonical`, `canonScore`, `promptHashOf`, the chain update
 * format) are byte-identical to scripts/lib/instrumented-reranker.mjs so a
 * scorer-emitted trace can be cross-checked against a CPU parity run. Ported
 * to TS here (instead of importing the .mjs) so it ships inside the package
 * `dist/` and is callable from the keyless `coretex-scorer-server` bin.
 *
 * Keyless: this module touches NO signing material — it only hashes the
 * reranker's inputs and outputs.
 */
import { createHash, type Hash } from 'node:crypto';

import type { CrossEncoderReranker } from '../eval/reranker.js';

function sha256Hex(s: string): string {
  return '0x' + createHash('sha256').update(s).digest('hex');
}

/** Stable canonical JSON — object keys sorted — matching instrumented-reranker.mjs. */
function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const obj = value as Record<string, unknown>;
  return '{' + Object.keys(obj).sort().map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`).join(',') + '}';
}

/** Canonicalize a float score to a fixed, reproducible decimal string.
 *  toPrecision(17) round-trips an IEEE-754 double exactly. -0 → '0'. */
function canonScore(x: number): string {
  return Object.is(x, -0) ? '0' : Number(x).toPrecision(17);
}

/** promptHash = sha256 of the canonical JSON of the exact {query, document}
 *  the backend receives. Single bytes-identity hash for one scoring. */
function promptHashOf(pair: { query?: string; document?: string }): string {
  return sha256Hex(canonical({ query: pair.query ?? '', document: pair.document ?? '' }));
}

export interface ScorerPairTraceSnapshot {
  readonly totalScoredPairCount: number;
  readonly pairTraceHash: string;
  readonly scoreArrayHash: string;
}

export interface TracedReranker extends CrossEncoderReranker {
  /** Snapshot the ordered trace WITHOUT consuming the running chains. */
  traceSnapshot(): ScorerPairTraceSnapshot;
  /** Reset both chains + counter to a clean slate (per-job boundary). */
  resetTrace(): void;
  close?(): Promise<void>;
}

/**
 * Wrap a reranker so every scored (query, document) pair is folded into the
 * ordered promptHash + score chains, exactly like the CPU parity harness.
 * No caching, no persistence — the keyless scorer scores every pair the
 * evaluator asks for and emits the chain digests per job.
 */
export function wrapRerankerWithPairTrace(reranker: CrossEncoderReranker): TracedReranker {
  if (!reranker || typeof reranker.score !== 'function') {
    throw new Error('wrapRerankerWithPairTrace requires reranker.score');
  }
  let pairOrder = 0;
  let scoredPairCount = 0;
  let promptHashChain: Hash = createHash('sha256');
  let scoreChain: Hash = createHash('sha256');

  const wrapped: TracedReranker = {
    model: reranker.model,
    async score(pairs) {
      if (!pairs?.length) return [];
      const out = await reranker.score(pairs);
      if (out.length !== pairs.length) {
        throw new Error(`traced reranker expected ${pairs.length} scores, got ${out.length}`);
      }
      for (let i = 0; i < pairs.length; i++) {
        const score = out[i];
        if (typeof score !== 'number' || !Number.isFinite(score)) {
          throw new Error(`traced reranker got non-finite score at index ${i}`);
        }
        // NUL separator (\0) — byte-identical to scripts/lib/instrumented-reranker.mjs.
        const promptHash = promptHashOf(pairs[i] as { query?: string; document?: string });
        promptHashChain.update(`${pairOrder}\0${promptHash}\n`);
        scoreChain.update(`${pairOrder}\0${canonScore(score)}\n`);
        pairOrder++;
      }
      scoredPairCount = pairOrder;
      return out;
    },
    traceSnapshot() {
      return {
        totalScoredPairCount: scoredPairCount,
        pairTraceHash: '0x' + promptHashChain.copy().digest('hex'),
        scoreArrayHash: '0x' + scoreChain.copy().digest('hex'),
      };
    },
    resetTrace() {
      pairOrder = 0;
      scoredPairCount = 0;
      promptHashChain = createHash('sha256');
      scoreChain = createHash('sha256');
    },
  };
  const closable = reranker as CrossEncoderReranker & { close?: () => Promise<void> };
  if (typeof closable.close === 'function') {
    wrapped.close = () => closable.close!();
  }
  return wrapped;
}
