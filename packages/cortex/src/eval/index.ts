/**
 * Phase 3 — Eval harness, eval report formatter, deterministic report hash.
 *
 * Responsibilities (§4):
 *   4. Run deterministic CortexBench tasks against experienceCorpusRoot (stub corpus).
 *   5. Apply candidate patches.
 *   6. Recompute state root.
 *   7. Emit reproducible eval report.
 *
 * Phase 4 corpus loader interface contract:
 *   The harness accepts a CorpusLoader interface. Phase 4 must provide an object
 *   implementing CorpusLoader. The stub below is a drop-in until then.
 *
 * Performance budget: <10 ms p50, <50 ms p99 per patch-eval on commodity CPU.
 * No frontier / API model in canonical scoring.
 */

import type { CortexState, Patch, PatchError, MerkleTreeCache } from '../state/index.js';
import {
  buildMerkleCache,
  updateMerkleCache,
  bytesToHex,
  ERROR_NAMES,
  RANGES,
  hasNonZeroReservedBits,
} from '../state/index.js';
import { keccak256 } from '../state/keccak256.js';
import { decodeCortexState } from '../decoder/index.js';
import type { DecodedCortexState } from '../decoder/index.js';

// ─── Phase 4 corpus loader interface contract ─────────────────────────────────
//
// Phase 4 MUST implement this interface to plug in real CortexBench tasks.
// The stub below (StubCorpusLoader) satisfies the contract for Phase 3.
//
// CONTRACT (document for Phase 4):
//   - score() must be pure and deterministic: same (state, corpus) → same score.
//   - score() must not make external calls.
//   - score() returns a value in [0, 1] (as a number; internally stored ×1e6 bigint).
//   - shardId: a 32-byte identifier selecting a corpus shard.
//   - corpusRoot: the Merkle root of this loader's corpus epoch (bytes32 as hex).

export interface CorpusLoader {
  /** Corpus Merkle root (0x-prefixed 64-char hex string). */
  readonly corpusRoot: string;
  /** Evaluate a decoded state against the corpus and return a score in [0, 1]. */
  score(decoded: DecodedCortexState, shardId: Uint8Array): number;
}

/**
 * Stub corpus loader — always returns 0.5.
 * Used until Phase 4 delivers real benchmark generators.
 */
export class StubCorpusLoader implements CorpusLoader {
  readonly corpusRoot: string;

  constructor(corpusRoot: string = '0x' + '00'.repeat(32)) {
    this.corpusRoot = corpusRoot;
  }

  score(_decoded: DecodedCortexState, _shardId: Uint8Array): number {
    // Phase 3 stub — deterministic, always 0.5.
    // Phase 4 replaces this with actual benchmark scoring.
    return 0.5;
  }
}

// ─── Eval report types ────────────────────────────────────────────────────────

export interface EvalReport {
  /** Protocol version string. */
  readonly version: string;
  /** Parent state root (0x-prefixed hex). */
  readonly parentStateRoot: string;
  /** New state root after applying the patch (0x-prefixed hex), or null on rejection. */
  readonly newStateRoot: string | null;
  /** Patch hash: keccak256 of encodePatch output (0x-prefixed hex). */
  readonly patchHash: string;
  /** Whether the patch was accepted. */
  readonly accepted: boolean;
  /** Rejection error code if not accepted, null otherwise. */
  readonly errorCode: string | null;
  /** Rejection message if not accepted, null otherwise. */
  readonly errorMessage: string | null;
  /** Baseline score ×1e6 (before patch). */
  readonly baselineScore: bigint;
  /** Candidate score ×1e6 (after patch, if accepted). */
  readonly candidateScore: bigint;
  /** Score delta ×1e6. */
  readonly scoreDelta: bigint;
  /** Corpus root used for this eval. */
  readonly corpusRoot: string;
  /** Shard ID (0x-prefixed hex). */
  readonly shardId: string;
  /** Eval timestamp (unix ms, as string to avoid precision issues). */
  readonly evalTimestampMs: string;
  /** Eval duration in microseconds. */
  readonly evalDurationUs: number;
  /** Report hash: keccak256 of canonical JSON (0x-prefixed hex). */
  readonly reportHash: string;
}

// ─── Canonical JSON serialisation ────────────────────────────────────────────
//
// Deterministic: sorted keys, no whitespace, bigint encoded as decimal string
// with suffix "n" to distinguish from plain numbers.

function canonicalValue(v: unknown): string {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return String(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'bigint') return `"${v.toString()}n"`;
  if (Array.isArray(v)) {
    return '[' + (v as unknown[]).map(canonicalValue).join(',') + ']';
  }
  if (typeof v === 'object') {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return '{' + keys.map((k) => `${JSON.stringify(k)}:${canonicalValue(obj[k])}`).join(',') + '}';
  }
  throw new TypeError(`canonicalValue: unsupported type ${typeof v}`);
}

export function canonicalJson(report: Omit<EvalReport, 'reportHash'>): Uint8Array {
  const json = canonicalValue(report);
  return new TextEncoder().encode(json);
}

// ─── Eval harness ─────────────────────────────────────────────────────────────

export interface EvalOptions {
  /** Corpus loader. Defaults to StubCorpusLoader. */
  loader?: CorpusLoader;
  /** Shard ID (32 bytes). Defaults to zeros. */
  shardId?: Uint8Array;
  /** Patch wire bytes (for hash computation). Provide the encoded patch bytes. */
  patchWireBytes: Uint8Array;
  /**
   * Optional Merkle cache for `state`.
   *
   * Production callers should keep one cache per canonical parent state and
   * pass it here. evalPatch treats the cache as immutable and returns roots
   * from incremental leaf-path recomputation.
   */
  merkleCache?: MerkleTreeCache;
}

/**
 * Run a full patch eval:
 *   1. Decode parent state.
 *   2. Score baseline.
 *   3. Apply patch.
 *   4. Score candidate (if accepted).
 *   5. Emit deterministic EvalReport with reportHash.
 *
 * This function is synchronous and safe to call from a worker thread.
 * Never call on the HTTP request thread directly — use the worker pool.
 */
export function evalPatch(
  state: CortexState,
  patch: Patch,
  opts: EvalOptions,
): EvalReport {
  const t0 = process.hrtime.bigint();

  const loader: CorpusLoader = opts.loader ?? new StubCorpusLoader();
  const shardId: Uint8Array = opts.shardId ?? new Uint8Array(32);

  const parentCache = opts.merkleCache ?? buildMerkleCache(state);
  const parentRootBytes = parentCache.root;
  const parentStateRoot = bytesToHex(parentRootBytes);

  // Compute patch hash
  const patchHash = bytesToHex(keccak256(opts.patchWireBytes));

  // Baseline score
  const decodeResult = decodeCortexState(state);
  let baselineScore = 0n;
  if (decodeResult.ok) {
    baselineScore = BigInt(Math.round(loader.score(decodeResult.decoded, shardId) * 1_000_000));
  }

  const patchResult = applyPatchWithCachedParent(state, patch, parentRootBytes);

  let newStateRoot: string | null = null;
  let candidateScore = 0n;
  let accepted = false;
  let errorCode: string | null = null;
  let errorMessage: string | null = null;

  if (patchResult.ok) {
    accepted = true;
    const nextCache = updateMerkleCache(parentCache, patchResult.updates);
    newStateRoot = bytesToHex(nextCache.root);
    const candidateDecodeResult = decodeCortexState(patchResult.state);
    if (candidateDecodeResult.ok) {
      candidateScore = BigInt(Math.round(loader.score(candidateDecodeResult.decoded, shardId) * 1_000_000));
    }
  } else {
    errorCode = patchResult.code;
    errorMessage = patchResult.message;
    candidateScore = baselineScore; // no change on rejection
  }

  const scoreDelta = candidateScore - baselineScore;

  const t1 = process.hrtime.bigint();
  const evalDurationUs = Number((t1 - t0) / 1000n);
  const evalTimestampMs = String(Date.now());

  // Assemble report without hash first
  const reportWithoutHash: Omit<EvalReport, 'reportHash'> = {
    version: 'cortex-eval-v0',
    parentStateRoot,
    newStateRoot,
    patchHash,
    accepted,
    errorCode,
    errorMessage,
    baselineScore,
    candidateScore,
    scoreDelta,
    corpusRoot: loader.corpusRoot,
    shardId: bytesToHex(shardId),
    evalTimestampMs,
    evalDurationUs,
  };

  // Compute report hash over canonical JSON (deterministic)
  const canonBytes = canonicalJson(reportWithoutHash);
  const reportHash = bytesToHex(keccak256(canonBytes));

  return { ...reportWithoutHash, reportHash };
}

interface CachedApplySuccess {
  readonly ok: true;
  readonly state: CortexState;
  readonly updates: readonly { readonly index: number; readonly word: bigint }[];
}

type CachedApplyResult = CachedApplySuccess | PatchError;

function applyPatchWithCachedParent(
  state: CortexState,
  patch: Patch,
  parentRoot: Uint8Array,
): CachedApplyResult {
  if (patch.wordCount < 1 || patch.wordCount > 4) {
    return patchError('E03');
  }

  if (!bytesEqual(patch.parentStateRoot, parentRoot)) {
    return patchError('E01');
  }

  let anyChange = false;
  for (let i = 0; i < patch.wordCount; i++) {
    const idx = patch.indices[i]!;
    if ((state.words[idx] ?? 0n) !== (patch.newWords[i] ?? 0n)) {
      anyChange = true;
      break;
    }
  }
  if (!anyChange) {
    return patchError('E05');
  }

  const newWords: bigint[] = [...state.words];
  const updates: { index: number; word: bigint }[] = [];
  for (let i = 0; i < patch.wordCount; i++) {
    const idx = patch.indices[i]!;
    if (idx >= RANGES.RESERVED_START && idx <= RANGES.RESERVED_END) {
      return patchError('E02');
    }
    if (!Number.isInteger(idx) || idx < 0 || idx >= RANGES.WORD_COUNT) {
      return patchError('E02');
    }

    const word = patch.newWords[i] ?? 0n;
    newWords[idx] = word;
    updates.push({ index: idx, word });
  }

  const resultState: CortexState = { words: newWords };
  if (hasNonZeroReservedBits(resultState)) {
    return patchError('E04');
  }

  return { ok: true, state: resultState, updates };
}

function patchError(code: PatchError['code']): PatchError {
  return { ok: false, code, message: `${code}: ${ERROR_NAMES[code]}` };
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
