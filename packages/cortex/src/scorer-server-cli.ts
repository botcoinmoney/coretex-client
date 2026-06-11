#!/usr/bin/env node
/**
 * coretex-scorer-server — keyless GPU production-evaluator sidecar.
 *
 * ARCHITECTURE (trusted internal acceleration worker): this is the GPU half of
 * the coordinator/scorer split. It is KEYLESS — it never holds the coordinator
 * signing key and never signs anything. It loads the pinned production CoreTex
 * evaluator ONCE (real Qwen3 reranker on CUDA, fp32 / tf32=false), accepts an
 * eval JOB over HTTP, runs `runPerPatchEvaluation` (via the production
 * evaluator's scorePatch), and returns the scores + a full scored-pair trace +
 * a runtime health fingerprint. The coordinator (EC2, non-CUDA, holds the key)
 * VERIFIES the returned result against live chain/coordinator state and the
 * live threshold, then signs. The scorer is trusted for COMPUTE, never for
 * authority: it returns scores, the coordinator re-derives the accept/reject
 * decision.
 *
 * Fail-closed boot env (same contract as the coordinator's production
 * evaluator, plus CUDA enabled):
 *   CORETEX_RERANKER=qwen3 CORTEX_REAL_EVAL=1 CORETEX_RERANKER_PRODUCTION=1
 *   CORETEX_RERANKER_MODE=streaming CORETEX_RERANKER_ALLOW_CUDA=1
 *   RERANKER_INNER_BATCH (default 8)
 * plus CORETEX_BUNDLE_MANIFEST_PATH, CORETEX_CORPUS_PATH, CORETEX_EPOCH_ID,
 * CORETEX_EPOCH_SECRET, CORETEX_PER_MINER_SCREENER_CAP, BASE_RPC_URL.
 *
 * POST /score-job — see ScorerJobRequest / ScorerJobResult below.
 * GET  /healthz   — liveness + the loaded pins + scorerHealth.
 *
 * The pair-trace (pairTraceHash / scoreArrayHash) reuses the SAME ordered
 * promptHash + score chain mechanism as the CPU parity harness
 * (scripts/lib/instrumented-reranker.mjs), ported in
 * coordinator/scorer-pair-trace.ts.
 */
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

import {
  createProductionCoreTexEvaluator,
  createInMemoryDedupStore,
  type CoreTexEvalSeedContext,
  type ProductionCoreTexEvaluator,
  type ProductionRerankerPlan,
} from './coordinator/production-evaluator.js';
import { wrapRerankerWithPairTrace, type TracedReranker } from './coordinator/scorer-pair-trace.js';
import type { CoreTexDualPackEvaluationProof } from './coordinator/coretex-coordinator-core.js';
import type { CoreTexPostRevealEvalReportArtifact } from './replay/eval-report-artifact.js';
import {
  createStreamingQwen3Reranker,
  qwenRerankerPromptTemplateHash,
  resolveQwenRerankerInstruction,
  resolveRerankerScriptPath,
  getRerankerCacheStats,
  type CrossEncoderReranker,
  type RerankerCacheStats,
} from './eval/reranker.js';
import { loadProductionCorpus } from './eval/retrieval-corpus.js';
import type { CoreTexBundleManifest } from './bundle/index.js';
import type { ProductionEvalResult } from './coordinator/production-evaluator.js';
import { unpack, merkleizeState, bytesToHex, hexToBytes, PACKED_SIZE } from './index.js';
import type { CortexState } from './index.js';

// ─── Wire schemas ─────────────────────────────────────────────────────────────

/** Pins the coordinator asserts the scorer must have loaded. The scorer
 *  REFUSES (no eval) on any mismatch — it never silently scores against a
 *  different model/bundle/corpus than the coordinator expects. */
export interface ScorerExpectedPins {
  readonly modelId: string;
  readonly revision: string;
  readonly promptTemplateHash: string;
  readonly bundleHash: string;
  readonly corpusRoot: string;
}

export interface ScorerPublicEvalContext {
  /** §8 anti-grinding — the COORDINATOR-PINNED future-blockhash dual-pack seed
   *  context. On the keyless remote path the coordinator draws + DURABLY records
   *  this seed and ships it with the job; the scorer injects it verbatim and
   *  NEVER draws its own (seed is coordinator-authoritative + crash-safe). When
   *  receivedAtBlock/targetBlock/blockhash are all present the scorer uses THEM;
   *  if absent (legacy / local replay) the scorer falls back to its own
   *  BASE_RPC_URL blockhash binding. targetBlockOffset / hiddenSeedCommit are
   *  surfaced for visibility / replay. */
  readonly receivedAtBlock?: number;
  readonly targetBlock?: number;
  readonly blockhash?: string;
  readonly targetBlockOffset?: number;
  readonly hiddenSeedCommit?: string;
}

export interface ScorerJobRequest {
  readonly jobId: string;
  readonly epochId: number;
  readonly parentStateRoot: string;
  /** The verified parent substrate, packed via the canonical state codec
   *  (`pack(state)` → hex). REQUIRED: the keyless scorer holds no chain state,
   *  so the coordinator (which already holds the merkle-verified parent) ships
   *  the substrate with the job. The scorer re-merkleizes it and REFUSES
   *  (`SCORER_PARENT_STATE_MISMATCH`) unless `merkleizeState(unpack(hex)) ==
   *  parentStateRoot` — only then is it the parent the evaluator scores against
   *  to compute scoreBefore + apply the patch. */
  readonly packedParentStateHex: string;
  readonly patchHash: string;
  readonly corpusRoot: string;
  readonly bundleHash: string;
  readonly coreVersionHash: string;
  /** LIVE screener threshold (ppm) the coordinator is enforcing for THIS job.
   *  The scorer uses THIS for its advisory accept/reject + the committed
   *  artifact thresholdPpm — never CORETEX_SCREENER_THRESHOLD_PPM env, which
   *  can drift — and echoes it back as `thresholdPpmUsed`. The coordinator
   *  rejects the result if the echo != the threshold it sent. */
  readonly thresholdPpm: number;
  /** Policy / core-version hash the coordinator pins for this job. Echoed back
   *  in the result so the coordinator can reject a result computed under a
   *  drifted policy (defense-in-depth alongside the pin checks). */
  readonly policyHash: string;
  readonly publicEvalContext?: ScorerPublicEvalContext;
  readonly compactPatchBytesHex: string;
  readonly miner: string;
  readonly expectedScorerPins: ScorerExpectedPins;
}

/** Runtime fingerprint the coordinator checks before signing (model/dtype/cuda
 *  must match the attested expectation). Carries NO signing material. */
export interface ScorerHealth {
  readonly commit: string;
  readonly modelId: string;
  readonly revision: string;
  readonly promptTemplateHash: string;
  readonly dtype: 'fp32';
  readonly tf32: false;
  readonly cuda: boolean;
  readonly device: string;
  readonly torch: string | null;
  readonly transformers: string | null;
  readonly python: string | null;
}

export interface ScorerJobResult {
  readonly jobId: string;
  readonly accepted: boolean;
  readonly rejectionReason?: string;
  readonly scoreBeforePpm: number | null;
  readonly scoreAfterPpm: number | null;
  readonly deltaPpm: number;
  readonly gateScorePpm: number;
  readonly confirmScorePpm: number;
  /** The screener threshold (ppm) the scorer ACTUALLY used — echoes
   *  `job.thresholdPpm`. The coordinator rejects the result unless this equals
   *  the live threshold it sent (no env drift). */
  readonly thresholdPpmUsed: number;
  /** Echoes `job.policyHash` so the coordinator can reject a result computed
   *  under a drifted policy/core-version pin. */
  readonly policyHash: string;
  /** Present only when accepted (built via the canonical eval-report builder). */
  readonly evalReportHash?: string;
  readonly artifactHash?: string;
  /** The FULL canonical CoreTexPostRevealEvalReportArtifact (§3) — the exact
   *  object buildPostRevealEvalReportArtifact produced, whose single hash is
   *  BOTH evalReportHash and artifactHash. Present only when accepted. The
   *  coordinator recomputes hashPostRevealEvalReportArtifact(artifact), verifies
   *  it == artifactHash == evalReportHash + the context pins, then spools the
   *  bytes atomically to the artifact spool BEFORE signing. */
  readonly artifact?: CoreTexPostRevealEvalReportArtifact;
  /** Dual-pack proof the coordinator re-validates against live pins before signing. */
  readonly evaluationProof?: CoreTexDualPackEvaluationProof;
  /** Coord-rewritten patch bytes (state_advance only) — the embedded scoreDelta
   *  equals scoreAfter - scoreBefore. The coordinator re-checks semantics. */
  readonly rewrittenPatchBytesHex?: string;
  readonly pairTraceHash: string;
  readonly scoreArrayHash: string;
  readonly totalScoredPairCount: number;
  readonly wallMs: number;
  readonly telemetry: unknown;
  readonly scorerHealth: ScorerHealth;
}

// ─── Loaded-pins computation (shared with the coordinator's expectation) ─────

export interface ScorerLoadedPins {
  readonly modelId: string;
  readonly revision: string;
  readonly promptTemplateHash: string;
  readonly bundleHash: string;
  readonly corpusRoot: string;
  readonly coreVersionHash: string;
}

function hexEq(a: string | undefined, b: string | undefined): boolean {
  return typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
}

/**
 * Validate a job's pins against what the scorer actually loaded. Returns a
 * refusal reason string, or null when the job may proceed. Pure — unit-tested
 * directly with a fake set of loaded pins.
 */
export function checkScorerJobPins(job: ScorerJobRequest, loaded: ScorerLoadedPins): string | null {
  const p = job.expectedScorerPins;
  if (!p || typeof p !== 'object') return 'expectedScorerPins missing';
  if (p.modelId !== loaded.modelId) return `expectedScorerPins.modelId ${p.modelId} != loaded ${loaded.modelId}`;
  if (p.revision !== loaded.revision) return `expectedScorerPins.revision ${p.revision} != loaded ${loaded.revision}`;
  if (!hexEq(p.promptTemplateHash, loaded.promptTemplateHash)) {
    return `expectedScorerPins.promptTemplateHash != loaded ${loaded.promptTemplateHash}`;
  }
  if (!hexEq(p.bundleHash, loaded.bundleHash)) return `expectedScorerPins.bundleHash != loaded ${loaded.bundleHash}`;
  if (!hexEq(p.corpusRoot, loaded.corpusRoot)) return `expectedScorerPins.corpusRoot != loaded ${loaded.corpusRoot}`;
  // Job-level context pins must ALSO match what was loaded (the coordinator
  // sends them independently of expectedScorerPins; both must agree).
  if (!hexEq(job.corpusRoot, loaded.corpusRoot)) return `job.corpusRoot != loaded ${loaded.corpusRoot}`;
  if (!hexEq(job.bundleHash, loaded.bundleHash)) return `job.bundleHash != loaded ${loaded.bundleHash}`;
  if (!hexEq(job.coreVersionHash, loaded.coreVersionHash)) return `job.coreVersionHash != loaded ${loaded.coreVersionHash}`;
  return null;
}

/**
 * Verify the job's packed parent substrate against its pinned `parentStateRoot`.
 * The keyless scorer holds no chain state, so the parent substrate is supplied
 * WITH the job; this is the load-bearing trust check that makes scoring honest —
 * the evaluator only ever scores against a substrate that re-merkleizes to the
 * pin the coordinator (and chain) attest. Returns the verified `CortexState` on
 * match, or a refusal reason string. Pure — unit-tested directly.
 */
export function verifyJobParentState(
  job: Pick<ScorerJobRequest, 'parentStateRoot' | 'packedParentStateHex'>,
): { readonly ok: true; readonly state: CortexState } | { readonly ok: false; readonly reason: string } {
  let state: CortexState;
  try {
    state = unpack(hexToBytes(job.packedParentStateHex));
  } catch (e) {
    return { ok: false, reason: `packedParentStateHex did not unpack: ${(e as Error).message}` };
  }
  const recomputed = bytesToHex(merkleizeState(state)).toLowerCase();
  if (recomputed !== job.parentStateRoot.toLowerCase()) {
    return { ok: false, reason: `packedParentStateHex merkles to ${recomputed} != job.parentStateRoot ${job.parentStateRoot.toLowerCase()}` };
  }
  return { ok: true, state };
}

/**
 * Resolve the §8 coordinator-pinned seed context from the job's
 * publicEvalContext. The keyless scorer is NEVER allowed to draw its own
 * future blockhash on the remote path: the seed is coordinator-authoritative.
 * Returns:
 *   - `{ seedContext }` when receivedAtBlock + targetBlock + blockhash are ALL
 *     present and well-formed (the scorer injects it verbatim);
 *   - `{}` when ALL three are absent (legacy/local replay — the scorer may fall
 *     back to its own BASE_RPC_URL blockhash binding);
 *   - `{ error }` on a PARTIAL or malformed seed (fail-closed — a half-pinned
 *     seed must never silently fall back to a fresh draw). Pure — unit-tested.
 */
export function resolveJobSeedContext(
  job: Pick<ScorerJobRequest, 'publicEvalContext'>,
): { readonly seedContext?: CoreTexEvalSeedContext; readonly error?: string } {
  const ctx = job.publicEvalContext;
  const has = (v: unknown) => v !== undefined && v !== null;
  const present = ctx ? [ctx.receivedAtBlock, ctx.targetBlock, ctx.blockhash].filter(has).length : 0;
  if (!ctx || present === 0) return {};
  if (present !== 3) {
    return { error: 'publicEvalContext seed must carry receivedAtBlock + targetBlock + blockhash together (no partial pin)' };
  }
  const { receivedAtBlock, targetBlock, blockhash } = ctx;
  if (!Number.isSafeInteger(receivedAtBlock) || (receivedAtBlock as number) <= 0) {
    return { error: `publicEvalContext.receivedAtBlock must be a positive integer (got ${String(receivedAtBlock)})` };
  }
  if (!Number.isSafeInteger(targetBlock) || (targetBlock as number) <= 0) {
    return { error: `publicEvalContext.targetBlock must be a positive integer (got ${String(targetBlock)})` };
  }
  if (typeof blockhash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(blockhash)) {
    return { error: 'publicEvalContext.blockhash must be bytes32' };
  }
  return {
    seedContext: {
      receivedAtBlock: receivedAtBlock as number,
      targetBlock: targetBlock as number,
      blockhash: blockhash.toLowerCase(),
    },
  };
}

function validateJobShape(job: unknown): string | null {
  if (!job || typeof job !== 'object') return 'job must be an object';
  const j = job as Record<string, unknown>;
  if (typeof j.jobId !== 'string' || !j.jobId) return 'jobId required';
  if (!Number.isSafeInteger(j.epochId)) return 'epochId must be an integer';
  for (const key of ['parentStateRoot', 'patchHash', 'corpusRoot', 'bundleHash', 'coreVersionHash'] as const) {
    if (typeof j[key] !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(j[key] as string)) return `${key} must be bytes32`;
  }
  if (typeof j.compactPatchBytesHex !== 'string' || !/^0x[0-9a-fA-F]*$/.test(j.compactPatchBytesHex)) {
    return 'compactPatchBytesHex must be hex';
  }
  // The packed parent substrate MUST be exactly PACKED_SIZE bytes (1024×32) of
  // hex. Wrong-length bytes can never merkleize to the pinned root, but reject
  // early with a precise reason before the unpack attempt.
  if (typeof j.packedParentStateHex !== 'string' || !/^0x[0-9a-fA-F]*$/.test(j.packedParentStateHex)) {
    return 'packedParentStateHex must be hex';
  }
  if ((j.packedParentStateHex.length - 2) / 2 !== PACKED_SIZE) {
    return `packedParentStateHex must be ${PACKED_SIZE} bytes (got ${(j.packedParentStateHex.length - 2) / 2})`;
  }
  if (typeof j.miner !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(j.miner)) return 'miner must be an address';
  if (!Number.isSafeInteger(j.thresholdPpm) || (j.thresholdPpm as number) < 0) return 'thresholdPpm must be a non-negative integer';
  if (typeof j.policyHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(j.policyHash)) return 'policyHash must be bytes32';
  if (!j.expectedScorerPins || typeof j.expectedScorerPins !== 'object') return 'expectedScorerPins required';
  return null;
}

// ─── Job handler (pure, evaluator-injectable; CLI + tests share it) ──────────

export interface ScorerJobHandlerDeps {
  readonly evaluator: Pick<ProductionCoreTexEvaluator, 'scorePatch'>;
  readonly tracedReranker: Pick<TracedReranker, 'resetTrace' | 'traceSnapshot'>;
  readonly loadedPins: ScorerLoadedPins;
  readonly scorerHealth: ScorerHealth;
  /** Telemetry snapshot for the job (e.g. reranker cache stats). Optional. */
  readonly telemetry?: () => unknown;
  readonly now?: () => number;
}

export type ScorerJobResponse =
  | { readonly status: 200; readonly body: ScorerJobResult }
  | { readonly status: number; readonly body: { readonly error: string; readonly reason: string } };

/**
 * Run one scored job. REFUSES (4xx, no eval) on a malformed job or any pin
 * mismatch. Otherwise runs the production scorePatch, snapshots the per-job
 * pair-trace, and returns the full result. KEYLESS — no signing material is
 * ever in scope here.
 */
export async function handleScoreJob(
  job: ScorerJobRequest,
  deps: ScorerJobHandlerDeps,
): Promise<ScorerJobResponse> {
  const shape = validateJobShape(job);
  if (shape) return { status: 400, body: { error: 'invalid-job', reason: shape } };
  const pinMismatch = checkScorerJobPins(job, deps.loadedPins);
  if (pinMismatch) return { status: 409, body: { error: 'pin-mismatch', reason: pinMismatch } };
  // The keyless scorer holds no chain state: REFUSE (no eval) unless the parent
  // substrate shipped with the job re-merkleizes to the pinned parentStateRoot.
  // Only the verified state is handed to the evaluator (replacing the throwing
  // boot stub), so scoreBefore + applyPatch run against the attested parent.
  const parent = verifyJobParentState(job);
  if (!parent.ok) {
    return { status: 422, body: { error: 'SCORER_PARENT_STATE_MISMATCH', reason: parent.reason } };
  }

  // §8 anti-grinding: when the coordinator ships a PINNED seed context with the
  // job, the scorer injects it verbatim and NEVER draws its own future blockhash
  // (the seed is coordinator-authoritative + crash-safe). A retry of the same
  // (epochId, parentStateRoot, patchHash) thus scores the SAME hidden packs.
  const pinnedSeed = resolveJobSeedContext(job);
  if (pinnedSeed.error) {
    return { status: 422, body: { error: 'SCORER_SEED_CONTEXT_INVALID', reason: pinnedSeed.error } };
  }

  const now = deps.now ?? (() => Date.now());
  // Per-job trace: every scored pair in THIS job folds into a fresh chain.
  deps.tracedReranker.resetTrace();
  const start = now();
  let result: ProductionEvalResult;
  try {
    result = await deps.evaluator.scorePatch({
      patchBytesHex: job.compactPatchBytesHex,
      parentStateRoot: job.parentStateRoot,
      miner: job.miner,
      parentState: parent.state,
      // §2 (threshold honesty): the scorer uses the LIVE threshold the
      // coordinator shipped with the job — never CORETEX_SCREENER_THRESHOLD_PPM
      // env — for its advisory accept/reject + the committed artifact threshold.
      screenerThresholdPpm: job.thresholdPpm,
      // §8: inject the coordinator-pinned seed (when present) so the scorer
      // never re-rolls a fresh blockhash on a retry.
      ...(pinnedSeed.seedContext ? { seedContext: pinnedSeed.seedContext } : {}),
    });
  } catch (e) {
    return { status: 500, body: { error: 'eval-failure', reason: (e as Error)?.message ?? 'scorePatch threw' } };
  }
  const wallMs = now() - start;
  const trace = deps.tracedReranker.traceSnapshot();

  const base = {
    jobId: job.jobId,
    // §2: echo the threshold the scorer USED (the job's, not env) + the policy
    // pin, so the coordinator can reject a result computed under a drifted
    // threshold / policy.
    thresholdPpmUsed: job.thresholdPpm,
    policyHash: job.policyHash.toLowerCase(),
    pairTraceHash: trace.pairTraceHash,
    scoreArrayHash: trace.scoreArrayHash,
    totalScoredPairCount: trace.totalScoredPairCount,
    wallMs,
    telemetry: deps.telemetry ? deps.telemetry() : null,
    scorerHealth: deps.scorerHealth,
  };

  if (result.outcome === 'reject') {
    return {
      status: 200,
      body: {
        ...base,
        accepted: false,
        rejectionReason: result.code,
        scoreBeforePpm: null,
        scoreAfterPpm: null,
        deltaPpm: 0,
        gateScorePpm: 0,
        confirmScorePpm: 0,
      },
    };
  }

  const proof = result.evaluationProof;
  const gateScorePpm = proof?.gate.scorePpm ?? 0;
  const confirmScorePpm = proof?.confirm.scorePpm ?? 0;
  return {
    status: 200,
    body: {
      ...base,
      accepted: true,
      scoreBeforePpm: result.outcome === 'state_advance' ? result.scoreBeforePpm : null,
      scoreAfterPpm: result.outcome === 'state_advance' ? result.scoreAfterPpm : null,
      deltaPpm: result.deterministicDeltaPpm,
      gateScorePpm,
      confirmScorePpm,
      evalReportHash: result.evalReportHash,
      artifactHash: result.artifactHash,
      // §3: return the FULL canonical artifact bytes so the coordinator can
      // spool the identical on-disk artifact (tmp+rename) BEFORE signing.
      ...(result.artifact ? { artifact: result.artifact } : {}),
      ...(proof ? { evaluationProof: proof } : {}),
      ...(result.outcome === 'state_advance' ? { rewrittenPatchBytesHex: result.rewrittenPatchBytesHex } : {}),
    },
  };
}

// ─── Boot: build the keyless GPU evaluator + health (CLI only) ───────────────

function gitCommit(): string {
  try {
    return execFileSync('git', ['rev-parse', '--short', 'HEAD'], { encoding: 'utf8' }).trim() || 'unknown';
  } catch {
    return 'unknown';
  }
}

function probeRuntimeHealth(): Pick<ScorerHealth, 'cuda' | 'device' | 'torch' | 'transformers' | 'python'> {
  const pythonBin = process.env['CORETEX_RERANKER_PYTHON'] ?? 'python3';
  const script = resolveRerankerScriptPath();
  try {
    const out = execFileSync(pythonBin, [script, '--health'], {
      encoding: 'utf8',
      env: { ...process.env, CORETEX_RERANKER_ALLOW_CUDA: '1' },
    });
    const h = JSON.parse(out.trim().split('\n').pop() ?? '{}') as Record<string, unknown>;
    return {
      cuda: h.cuda === true,
      device: typeof h.device === 'string' ? h.device : 'unknown',
      torch: typeof h.torch === 'string' ? h.torch : null,
      transformers: typeof h.transformers === 'string' ? h.transformers : null,
      python: typeof h.python === 'string' ? h.python : null,
    };
  } catch (e) {
    process.stderr.write(`[scorer] runtime health probe failed: ${(e as Error).message}\n`);
    return { cuda: false, device: 'unknown', torch: null, transformers: null, python: null };
  }
}

interface BootedScorer {
  readonly evaluator: ProductionCoreTexEvaluator;
  readonly tracedReranker: TracedReranker;
  readonly loadedPins: ScorerLoadedPins;
  readonly scorerHealth: ScorerHealth;
  readonly telemetry: () => unknown;
}

async function bootScorer(env: NodeJS.ProcessEnv): Promise<BootedScorer> {
  // Fail-closed env: assert the production reranker contract BEFORE the heavy
  // model load, and assert CUDA is explicitly enabled (this is the GPU half).
  const required: Record<string, string> = {
    CORETEX_RERANKER: 'qwen3',
    CORTEX_REAL_EVAL: '1',
    CORETEX_RERANKER_PRODUCTION: '1',
    CORETEX_RERANKER_MODE: 'streaming',
    CORETEX_RERANKER_ALLOW_CUDA: '1',
  };
  for (const [name, value] of Object.entries(required)) {
    if (env[name] !== value) {
      throw new Error(`coretex-scorer-server requires ${name}=${value} (got ${env[name] ?? 'unset'})`);
    }
  }
  const bundleManifestPath = requiredEnv(env, 'CORETEX_BUNDLE_MANIFEST_PATH');
  const corpusPath = requiredEnv(env, 'CORETEX_CORPUS_PATH');
  const epochId = Number(requiredEnv(env, 'CORETEX_EPOCH_ID'));
  const epochSecret = requiredEnv(env, 'CORETEX_EPOCH_SECRET');
  const perMinerCap = Number(requiredEnv(env, 'CORETEX_PER_MINER_SCREENER_CAP'));
  const innerBatch = Number(env['RERANKER_INNER_BATCH'] ?? '8') || 8;

  const bundle = JSON.parse(readFileSync(bundleManifestPath, 'utf8')) as CoreTexBundleManifest;
  const corpus = loadProductionCorpus(corpusPath, { verifyCorpusRoot: true, verifySplits: true });

  // The traced reranker is captured so /score-job can reset+snapshot per job;
  // the inner streaming reranker is captured for cache telemetry (getRerankerCacheStats
  // keys on the withRerankerCache-wrapped object, i.e. the streaming reranker).
  let tracedReranker: TracedReranker | undefined;
  let innerReranker: CrossEncoderReranker | undefined;
  // The keyless GPU reranker: a CUDA-enabled streaming Qwen3 wrapped with the
  // SAME pair-trace as the CPU parity harness. ALLOW_CUDA is set; the Node-side
  // CPU guard only refuses when CUDA_VISIBLE_DEVICES / CORETEX_USE_GPU are set,
  // so we clear CUDA_VISIBLE_DEVICES at the Node layer and let the Python runner
  // place the model on CUDA via CORETEX_RERANKER_ALLOW_CUDA=1 (fp32/tf32=false).
  delete process.env['CUDA_VISIBLE_DEVICES'];
  delete process.env['CORETEX_USE_GPU'];
  const rerankerFactory = (plan: ProductionRerankerPlan): CrossEncoderReranker => {
    const numThreads = Number(env['RERANKER_NUM_THREADS'] ?? '0') || undefined;
    const cacheDir = env['CORTEX_LOCAL_MODEL_CACHE'];
    const streaming = createStreamingQwen3Reranker({
      model: plan.modelId,
      revision: plan.revision,
      ...(cacheDir ? { cacheDir } : {}),
      localOnly: env['CORTEX_LOCAL_MODEL_LOCAL_ONLY'] === '1',
      batchSize: innerBatch,
      ...(numThreads ? { numThreads } : {}),
    });
    innerReranker = streaming;
    tracedReranker = wrapRerankerWithPairTrace(streaming);
    return tracedReranker;
  };

  const evaluator = await createProductionCoreTexEvaluator({
    epochId,
    epochSecret,
    corpusPath,
    bundleManifestPath,
    // Keyless: the scorer holds no chain state. Every /score-job ships the
    // merkle-verified parent substrate (packedParentStateHex), which the job
    // handler unpacks, re-merkleizes against parentStateRoot, and passes to the
    // evaluator as `parentState` — so the production evaluator's
    // `input.parentState ?? parentStateLoader(...)` always takes the supplied
    // state. This loader is the defense-in-depth fallback: it must never be
    // reached (the handler refuses any job without a verified parent first).
    parentStateLoader: () => { throw new Error('coretex-scorer-server: parentState must be supplied with the job (parentStateLoader unset)'); },
    dedupStore: createInMemoryDedupStore(),
    perMinerCap,
    ...(env['CORETEX_SCREENER_THRESHOLD_PPM'] ? { screenerThresholdPpm: Number(env['CORETEX_SCREENER_THRESHOLD_PPM']) } : {}),
    rerankerFactory,
  });
  if (!tracedReranker) throw new Error('coretex-scorer-server: reranker factory was not invoked');

  const att = evaluator.bootAttestation;
  const loadedPins: ScorerLoadedPins = {
    modelId: att.rerankerModelId,
    revision: att.rerankerRevision,
    promptTemplateHash: att.promptTemplateHash.toLowerCase(),
    bundleHash: bundle.bundleHash.toLowerCase(),
    corpusRoot: corpus.corpusRoot.toLowerCase(),
    coreVersionHash: bundle.bundleHash.toLowerCase(),
  };
  const runtime = probeRuntimeHealth();
  const scorerHealth: ScorerHealth = {
    commit: gitCommit(),
    modelId: loadedPins.modelId,
    revision: loadedPins.revision,
    promptTemplateHash: loadedPins.promptTemplateHash,
    dtype: 'fp32',
    tf32: false,
    cuda: runtime.cuda,
    device: runtime.device,
    torch: runtime.torch,
    transformers: runtime.transformers,
    python: runtime.python,
  };
  // Cross-check the resolved prompt-template hash against the canonical render.
  const instructionHash = qwenRerankerPromptTemplateHash(resolveQwenRerankerInstruction(env));
  if (instructionHash.toLowerCase() !== loadedPins.promptTemplateHash) {
    throw new Error(`coretex-scorer-server: resolved promptTemplateHash ${instructionHash} != boot attestation ${loadedPins.promptTemplateHash}`);
  }
  const traced = tracedReranker;
  const inner = innerReranker;
  return {
    evaluator,
    tracedReranker: traced,
    loadedPins,
    scorerHealth,
    telemetry: () => {
      const stats: RerankerCacheStats | undefined = inner ? getRerankerCacheStats(inner) : undefined;
      return {
        rerankerCache: stats ? { hits: stats.hits, misses: stats.misses, evictions: stats.evictions, size: stats.size() } : null,
      };
    },
  };
}

function requiredEnv(env: NodeJS.ProcessEnv, name: string): string {
  const v = env[name];
  if (!v || !v.trim()) throw new Error(`coretex-scorer-server requires env ${name}`);
  return v.trim();
}

/** Default HTTP request-body byte limit. The body carries packedParentStateHex
 *  (PACKED_SIZE×2 ≈ 64 KB of hex) plus the patch bytes + public context, so the
 *  default is well clear of a realistic job; overridable via
 *  CORETEX_SCORER_BODY_LIMIT_BYTES. */
export const DEFAULT_SCORER_BODY_LIMIT_BYTES = 4 * 1024 * 1024;

function readJsonBody(req: http.IncomingMessage, maxBytes: number): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      try {
        resolve(raw.length > 0 ? JSON.parse(raw) : null);
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

async function main(): Promise<void> {
  const port = Number(process.env['CORETEX_SCORER_PORT'] ?? '8888') || 8888;
  const host = process.env['CORETEX_SCORER_HOST'] ?? '127.0.0.1';
  // The body now carries packedParentStateHex (PACKED_SIZE×2 ≈ 64 KB of hex)
  // plus the patch bytes + public context, so the default limit is raised well
  // clear of that (4 MB) — overridable via CORETEX_SCORER_BODY_LIMIT_BYTES.
  const bodyLimit = Number(process.env['CORETEX_SCORER_BODY_LIMIT_BYTES'] ?? String(DEFAULT_SCORER_BODY_LIMIT_BYTES)) || DEFAULT_SCORER_BODY_LIMIT_BYTES;

  process.stdout.write('[scorer] booting keyless GPU production evaluator (this loads the model once)...\n');
  const booted = await bootScorer(process.env);
  process.stdout.write(
    `[scorer] ready: model=${booted.loadedPins.modelId}@${booted.loadedPins.revision} ` +
    `bundle=${booted.loadedPins.bundleHash} corpus=${booted.loadedPins.corpusRoot} ` +
    `cuda=${booted.scorerHealth.cuda} device=${booted.scorerHealth.device} ` +
    `torch=${booted.scorerHealth.torch} commit=${booted.scorerHealth.commit}\n`,
  );

  const server = http.createServer((req, res) => {
    const send = (status: number, body: unknown) => {
      const json = JSON.stringify(body);
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(json);
    };
    void (async () => {
      if (req.method === 'GET' && req.url === '/healthz') {
        send(200, { ok: true, loadedPins: booted.loadedPins, scorerHealth: booted.scorerHealth });
        return;
      }
      if (req.method === 'POST' && (req.url === '/score-job' || req.url?.startsWith('/score-job?'))) {
        let job: unknown;
        try {
          job = await readJsonBody(req, bodyLimit);
        } catch (e) {
          send((e as Error).message.includes('too large') ? 413 : 400, { error: 'bad-body', reason: (e as Error).message });
          return;
        }
        const response = await handleScoreJob(job as ScorerJobRequest, booted);
        send(response.status, response.body);
        return;
      }
      send(404, { error: 'not-found', reason: `${req.method} ${req.url}` });
    })().catch((e) => {
      send(500, { error: 'internal', reason: (e as Error)?.message ?? 'unknown' });
    });
  });

  server.listen(port, host, () => {
    process.stdout.write(`[scorer] listening on http://${host}:${port}\n`);
  });
  const shutdown = () => server.close(() => process.exit(0));
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

// Run only when invoked as the bin (not when imported by tests).
const invokedDirectly = process.argv[1]?.endsWith('scorer-server-cli.js')
  || process.argv[1]?.endsWith('scorer-server-cli.ts');
if (invokedDirectly) {
  main().catch((e) => {
    process.stderr.write(`HARD FAIL: ${(e as Error)?.stack ?? e}\n`);
    process.exit(1);
  });
}
