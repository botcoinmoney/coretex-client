/**
 * Production CoreTex evaluator (§2/§3/§8 score-honesty lane).
 *
 * FAIL-CLOSED construction contract:
 *   - `createProductionCoreTexEvaluator` refuses to construct unless
 *     CORETEX_RERANKER=qwen3, CORETEX_RERANKER_PRODUCTION=1 and
 *     CORTEX_REAL_EVAL=1 are all set, and the resolved reranker reports the
 *     bundle-pinned model id + revision. The deterministic hashing stub is
 *     UNREACHABLE from this constructor regardless of env — it never calls
 *     `rerankerFromEnv`, it builds the pinned Qwen3 backend directly.
 *   - A persistent `CoreTexEvalDedupStore` and a finite `perMinerCap` are
 *     REQUIRED at construction (anti-grinding §8): seeds include
 *     receivedAtBlock, so without cross-restart dedup a miner could resubmit
 *     identical patch bytes to draw fresh gate/confirm packs until lucky.
 *   - The evaluator exposes a hash-bound boot attestation (resolved model,
 *     revision, mode, instruction, canonical prompt-template hash,
 *     Memory-IR mode) for the bundle/boot binding path.
 *
 * Eval-report commitment (§3): accepted submissions build the CANONICAL
 * `CoreTexPostRevealEvalReportArtifact` (replay/eval-report-artifact.ts);
 * its single hash is returned as BOTH evalReportHash and artifactHash, so
 * the on-chain commitment is verifiable against the published artifact at
 * `<base>/eval-reports/<artifactHash>.json`.
 */
import { readFileSync } from 'node:fs';

import type { CortexState, Patch } from '../state/index.js';
import { decodePatch, encodePatch } from '../state/patch.js';
import { hexToBytes, bytesToHex } from '../state/merkle.js';
import { keccak256 } from '../state/keccak256.js';
import {
  DEFAULT_PROFILE,
  buildCoordinatorBootAttestation,
  scoringOptionsFromProfile,
  type AttestedCoordinatorBootAttestation,
  type CoreTexBundleManifest,
  type EvaluatorProfile,
} from '../bundle/index.js';
import {
  loadProductionCorpus,
  type ProductionCorpus,
} from '../eval/retrieval-corpus.js';
import { deriveQueryPack } from '../eval/hidden-query-pack.js';
import {
  computeAcceptanceThresholdPpm,
  evaluateRetrievalBenchmarkPatch,
  type PatchEvalResult,
} from '../eval/retrieval-benchmark.js';
import { biEncoderFromEnv } from '../eval/bi-encoder.js';
import {
  createQwen3Reranker,
  createStreamingQwen3Reranker,
  qwenRerankerPromptTemplateHash,
  resolveQwenRerankerInstruction,
  type CrossEncoderReranker,
} from '../eval/reranker.js';
import { computePatchHash } from '../eval/seed-derivation.js';
import { biEncoderModelIdHash } from '../substrate/retrieval-decoder.js';
import {
  buildPostRevealEvalReportArtifact,
  type CoreTexPostRevealEvalReportArtifact,
} from '../replay/eval-report-artifact.js';
import { rpcFetchTarget } from '../replay/v4.js';
import {
  runPerPatchEvaluation,
  dualPackProofFromPerPatchReceipt,
  type PerPatchReceipt,
  type PerPatchScorer,
  type PerPatchSeedContext,
} from './per-patch-evaluator.js';
import type { BaseBlockResponse, BaseRpcClient } from './base-blockhash.js';
import type { EvalResult, RealEvaluator } from './coretex-coordinator-core.js';

// ─── Grinding dedup store (§8) ────────────────────────────────────────────────

export interface CoreTexEvalDedupKey {
  readonly epochId: number;
  readonly parentStateRoot: string;   // bytes32 hex, lowercase
  readonly patchHash: string;         // bytes32 hex, lowercase
}

export interface CoreTexEvalDedupRecord extends CoreTexEvalDedupKey {
  readonly outcome: 'reject' | 'screener_pass' | 'state_advance';
  readonly code?: string;
}

/**
 * §8 anti-grinding attempt state machine. Closes the seed-redraw gap, AND
 * makes the seed pin and the per-miner admission charge ATOMIC: the durable
 * dedup record (above) is written only AFTER a result, but the seed (future
 * blockhash) is drawn fresh per attempt. A crash AFTER the draw but BEFORE the
 * outcome would otherwise let a retry of the same
 * (epochId, parentStateRoot, patchHash) draw a FRESH blockhash → a fresh
 * hidden gate/confirm pack, and — because the admission was charged only after
 * the result — leave the admission UNCHARGED, so a miner could exceed the
 * per-miner cap via crash/retry.
 *
 * The attempt record PINS the seed at first draw (`state: 'drawn'`, with the
 * `seedContext`) AND charges the admission in the SAME atomic write (carrying
 * the `minerAddress` + an `admissionCharged` marker); it is upgraded to
 * `'rejected'`/`'accepted'` after the result. On a retry, an existing
 * attempt's `seedContext` is REUSED (injected into runPerPatchEvaluation), so
 * the same packs are scored — never a fresh draw — and the admission is NOT
 * re-charged (exactly-once across crashes/restarts).
 * `recordSeedDrawnAndAdmission` MUST be durable BEFORE any scoring.
 */
export interface CoreTexEvalSeedContext {
  readonly receivedAtBlock: number;
  readonly targetBlock: number;
  readonly blockhash: string;         // bytes32 hex, lowercase
}

export interface CoreTexEvalAttemptRecord extends CoreTexEvalDedupKey {
  readonly state: 'drawn' | 'rejected' | 'accepted';
  readonly seedContext: CoreTexEvalSeedContext;
  /** Miner the atomic admission was charged to (lowercased). */
  readonly minerAddress: string;
  /** Set true by the atomic seed-draw write — the per-miner admission count is
   *  derived from these marked rows, so seed pin and admission charge can never
   *  diverge across a crash. */
  readonly admissionCharged: boolean;
  readonly outcome?: CoreTexEvalDedupRecord['outcome'];
  readonly code?: string;
}

/**
 * Persistence interface the host MUST provide. Records every evaluated
 * (epochId, parentStateRoot, patchHash) outcome so resubmitting identical
 * patch bytes can NEVER draw a fresh gate/confirm pack (the seeds include
 * receivedAtBlock — without this store, resubmission = retry-until-lucky).
 * Per-miner admission counts persist through the same interface so the cap
 * survives coordinator restarts.
 */
export interface CoreTexEvalDedupStore {
  get(key: CoreTexEvalDedupKey): Promise<CoreTexEvalDedupRecord | null> | CoreTexEvalDedupRecord | null;
  put(record: CoreTexEvalDedupRecord): Promise<void> | void;
  /** Per-miner admission count for the epoch, derived from the atomically-charged
   *  attempt rows (admissionCharged=1) so it can never diverge from the seed
   *  pins across a crash/restart. */
  minerAdmissions(epochId: number, minerAddress: string): Promise<number> | number;
  /** §8 seed-redraw closure: the in-flight attempt for a key (its pinned seed
   *  context + state), or null if no seed has been drawn yet. */
  getAttempt(key: CoreTexEvalDedupKey): Promise<CoreTexEvalAttemptRecord | null> | CoreTexEvalAttemptRecord | null;
  /** Atomically pin the drawn seed (state='drawn') AND charge the miner's
   *  admission in ONE durable transaction, BEFORE any scoring. The attempt row
   *  carries the miner + an admissionCharged marker, and `minerAddress` is the
   *  count the per-miner cap is derived from. Idempotent on the key: a re-draw
   *  on an existing attempt must NOT overwrite the pinned seedContext NOR charge
   *  the admission again (the retry already reuses the pinned seed + slot) →
   *  admission is charged exactly-once per distinct first-time draw, even across
   *  crashes/restarts. */
  recordSeedDrawnAndAdmission(
    key: CoreTexEvalDedupKey,
    seedContext: CoreTexEvalSeedContext,
    minerAddress: string,
  ): Promise<void> | void;
  /** Upgrade the attempt to its terminal state ('rejected'/'accepted') after the
   *  verified result, preserving the pinned seedContext + the charged admission. */
  recordAttemptOutcome(
    key: CoreTexEvalDedupKey,
    state: 'rejected' | 'accepted',
    outcome: CoreTexEvalDedupRecord['outcome'],
    code?: string,
  ): Promise<void> | void;
}

/** In-memory store for tests and for a persistent sidecar to wrap. The
 *  production constructor does NOT default to this — pass a store that
 *  actually persists across restarts. */
export function createInMemoryDedupStore(): CoreTexEvalDedupStore {
  const records = new Map<string, CoreTexEvalDedupRecord>();
  const attempts = new Map<string, CoreTexEvalAttemptRecord>();
  const recordKey = (k: CoreTexEvalDedupKey) =>
    `${k.epochId}|${k.parentStateRoot.toLowerCase()}|${k.patchHash.toLowerCase()}`;
  const normalizeKey = (k: CoreTexEvalDedupKey): CoreTexEvalDedupKey => ({
    epochId: k.epochId,
    parentStateRoot: k.parentStateRoot.toLowerCase(),
    patchHash: k.patchHash.toLowerCase(),
  });
  return {
    get(key) { return records.get(recordKey(key)) ?? null; },
    put(record) { records.set(recordKey(record), record); },
    // Admission count is DERIVED from the atomically-charged attempt rows: the
    // count and the seed pins are the SAME write, so they can never diverge.
    minerAdmissions(epochId, minerAddress) {
      const miner = minerAddress.toLowerCase();
      let count = 0;
      for (const a of attempts.values()) {
        if (a.epochId === epochId && a.admissionCharged && a.minerAddress === miner) count += 1;
      }
      return count;
    },
    getAttempt(key) { return attempts.get(recordKey(key)) ?? null; },
    // Atomic (single synchronous call): pin the seed AND charge the admission.
    // Idempotent on the key — an existing attempt is left untouched (the retry
    // reuses the pinned seed and is NOT re-charged), so admission is charged
    // exactly-once per first-time draw.
    recordSeedDrawnAndAdmission(key, seedContext, minerAddress) {
      const mapKey = recordKey(key);
      if (attempts.has(mapKey)) return;
      attempts.set(mapKey, {
        ...normalizeKey(key),
        state: 'drawn',
        seedContext: { ...seedContext, blockhash: seedContext.blockhash.toLowerCase() },
        minerAddress: minerAddress.toLowerCase(),
        admissionCharged: true,
      });
    },
    recordAttemptOutcome(key, state, outcome, code) {
      const mapKey = recordKey(key);
      const prior = attempts.get(mapKey);
      if (!prior) {
        throw new Error('recordAttemptOutcome called before recordSeedDrawnAndAdmission (no pinned seed)');
      }
      attempts.set(mapKey, { ...prior, state, outcome, ...(code ? { code } : {}) });
    },
  };
}

// ─── Fail-closed reranker resolution (§2) ─────────────────────────────────────

export interface ProductionRerankerPin {
  readonly modelId: string;
  readonly revision: string;
}

export interface ProductionRerankerPlan {
  readonly mode: 'qwen3-streaming' | 'qwen3-per-batch';
  readonly modelId: string;
  readonly revision: string;
  readonly instruction: string;
}

/**
 * Pure fail-closed env resolution. Throws unless the environment explicitly
 * opts into the production Qwen3 path AND agrees with the bundle pin. There
 * is NO branch that yields the deterministic stub — by construction.
 */
export function resolveProductionRerankerPlan(
  pin: ProductionRerankerPin,
  env: NodeJS.ProcessEnv = process.env,
): ProductionRerankerPlan {
  if (!pin.modelId || !pin.revision) {
    throw new Error('production CoreTex evaluator requires a bundle reranker pin (modelId + revision)');
  }
  for (const name of ['CORTEX_REAL_EVAL', 'CORETEX_RERANKER_PRODUCTION'] as const) {
    if (env[name] !== '1') {
      throw new Error(
        `production CoreTex evaluator refuses to construct: ${name}=1 is required (got ${env[name] ?? 'unset'})`,
      );
    }
  }
  if (env['CORETEX_RERANKER'] !== 'qwen3') {
    throw new Error(
      `production CoreTex evaluator refuses to construct: CORETEX_RERANKER=qwen3 is required (got ${env['CORETEX_RERANKER'] ?? 'unset'})`,
    );
  }
  if (env['CORETEX_ALLOW_DETERMINISTIC_RERANKER'] === '1') {
    throw new Error(
      'production CoreTex evaluator refuses to construct with CORETEX_ALLOW_DETERMINISTIC_RERANKER=1 (test-only escape hatch)',
    );
  }
  const modelOverride = env['CORETEX_RERANKER_MODEL_ID'];
  if (modelOverride !== undefined && modelOverride !== pin.modelId) {
    throw new Error(
      `CORETEX_RERANKER_MODEL_ID=${modelOverride} conflicts with bundle reranker pin ${pin.modelId}`,
    );
  }
  const revisionOverride = env['CORETEX_RERANKER_REVISION'];
  if (revisionOverride !== undefined && revisionOverride !== pin.revision) {
    throw new Error(
      `CORETEX_RERANKER_REVISION=${revisionOverride} conflicts with bundle reranker pin revision ${pin.revision}`,
    );
  }
  // Production defaults to the persistent streaming model server: ONE python
  // process loads Qwen once and stays warm. The per-batch path re-spawns
  // python and reloads the ~0.6GB model for every batch (default 4 pairs) —
  // an eval over tens of thousands of pairs becomes thousands of cold model
  // loads, turning a ~minutes eval into hours. It is reachable only under an
  // explicit dev/test escape, never by default.
  let mode: ProductionRerankerPlan['mode'] = 'qwen3-streaming';
  const modeEnv = env['CORETEX_RERANKER_MODE'];
  if (modeEnv === 'per-batch' || modeEnv === 'per_batch') {
    if (env['CORETEX_ALLOW_PER_BATCH_RERANKER'] !== 'dev-only-i-understand') {
      throw new Error(
        'production CoreTex evaluator refuses CORETEX_RERANKER_MODE=per-batch: it reloads the ' +
          'model for every batch (catastrophic on a live coordinator). Unset CORETEX_RERANKER_MODE ' +
          'to use the streaming model server, or set CORETEX_ALLOW_PER_BATCH_RERANKER=dev-only-i-understand ' +
          'for a dev/test run.',
      );
    }
    mode = 'qwen3-per-batch';
  } else if (modeEnv !== undefined && modeEnv !== 'streaming') {
    throw new Error(`unknown CORETEX_RERANKER_MODE=${modeEnv} (expected 'streaming', 'per-batch', or unset)`);
  }
  return {
    mode,
    modelId: pin.modelId,
    revision: pin.revision,
    instruction: resolveQwenRerankerInstruction(env),
  };
}

function assertResolvedRerankerMatchesPin(reranker: CrossEncoderReranker, plan: ProductionRerankerPlan): void {
  const expected = `${plan.modelId}@${plan.revision}`;
  if (reranker.model !== expected) {
    throw new Error(`resolved reranker '${reranker.model}' does not report the pinned '${expected}'`);
  }
}

// ─── Evaluator types ──────────────────────────────────────────────────────────

/** Production reject results carry NO score telemetry (§8 envelope strip):
 *  deterministicDeltaPpm / requiredDeltaPpm leak a per-pack score oracle to
 *  the submitting miner, so the production evaluator's reject type omits
 *  them entirely. coretex-coordinator-core spreads them conditionally, so
 *  this narrower type stays assignable to its EvalResult. */
export type ProductionEvalRejectResult = {
  readonly outcome: 'reject';
  readonly code: string;
  readonly reason: string;
};

/** §3 artifact-bytes return: accepted production results carry the FULL
 *  canonical post-reveal eval-report artifact (the exact object whose single
 *  hash is BOTH evalReportHash and artifactHash). The keyless scorer server
 *  returns these bytes to the coordinator so the remote path can spool the
 *  identical on-disk artifact the local publishArtifact hook would write —
 *  BEFORE signing. The local coordinator path ignores this field (it spools
 *  via publishArtifact directly). Optional so the narrower type stays
 *  assignable to the core's EvalResult. */
export type ProductionEvalResult =
  | ProductionEvalRejectResult
  | (Extract<EvalResult, { readonly outcome: 'screener_pass' }> & { readonly artifact?: CoreTexPostRevealEvalReportArtifact })
  | (Extract<EvalResult, { readonly outcome: 'state_advance' }> & { readonly artifact?: CoreTexPostRevealEvalReportArtifact });

export type ProductionCoreTexEvaluator = RealEvaluator & {
  scorePatch(input: {
    patchBytesHex: string;
    parentStateRoot: string;
    miner: string;
    parentState?: CortexState;
    /** Per-job screener threshold (ppm) override. The keyless scorer server
     *  passes the LIVE threshold carried in the job here so its advisory
     *  accept/reject + the committed artifact `thresholdPpm` reflect the
     *  threshold the coordinator sent — never a drifted CORETEX_SCREENER_THRESHOLD_PPM
     *  env. When omitted, the construction-time `screenerThresholdPpm` is used
     *  (the local CPU path is unchanged). The coordinator still re-derives the
     *  final decision from the returned scores vs its live threshold. */
    screenerThresholdPpm?: number;
    /** §8 anti-grinding (REMOTE/keyless path) — the coordinator-pinned seed
     *  context. On the keyless scorer path the COORDINATOR draws + DURABLY
     *  records the future-blockhash seed and ships it with the job; the scorer
     *  NEVER draws its own (seed is coordinator-authoritative + crash-safe).
     *  When supplied, it is injected into runPerPatchEvaluation verbatim (no RPC
     *  blockhash wait, no attempt-store draw of its own). The LOCAL CPU path
     *  omits this and pins via the durable attempt store instead. Scoring given
     *  the seed is byte-unchanged either way. */
    seedContext?: CoreTexEvalSeedContext;
  }): Promise<ProductionEvalResult>;
  /** Hash-bound boot attestation (§2): resolved model id + revision +
   *  reranker mode + instruction + prompt-template hash + Memory-IR mode. */
  readonly bootAttestation: AttestedCoordinatorBootAttestation;
  close?: () => Promise<void>;
};

export interface ProductionCoreTexEvaluatorOptions {
  readonly epochId: number;
  readonly epochSecret: string;
  readonly corpusPath: string;
  readonly bundleManifestPath: string;
  readonly parentStateLoader: (parentStateRoot: string) => Promise<CortexState> | CortexState;
  /** REQUIRED persistent grinding-dedup + per-miner-admission store. No
   *  in-memory default in production (createInMemoryDedupStore is for tests
   *  and for the persistence sidecar to wrap). */
  readonly dedupStore: CoreTexEvalDedupStore;
  /** REQUIRED finite per-miner live-eval admission cap (from the profile /
   *  operator config). MAX_SAFE_INTEGER or undefined is a construction error. */
  readonly perMinerCap: number;
  readonly rpcClient?: BaseRpcClient;
  readonly targetBlockOffset?: number;
  readonly screenerThresholdPpm?: number;
  /** Publish hook for the canonical eval-report artifact. Called BEFORE the
   *  accepted result is returned; a publish failure fails the evaluation
   *  (the on-chain hash must never commit to an unpublished artifact). */
  readonly publishArtifact?: (artifact: CoreTexPostRevealEvalReportArtifact) => Promise<void> | void;
  /** OPTIONAL reranker construction override. Default builds the pinned CPU-only
   *  streaming/per-batch Qwen3 backend. The keyless GPU scorer server injects an
   *  instrumented, CUDA-allowed reranker here so it can emit a pair-trace; the
   *  resolved reranker MUST still report the bundle-pinned `${modelId}@${revision}`
   *  (assertResolvedRerankerMatchesPin enforces this). The integration sidecar
   *  passes nothing, so the default CPU path is unchanged. */
  readonly rerankerFactory?: (plan: ProductionRerankerPlan) => Promise<CrossEncoderReranker> | CrossEncoderReranker;
}

// ─── Core orchestration (scorer-injectable; production + tests share it) ─────

export interface ProductionCoreTexEvaluatorCoreDeps {
  readonly epochId: number;
  readonly epochSecret: string;       // bytes32 hex
  readonly corpusRoot: string;        // bytes32 hex
  readonly bundleHash: string;        // bytes32 hex
  readonly stateThresholdPpm: number;
  readonly screenerThresholdPpm: number;
  readonly replayTolerancePpm: number;
  readonly targetBlockOffset: number;
  readonly perMinerCap: number;
  readonly rpcClient: BaseRpcClient;
  readonly dedupStore: CoreTexEvalDedupStore;
  readonly bootAttestation: AttestedCoordinatorBootAttestation;
  readonly parentStateLoader: (parentStateRoot: string) => Promise<CortexState> | CortexState;
  /** Canonical per-seed scorer. Production binds
   *  `evaluateRetrievalBenchmarkPatch` over the pinned corpus + models;
   *  tests pass a counting fake. */
  readonly seedScorer: (args: {
    readonly parent: CortexState;
    readonly normalizedPatchBytes: Uint8Array;
    readonly evalSeed: string;
    /** Effective screener threshold (ppm) for THIS evaluation — the per-job
     *  override when supplied, else the construction-time default. The seed
     *  scorer's acceptance floors honor exactly this number. */
    readonly thresholdPpm: number;
  }) => Promise<PatchEvalResult>;
  readonly publishArtifact?: (artifact: CoreTexPostRevealEvalReportArtifact) => Promise<void> | void;
  readonly close?: () => Promise<void>;
}

export function createCoreTexEvaluatorCore(deps: ProductionCoreTexEvaluatorCoreDeps): ProductionCoreTexEvaluator {
  validatePerMinerCap(deps.perMinerCap);
  if (!deps.dedupStore) {
    throw new Error('production CoreTex evaluator requires a CoreTexEvalDedupStore (fail-closed: no in-memory default)');
  }
  const hiddenSeedCommit = bytesToHex(keccak256(parseHex(deps.epochSecret, 'epochSecret'))).toLowerCase();

  const evaluator: ProductionCoreTexEvaluator = {
    bootAttestation: deps.bootAttestation,
    async scorePatch(input) {
      const patchBytes = parseHex(input.patchBytesHex, 'patchBytesHex');
      const patch = decodePatch(patchBytes);
      const parentStateRoot = input.parentStateRoot.toLowerCase();
      const patchHash = computePatchHash(patchBytes).toLowerCase();
      const dedupKey: CoreTexEvalDedupKey = { epochId: deps.epochId, parentStateRoot, patchHash };
      // Per-job screener-threshold override (keyless scorer ships the LIVE
      // threshold with the job so its advisory accept/reject + committed
      // artifact thresholdPpm never use a drifted env). Defaults to the
      // construction-time threshold (local CPU path unchanged).
      const effectiveThresholdPpm = input.screenerThresholdPpm ?? deps.screenerThresholdPpm;
      if (!Number.isSafeInteger(effectiveThresholdPpm) || effectiveThresholdPpm < 0) {
        throw new Error(`scorePatch: screenerThresholdPpm override must be a non-negative integer (got ${String(input.screenerThresholdPpm)})`);
      }

      // §8 grinding dedup: a patch already evaluated at the same
      // (epochId, parentStateRoot) is rejected WITHOUT re-evaluation —
      // no new pack draw, no scorer run, no RPC blockhash wait.
      const prior = await deps.dedupStore.get(dedupKey);
      if (prior) {
        return {
          outcome: 'reject',
          code: 'duplicate_submission',
          reason: `patch ${patchHash} already evaluated at parent ${parentStateRoot} in epoch ${deps.epochId} (prior outcome: ${prior.outcome})`,
        };
      }

      const miner = input.miner.toLowerCase();
      const parent = input.parentState ?? await deps.parentStateLoader(input.parentStateRoot);
      const perSeed = new Map<string, PatchEvalResult>();
      const scorer: PerPatchScorer = async ({ normalizedPatchBytes, evalSeed }) => {
        const result = await deps.seedScorer({ parent, normalizedPatchBytes, evalSeed, thresholdPpm: effectiveThresholdPpm });
        perSeed.set(evalSeed.toLowerCase(), result);
        const score = {
          scorePpm: result.deltaPpm,
          accepted: result.accepted,
        };
        return result.reason ? { ...score, rejectionReason: result.reason } : score;
      };

      // §8 SEED-REDRAW CLOSURE. Two ways the seed is pinned:
      //
      //  REMOTE/keyless path (input.seedContext supplied): the COORDINATOR drew
      //  + DURABLY recorded the seed and shipped it with the job. The scorer
      //  injects it verbatim and NEVER draws its own (seed is coordinator-
      //  authoritative + crash-safe). No attempt-store draw happens here.
      //
      //  LOCAL CPU path (no input.seedContext): pin the future-blockhash seed at
      //  first draw and REUSE it on retry. A crash AFTER the draw but BEFORE the
      //  recorded outcome leaves a 'drawn' attempt; the retry below injects that
      //  pinned seed (no fresh blockhash → no fresh hidden pack). On the first
      //  attempt we pass `onSeedDerived` to record it DURABLY before any scoring.
      //  (The dedup short-circuit above already handles a COMPLETED prior eval;
      //  this handles the crashed-mid-eval window.)
      const coordinatorPinnedSeed: PerPatchSeedContext | undefined = input.seedContext
        ? { ...input.seedContext, blockhash: input.seedContext.blockhash.toLowerCase() }
        : undefined;
      const priorAttempt = coordinatorPinnedSeed ? null : await deps.dedupStore.getAttempt(dedupKey);
      const injectedSeedContext: PerPatchSeedContext | undefined = coordinatorPinnedSeed
        ?? (priorAttempt ? priorAttempt.seedContext : undefined);
      // Cap check is for the FIRST draw only. On a retry of an existing attempt
      // the admission was already charged atomically at its first draw (it is
      // counted in minerAdmissions), and the reused row passed the cap then — so
      // the retry is always admitted (feed the gate 0) and never re-charged.
      // On a first draw the gate sees the real derived count (this key is not yet
      // charged), so it rejects with NO draw and NO charge iff count >= cap.
      const minerAdmissions = priorAttempt ? 0 : await deps.dedupStore.minerAdmissions(deps.epochId, miner);
      // §8 ATOMIC seed-pin + admission-charge BEFORE scoring, unless this is a
      // retry that already has a 'drawn' attempt (its seed is reused, its
      // admission already charged). On the remote path the coordinator-pinned
      // seed is still mirrored into the scorer's (in-memory, defense-in-depth)
      // store so its attempt state machine stays consistent (outcome upgrade
      // follows a recorded draw). recordSeedDrawnAndAdmission is idempotent on
      // the key, so this never re-rolls the seed nor double-charges the miner.
      const onSeedDerived = priorAttempt
        ? undefined
        : (seedContext: PerPatchSeedContext) => deps.dedupStore.recordSeedDrawnAndAdmission(dedupKey, seedContext, miner);

      const dual = await runPerPatchEvaluation({
        normalizedPatchBytes: patchBytes,
        parentRoot: parentStateRoot,
        minerAddress: miner,
        epochId: deps.epochId,
        structurallyValid: true,
      }, {
        rpcClient: deps.rpcClient,
        scorer,
        targetBlockOffset: deps.targetBlockOffset,
        thresholdPpm: effectiveThresholdPpm,
        perMinerCap: deps.perMinerCap,
        epochSecret: deps.epochSecret,
        corpusRoot: deps.corpusRoot,
        bundleHash: deps.bundleHash,
        // Cross-call dedup lives in the persistent store (checked above);
        // per-miner counts come from the same store (derived from atomic rows).
        dedupCache: new Map(),
        minerAdmissions: new Map([[miner, minerAdmissions]]),
        ...(injectedSeedContext ? { seedContext: injectedSeedContext } : {}),
        ...(onSeedDerived ? { onSeedDerived } : {}),
      });

      // The patch consumed a pack draw iff seeds were derived. The admission was
      // ALREADY charged ATOMICALLY with the seed pin inside onSeedDerived (which
      // runPerPatchEvaluation invokes only AFTER the admission gate passes and
      // the seed is derived) — so there is no separate post-result charge to
      // make here (exactly-once, crash-safe). We only record the dedup outcome,
      // which is what short-circuits a completed resubmission.
      const drewPacks = dual.receivedAtBlock > 0;
      const record = (outcome: CoreTexEvalDedupRecord['outcome'], code?: string) => {
        const attemptState = outcome === 'reject' ? 'rejected' as const : 'accepted' as const;
        return Promise.resolve(deps.dedupStore.recordAttemptOutcome(dedupKey, attemptState, outcome, code))
          .then(() => deps.dedupStore.put({ ...dedupKey, outcome, ...(code ? { code } : {}) }));
      };

      if (!dual.accepted) {
        const code = dual.rejectionReason ?? 'no_retrieval_improvement';
        if (drewPacks) await record('reject', code);
        return {
          outcome: 'reject',
          code,
          reason: 'dual-pack evaluator rejected patch',
        };
      }

      const chosen = chooseStateAdvanceScore(dual, perSeed);
      const minDualDelta = Math.min(dual.gateScorePpm, dual.confirmScorePpm);
      const stateAdvance = minDualDelta >= deps.stateThresholdPpm && chosen.accepted;
      const artifact = buildPostRevealEvalReportArtifact({
        version: 'coretex-post-reveal-eval-report-v1',
        epochId: deps.epochId,
        minerAddress: miner,
        outcome: stateAdvance ? 'STATE_ADVANCE' : 'SCREENER_PASS',
        compactPatchBytesHex: bytesToHex(patchBytes).toLowerCase(),
        thresholdPpm: effectiveThresholdPpm,
        seedDerivation: {
          mode: 'future_blockhash_dual_pack',
          epochId: deps.epochId,
          receivedAtBlock: dual.receivedAtBlock,
          targetBlock: dual.targetBlock,
          targetBlockOffset: deps.targetBlockOffset,
          blockhash: dual.blockhash.toLowerCase(),
          patchHash,
          parentStateRoot,
          corpusRoot: deps.corpusRoot.toLowerCase(),
          bundleHash: deps.bundleHash.toLowerCase(),
        },
        receipt: dual,
        context: {
          parentStateRoot,
          corpusRoot: deps.corpusRoot.toLowerCase(),
          coreVersionHash: deps.bundleHash.toLowerCase(),
          hiddenSeedCommit,
          replayTolerancePpm: deps.replayTolerancePpm,
        },
      });
      if (deps.publishArtifact) await deps.publishArtifact(artifact);
      const proof = dualPackProofFromPerPatchReceipt(dual, {
        corpusRoot: deps.corpusRoot,
        coreVersionHash: deps.bundleHash,
        hiddenSeedCommit,
        targetBlockOffset: deps.targetBlockOffset,
      });

      if (stateAdvance) {
        const scoreBeforePpm = ppm(chosen.before.composite);
        const scoreAfterPpm = scoreBeforePpm + minDualDelta;
        const rewrittenPatchBytesHex = bytesToHex(encodePatch({
          ...patch,
          scoreDelta: BigInt(minDualDelta),
        }));
        await record('state_advance');
        return {
          outcome: 'state_advance',
          deterministicDeltaPpm: minDualDelta,
          evalReportHash: artifact.evalReportHash,
          artifactHash: artifact.artifactHash,
          scoreBeforePpm,
          scoreAfterPpm,
          rewrittenPatchBytesHex,
          evaluationProof: proof,
          artifact,
        };
      }

      await record('screener_pass');
      return {
        outcome: 'screener_pass',
        deterministicDeltaPpm: minDualDelta,
        evalReportHash: artifact.evalReportHash,
        artifactHash: artifact.artifactHash,
        evaluationProof: proof,
        artifact,
      };
    },
  };
  if (deps.close) evaluator.close = deps.close;
  return evaluator;
}

// ─── Production constructor (fail-closed) ─────────────────────────────────────

export async function createProductionCoreTexEvaluator(
  options: ProductionCoreTexEvaluatorOptions,
): Promise<ProductionCoreTexEvaluator> {
  const bundle = JSON.parse(readFileSync(options.bundleManifestPath, 'utf8')) as CoreTexBundleManifest;
  const profile = bundle.evaluator?.profile ?? DEFAULT_PROFILE;
  const rerankerPin = bundle.model?.reranker;
  if (!rerankerPin?.modelId || !rerankerPin?.revision) {
    throw new Error(`bundle manifest ${options.bundleManifestPath} has no model.reranker pin (modelId + revision)`);
  }
  // Fail-closed gates run BEFORE any heavy load: env contract, cap, store.
  const plan = resolveProductionRerankerPlan({ modelId: rerankerPin.modelId, revision: rerankerPin.revision });
  validatePerMinerCap(options.perMinerCap);
  if (!options.dedupStore) {
    throw new Error('production CoreTex evaluator requires a CoreTexEvalDedupStore (fail-closed: no in-memory default)');
  }

  const corpus = loadProductionCorpus(options.corpusPath, {
    verifyCorpusRoot: true,
    verifySplits: true,
  });
  const layout = corpus.biEncoderRetrievalKeyLayout;
  const biEncoder = biEncoderFromEnv(layout, {
    modelId: corpus.biEncoderModelId,
    revision: corpus.biEncoderRevision,
  });
  const reranker = await (options.rerankerFactory ? options.rerankerFactory(plan) : createPinnedQwen3Reranker(plan));
  assertResolvedRerankerMatchesPin(reranker, plan);
  const memoryIRMode = profile.rerankerMemoryIRMode ?? 'off';
  const bootAttestation = buildCoordinatorBootAttestation({
    bundleHash: bundle.bundleHash,
    rerankerModelId: plan.modelId,
    rerankerRevision: plan.revision,
    rerankerMode: plan.mode,
    rerankerInstruction: plan.instruction,
    promptTemplateHash: qwenRerankerPromptTemplateHash(plan.instruction),
    memoryIRMode,
  });

  const biEncoderHash = biEncoderModelIdHash(corpus.biEncoderModelId, corpus.biEncoderRevision, 'dense');
  const scoringOpts = scoringOptionsFromProfile(profile, {
    biEncoder,
    reranker,
    biEncoderHash,
    retrievalKeyLayout: layout,
  });
  const stateThresholdPpm = computeAcceptanceThresholdPpm(profile);
  const screenerThresholdPpm = options.screenerThresholdPpm ?? Math.min(stateThresholdPpm, 355);

  const closable = reranker as CrossEncoderReranker & { close?: () => Promise<void> };
  return createCoreTexEvaluatorCore({
    epochId: options.epochId,
    epochSecret: options.epochSecret,
    corpusRoot: corpus.corpusRoot,
    bundleHash: bundle.bundleHash,
    stateThresholdPpm,
    screenerThresholdPpm,
    replayTolerancePpm: profile.replayTolerancePpm,
    targetBlockOffset: options.targetBlockOffset ?? 30,
    perMinerCap: options.perMinerCap,
    rpcClient: options.rpcClient ?? new EnvBaseRpcClient(),
    dedupStore: options.dedupStore,
    bootAttestation,
    parentStateLoader: options.parentStateLoader,
    seedScorer: async ({ parent, normalizedPatchBytes, evalSeed, thresholdPpm }) => {
      const seedPatch = decodePatch(normalizedPatchBytes);
      return scoreAgainstSeed({
        epochId: options.epochId,
        parent,
        patch: seedPatch,
        corpus,
        profile,
        evalSeed,
        scoringOpts,
        thresholdPpm,
      });
    },
    ...(options.publishArtifact ? { publishArtifact: options.publishArtifact } : {}),
    ...(typeof closable.close === 'function' ? { close: () => closable.close!() } : {}),
  });
}

async function createPinnedQwen3Reranker(plan: ProductionRerankerPlan): Promise<CrossEncoderReranker> {
  if (plan.mode === 'qwen3-streaming') {
    const cacheDir = process.env['CORTEX_LOCAL_MODEL_CACHE'];
    const numThreads = Number(process.env['RERANKER_NUM_THREADS'] ?? '0') || undefined;
    return createStreamingQwen3Reranker({
      model: plan.modelId,
      revision: plan.revision,
      ...(cacheDir ? { cacheDir } : {}),
      localOnly: process.env['CORTEX_LOCAL_MODEL_LOCAL_ONLY'] === '1',
      batchSize: Number(process.env['CORETEX_RERANKER_BATCH_SIZE'] ?? '8'),
      ...(numThreads ? { numThreads } : {}),
    });
  }
  return createQwen3Reranker({
    model: plan.modelId,
    revision: plan.revision,
    cacheDir: process.env['CORTEX_LOCAL_MODEL_CACHE'],
    localOnly: process.env['CORTEX_LOCAL_MODEL_LOCAL_ONLY'] === '1',
  });
}

function validatePerMinerCap(perMinerCap: number | undefined): void {
  if (
    perMinerCap === undefined
    || !Number.isSafeInteger(perMinerCap)
    || perMinerCap <= 0
    || perMinerCap >= Number.MAX_SAFE_INTEGER
  ) {
    throw new Error(
      `production CoreTex evaluator requires a finite perMinerCap from the profile/options (got ${String(perMinerCap)})`,
    );
  }
}

async function scoreAgainstSeed(args: {
  readonly epochId: number;
  readonly parent: CortexState;
  readonly patch: Patch;
  readonly corpus: ProductionCorpus;
  readonly profile: EvaluatorProfile;
  readonly evalSeed: string;
  readonly scoringOpts: ReturnType<typeof scoringOptionsFromProfile>;
  readonly thresholdPpm: number;
}): Promise<PatchEvalResult> {
  const pack = deriveQueryPack(args.epochId, args.evalSeed, args.corpus, args.profile.hiddenPack);
  return evaluateRetrievalBenchmarkPatch(args.parent, args.patch, args.corpus, pack, args.scoringOpts, {
    ...args.profile.patchAcceptanceFloors,
    acceptanceThresholdPpm: args.thresholdPpm,
  });
}

function chooseStateAdvanceScore(
  receipt: PerPatchReceipt,
  perSeed: ReadonlyMap<string, PatchEvalResult>,
): PatchEvalResult {
  const gate = perSeed.get(receipt.gateSeed.toLowerCase());
  const confirm = perSeed.get(receipt.confirmSeed.toLowerCase());
  const chosen = receipt.gateScorePpm <= receipt.confirmScorePpm ? gate : confirm;
  if (!chosen) throw new Error('production evaluator internal error: missing dual-pack score');
  return chosen;
}

function ppm(value: number): number {
  return Math.max(0, Math.min(1_000_000, Math.round(value * 1_000_000)));
}

function parseHex(value: string, label: string): Uint8Array {
  if (!/^0x[0-9a-fA-F]*$/.test(value) || value.length % 2 !== 0) throw new Error(`${label} must be hex`);
  return hexToBytes(value);
}

class EnvBaseRpcClient implements BaseRpcClient {
  private readonly rpcUrl: string;

  constructor() {
    const rpcUrl = process.env['BASE_RPC_URL'];
    if (!rpcUrl) throw new Error('BASE_RPC_URL is required for production CoreTex evaluator blockhash binding');
    this.rpcUrl = rpcUrl;
  }

  async getLatestBlockNumber(): Promise<number> {
    return Number(BigInt(await rpcCall<string>(this.rpcUrl, 'eth_blockNumber', [])));
  }

  async getBlockHash(blockNumber: number): Promise<string> {
    const block = await rpcCall<{ hash?: string } | null>(this.rpcUrl, 'eth_getBlockByNumber', [`0x${blockNumber.toString(16)}`, false]);
    if (!block?.hash) throw new Error(`block ${blockNumber} not available`);
    return block.hash.toLowerCase();
  }

  async waitForBlock(blockNumber: number, timeoutMs: number): Promise<BaseBlockResponse> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const head = await this.getLatestBlockNumber();
      if (head >= blockNumber) {
        const block = await rpcCall<{ hash?: string; timestamp?: string } | null>(
          this.rpcUrl,
          'eth_getBlockByNumber',
          [`0x${blockNumber.toString(16)}`, false],
        );
        if (!block?.hash || !block.timestamp) throw new Error(`block ${blockNumber} not available`);
        return {
          number: blockNumber,
          blockhash: block.hash.toLowerCase(),
          timestamp: Number(BigInt(block.timestamp)),
        };
      }
      if (Date.now() >= deadline) throw new Error(`timed out waiting for block ${blockNumber}`);
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
}

async function rpcCall<T>(rpcUrl: string, method: string, params: readonly unknown[]): Promise<T> {
  // rpcFetchTarget (replay/v4.ts) extracts embedded basic-auth userinfo into
  // an Authorization header — Node fetch/undici hard-rejects credentialed
  // URLs (observed live: every production eval failed against a credentialed
  // Base RPC URL until this was routed through the shared helper).
  const { url, headers } = rpcFetchTarget(rpcUrl);
  const res = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`RPC ${method} HTTP ${res.status}`);
  const json = await res.json() as { result?: T; error?: { message?: string } };
  if (json.error) throw new Error(json.error.message ?? `RPC ${method} error`);
  if (json.result === undefined) throw new Error(`RPC ${method} missing result`);
  return json.result;
}
