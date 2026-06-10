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
  minerAdmissions(epochId: number, minerAddress: string): Promise<number> | number;
  recordMinerAdmission(epochId: number, minerAddress: string): Promise<void> | void;
}

/** In-memory store for tests and for a persistent sidecar to wrap. The
 *  production constructor does NOT default to this — pass a store that
 *  actually persists across restarts. */
export function createInMemoryDedupStore(): CoreTexEvalDedupStore {
  const records = new Map<string, CoreTexEvalDedupRecord>();
  const admissions = new Map<string, number>();
  const recordKey = (k: CoreTexEvalDedupKey) =>
    `${k.epochId}|${k.parentStateRoot.toLowerCase()}|${k.patchHash.toLowerCase()}`;
  const admissionKey = (epochId: number, miner: string) => `${epochId}|${miner.toLowerCase()}`;
  return {
    get(key) { return records.get(recordKey(key)) ?? null; },
    put(record) { records.set(recordKey(record), record); },
    minerAdmissions(epochId, minerAddress) { return admissions.get(admissionKey(epochId, minerAddress)) ?? 0; },
    recordMinerAdmission(epochId, minerAddress) {
      const key = admissionKey(epochId, minerAddress);
      admissions.set(key, (admissions.get(key) ?? 0) + 1);
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
  return {
    mode: env['CORETEX_RERANKER_MODE'] === 'streaming' ? 'qwen3-streaming' : 'qwen3-per-batch',
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

export type ProductionEvalResult =
  | ProductionEvalRejectResult
  | Extract<EvalResult, { readonly outcome: 'screener_pass' }>
  | Extract<EvalResult, { readonly outcome: 'state_advance' }>;

export type ProductionCoreTexEvaluator = RealEvaluator & {
  scorePatch(input: {
    patchBytesHex: string;
    parentStateRoot: string;
    miner: string;
    parentState?: CortexState;
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
      const minerAdmissions = await deps.dedupStore.minerAdmissions(deps.epochId, miner);
      const parent = input.parentState ?? await deps.parentStateLoader(input.parentStateRoot);
      const perSeed = new Map<string, PatchEvalResult>();
      const scorer: PerPatchScorer = async ({ normalizedPatchBytes, evalSeed }) => {
        const result = await deps.seedScorer({ parent, normalizedPatchBytes, evalSeed });
        perSeed.set(evalSeed.toLowerCase(), result);
        const score = {
          scorePpm: result.deltaPpm,
          accepted: result.accepted,
        };
        return result.reason ? { ...score, rejectionReason: result.reason } : score;
      };
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
        thresholdPpm: deps.screenerThresholdPpm,
        perMinerCap: deps.perMinerCap,
        epochSecret: deps.epochSecret,
        corpusRoot: deps.corpusRoot,
        bundleHash: deps.bundleHash,
        // Cross-call dedup lives in the persistent store (checked above);
        // per-miner counts come from the same store.
        dedupCache: new Map(),
        minerAdmissions: new Map([[miner, minerAdmissions]]),
      });

      // The patch consumed a pack draw iff seeds were derived. Record both
      // the admission and the dedup outcome through the persistent store so
      // neither resets on coordinator restart.
      const drewPacks = dual.receivedAtBlock > 0;
      if (drewPacks) await deps.dedupStore.recordMinerAdmission(deps.epochId, miner);
      const record = (outcome: CoreTexEvalDedupRecord['outcome'], code?: string) =>
        deps.dedupStore.put({ ...dedupKey, outcome, ...(code ? { code } : {}) });

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
        thresholdPpm: deps.screenerThresholdPpm,
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
        };
      }

      await record('screener_pass');
      return {
        outcome: 'screener_pass',
        deterministicDeltaPpm: minDualDelta,
        evalReportHash: artifact.evalReportHash,
        artifactHash: artifact.artifactHash,
        evaluationProof: proof,
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
  const reranker = await createPinnedQwen3Reranker(plan);
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
    seedScorer: async ({ parent, normalizedPatchBytes, evalSeed }) => {
      const seedPatch = decodePatch(normalizedPatchBytes);
      return scoreAgainstSeed({
        epochId: options.epochId,
        parent,
        patch: seedPatch,
        corpus,
        profile,
        evalSeed,
        scoringOpts,
        thresholdPpm: screenerThresholdPpm,
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
