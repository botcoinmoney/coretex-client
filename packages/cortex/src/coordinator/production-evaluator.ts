import { readFileSync } from 'node:fs';

import type { CortexState, Patch } from '../state/index.js';
import { decodePatch, encodePatch } from '../state/patch.js';
import { hexToBytes, bytesToHex } from '../state/merkle.js';
import { keccak256 } from '../state/keccak256.js';
import {
  DEFAULT_PROFILE,
  scoringOptionsFromProfile,
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
import { rerankerFromEnv, type CrossEncoderReranker } from '../eval/reranker.js';
import { biEncoderModelIdHash } from '../substrate/retrieval-decoder.js';
import {
  runPerPatchEvaluation,
  dualPackProofFromPerPatchReceipt,
  type PerPatchReceipt,
  type PerPatchScorer,
} from './per-patch-evaluator.js';
import type { BaseBlockResponse, BaseRpcClient } from './base-blockhash.js';
import type { EvalResult, RealEvaluator } from './coretex-coordinator-core.js';

export interface ProductionCoreTexEvaluatorOptions {
  readonly epochId: number;
  readonly epochSecret: string;
  readonly corpusPath: string;
  readonly bundleManifestPath: string;
  readonly parentStateLoader: (parentStateRoot: string) => Promise<CortexState> | CortexState;
  readonly rpcClient?: BaseRpcClient;
  readonly targetBlockOffset?: number;
  readonly perMinerCap?: number;
  readonly screenerThresholdPpm?: number;
}

export type ProductionCoreTexEvaluator = RealEvaluator & {
  close?: () => Promise<void>;
};

export async function createProductionCoreTexEvaluator(
  options: ProductionCoreTexEvaluatorOptions,
): Promise<ProductionCoreTexEvaluator> {
  const bundle = JSON.parse(readFileSync(options.bundleManifestPath, 'utf8')) as CoreTexBundleManifest;
  const profile = bundle.evaluator?.profile ?? DEFAULT_PROFILE;
  const corpus = loadProductionCorpus(options.corpusPath, {
    verifyCorpusRoot: true,
    verifySplits: true,
  });
  const layout = corpus.biEncoderRetrievalKeyLayout;
  const biEncoder = biEncoderFromEnv(layout, {
    modelId: corpus.biEncoderModelId,
    revision: corpus.biEncoderRevision,
  });
  const reranker = await rerankerFromEnv();
  const biEncoderHash = biEncoderModelIdHash(corpus.biEncoderModelId, corpus.biEncoderRevision, 'dense');
  const scoringOpts = scoringOptionsFromProfile(profile, {
    biEncoder,
    reranker,
    biEncoderHash,
    retrievalKeyLayout: layout,
  });
  const stateThresholdPpm = computeAcceptanceThresholdPpm(profile);
  const screenerThresholdPpm = options.screenerThresholdPpm ?? Math.min(stateThresholdPpm, 355);
  const targetBlockOffset = options.targetBlockOffset ?? 30;
  const rpcClient = options.rpcClient ?? new EnvBaseRpcClient();

  const evaluator: ProductionCoreTexEvaluator = {
    async scorePatch(input) {
      const patchBytes = parseHex(input.patchBytesHex, 'patchBytesHex');
      const patch = decodePatch(patchBytes);
      const parent = input.parentState ?? await options.parentStateLoader(input.parentStateRoot);
      const perSeed = new Map<string, PatchEvalResult>();
      const scorer: PerPatchScorer = async ({ normalizedPatchBytes, evalSeed }) => {
        const seedPatch = decodePatch(normalizedPatchBytes);
        const result = await scoreAgainstSeed({
          epochId: options.epochId,
          parent,
          patch: seedPatch,
          corpus,
          profile,
          evalSeed,
          scoringOpts,
          thresholdPpm: screenerThresholdPpm,
        });
        perSeed.set(evalSeed.toLowerCase(), result);
        const score = {
          scorePpm: result.deltaPpm,
          accepted: result.accepted,
        };
        return result.reason ? { ...score, rejectionReason: result.reason } : score;
      };
      const dual = await runPerPatchEvaluation({
        normalizedPatchBytes: patchBytes,
        parentRoot: input.parentStateRoot,
        minerAddress: input.miner,
        epochId: options.epochId,
        structurallyValid: true,
      }, {
        rpcClient,
        scorer,
        targetBlockOffset,
        thresholdPpm: screenerThresholdPpm,
        perMinerCap: options.perMinerCap ?? Number.MAX_SAFE_INTEGER,
        epochSecret: options.epochSecret,
        corpusRoot: corpus.corpusRoot,
        bundleHash: bundle.bundleHash,
        dedupCache: new Map(),
        minerAdmissions: new Map(),
      });

      if (!dual.accepted) {
        return {
          outcome: 'reject',
          code: dual.rejectionReason ?? 'no_retrieval_improvement',
          reason: dual.rejectionReason ?? 'dual-pack evaluator rejected patch',
          deterministicDeltaPpm: Math.max(dual.gateScorePpm, dual.confirmScorePpm),
          requiredDeltaPpm: screenerThresholdPpm,
        };
      }

      const chosen = chooseStateAdvanceScore(dual, perSeed);
      const artifact = buildEvalArtifact({
        bundleHash: bundle.bundleHash,
        corpusRoot: corpus.corpusRoot,
        parentStateRoot: input.parentStateRoot,
        patchBytesHex: bytesToHex(patchBytes),
        dual,
        chosen,
      });
      const minDualDelta = Math.min(dual.gateScorePpm, dual.confirmScorePpm);
      const proof = dualPackProofFromPerPatchReceipt(dual, {
        corpusRoot: corpus.corpusRoot,
        coreVersionHash: bundle.bundleHash,
        hiddenSeedCommit: bytesToHex(keccak256(parseHex(options.epochSecret, 'epochSecret'))),
        targetBlockOffset,
      });

      if (minDualDelta >= stateThresholdPpm && chosen.accepted) {
        const scoreBeforePpm = ppm(chosen.before.composite);
        const scoreAfterPpm = scoreBeforePpm + minDualDelta;
        const rewrittenPatchBytesHex = bytesToHex(encodePatch({
          ...patch,
          scoreDelta: BigInt(minDualDelta),
        }));
        return {
          outcome: 'state_advance',
          deterministicDeltaPpm: minDualDelta,
          evalReportHash: artifact.hash,
          artifactHash: artifact.hash,
          scoreBeforePpm,
          scoreAfterPpm,
          rewrittenPatchBytesHex,
          evaluationProof: proof,
        };
      }

      return {
        outcome: 'screener_pass',
        deterministicDeltaPpm: minDualDelta,
        evalReportHash: artifact.hash,
        artifactHash: artifact.hash,
        evaluationProof: proof,
      };
    },
  };
  if (typeof (reranker as CrossEncoderReranker & { close?: () => Promise<void> }).close === 'function') {
    evaluator.close = () => (reranker as CrossEncoderReranker & { close: () => Promise<void> }).close();
  }
  return evaluator;
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

function buildEvalArtifact(value: unknown): { readonly hash: string } {
  const hash = bytesToHex(keccak256(new TextEncoder().encode(canonicalJson(value)))).toLowerCase();
  return { hash };
}

function ppm(value: number): number {
  return Math.max(0, Math.min(1_000_000, Math.round(value * 1_000_000)));
}

function parseHex(value: string, label: string): Uint8Array {
  if (!/^0x[0-9a-fA-F]*$/.test(value) || value.length % 2 !== 0) throw new Error(`${label} must be hex`);
  return hexToBytes(value);
}

function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : 'null';
  if (typeof value === 'bigint') return JSON.stringify(value.toString());
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
  }
  return 'null';
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
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`RPC ${method} HTTP ${res.status}`);
  const json = await res.json() as { result?: T; error?: { message?: string } };
  if (json.error) throw new Error(json.error.message ?? `RPC ${method} error`);
  if (json.result === undefined) throw new Error(`RPC ${method} missing result`);
  return json.result;
}
