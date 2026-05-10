/**
 * CoreTex bundle manifest — production retrieval-benchmark form.
 *
 * Specs:
 *   - specs/retrieval_benchmark_v0.md
 *   - specs/substrate_retrieval_semantics_v0.md
 *   - specs/corpus_retrieval_v0.md
 *   - specs/hidden_query_pack_v0.md
 *   - specs/determinism_v0.md
 *
 * The bundle pins:
 *   - bi-encoder + revision + per-file SHA-256 + retrieval-key layout
 *   - production cross-encoder reranker + revision + per-file SHA-256
 *   - labeling cross-encoder reranker (separate, stronger; for qrel labeling)
 *   - runtime versions (CPU-only)
 *   - composite weights (retrieval-dominant)
 *   - hidden-pack profile (size + quotas)
 *   - calibration outputs (`replayTolerancePpm`, floors, hop budget)
 *
 * `bundleHash = keccak256(canonicalJson(manifest \ bundleHash))`. The
 * coordinator startup assertion refuses to run if the on-chain
 * `coreVersionHash` does not equal `bundleHash`.
 */

import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { basename, relative, resolve } from 'node:path';

import { bytesToHex } from '../state/merkle.js';
import { keccak256 } from '../state/keccak256.js';
import type { RetrievalKeyLayout } from '../eval/retrieval-corpus.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface BundleFile {
  readonly role: string;
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
}

export interface ModelFileFetch {
  readonly path: string;
  readonly sha256: string;
  readonly bytes?: number;
}

export type RuntimeFlavor = 'torch-transformers' | 'onnxruntime-cpu';

export interface RuntimePin {
  readonly flavor: RuntimeFlavor;
  readonly versions: Record<string, string>;
  readonly buildFlags: readonly string[];
}

export type Quantization =
  | { readonly weights: 'int8'; readonly activations: 'fp32'; readonly accumulation: 'fp32'; readonly scheme: 'symmetric_per_channel' | 'asymmetric_per_tensor' }
  | { readonly weights: 'bf16'; readonly activations: 'bf16'; readonly accumulation: 'fp32'; readonly flushDenormals: true };

export interface BiEncoderManifest {
  readonly provider: 'huggingface';
  readonly modelId: string;
  readonly revision: string;
  readonly mode: 'dense';
  readonly outputDim: number;
  readonly tokenizerRevision: string;
  readonly quantization: Quantization;
  readonly retrievalKeyLayout: RetrievalKeyLayout;
  readonly files: readonly ModelFileFetch[];
}

export interface RerankerManifest {
  readonly provider: 'huggingface';
  readonly modelId: string;
  readonly revision: string;
  readonly files: readonly ModelFileFetch[];
}

export interface PackQuotaPin {
  readonly stratum: string;
  readonly minCount: number;
}

export interface HiddenPackProfilePin {
  readonly packSize: number;
  readonly quotas: readonly PackQuotaPin[];
}

export interface CompositeWeightPin {
  readonly w_retrieval: number;
  readonly w_temporal: number;
  readonly w_relation_recall: number;
  readonly w_abstention: number;
  readonly w_structural_sanity: number;
}

export interface PatchAcceptanceFloorsPin {
  readonly minImprovementPpm: number;
  readonly structuralFloor: number;
  readonly protectedRegressionFloor: number;
  readonly familyCatastrophicFloor: number;
}

export interface SplitRatiosPin {
  readonly trainVisiblePct: number;
  readonly calibrationPct: number;
  readonly evalHiddenPct: number;
  readonly canaryPct: number;
}

export interface EvaluatorProfile {
  readonly name: string;
  readonly version: string;
  readonly scoreScale: 'ppm';
  readonly scorePpmEncoding: 'uint32-0-to-1000000';
  readonly patchScoreDeltaEncoding: 'int64-ppm';
  readonly primaryMetric: 'ndcg@10';
  readonly acceleratorPolicy: 'cpu_only';
  readonly runtimePin: RuntimePin;
  readonly replayTolerancePpm: number;
  readonly compositeWeights: CompositeWeightPin;
  readonly patchAcceptanceFloors: PatchAcceptanceFloorsPin;
  readonly splitRatios: SplitRatiosPin;
  readonly hiddenPack: HiddenPackProfilePin;
  readonly relationHopBudget: number;
  readonly abstentionThreshold: number;
  readonly rerankerTopK: number;
  readonly retrievalKeyTopK: number;
  readonly relationEdgeTypes: readonly string[];
  readonly revealGracePeriodSeconds: number;
}

export interface CoreTexBundleManifest {
  readonly schemaVersion: 'coretex.client-bundle.v2';
  readonly generatedAt: string;
  readonly bundleName: string;
  readonly substrate: {
    readonly wordCount: 1024;
    readonly packedBytes: 32768;
    readonly specs: readonly BundleFile[];
    readonly implementation: readonly BundleFile[];
  };
  readonly corpus: {
    readonly root: string;
    readonly files: readonly BundleFile[];
  };
  readonly evaluator: {
    readonly profile: EvaluatorProfile;
    readonly files: readonly BundleFile[];
  };
  readonly model: {
    readonly biEncoder: BiEncoderManifest;
    readonly reranker: RerankerManifest;
    readonly labelingReranker: RerankerManifest;
  };
  readonly replay: {
    readonly commands: readonly string[];
    readonly coordinatorCacheOptional: true;
    readonly snapshots: readonly BundleFile[];
  };
  readonly bundleHash: string;
}

// ─── BGE-M3 bi-encoder manifest factory ──────────────────────────────────────

/**
 * Default retrieval-key layout for BGE-M3 dense mode at 256-byte slot budget.
 * Calibration may pin a smaller dim; defaults are conservative.
 */
export const BGE_M3_DEFAULT_LAYOUT: RetrievalKeyLayout = {
  dim: 243,           // 256 - 9 header - 4-byte int8 scale = 243 payload scalars
  quantization: 'int8',
  headerBytes: 9,
};

export const BGE_M3_DEFAULT_REVISION = '5617a9f61b028005a4858fdac845db406aefb181';

export const BGE_M3_DENSE_FILES: readonly ModelFileFetch[] = [
  { path: '1_Pooling/config.json', sha256: 'e54c164a07274f2eb45bb724f54a79d1efcc90c41573887cd9a29aeee0597352', bytes: 191 },
  { path: 'colbert_linear.pt', sha256: '19bfbae397c2b7524158c919d0e9b19393c5639d098f0a66932c91ed8f5f9abb', bytes: 2100674 },
  { path: 'config.json', sha256: '26159e7ad065073448460117eb24b7a4572f6f4e78eadff65dc0a11c052449fa', bytes: 687 },
  { path: 'config_sentence_transformers.json', sha256: '1eef72430e7194a1e59680e635aed81ffa083f05668dbc5bb1c56c04c0999c38', bytes: 123 },
  { path: 'modules.json', sha256: '84e40c8e006c9b1d6c122e02cba9b02458120b5fb0c87b746c41e0207cf642cf', bytes: 349 },
  { path: 'pytorch_model.bin', sha256: 'b5e0ce3470abf5ef3831aa1bd5553b486803e83251590ab7ff35a117cf6aad38', bytes: 2271145830 },
  { path: 'sentence_bert_config.json', sha256: 'eb9b44b13c0f52a3b3685c3b1cbdea1ba8b04bea123b98f61610048940776eb1', bytes: 54 },
  { path: 'sentencepiece.bpe.model', sha256: 'cfc8146abe2a0488e9e2a0c56de7952f7c11ab059eca145a0a727afce0db2865', bytes: 5069051 },
  { path: 'sparse_linear.pt', sha256: '45c93804d2142b8f6d7ec6914ae23a1eee9c6a1d27d83d908a20d2afb3595ad9', bytes: 3516 },
  { path: 'special_tokens_map.json', sha256: '8c785abebea9ae3257b61681b4e6fd8365ceafde980c21970d001e834cf10835', bytes: 964 },
  { path: 'tokenizer.json', sha256: '21106b6d7dab2952c1d496fb21d5dc9db75c28ed361a05f5020bbba27810dd08', bytes: 17098108 },
  { path: 'tokenizer_config.json', sha256: 'a62b2b6784f990259fddef5f16388693a8043be4f69179e6a5257eeb3f9abac4', bytes: 444 },
];

export interface BgeM3ManifestOptions {
  readonly revision?: string;
  readonly tokenizerRevision?: string;
  readonly outputDim?: number;
  readonly quantization?: Quantization;
  readonly retrievalKeyLayout?: RetrievalKeyLayout;
  readonly files?: readonly ModelFileFetch[];
}

export function bgeM3DenseManifest(opts: BgeM3ManifestOptions = {}): BiEncoderManifest {
  return {
    provider: 'huggingface',
    modelId: 'BAAI/bge-m3',
    revision: opts.revision ?? BGE_M3_DEFAULT_REVISION,
    mode: 'dense',
    outputDim: opts.outputDim ?? 1024,
    tokenizerRevision: opts.tokenizerRevision ?? opts.revision ?? BGE_M3_DEFAULT_REVISION,
    quantization: opts.quantization ?? {
      weights: 'int8',
      activations: 'fp32',
      accumulation: 'fp32',
      scheme: 'symmetric_per_channel',
    },
    retrievalKeyLayout: opts.retrievalKeyLayout ?? BGE_M3_DEFAULT_LAYOUT,
    files: opts.files ?? BGE_M3_DENSE_FILES,
  };
}

// ─── Reranker factories ──────────────────────────────────────────────────────

export const QWEN3_RERANKER_DEFAULT_REVISION = 'e61197ed45024b0ed8a2d74b80b4d909f1255473';

export const QWEN3_RERANKER_06B_FILES: readonly ModelFileFetch[] = [
  { path: 'config.json', sha256: 'd479c427a9ca5295218063d4f9aca4f297ab4ac27487cca7af42c84643d51ef0', bytes: 727 },
  { path: 'config_sentence_transformers.json', sha256: '6a153d6696f78fd588c1c728967f0b773ea869d3c6028f151ce71ebe49140762', bytes: 325 },
  { path: 'generation_config.json', sha256: '81051cd3f6e77013827148d0b8a6ead93f8ac390d5ab805f849199f0af6a08db', bytes: 214 },
  { path: 'modules.json', sha256: '6f13b6b4a89e577b591b2077bca40c67c26541a6740a8809267cb474f90806a9', bytes: 280 },
  { path: 'sentence_bert_config.json', sha256: '3234ebd224d492cbe8d55d5ec80a3f408451c4db3005bafb64fe1c51c763e01e', bytes: 362 },
  { path: 'tokenizer_config.json', sha256: '253153d0738ceb4c668d2eff957714dd2bea0b56de772a9fdccd96cbf517e6a0', bytes: 9706 },
  { path: 'vocab.json', sha256: 'ca10d7e9fb3ed18575dd1e277a2579c16d108e32f27439684afa0e10b1440910', bytes: 2776833 },
  { path: 'merges.txt', sha256: '8831e4f1a044471340f7c0a83d7bd71306a5b867e95fd870f74d0c5308a904d5', bytes: 1671853 },
  { path: 'tokenizer.json', sha256: 'aeb13307a71acd8fe81861d94ad54ab689df773318809eed3cbe794b4492dae4', bytes: 11422654 },
  { path: 'model.safetensors', sha256: '27cd75a405b9c1b46b59abfd88aaa209e6fed2a1972cde9b70e7659537c5e65b', bytes: 1191588280 },
  { path: '1_LogitScore/config.json', sha256: '73e3156450564d8a98b7e47bcf5aace0f29600828b51937da545571e84db3ff3', bytes: 57 },
  { path: 'chat_template.jinja', sha256: '6f682162495ec5b39fd9005c01b6aa2a74669379fe967039f1e2cbbe8752369d', bytes: 741 },
];

export interface RerankerManifestOptions {
  readonly revision?: string;
  readonly files?: readonly ModelFileFetch[];
}

export function qwen3Reranker06BManifest(opts: RerankerManifestOptions = {}): RerankerManifest {
  return {
    provider: 'huggingface',
    modelId: 'Qwen/Qwen3-Reranker-0.6B',
    revision: opts.revision ?? QWEN3_RERANKER_DEFAULT_REVISION,
    files: opts.files ?? QWEN3_RERANKER_06B_FILES,
  };
}

export interface MemRerankerManifestOptions {
  readonly modelId: 'memreranker/0.6B' | 'memreranker/4B' | string;
  readonly revision: string;
  readonly files: readonly ModelFileFetch[];
}

export function memRerankerManifest(opts: MemRerankerManifestOptions): RerankerManifest {
  return {
    provider: 'huggingface',
    modelId: opts.modelId,
    revision: opts.revision,
    files: opts.files,
  };
}

export const MEMRERANKER_4B_DEFAULT_REVISION = '7fe33c1385f652f52d370b8822d6b620b32b6ec4';

export const MEMRERANKER_4B_FILES: readonly ModelFileFetch[] = [
  { path: '1_LogitScore/config.json', sha256: '73e3156450564d8a98b7e47bcf5aace0f29600828b51937da545571e84db3ff3', bytes: 57 },
  { path: 'chat_template.jinja', sha256: '6f682162495ec5b39fd9005c01b6aa2a74669379fe967039f1e2cbbe8752369d', bytes: 741 },
  { path: 'config.json', sha256: '82d53bdb18bfab8cd5ec620710f1561903dfdbdf8f5cf81d2237f7fa62766502', bytes: 1593 },
  { path: 'config_sentence_transformers.json', sha256: '6a153d6696f78fd588c1c728967f0b773ea869d3c6028f151ce71ebe49140762', bytes: 325 },
  { path: 'generation_config.json', sha256: 'ba8396a48fbb26b33af6cdf4463ec064e5f3b692bf5eb0ca1c9d964df377cf2d', bytes: 213 },
  { path: 'model.safetensors', sha256: '48aef1a3c826aabaf8a3852d3d5122ebd456d166ae3e1e401279fc82c15e0ec2', bytes: 8820160440 },
  { path: 'modules.json', sha256: '6f13b6b4a89e577b591b2077bca40c67c26541a6740a8809267cb474f90806a9', bytes: 280 },
  { path: 'sentence_bert_config.json', sha256: '3234ebd224d492cbe8d55d5ec80a3f408451c4db3005bafb64fe1c51c763e01e', bytes: 362 },
  { path: 'special_tokens_map.json', sha256: '76862e765266b85aa9459767e33cbaf13970f327a0e88d1c65846c2ddd3a1ecd', bytes: 613 },
  { path: 'tokenizer.json', sha256: 'be75606093db2094d7cd20f3c2f385c212750648bd6ea4fb2bf507a6a4c55506', bytes: 11422650 },
  { path: 'tokenizer_config.json', sha256: '579073f506a3f85caed232bb91617cfb93028408d1f43ffaf66f3fc1aee9a9af', bytes: 348 },
];

export function memReranker4BManifest(opts: RerankerManifestOptions = {}): RerankerManifest {
  return {
    provider: 'huggingface',
    modelId: 'IAAR-Shanghai/MemReranker-4B',
    revision: opts.revision ?? MEMRERANKER_4B_DEFAULT_REVISION,
    files: opts.files ?? MEMRERANKER_4B_FILES,
  };
}

// ─── Default profile ─────────────────────────────────────────────────────────

const DEFAULT_SPEC_FILES = [
  'specs/cortex_state_v0.md',
  'specs/cortex_schema_v0.json',
  'specs/packing_spec_v0.md',
  'specs/merkleization_spec_v0.md',
  'specs/patch_format_v0.md',
  'specs/retrieval_benchmark_v0.md',
  'specs/substrate_retrieval_semantics_v0.md',
  'specs/corpus_retrieval_v0.md',
  'specs/hidden_query_pack_v0.md',
  'specs/determinism_v0.md',
] as const;

const DEFAULT_IMPL_FILES = [
  'packages/cortex/src/state/codec.ts',
  'packages/cortex/src/state/merkle.ts',
  'packages/cortex/src/state/patch.ts',
  'packages/cortex/src/state/types.ts',
  'packages/cortex/src/state/validate.ts',
  'packages/cortex-py/cortex_py/codec.py',
  'packages/cortex-py/cortex_py/merkle.py',
  'packages/cortex-py/cortex_py/patch.py',
  'packages/cortex-py/cortex_py/types.py',
] as const;

const DEFAULT_EVALUATOR_FILES = [
  'packages/cortex/src/eval/retrieval-corpus.ts',
  'packages/cortex/src/eval/retrieval-benchmark.ts',
  'packages/cortex/src/eval/ir-metrics.ts',
  'packages/cortex/src/eval/hidden-query-pack.ts',
  'packages/cortex/src/eval/bi-encoder.ts',
  'packages/cortex/src/eval/reranker.ts',
  'packages/cortex/src/substrate/retrieval-decoder.ts',
  'packages/cortex/src/substrate/structural-validity.ts',
  'packages/cortex/src/substrate/slot-policy.ts',
  'packages/cortex/src/corpus/admission.ts',
  'packages/cortex/src/corpus/delta.ts',
  'packages/cortex/src/corpus/epoch-rotation.ts',
  'packages/cortex/src/rewards/difficulty.ts',
  'packages/cortex/src/coordinator/endpoints.ts',
  'packages/cortex/src/replay/v4.ts',
  'packages/cortex/src/replay-cli.ts',
] as const;

export const DEFAULT_RUNTIME_PIN: RuntimePin = {
  flavor: 'torch-transformers',
  versions: {
    torch: '2.4.*',
    transformers: '4.46.*',
    'huggingface_hub': '0.26.*',
    tokenizers: '0.20.*',
  },
  buildFlags: ['cpu-only'],
};

export const DEFAULT_COMPOSITE_WEIGHTS_PIN: CompositeWeightPin = {
  w_retrieval: 0.75,
  w_temporal: 0.08,
  w_relation_recall: 0.07,
  w_abstention: 0.05,
  w_structural_sanity: 0.05,
};

export const DEFAULT_PATCH_FLOORS: PatchAcceptanceFloorsPin = {
  minImprovementPpm: 2500,
  structuralFloor: 0.95,
  protectedRegressionFloor: 0.05,
  familyCatastrophicFloor: 0.85,
};

export const DEFAULT_SPLIT_RATIOS_PIN: SplitRatiosPin = {
  trainVisiblePct: 70,
  calibrationPct: 10,
  evalHiddenPct: 15,
  canaryPct: 5,
};

export const DEFAULT_HIDDEN_PACK_PROFILE: HiddenPackProfilePin = {
  packSize: 64,
  quotas: [
    { stratum: 'family=near_collision,bucket=hard', minCount: 4 },
    { stratum: 'family=temporal,bucket=hard', minCount: 4 },
    { stratum: 'family=long_horizon,bucket=hard', minCount: 4 },
    { stratum: 'family=multi_hop_relation,bucket=hard', minCount: 4 },
  ],
};

export const DEFAULT_RELATION_EDGE_TYPES = [
  'supports',
  'supersedes',
  'coreference_of',
  'causes',
  'derived_from',
  'co_occurs_with',
] as const;

export const DEFAULT_PROFILE: EvaluatorProfile = {
  name: 'coretex-v4-launch',
  version: 'v2',
  scoreScale: 'ppm',
  scorePpmEncoding: 'uint32-0-to-1000000',
  patchScoreDeltaEncoding: 'int64-ppm',
  primaryMetric: 'ndcg@10',
  acceleratorPolicy: 'cpu_only',
  runtimePin: DEFAULT_RUNTIME_PIN,
  replayTolerancePpm: 250,            // canonical replay disagreement ceiling
  compositeWeights: DEFAULT_COMPOSITE_WEIGHTS_PIN,
  patchAcceptanceFloors: DEFAULT_PATCH_FLOORS,
  splitRatios: DEFAULT_SPLIT_RATIOS_PIN,
  hiddenPack: DEFAULT_HIDDEN_PACK_PROFILE,
  relationHopBudget: 3,
  abstentionThreshold: 0.001,
  rerankerTopK: 10,
  retrievalKeyTopK: 50,
  relationEdgeTypes: DEFAULT_RELATION_EDGE_TYPES,
  revealGracePeriodSeconds: 60 * 60 * 6,  // 6h pre-calibration; calibrate replaces
};

// ─── Build / verify ──────────────────────────────────────────────────────────

export interface BuildBundleManifestOptions {
  readonly repoRoot: string;
  readonly bundleName?: string;
  readonly generatedAt?: string;
  readonly corpusRoot: string;
  readonly corpusFiles: readonly string[];
  readonly biEncoder: BiEncoderManifest;
  readonly reranker: RerankerManifest;
  readonly labelingReranker: RerankerManifest;
  readonly evaluatorProfile?: Partial<EvaluatorProfile>;
  readonly extraEvaluatorFiles?: readonly string[];
  readonly snapshotFiles?: readonly string[];
}

export function buildBundleManifest(opts: BuildBundleManifestOptions): CoreTexBundleManifest {
  assertBytes32(opts.corpusRoot, 'corpusRoot');
  validateBiEncoderManifest(opts.biEncoder);
  validateRerankerManifest(opts.reranker, 'reranker');
  validateRerankerManifest(opts.labelingReranker, 'labelingReranker');
  assertSeparateLabelingModel(opts.reranker, opts.labelingReranker);

  const generatedAt = opts.generatedAt ?? new Date(0).toISOString();
  const profile: EvaluatorProfile = { ...DEFAULT_PROFILE, ...opts.evaluatorProfile };
  validateProfile(profile);

  const evaluatorFiles = [...DEFAULT_EVALUATOR_FILES, ...(opts.extraEvaluatorFiles ?? [])];

  const withoutHash = {
    schemaVersion: 'coretex.client-bundle.v2' as const,
    generatedAt,
    bundleName: opts.bundleName ?? 'botcoin-coretex-v4',
    substrate: {
      wordCount: 1024 as const,
      packedBytes: 32768 as const,
      specs: DEFAULT_SPEC_FILES.map((path) => hashFile(opts.repoRoot, path, 'substrate-spec')),
      implementation: DEFAULT_IMPL_FILES.map((path) => hashFile(opts.repoRoot, path, 'substrate-impl')),
    },
    corpus: {
      root: opts.corpusRoot,
      files: opts.corpusFiles.map((path) => hashFile(opts.repoRoot, path, 'corpus')),
    },
    evaluator: {
      profile,
      files: evaluatorFiles.map((path) => hashFile(opts.repoRoot, path, 'evaluator')),
    },
    model: {
      biEncoder: opts.biEncoder,
      reranker: opts.reranker,
      labelingReranker: opts.labelingReranker,
    },
    replay: {
      commands: [
        'coretex-replay tx --tx <hash> --rpc <url> --parent-state <state.bin> --bundle-manifest <manifest.json> --core-version-hash <bundleHash>',
        'coretex-replay current --events <events.json> --parent-state <state.bin> --bundle-manifest <manifest.json> --core-version-hash <bundleHash>',
        'coretex-replay watch --rpc <url> --v4 <address> --cortex-state <address> --from-block <n> --parent-state <state.bin> --bundle-manifest <manifest.json> --core-version-hash <bundleHash>',
      ],
      coordinatorCacheOptional: true as const,
      snapshots: (opts.snapshotFiles ?? []).map((path) => hashFile(opts.repoRoot, path, 'substrate-snapshot')),
    },
  };

  const bundleHash = hashJson(withoutHash);
  return { ...withoutHash, bundleHash };
}

export function verifyBundleManifest(manifest: CoreTexBundleManifest, repoRoot: string): string[] {
  const errors: string[] = [];
  if (manifest.schemaVersion !== 'coretex.client-bundle.v2') errors.push('bad schemaVersion');
  if (manifest.substrate.wordCount !== 1024) errors.push('substrate.wordCount must be 1024');
  if (manifest.substrate.packedBytes !== 32768) errors.push('substrate.packedBytes must be 32768');
  validateBytes32(manifest.corpus.root, 'corpus.root', errors);
  validateBiEncoderManifest(manifest.model.biEncoder, errors);
  validateRerankerManifest(manifest.model.reranker, 'reranker', errors);
  validateRerankerManifest(manifest.model.labelingReranker, 'labelingReranker', errors);
  if (manifest.model.reranker.modelId === manifest.model.labelingReranker.modelId
   && manifest.model.reranker.revision === manifest.model.labelingReranker.revision) {
    errors.push('labelingReranker must differ from production reranker');
  }
  validateProfile(manifest.evaluator.profile, errors);

  for (const file of [
    ...manifest.substrate.specs,
    ...manifest.substrate.implementation,
    ...manifest.corpus.files,
    ...manifest.evaluator.files,
    ...manifest.replay.snapshots,
  ]) {
    const abs = resolve(repoRoot, file.path);
    if (!existsSync(abs)) {
      errors.push(`${file.path}: missing`);
      continue;
    }
    const got = sha256Hex(readFileSync(abs));
    if (got !== file.sha256.toLowerCase()) errors.push(`${file.path}: sha256 mismatch`);
  }

  const { bundleHash: _bundleHash, ...withoutHash } = manifest;
  const expected = hashJson(withoutHash);
  if (expected !== manifest.bundleHash.toLowerCase()) {
    errors.push(`bundleHash mismatch: expected ${expected} got ${manifest.bundleHash}`);
  }
  return errors;
}

function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'undefined') return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return JSON.stringify(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'bigint') return JSON.stringify(value.toString());
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(obj[key])}`).join(',')}}`;
  }
  throw new TypeError(`canonicalJson: unsupported ${typeof value}`);
}

function hashFile(repoRoot: string, filePath: string, role: string): BundleFile {
  const abs = resolve(repoRoot, filePath);
  const bytes = readFileSync(abs);
  return {
    role,
    path: slash(relative(repoRoot, abs)) || basename(abs),
    sha256: sha256Hex(bytes),
    bytes: bytes.length,
  };
}

function hashJson(value: unknown): string {
  return bytesToHex(keccak256(new TextEncoder().encode(canonicalJson(value))));
}

function sha256Hex(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

function validateBiEncoderManifest(manifest: BiEncoderManifest, errors?: string[]): void {
  const out = errors ?? [];
  if (manifest.provider !== 'huggingface') out.push('biEncoder.provider must be huggingface');
  if (!manifest.modelId) out.push('biEncoder.modelId is required');
  validateRevision(manifest.revision, 'biEncoder.revision', out);
  validateRevision(manifest.tokenizerRevision, 'biEncoder.tokenizerRevision', out);
  if (manifest.mode !== 'dense') out.push('biEncoder.mode must be dense');
  if (manifest.outputDim <= 0) out.push('biEncoder.outputDim must be positive');
  if (manifest.retrievalKeyLayout.headerBytes < 9) out.push('retrievalKeyLayout.headerBytes must be >= 9');
  validateModelFiles(manifest.files, 'biEncoder', out);
  if (!errors && out.length) throw new Error(out.join('; '));
}

function validateRerankerManifest(manifest: RerankerManifest, role: string, errors?: string[]): void {
  const out = errors ?? [];
  if (manifest.provider !== 'huggingface') out.push(`${role}.provider must be huggingface`);
  if (!manifest.modelId) out.push(`${role}.modelId is required`);
  validateRevision(manifest.revision, `${role}.revision`, out);
  validateModelFiles(manifest.files, role, out);
  if (!errors && out.length) throw new Error(out.join('; '));
}

function assertSeparateLabelingModel(prod: RerankerManifest, lab: RerankerManifest): void {
  if (prod.modelId === lab.modelId && prod.revision === lab.revision) {
    throw new Error('labelingReranker must differ from production reranker (modelId or revision)');
  }
}

function validateRevision(revision: string, field: string, errors: string[]): void {
  const value = revision?.trim() ?? '';
  if (!value || isMutableOrPlaceholderRevision(value)) {
    errors.push(`${field} must be a pinned immutable commit sha, not a mutable ref or placeholder`);
    return;
  }
  if (!/^[0-9a-f]{40}$/i.test(value)) {
    errors.push(`${field} must be a 40-hex Hugging Face commit sha`);
  }
}

function validateModelFiles(files: readonly ModelFileFetch[], role: string, errors: string[]): void {
  if (files.length === 0) errors.push(`${role}.files must not be empty`);
  for (const file of files) {
    if (!file.path) errors.push(`${role} file path is required`);
    if (!/^[0-9a-f]{64}$/i.test(file.sha256)) errors.push(`${role} ${file.path}: sha256 must be 64 hex chars`);
    if (file.bytes !== undefined && (!Number.isSafeInteger(file.bytes) || file.bytes <= 0)) {
      errors.push(`${role} ${file.path}: bytes must be a positive safe integer`);
    }
  }
}

function validateProfile(profile: EvaluatorProfile, errors?: string[]): void {
  const out = errors ?? [];
  if (profile.acceleratorPolicy !== 'cpu_only') out.push("acceleratorPolicy must be 'cpu_only'");
  if (profile.primaryMetric !== 'ndcg@10') out.push("primaryMetric must be 'ndcg@10'");
  const w = profile.compositeWeights;
  const sum = w.w_retrieval + w.w_temporal + w.w_relation_recall + w.w_abstention + w.w_structural_sanity;
  if (Math.abs(sum - 1) > 1e-6) out.push(`compositeWeights must sum to 1.0 (got ${sum})`);
  if (w.w_retrieval < 0.7 - 1e-9) out.push(`w_retrieval must be >= 0.70 (got ${w.w_retrieval})`);
  if (w.w_structural_sanity > 0.10 + 1e-9) out.push(`w_structural_sanity must be <= 0.10 (got ${w.w_structural_sanity})`);
  if (w.w_temporal <= 0 || w.w_relation_recall <= 0 || w.w_abstention <= 0)
    out.push('w_temporal, w_relation_recall, w_abstention must all be > 0');
  const sr = profile.splitRatios;
  if (sr.trainVisiblePct + sr.calibrationPct + sr.evalHiddenPct + sr.canaryPct !== 100)
    out.push('splitRatios must sum to 100');
  if (profile.relationHopBudget < 1 || profile.relationHopBudget > 6)
    out.push('relationHopBudget must be in [1,6]');
  if (profile.replayTolerancePpm > profile.patchAcceptanceFloors.minImprovementPpm)
    out.push('replayTolerancePpm must be <= patchAcceptanceFloors.minImprovementPpm');
  if (!errors && out.length) throw new Error(out.join('; '));
}

function isMutableOrPlaceholderRevision(revision: string): boolean {
  const lower = revision.toLowerCase();
  return ['main', 'master', 'latest', 'head', 'placeholder', 'todo', 'v0.1.0'].includes(lower);
}

function validateBytes32(value: string, name: string, errors: string[]) {
  if (!isBytes32(value)) errors.push(`${name} must be bytes32 hex`);
}

function assertBytes32(value: string, name: string) {
  if (!isBytes32(value)) throw new Error(`${name} must be bytes32 hex`);
}

function isBytes32(value: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function slash(path: string): string {
  return path.replaceAll('\\', '/');
}

// ─── Coordinator startup assertion ───────────────────────────────────────────

/**
 * Refuses to return when GPU acceleration is hinted at by environment, when
 * the runtime versions don't match the bundle's runtimePin, or when the
 * on-chain coreVersionHash differs from the bundle hash.
 *
 * Spec: specs/determinism_v0.md §Refusal.
 */
export function assertBundleBindingAtStartup(opts: {
  readonly manifest: CoreTexBundleManifest;
  readonly onChainCoreVersionHash: string;
  readonly installedRuntimeVersions: Readonly<Record<string, string>>;
}): void {
  if (opts.manifest.bundleHash.toLowerCase() !== opts.onChainCoreVersionHash.toLowerCase()) {
    throw new Error(
      `coreVersionHash mismatch: on-chain ${opts.onChainCoreVersionHash} vs bundle ${opts.manifest.bundleHash}`,
    );
  }
  if (opts.manifest.evaluator.profile.acceleratorPolicy !== 'cpu_only') {
    throw new Error("acceleratorPolicy must be 'cpu_only'");
  }
  for (const envVar of ['CORETEX_USE_GPU', 'PYTORCH_USE_MPS']) {
    const v = process.env[envVar];
    if (v && v !== '0') throw new Error(`refuse to start with ${envVar}=${v}`);
  }
  if (process.env['CUDA_VISIBLE_DEVICES']) {
    throw new Error('refuse to start with CUDA_VISIBLE_DEVICES set');
  }
  const ortProviders = process.env['ONNXRUNTIME_PROVIDERS'] ?? '';
  if (ortProviders.includes('CUDA') || ortProviders.includes('MPS')) {
    throw new Error(`refuse to start with ONNXRUNTIME_PROVIDERS=${ortProviders}`);
  }
  // Validate runtime pin: every required version must match.
  const expected = opts.manifest.evaluator.profile.runtimePin.versions;
  for (const [pkg, range] of Object.entries(expected)) {
    const installed = opts.installedRuntimeVersions[pkg];
    if (!installed) throw new Error(`runtime mismatch: ${pkg} not installed (expected ${range})`);
    if (!matchSemverRange(installed, range)) {
      throw new Error(`runtime mismatch: ${pkg} ${installed} does not match ${range}`);
    }
  }
}

function matchSemverRange(installed: string, range: string): boolean {
  if (range === installed) return true;
  // Match X.Y.* against installed X.Y.Z
  const m = range.match(/^(\d+)\.(\d+)\.\*$/);
  if (m) {
    const [, maj, min] = m;
    const re = new RegExp(`^${maj}\\.${min}\\.\\d+$`);
    return re.test(installed);
  }
  // Match X.* against installed X.Y.Z
  const major = range.match(/^(\d+)\.\*$/);
  if (major) {
    const [, maj] = major;
    const re = new RegExp(`^${maj}\\.\\d+\\.\\d+$`);
    return re.test(installed);
  }
  return false;
}
