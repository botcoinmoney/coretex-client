import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { basename, relative, resolve } from 'node:path';

import { bytesToHex } from '../state/merkle.js';
import { keccak256 } from '../state/keccak256.js';

export interface BundleFile {
  readonly role: string;
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
}

export interface ModelFetchManifest {
  readonly provider: 'huggingface';
  readonly modelId: string;
  readonly revision: string;
  readonly files: readonly {
    readonly path: string;
    readonly sha256: string;
    readonly bytes?: number;
  }[];
}

export interface EvaluatorProfile {
  readonly name: string;
  readonly version: string;
  readonly scoreScale: 'ppm';
  readonly scorePpmEncoding: 'uint32-0-to-1000000';
  readonly patchScoreDeltaEncoding: 'int64-ppm';
  readonly primaryMetric: 'ndcg@10' | 'map' | 'composite';
  readonly replayTolerancePpm: number;
  readonly rerankerThresholdPpm: number;
  /**
   * F3 fix: minimum reranker score for a (query, document) pair to count as a
   * "hit" in evaluateStateWithReranker / evaluatePatchWithReranker.
   *
   * Calibration from Qwen3-Reranker-0.6B on a representative DACR sample:
   *   relevant pairs:   mean score ≈ 0.0068
   *   unrelated pairs:  mean score ≈ 0.00028
   *   ratio: 24×  →  threshold at 0.002 cleanly separates relevant from unrelated.
   *
   * The old threshold of 1/(topK+1) = 0.5 never fires against the real model
   * because Qwen3 outputs logit-scaled scores ≪ 0.5.
   *
   * Default: 0.002 (between relevant 0.0068 and unrelated 0.00028, with margin).
   */
  readonly rerankerHitThreshold: number;
  readonly familyWeights: Record<string, number>;
  readonly protectedRegressionVeto: boolean;
}

export interface CoreTexBundleManifest {
  readonly schemaVersion: 'coretex.client-bundle.v1';
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
  readonly model: ModelFetchManifest;
  readonly replay: {
    readonly commands: readonly string[];
    readonly coordinatorCacheOptional: true;
    readonly snapshots: readonly BundleFile[];
  };
  readonly bundleHash: string;
}

export interface BuildBundleManifestOptions {
  readonly repoRoot: string;
  readonly bundleName?: string;
  readonly generatedAt?: string;
  readonly corpusRoot: string;
  readonly corpusFiles: readonly string[];
  readonly model: ModelFetchManifest;
  readonly evaluatorProfile?: Partial<EvaluatorProfile>;
  readonly extraEvaluatorFiles?: readonly string[];
  readonly snapshotFiles?: readonly string[];
}

const DEFAULT_SPEC_FILES = [
  'docs/state-spec.md',
  'specs/cortex_state_v0.md',
  'specs/cortex_schema_v0.json',
  'specs/packing_spec_v0.md',
  'specs/merkleization_spec_v0.md',
  'specs/patch_format_v0.md',
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
  'packages/cortex/src/eval/index.ts',
  'packages/cortex/src/eval/corpus.ts',
  'packages/cortex/src/eval/reranker.ts',
  'packages/cortex/src/eval/reranker-eval.ts',
  'packages/cortex/src/corpus/admission.ts',
  'packages/cortex/src/corpus/dacr-bridge.ts',
  'packages/cortex/src/corpus/delta.ts',
  'packages/cortex/src/corpus/epoch-rotation.ts',
  'packages/cortex/src/corpus/v3-bridge.ts',
  'packages/cortex/src/rewards/difficulty.ts',
  'packages/cortex/src/coordinator/endpoints.ts',
  'packages/cortex/src/substrate/slot-policy.ts',
  'packages/cortex/src/replay/v4.ts',
  'packages/cortex/src/replay-cli.ts',
] as const;

const DEFAULT_PROFILE: EvaluatorProfile = {
  name: 'coretex-v4-launch',
  version: 'v1',
  scoreScale: 'ppm',
  scorePpmEncoding: 'uint32-0-to-1000000',
  patchScoreDeltaEncoding: 'int64-ppm',
  primaryMetric: 'composite',
  replayTolerancePpm: 250,
  rerankerThresholdPpm: 2500,
  // F3 fix: calibrated threshold for Qwen3-Reranker-0.6B.
  // relevant ≈ 0.0068 > 0.002 > unrelated ≈ 0.00028 (24× separation on DACR sample).
  rerankerHitThreshold: 0.002,
  protectedRegressionVeto: true,
  familyWeights: {
    near_collision_retrieval: 20,
    temporal_current_stale: 20,
    long_horizon: 20,
    relation_multi_hop: 20,
    codebook_compression: 10,
    local_model_agreement: 10,
  },
};

/**
 * The default pinned revision for the Qwen3-Reranker-0.6B model.
 * Update this only by refreshing the file SHA-256 table below.
 */
export const QWEN3_RERANKER_DEFAULT_REVISION = 'e61197ed45024b0ed8a2d74b80b4d909f1255473';

export const QWEN3_RERANKER_06B_FILES: ModelFetchManifest['files'] = [
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
] as const;

export function qwen3Reranker06BManifest(
  revisionOrFiles?: string | ModelFetchManifest['files'],
  files?: ModelFetchManifest['files'],
): ModelFetchManifest {
  // Support three call signatures:
  //   qwen3Reranker06BManifest(revision, files)   — original positional form
  //   qwen3Reranker06BManifest(files)              — revision defaults
  //   qwen3Reranker06BManifest()                   — both default (empty files)
  let resolvedRevision: string;
  let resolvedFiles: ModelFetchManifest['files'];

  if (typeof revisionOrFiles === 'string') {
    // Original positional form: (revision, files)
    resolvedRevision = revisionOrFiles;
    resolvedFiles = files ?? [];
  } else if (Array.isArray(revisionOrFiles)) {
    // New form: (files) — revision defaults
    resolvedRevision = QWEN3_RERANKER_DEFAULT_REVISION;
    resolvedFiles = revisionOrFiles;
  } else {
    // No-arg form
    resolvedRevision = QWEN3_RERANKER_DEFAULT_REVISION;
    resolvedFiles = files ?? QWEN3_RERANKER_06B_FILES;
  }

  return {
    provider: 'huggingface',
    modelId: 'Qwen/Qwen3-Reranker-0.6B',
    revision: resolvedRevision,
    files: resolvedFiles,
  };
}

export function buildBundleManifest(opts: BuildBundleManifestOptions): CoreTexBundleManifest {
  assertBytes32(opts.corpusRoot, 'corpusRoot');
  validateModelManifest(opts.model);
  const generatedAt = opts.generatedAt ?? new Date(0).toISOString();
  const profile = { ...DEFAULT_PROFILE, ...opts.evaluatorProfile };
  const evaluatorFiles = [...DEFAULT_EVALUATOR_FILES, ...(opts.extraEvaluatorFiles ?? [])];

  const withoutHash = {
    schemaVersion: 'coretex.client-bundle.v1' as const,
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
    model: opts.model,
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
  if (manifest.schemaVersion !== 'coretex.client-bundle.v1') errors.push('bad schemaVersion');
  if (manifest.substrate.wordCount !== 1024) errors.push('substrate.wordCount must be 1024');
  if (manifest.substrate.packedBytes !== 32768) errors.push('substrate.packedBytes must be 32768');
  validateBytes32(manifest.corpus.root, 'corpus.root', errors);
  validateModelManifest(manifest.model, errors);

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

function validateModelManifest(manifest: ModelFetchManifest, errors?: string[]): void {
  const out = errors ?? [];
  if (manifest.provider !== 'huggingface') out.push('model.provider must be huggingface');
  if (!manifest.modelId) out.push('model.modelId is required');
  const revision = manifest.revision?.trim();
  if (!revision || isMutableOrPlaceholderRevision(revision)) {
    out.push('model.revision must be a pinned immutable commit sha, not a mutable ref or placeholder');
  } else if (manifest.modelId === 'Qwen/Qwen3-Reranker-0.6B' && !/^[0-9a-f]{40}$/i.test(revision)) {
    out.push('model.revision for Qwen/Qwen3-Reranker-0.6B must be a 40-hex Hugging Face commit sha');
  }
  if (manifest.files.length === 0) out.push('model.files must not be empty');
  for (const file of manifest.files) {
    if (!file.path) out.push('model file path is required');
    if (!/^[0-9a-f]{64}$/i.test(file.sha256)) out.push(`${file.path}: model sha256 must be 64 hex chars`);
    if (file.bytes !== undefined && (!Number.isSafeInteger(file.bytes) || file.bytes <= 0)) {
      out.push(`${file.path}: model bytes must be a positive safe integer`);
    }
  }
  if (!errors && out.length) throw new Error(out.join('; '));
}

function isMutableOrPlaceholderRevision(revision: string): boolean {
  const lower = revision.toLowerCase();
  return [
    'main',
    'master',
    'latest',
    'head',
    'placeholder',
    'todo',
    'v0.1.0',
  ].includes(lower);
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
