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
  readonly primaryMetric: 'ndcg@10' | 'map' | 'composite';
  readonly replayTolerancePpm: number;
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
  'packages/cortex/src/replay/v4.ts',
  'packages/cortex/src/replay-cli.ts',
] as const;

const DEFAULT_PROFILE: EvaluatorProfile = {
  name: 'coretex-v4-launch',
  version: 'v1',
  scoreScale: 'ppm',
  primaryMetric: 'composite',
  replayTolerancePpm: 250,
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
 * Update this when a new reproducible release is available.
 * 'main' is intentionally rejected by validateModelManifest — this must
 * be a pinned commit sha or version tag.
 */
export const QWEN3_RERANKER_DEFAULT_REVISION = 'v0.1.0';

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
    resolvedFiles = files ?? [];
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
        'coretex-replay tx --tx <hash> --rpc <url> --parent-state <state.bin>',
        'coretex-replay current --events <events.json> --parent-state <state.bin>',
        'coretex-replay watch --rpc <url> --v4 <address> --cortex-state <address> --from-block <n> --parent-state <state.bin>',
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
  if (!manifest.revision || manifest.revision === 'main') {
    out.push('model.revision must be a pinned commit/tag, not main');
  }
  if (manifest.files.length === 0) out.push('model.files must not be empty');
  for (const file of manifest.files) {
    if (!file.path) out.push('model file path is required');
    if (!/^[0-9a-f]{64}$/i.test(file.sha256)) out.push(`${file.path}: model sha256 must be 64 hex chars`);
  }
  if (!errors && out.length) throw new Error(out.join('; '));
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
