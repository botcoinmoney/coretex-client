#!/usr/bin/env node
/**
 * coretex-validator-sync — one-command validator sync + audit CLI.
 *
 * sync (default): with only BASE_RPC_URL + CORETEX_REGISTRY_ADDRESS +
 * BOTCOIN_MINING_CONTRACT_ADDRESS + CORETEX_ARTIFACT_BASE_URL set and
 * `coretex-validator-setup` completed, a bare `coretex-validator-sync`:
 *   1. Derives the epoch from V4 `currentEpoch()` on chain (--epoch overrides)
 *      and reads the on-chain epoch pins (registry + V4 mining context)
 *      including the epoch-secret reveal status
 *      (`awaiting_epoch_secret_reveal` before reveal).
 *   2. Self version-check: the local bundle manifest's bundleHash MUST equal
 *      the on-chain coreVersionHash (escape: --allow-version-mismatch,
 *      read-only). Bundle manifest path comes from the validator state file
 *      written by setup (--bundle-manifest / CORETEX_BUNDLE_MANIFEST override).
 *   3. Fetches the signed EpochRotationManifest + signed CorpusDelta and
 *      verifies signatures (MANDATORY — a missing public key is a hard error)
 *      under a TOFU-pinned epoch signing key.
 *   4. Corpus-delta continuity: delta.previousRoot must equal the LOCAL
 *      previous corpus root (validator state file / --previous-corpus-root /
 *      bundle corpus.root).
 *   5. Replays the registry logs BY DEFAULT (paginated + confirmation-depth
 *      capped) against the on-chain liveStateRoot. The parent substrate is
 *      bootstrapped from the launch/blank substrate when the chain parent root
 *      equals the launch parent root (or when replaying from the registry
 *      deploy block), else from the snapshot persisted by the previous sync
 *      (state dir `substrate-state.bin` + cursor block → incremental syncs).
 *   6. After replay, if the epoch secret is revealed on chain, AUTOMATICALLY
 *      fetches the post-reveal eval artifacts for every accepted advance in
 *      the synced window and verifies each through
 *      `verifyPostRevealEvalReportArtifact` — INCLUDING score re-scoring with
 *      the FAIL-CLOSED validator scorer (pinned qwen3 from the bundle
 *      manifest; the deterministic stub is unreachable). `--skip-score-replay`
 *      is the only way to skip (loud warning, exit code 3 — distinct from
 *      success).
 *
 * verify-patch --hash 0x…:
 *   Fetches a post-reveal eval artifact by hash from CORETEX_ARTIFACT_BASE_URL
 *   and replays it through verifyPostRevealEvalReportArtifact (the single
 *   entrypoint) with the same fail-closed scorer gate.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, unlinkSync, realpathSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import http from 'node:http';
import https from 'node:https';

import {
  coretexRangeLogs,
  decodeCoreTexStateAdvanced,
  replayCoreTexFromLogs,
  CORETEX_DEFAULT_CONFIRMATION_DEPTH,
  type CoreTexRangeLogOptions,
  type CoreTexStateAdvancedEvent,
} from './replay/coretex-registry.js';
import { loadPackedState, rpcCall } from './replay/v4.js';
import { bytesToHex, hexToBytes, merkleizeState } from './state/merkle.js';
import { pack, unpack, PACKED_SIZE } from './state/codec.js';
import { applyPatch, decodePatch } from './state/patch.js';
import type { CortexState } from './state/types.js';
import { keccak256 } from './state/keccak256.js';
import { computePatchHash } from './eval/seed-derivation.js';
import { hashCorpusDelta, hashJson, verifyEpochRotationManifestSignature } from './corpus/epoch-rotation.js';
import { parseCorpusDelta, verifyCorpusDeltaSignature } from './corpus/delta.js';
import {
  evalReportArtifactUrl,
  hashPostRevealEvalReportArtifact,
  verifyPostRevealEvalReportArtifact,
  type CoreTexPostRevealEvalReportArtifact,
} from './replay/eval-report-artifact.js';
import { DEFAULT_PROFILE, scoringOptionsFromProfile, type CoreTexBundleManifest } from './bundle/index.js';
import { loadProductionCorpus, type ProductionCorpus } from './eval/retrieval-corpus.js';
import { deriveQueryPack } from './eval/hidden-query-pack.js';
import { computeAcceptanceThresholdPpm, evaluateRetrievalBenchmarkPatch } from './eval/retrieval-benchmark.js';
import { biEncoderFromEnv } from './eval/bi-encoder.js';
import {
  assertValidatorRerankerEnv,
  createValidatorReranker,
  qwenRerankerPromptTemplateHash,
  resolveQwenRerankerInstruction,
  resolveRerankerScriptPath,
  type ValidatorRerankerPins,
} from './eval/reranker.js';
import { biEncoderModelIdHash } from './substrate/retrieval-decoder.js';
import { createBaseRpcClient } from './coordinator/base-blockhash.js';
import {
  applyRerankerThreadDefault,
  makeProgress,
  probeScorerHealth,
  realSyncSpawner,
  renderSummaryBlock,
  scorerRuntimeMatchesBundle,
  type ScorerRuntimeBundlePins,
  type ThreadDefaultResult,
} from './validator-runtime.js';

const ZERO32 = `0x${'00'.repeat(32)}`;
const args = process.argv.slice(2);

/** Exit code when score replay was explicitly skipped: the run is NOT a score
 *  attestation and must be distinguishable from a fully verified sync (0). */
export const SKIP_SCORE_REPLAY_EXIT_CODE = 3;

const USAGE = `coretex-validator-sync — one-command CoreTex validator sync + audit

Usage:
  coretex-validator-sync [flags]                 sync (default command)
  coretex-validator-sync verify-patch --hash 0x… verify one post-reveal eval artifact

One-command sync env (after coretex-validator-setup):
  BASE_RPC_URL, CORETEX_REGISTRY_ADDRESS, BOTCOIN_MINING_CONTRACT_ADDRESS,
  CORETEX_ARTIFACT_BASE_URL

Common flags (all optional overrides of setup/state-file/chain defaults):
  --epoch <n>                  override the chain-derived V4 currentEpoch()
  --bundle-manifest <path>     override the setup-recorded bundle manifest
  --previous-corpus-root 0x…   override the state-file previous corpus root
  --from-block <n>             override the replay window start
  --parent-state <state.bin>   override the replay parent substrate
  --corpus <corpus.json>       override the setup-recorded materialized corpus
  --state-dir <dir>            validator state dir (default .coretex-validator)
  --skip-score-replay          SKIP post-reveal score re-scoring (loud; exit ${SKIP_SCORE_REPLAY_EXIT_CODE})
  --allow-version-mismatch     read-only escape for the bundle version check
  --no-progress                suppress stderr progress/ETA (auto-off on CI=1 / non-TTY)
  --help                       this text

Runtime: when set up via coretex-validator-setup, score replay reuses the
recorded scorer venv (CORETEX_RERANKER_PYTHON, override always wins) and picks a
sane RERANKER_NUM_THREADS (min(physical cores, ${16}); operator override wins).
These affect runtime speed only — never scores. Progress/ETA print to stderr;
the machine-readable JSON status stays on stdout.`;

function opt(name: string, fallback?: string): string | undefined {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : fallback;
}
function all(name: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) if (args[i] === `--${name}` && args[i + 1]) out.push(args[i + 1]!);
  return out;
}
function has(name: string): boolean {
  return args.includes(`--${name}`);
}
function die(message: string): never {
  process.stderr.write(`HARD FAIL: ${message}\n`);
  process.exit(1);
}
function warn(message: string): void {
  process.stderr.write(`${message}\n`);
}
function isBytes32(value: unknown): value is string {
  return typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value);
}
function isAddress(value: unknown): value is string {
  return typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/.test(value);
}
function selector(signature: string): string {
  return bytesToHex(keccak256(new TextEncoder().encode(signature))).slice(0, 10);
}
function uint64Word(value: string | number | bigint): string {
  const n = BigInt(value);
  if (n < 0n || n > 0xffffffffffffffffn) throw new Error(`uint64 out of range: ${value}`);
  return n.toString(16).padStart(64, '0');
}
function calldata(signature: string, callArgs: readonly (string | number | bigint)[] = []): string {
  return selector(signature) + callArgs.map(uint64Word).join('');
}
function decodeBytes32(result: string, label: string): string {
  if (!/^0x[0-9a-fA-F]{64,}$/.test(result)) throw new Error(`${label} returned malformed bytes32`);
  return `0x${result.slice(2, 66).toLowerCase()}`;
}
function decodeAddress(result: string, label: string): string {
  const word = decodeBytes32(result, label);
  return `0x${word.slice(-40)}`;
}
function decodeUint(result: string, label: string): number {
  if (!/^0x[0-9a-fA-F]+$/.test(result)) throw new Error(`${label} returned malformed uint`);
  const n = BigInt(result);
  if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`${label} exceeds safe integer`);
  return Number(n);
}
async function ethCall(
  rpcUrl: string,
  to: string,
  signature: string,
  callArgs: readonly (string | number | bigint)[] = [],
  blockTag: string = 'latest',
): Promise<string> {
  return rpcCall<string>(rpcUrl, 'eth_call', [{ to, data: calldata(signature, callArgs) }, blockTag]);
}
async function readJsonUri(uri: string): Promise<unknown> {
  if (uri.startsWith('http://') || uri.startsWith('https://')) return JSON.parse(await download(uri));
  if (uri.startsWith('file://')) return JSON.parse(readFileSync(new URL(uri), 'utf8'));
  return JSON.parse(readFileSync(uri, 'utf8'));
}
async function readTextUri(uri: string): Promise<string> {
  if (uri.startsWith('http://') || uri.startsWith('https://')) return download(uri);
  if (uri.startsWith('file://')) return readFileSync(new URL(uri), 'utf8');
  return readFileSync(uri, 'utf8');
}
function download(url: string, redirects = 0): Promise<string> {
  return new Promise((resolvePromise, reject) => {
    const client = url.startsWith('https:') ? https : http;
    const req = client.get(url, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode ?? 0)) {
        res.resume();
        if (!res.headers.location || redirects >= 5) return reject(new Error(`redirect failed for ${url}`));
        return resolvePromise(download(new URL(res.headers.location, url).toString(), redirects + 1));
      }
      if ((res.statusCode ?? 0) < 200 || (res.statusCode ?? 0) >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      let out = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { out += d; });
      res.on('end', () => resolvePromise(out));
    });
    req.on('error', reject);
  });
}
function joinUrl(base: string | undefined, child: string): string | undefined {
  return base ? `${base.replace(/\/+$/, '')}/${child.replace(/^\/+/, '')}` : undefined;
}
function stringField(obj: Record<string, unknown> | null | undefined, key: string): string | undefined {
  const value = obj?.[key];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}
function blockHex(block: bigint): string {
  return `0x${block.toString(16)}`;
}
async function latestBlock(rpcUrl: string): Promise<bigint> {
  return BigInt(await rpcCall<string>(rpcUrl, 'eth_blockNumber', []));
}
function cmpBig(a: bigint, b: bigint): number { return a < b ? -1 : a > b ? 1 : 0; }

// ── exported audit primitives (unit-tested directly) ─────────────────────────

export function sha256Fingerprint(text: string): string {
  return `0x${createHash('sha256').update(text).digest('hex')}`;
}

/**
 * Corpus-delta continuity: the signed delta must chain off the validator's OWN
 * previous corpus root (ported from scripts/coretex-validator-sync.mjs). Without
 * this, a coordinator could serve a delta chaining off a root the validator
 * never held and the validator would silently adopt a forked corpus.
 */
export function checkCorpusDeltaContinuity(deltaPreviousRoot: string, localPreviousRoot: string | undefined): void {
  if (!isBytes32(localPreviousRoot)) {
    throw new Error('corpus-delta continuity: local previous corpus root unavailable — pass --previous-corpus-root, point --state-dir at the validator sync state, or use a bundle manifest with corpus.root');
  }
  if (deltaPreviousRoot.toLowerCase() !== localPreviousRoot.toLowerCase()) {
    throw new Error(`corpus-delta continuity: delta.previousRoot ${deltaPreviousRoot} != local previous corpus root ${localPreviousRoot}`);
  }
}

/**
 * TOFU key check: compares the served epoch signing key against the pinned one.
 * Hard error if a pin exists and the served key differs. Returns pinned=false
 * when no pin exists yet (caller writes the pin AFTER signatures verify).
 */
export function checkTofuKeyPin(pinPath: string, publicKeyPem: string): { fingerprint: string; pinned: boolean } {
  const fingerprint = sha256Fingerprint(publicKeyPem);
  if (!existsSync(pinPath)) return { fingerprint, pinned: false };
  const pin = JSON.parse(readFileSync(pinPath, 'utf8')) as { fingerprint?: string; publicKeyPem?: string };
  if (String(pin.fingerprint).toLowerCase() !== fingerprint.toLowerCase() || pin.publicKeyPem !== publicKeyPem) {
    throw new Error(`TOFU key pin mismatch: served epoch signing key fingerprint ${fingerprint} != pinned ${pin.fingerprint} (${pinPath}) — refusing to sync; verify the key rotation out-of-band before replacing the pin file`);
  }
  return { fingerprint, pinned: true };
}

/** Canonical serialized TOFU pin file body (shared by the eager + staged writers). */
export function serializeTofuKeyPin(publicKeyPem: string): { fingerprint: string; body: string } {
  const fingerprint = sha256Fingerprint(publicKeyPem);
  const body = JSON.stringify({
    schema: 'coretex.epoch-signing-key-pin.v1',
    pinnedAt: new Date().toISOString(),
    fingerprint,
    publicKeyPem,
  }, null, 2) + '\n';
  return { fingerprint, body };
}

/** Write the TOFU pin after the FIRST fully verified sync. */
export function writeTofuKeyPin(pinPath: string, publicKeyPem: string): { fingerprint: string } {
  const { fingerprint, body } = serializeTofuKeyPin(publicKeyPem);
  mkdirSync(dirname(resolve(pinPath)), { recursive: true });
  writeFileSync(pinPath, body);
  return { fingerprint };
}

// ── atomic trusted-state staging (Finding 7) ──────────────────────────────────

/**
 * Stage trusted-state writes (the TOFU pin, the substrate snapshot, the state
 * file) to temp files and atomically commit (rename) them ONLY AFTER every
 * mandatory check for the sync pass has passed. If any mandatory check throws
 * before `commit()`, NOTHING in trusted state is mutated — `dispose()` removes
 * the temp files and the prior pin/snapshot/state remain byte-unchanged.
 *
 * Atomicity is per-file (rename(2) is atomic per path); we commit the snapshot
 * first, then the state file, then the TOFU pin, so a crash mid-commit can only
 * leave already-trusted artifacts (never a half-written file claimed as
 * trusted). All mandatory verification happens before the first rename.
 */
export class TrustedStateStaging {
  private readonly staged: { tmp: string; dest: string }[] = [];

  /** Queue a file write to `dest`, materialized at a sibling temp path. */
  stage(dest: string, contents: string | Uint8Array): void {
    mkdirSync(dirname(resolve(dest)), { recursive: true });
    const tmp = `${dest}.tmp-${process.pid}-${this.staged.length}`;
    try { if (existsSync(tmp)) unlinkSync(tmp); } catch { /* stale tmp */ }
    writeFileSync(tmp, contents);
    this.staged.push({ tmp, dest });
  }

  /** Atomically commit every staged write (rename temp → dest), in stage order. */
  commit(): void {
    for (const { tmp, dest } of this.staged) renameSync(tmp, dest);
    this.staged.length = 0;
  }

  /** Remove any uncommitted temp files (best-effort; safe to call always). */
  dispose(): void {
    for (const { tmp } of this.staged) {
      try { if (existsSync(tmp)) unlinkSync(tmp); } catch { /* already gone */ }
    }
    this.staged.length = 0;
  }
}

/** Merge a state-file patch over the on-disk state and return the serialized
 *  body (same merge semantics as mergeValidatorStateFile, but WITHOUT writing —
 *  the body is staged and committed atomically by TrustedStateStaging). */
export function serializeMergedValidatorState(
  statePath: string,
  patch: Record<string, unknown>,
): string {
  let previous: Record<string, unknown> = {};
  if (existsSync(statePath)) {
    try { previous = JSON.parse(readFileSync(statePath, 'utf8')) as Record<string, unknown>; } catch { previous = {}; }
  }
  const merged = {
    schema: 'coretex.validator-sync-state.v1',
    ...previous,
    ...patch,
    updatedAt: new Date().toISOString(),
  };
  return JSON.stringify(merged, null, 2) + '\n';
}

/**
 * Self version-check: the local bundle manifest must be the one pinned on chain.
 * On mismatch this throws a 'validator client outdated' error naming the required
 * bundle hash, unless allowMismatch (read-only inspection) — then it loud-warns.
 */
export function checkValidatorBundleVersion(
  localBundleHash: string,
  chainCoreVersionHash: string,
  allowMismatch: boolean,
  warnFn: (message: string) => void = (m) => process.stderr.write(`${m}\n`),
): { match: boolean } {
  if (localBundleHash.toLowerCase() === chainCoreVersionHash.toLowerCase()) return { match: true };
  const message = `validator client outdated: local bundle ${localBundleHash} != on-chain coreVersionHash ${chainCoreVersionHash}. Required bundle hash: ${chainCoreVersionHash}`;
  if (!allowMismatch) throw new Error(message);
  warnFn(`WARNING: ${message} — continuing READ-ONLY because --allow-version-mismatch was passed; do NOT attest from this run`);
  return { match: false };
}

/** Epoch-secret reveal status: zero secret = pre-reveal (eval replay must wait). */
export function deriveEpochSecretRevealStatus(hiddenSeedCommit: string, epochSecret: string): {
  evalReplayStatus: 'epoch_secret_revealed' | 'awaiting_epoch_secret_reveal';
  epochSecretRevealed: boolean;
} {
  if (epochSecret.toLowerCase() === ZERO32) {
    return { evalReplayStatus: 'awaiting_epoch_secret_reveal', epochSecretRevealed: false };
  }
  const commit = bytesToHex(keccak256(hexToBytes(epochSecret))).toLowerCase();
  if (commit !== hiddenSeedCommit.toLowerCase()) {
    throw new Error(`mining epochSecret commit ${commit} != registry hiddenSeedCommit ${hiddenSeedCommit}`);
  }
  return { evalReplayStatus: 'epoch_secret_revealed', epochSecretRevealed: true };
}

/** Mode flags derive HARD from the chain-pinned bundle manifest — never a silent default. */
export function policyAtomsModeFromManifest(manifest: { evaluator?: { profile?: { pipelineVersion?: string } } }): boolean {
  return manifest.evaluator?.profile?.pipelineVersion === 'coretex-retrieval-v2-policy-r5';
}

// ── one-command defaults (unit-tested directly) ───────────────────────────────

/**
 * One accepted on-chain advance that still owes a post-reveal score replay.
 * Persisted in the state file so a validator that restarts BETWEEN the epoch
 * secret reveal and the next sync can never permanently skip the required
 * score verification (Finding 5). An entry is only removed once its score
 * replay PASSES — never dropped silently.
 */
export interface EvalBacklogEntry {
  readonly epochId: number;
  /** Block the CoreTexStateAdvanced log was confirmed at (for ordering / audit). */
  readonly advanceBlock: number;
  /** On-chain evalReportHash == published artifactHash for this advance. */
  readonly artifactHash: string;
  readonly miner: string;
  /** Replay reason this entry is still pending (e.g. awaiting reveal / context). */
  readonly reason: 'awaiting_epoch_secret_reveal' | 'epoch-context-unavailable';
  /** The advance's on-chain pins — used to bind the artifact on a later sync. */
  readonly parentStateRoot: string;
  readonly corpusRoot: string;
  readonly coreVersionHash: string;
  readonly patchHash: string;
}

export interface ValidatorSyncStateFile {
  readonly schema?: string;
  readonly epoch?: number;
  readonly bundleHash?: string;
  readonly corpusRoot?: string;
  readonly registryDeployBlock?: number;
  readonly setup?: {
    readonly bundleManifestPath?: string;
    readonly profilePath?: string;
    readonly corpusPath?: string;
    readonly materializedRoot?: string;
    readonly artifactBaseUrl?: string;
    /** Scorer interpreter recorded by setup's venv bootstrap (BUILD 1). */
    readonly scorerPython?: string;
    readonly scorerVenvStatus?: string;
  };
  readonly replay?: {
    readonly stateRoot?: string;
    readonly cursorBlock?: number;
    readonly statePath?: string;
    readonly epochTransitions?: Record<string, number>;
  };
  /** Accepted advances not yet score-verified (Finding 5). Survives restarts;
   *  drained only by a PASSING score replay on a later (post-reveal) sync. */
  readonly evalBacklog?: readonly EvalBacklogEntry[];
  /** Highest confirmed block through which EVERY accepted advance's score has
   *  been replayed (empty backlog up to here). Tracked independently of the
   *  root-continuity cursor so semantic-verification completeness is explicit. */
  readonly evalVerifiedThroughBlock?: number;
}

export function readValidatorStateFile(statePath: string): ValidatorSyncStateFile | null {
  if (!existsSync(statePath)) return null;
  try {
    return JSON.parse(readFileSync(statePath, 'utf8')) as ValidatorSyncStateFile;
  } catch {
    return null;
  }
}

/** The launch/blank substrate: all-zero packed state (the registry's launch
 *  epochParentStateRoot is the merkle root of exactly this state). */
export function blankSubstrateState(): CortexState {
  return unpack(new Uint8Array(PACKED_SIZE));
}

export function blankSubstrateStateRoot(): string {
  return bytesToHex(merkleizeState(blankSubstrateState()));
}

export type ReplayFromBlockSource = 'flag' | 'env' | 'snapshot-cursor' | 'state-deploy-block' | 'env-deploy-block';

/**
 * Replay window start, in precedence order: --from-block flag →
 * CORETEX_REPLAY_FROM_BLOCK → snapshot cursor + 1 (incremental sync) →
 * state-file registry deploy block (written by setup) →
 * CORETEX_REGISTRY_DEPLOY_BLOCK. Registry replay is mandatory, so having no
 * source is a hard error pointing at setup.
 */
export function resolveReplayFromBlock(inputs: {
  readonly flag?: string | undefined;
  readonly envReplayFromBlock?: string | undefined;
  readonly envRegistryDeployBlock?: string | undefined;
  readonly snapshotCursorBlock?: number | undefined;
  readonly stateRegistryDeployBlock?: number | undefined;
}): { fromBlock: bigint; source: ReplayFromBlockSource } {
  if (inputs.flag !== undefined) return { fromBlock: BigInt(inputs.flag), source: 'flag' };
  if (inputs.envReplayFromBlock !== undefined) return { fromBlock: BigInt(inputs.envReplayFromBlock), source: 'env' };
  if (inputs.snapshotCursorBlock !== undefined) return { fromBlock: BigInt(inputs.snapshotCursorBlock) + 1n, source: 'snapshot-cursor' };
  if (inputs.stateRegistryDeployBlock !== undefined) return { fromBlock: BigInt(inputs.stateRegistryDeployBlock), source: 'state-deploy-block' };
  if (inputs.envRegistryDeployBlock !== undefined) return { fromBlock: BigInt(inputs.envRegistryDeployBlock), source: 'env-deploy-block' };
  throw new Error(
    'registry replay needs a from-block: run coretex-validator-setup with --registry-deploy-block (or set CORETEX_REGISTRY_DEPLOY_BLOCK), or pass --from-block',
  );
}

export type ReplayParentSource = 'explicit-file' | 'snapshot' | 'blank-substrate';

/**
 * Parent-substrate bootstrap for the default registry replay:
 *   1. --parent-state / CORETEX_PARENT_STATE_PATH (explicit override)
 *   2. the snapshot persisted by the previous sync (incremental)
 *   3. the launch/blank substrate — valid when the chain parent root equals
 *      the launch/blank root, or when replaying the FULL history from the
 *      registry deploy block (per-advance parent continuity then proves the
 *      chain from genesis).
 * Anything else is a hard error: silently replaying from a wrong parent would
 * produce a wrong root and a confusing liveStateRoot mismatch.
 */
export function resolveReplayParentBootstrap(inputs: {
  readonly explicitParentStatePath?: string | undefined;
  readonly snapshotAvailable: boolean;
  readonly chainParentStateRoot: string;
  readonly blankRoot: string;
  readonly fromBlockSource: ReplayFromBlockSource;
}): { source: ReplayParentSource } {
  if (inputs.explicitParentStatePath) return { source: 'explicit-file' };
  if (inputs.snapshotAvailable) return { source: 'snapshot' };
  const deployBootstrap = inputs.fromBlockSource === 'state-deploy-block' || inputs.fromBlockSource === 'env-deploy-block';
  if (inputs.chainParentStateRoot.toLowerCase() === inputs.blankRoot.toLowerCase() || deployBootstrap) {
    return { source: 'blank-substrate' };
  }
  throw new Error(
    `cannot bootstrap replay parent substrate: chain epochParentStateRoot ${inputs.chainParentStateRoot} != launch/blank substrate root ${inputs.blankRoot}, `
    + 'no previous-sync snapshot exists, and the from-block is not the registry deploy block — '
    + 'replay the full history from the deploy block (coretex-validator-setup --registry-deploy-block / CORETEX_REGISTRY_DEPLOY_BLOCK) or pass --parent-state',
  );
}

/** Pins for the fail-closed validator scorer, read HARD from the bundle manifest. */
export function validatorRerankerPinsFromManifest(manifest: CoreTexBundleManifest): ValidatorRerankerPins {
  const reranker = manifest.model?.reranker;
  if (!reranker?.modelId || !reranker?.revision) {
    throw new Error('bundle manifest has no model.reranker.modelId/revision pins — the fail-closed validator scorer cannot be constructed');
  }
  return { modelId: reranker.modelId, revision: reranker.revision };
}

/**
 * Bundle pins the scorer runtime fingerprint is asserted against before any
 * score replay (runtime-pin assertion). modelId/revision come from
 * model.reranker; the torch/transformers ranges + cpu-only flag come from the
 * profile runtimePin; an optional promptTemplateHash binds the resolved
 * template exactly when the bundle records one. A missing runtimePin is a hard
 * error — the validator will not score against an unpinned runtime.
 */
export function scorerRuntimeBundlePinsFromManifest(manifest: CoreTexBundleManifest): ScorerRuntimeBundlePins {
  const { modelId, revision } = validatorRerankerPinsFromManifest(manifest);
  const runtimePin = manifest.evaluator?.profile?.runtimePin;
  const torchRange = runtimePin?.versions?.['torch'];
  const transformersRange = runtimePin?.versions?.['transformers'];
  if (!torchRange || !transformersRange) {
    throw new Error('bundle manifest profile has no runtimePin.versions.torch/transformers — the scorer runtime fingerprint cannot be pinned');
  }
  const reranker = manifest.model?.reranker as { promptTemplateHash?: string } | undefined;
  return {
    modelId,
    revision,
    torchRange,
    transformersRange,
    ...(runtimePin?.buildFlags ? { buildFlags: runtimePin.buildFlags } : {}),
    ...(isBytes32(reranker?.promptTemplateHash) ? { promptTemplateHash: reranker!.promptTemplateHash } : {}),
  };
}

// ── per-advance binding + per-epoch context (unit-tested directly) ────────────

/**
 * Finding 4: bind the fetched eval artifact to the EXACT decoded
 * CoreTexStateAdvanced event for that advance BEFORE any rescore, so that root
 * replay and score replay provably concern the same patch. Throws (clear
 * error) on the first mismatch of epochId, patchHash (artifact seed-derivation,
 * the recomputed hash of the event's compactPatchBytes, AND the event's
 * patchHash), parentStateRoot, corpusRoot, coreVersionHash, or miner.
 */
export function assertArtifactBoundToAdvance(
  artifact: CoreTexPostRevealEvalReportArtifact,
  event: CoreTexStateAdvancedEvent,
): void {
  const label = `eval artifact ${artifact.artifactHash}`;
  if (artifact.epochId !== Number(event.epoch)) {
    throw new Error(`${label} epochId ${artifact.epochId} != advance epoch ${event.epoch}`);
  }
  const computedPatchHash = computePatchHash(event.compactPatchBytes);
  if (computedPatchHash.toLowerCase() !== event.patchHash.toLowerCase()) {
    throw new Error(`${label} advance patchHash ${event.patchHash} != recomputed ${computedPatchHash} from event compactPatchBytes`);
  }
  if (artifact.seedDerivation.patchHash.toLowerCase() !== event.patchHash.toLowerCase()) {
    throw new Error(`${label} seedDerivation.patchHash ${artifact.seedDerivation.patchHash} != advance patchHash ${event.patchHash}`);
  }
  if (artifact.context.parentStateRoot.toLowerCase() !== event.parentStateRoot.toLowerCase()) {
    throw new Error(`${label} context.parentStateRoot ${artifact.context.parentStateRoot} != advance parentStateRoot ${event.parentStateRoot}`);
  }
  if (artifact.context.corpusRoot.toLowerCase() !== event.corpusRoot.toLowerCase()) {
    throw new Error(`${label} context.corpusRoot ${artifact.context.corpusRoot} != advance corpusRoot ${event.corpusRoot}`);
  }
  if (artifact.context.coreVersionHash.toLowerCase() !== event.coreVersionHash.toLowerCase()) {
    throw new Error(`${label} context.coreVersionHash ${artifact.context.coreVersionHash} != advance coreVersionHash ${event.coreVersionHash}`);
  }
  if (artifact.minerAddress.toLowerCase() !== event.miner.toLowerCase()) {
    throw new Error(`${label} minerAddress ${artifact.minerAddress} != advance miner ${event.miner}`);
  }
}

/** The currently-loaded scorer/corpus context's pinned identity (Finding 8). */
export interface LoadedScorerContextPins {
  readonly corpusRoot: string;
  readonly coreVersionHash: string;
}

export type ScorerContextSelection =
  | { readonly action: 'rescore' }
  | { readonly action: 'pending'; readonly reason: 'epoch-context-unavailable'; readonly detail: string };

/**
 * Finding 8 (SAFE version): select the scorer/corpus context for ONE advance.
 * A rescore must ONLY happen with the corpus/bundle that matches the advance's
 * on-chain pins. When the advance's pinned corpusRoot + coreVersionHash match
 * the loaded context → rescore. When they differ (a late validator replaying an
 * older epoch whose pinned corpus/bundle differs), we do NOT silently rescore
 * with the wrong context — the advance is left pending with a clear
 * `epoch-context-unavailable` reason rather than producing a bogus score.
 */
export function selectScorerContextForAdvance(
  advance: { readonly corpusRoot: string; readonly coreVersionHash: string },
  loaded: LoadedScorerContextPins,
): ScorerContextSelection {
  const corpusMatch = advance.corpusRoot.toLowerCase() === loaded.corpusRoot.toLowerCase();
  const versionMatch = advance.coreVersionHash.toLowerCase() === loaded.coreVersionHash.toLowerCase();
  if (corpusMatch && versionMatch) return { action: 'rescore' };
  const drift: string[] = [];
  if (!corpusMatch) drift.push(`corpusRoot ${advance.corpusRoot} != loaded ${loaded.corpusRoot}`);
  if (!versionMatch) drift.push(`coreVersionHash ${advance.coreVersionHash} != loaded ${loaded.coreVersionHash}`);
  return {
    action: 'pending',
    reason: 'epoch-context-unavailable',
    detail: `advance pins differ from the loaded scorer context (${drift.join('; ')}); leaving pending rather than rescoring with the wrong corpus/bundle`,
  };
}

// ── eval-verification backlog (Finding 5; unit-tested directly) ───────────────

/** Build a backlog entry for one accepted advance owed a score replay. */
export function evalBacklogEntryFromAdvance(
  adv: CoreTexStateAdvancedEvent,
  advanceBlock: number,
  reason: EvalBacklogEntry['reason'],
): EvalBacklogEntry {
  return {
    epochId: Number(adv.epoch),
    advanceBlock,
    artifactHash: adv.evalReportHash.toLowerCase(),
    miner: adv.miner.toLowerCase(),
    reason,
    parentStateRoot: adv.parentStateRoot.toLowerCase(),
    corpusRoot: adv.corpusRoot.toLowerCase(),
    coreVersionHash: adv.coreVersionHash.toLowerCase(),
    patchHash: adv.patchHash.toLowerCase(),
  };
}

/** Stable key for a backlog entry: an advance is uniquely (epochId, artifactHash). */
export function evalBacklogKey(entry: { epochId: number; artifactHash: string }): string {
  return `${entry.epochId}:${entry.artifactHash.toLowerCase()}`;
}

/**
 * Merge freshly-pending entries into an existing backlog WITHOUT dropping any.
 * Existing entries are preserved (their reason may be refreshed); new entries
 * are appended. The result is ordered by (advanceBlock, key) for determinism.
 * Nothing is ever removed here — only a passing score replay removes an entry
 * (see removeFromEvalBacklog).
 */
export function upsertEvalBacklog(
  existing: readonly EvalBacklogEntry[] | undefined,
  incoming: readonly EvalBacklogEntry[],
): EvalBacklogEntry[] {
  const byKey = new Map<string, EvalBacklogEntry>();
  for (const e of existing ?? []) byKey.set(evalBacklogKey(e), e);
  for (const e of incoming) {
    const key = evalBacklogKey(e);
    const prior = byKey.get(key);
    // Preserve the original advanceBlock when re-observed; refresh the reason.
    byKey.set(key, prior ? { ...e, advanceBlock: prior.advanceBlock } : e);
  }
  return [...byKey.values()].sort(
    (a, b) => a.advanceBlock - b.advanceBlock || evalBacklogKey(a).localeCompare(evalBacklogKey(b)),
  );
}

/** Remove ONE entry from the backlog (only ever called after a PASSING replay). */
export function removeFromEvalBacklog(
  backlog: readonly EvalBacklogEntry[],
  entry: { epochId: number; artifactHash: string },
): EvalBacklogEntry[] {
  const key = evalBacklogKey(entry);
  return backlog.filter((e) => evalBacklogKey(e) !== key);
}

// ── chain context ─────────────────────────────────────────────────────────────

/** One eth_call against a contract method at a specific block tag. Injectable
 *  so the confirmed-tag consistency (Finding 6) is unit-testable with a fake
 *  RPC whose 'latest' values differ from the confirmed-head values. */
export type ChainCaller = (input: {
  to: string;
  signature: string;
  args: readonly (string | number | bigint)[];
  blockTag: string;
}) => Promise<string>;

/** Production caller: a thin closure over the real eth_call. */
export function rpcChainCaller(rpcUrl: string): ChainCaller {
  return ({ to, signature, args, blockTag }) => ethCall(rpcUrl, to, signature, args, blockTag);
}

/**
 * Read ALL registry/V4 pins + liveStateRoot + transitionCount + the
 * epoch-secret reveal status AT ONE confirmed block tag. Every value the sync
 * later compares — including the liveStateRoot the replayed root is checked
 * against — comes from the SAME confirmed block height the logs replay to
 * (`blockTag` = confirmedHead). Reading liveStateRoot at 'latest' while the
 * logs only reach confirmedHead lets a fast chain (Base, ~2s blocks) land new
 * advances mid-sync and trip a false drift failure (or hide a real one); the
 * single confirmed tag removes that race.
 */
export async function readChainContext(
  call: ChainCaller,
  registry: string,
  mining: string,
  epoch: number,
  blockTag: string,
) {
  const at = (to: string, signature: string, args: readonly (string | number | bigint)[] = []) =>
    call({ to, signature, args, blockTag });
  const chainRegistry = decodeAddress(await at(mining, 'coreTexRegistry()'), 'mining.coreTexRegistry');
  if (chainRegistry.toLowerCase() !== registry.toLowerCase()) throw new Error(`V4 coreTexRegistry ${chainRegistry} != ${registry}`);
  const contextSet = decodeUint(await at(mining, 'coreTexEpochContextSet(uint64)', [epoch]), 'mining.coreTexEpochContextSet');
  if (contextSet !== 1) throw new Error(`V4 CoreTex epoch context not set for epoch ${epoch}`);
  const pins = {
    parentStateRoot: decodeBytes32(await at(registry, 'epochParentStateRoot(uint64)', [epoch]), 'registry.epochParentStateRoot'),
    liveStateRoot: decodeBytes32(await at(registry, 'liveStateRoot(uint64)', [epoch]), 'registry.liveStateRoot'),
    transitionCount: decodeUint(await at(registry, 'transitionCount(uint64)', [epoch]), 'registry.transitionCount'),
    coreVersionHash: decodeBytes32(await at(registry, 'epochCoreVersionHash(uint64)', [epoch]), 'registry.epochCoreVersionHash'),
    corpusRoot: decodeBytes32(await at(registry, 'epochCorpusRoot(uint64)', [epoch]), 'registry.epochCorpusRoot'),
    activeFrontierRoot: decodeBytes32(await at(registry, 'epochActiveFrontierRoot(uint64)', [epoch]), 'registry.epochActiveFrontierRoot'),
    baselineManifestHash: decodeBytes32(await at(registry, 'epochBaselineManifestHash(uint64)', [epoch]), 'registry.epochBaselineManifestHash'),
    hiddenSeedCommit: decodeBytes32(await at(registry, 'epochHiddenSeedCommit(uint64)', [epoch]), 'registry.epochHiddenSeedCommit'),
  };
  const epochCommit = decodeBytes32(await at(mining, 'epochCommit(uint64)', [epoch]), 'mining.epochCommit');
  if (epochCommit.toLowerCase() !== pins.hiddenSeedCommit.toLowerCase()) {
    throw new Error(`V4 epochCommit ${epochCommit} != registry hiddenSeedCommit ${pins.hiddenSeedCommit}`);
  }
  if (epochCommit.toLowerCase() === ZERO32) throw new Error(`V4 epochCommit(${epoch}) is zero`);
  const epochSecret = decodeBytes32(await at(mining, 'epochSecret(uint64)', [epoch]), 'mining.epochSecret');
  const reveal = deriveEpochSecretRevealStatus(pins.hiddenSeedCommit, epochSecret);
  return { ...pins, ...reveal };
}

// ── sync (default command) ────────────────────────────────────────────────────

function resolvePreviousCorpusRoot(statePath: string, bundleManifest: CoreTexBundleManifest): { root?: string; source: string } {
  const explicit = opt('previous-corpus-root');
  if (explicit) {
    if (!isBytes32(explicit)) die('--previous-corpus-root must be bytes32 hex');
    return { root: explicit, source: 'flag' };
  }
  if (existsSync(statePath)) {
    const state = JSON.parse(readFileSync(statePath, 'utf8')) as { corpusRoot?: string };
    if (isBytes32(state.corpusRoot)) return { root: state.corpusRoot, source: 'validator-state' };
  }
  if (isBytes32(bundleManifest.corpus?.root)) return { root: bundleManifest.corpus.root, source: 'bundle-manifest' };
  return { source: 'unavailable' };
}

function rangeLogOptions(): CoreTexRangeLogOptions {
  const out: { chunkBlocks?: number; confirmationDepth?: number } = {};
  const chunk = opt('log-chunk-blocks');
  if (chunk !== undefined) out.chunkBlocks = Number(chunk);
  const depth = opt('confirmation-depth');
  if (depth !== undefined) out.confirmationDepth = Number(depth);
  return out;
}

interface ValidatorScorerContext {
  readonly corpus: ProductionCorpus;
  readonly profile: typeof DEFAULT_PROFILE;
  readonly scoringOpts: ReturnType<typeof scoringOptionsFromProfile>;
  readonly thresholdPpm: number;
  readonly reranker: { model: string; close?: () => Promise<void> };
}

/**
 * RUNTIME hygiene applied to process.env BEFORE the (expensive) scorer is
 * constructed. Sets CORETEX_RERANKER_PYTHON from the setup-recorded venv
 * interpreter when the operator has not already set one, and resolves a sane
 * RERANKER_NUM_THREADS default. NEITHER changes scoring semantics: the python
 * interpreter still runs the SAME pinned reranker_runner.py at the SAME pinned
 * model revision, and thread count only affects throughput. An operator value
 * always wins; we log what was selected and why. Returns the thread decision
 * for the summary block.
 */
function applyScorerRuntimeDefaults(setup: ValidatorSyncStateFile['setup'] | undefined): {
  scorerPython?: string;
  scorerPythonSource: 'operator' | 'setup-venv' | 'default';
  thread: ThreadDefaultResult;
} {
  let scorerPythonSource: 'operator' | 'setup-venv' | 'default' = 'default';
  if (process.env['CORETEX_RERANKER_PYTHON']) {
    scorerPythonSource = 'operator';
  } else if (setup?.scorerPython && existsSync(setup.scorerPython)) {
    process.env['CORETEX_RERANKER_PYTHON'] = setup.scorerPython;
    scorerPythonSource = 'setup-venv';
  }
  const thread = applyRerankerThreadDefault(process.env);
  warn(`[runtime] scorer python: ${process.env['CORETEX_RERANKER_PYTHON'] ?? 'python3'} (${scorerPythonSource}); ${thread.reason}`);
  return {
    ...(process.env['CORETEX_RERANKER_PYTHON'] ? { scorerPython: process.env['CORETEX_RERANKER_PYTHON'] } : {}),
    scorerPythonSource,
    thread,
  };
}

/** Build the FAIL-CLOSED scorer context shared by sync auto-verify and
 *  verify-patch: pinned corpus + pinned qwen3 reranker from the bundle. */
async function buildValidatorScorerContext(
  bundle: CoreTexBundleManifest,
  corpusPath: string,
): Promise<ValidatorScorerContext> {
  const profile = bundle.evaluator?.profile ?? DEFAULT_PROFILE;
  const corpus = loadProductionCorpus(corpusPath, { verifyCorpusRoot: true, verifySplits: true });
  const layout = corpus.biEncoderRetrievalKeyLayout;
  const biEncoder = biEncoderFromEnv(layout, { modelId: corpus.biEncoderModelId, revision: corpus.biEncoderRevision });
  const reranker = await createValidatorReranker(validatorRerankerPinsFromManifest(bundle));
  const scoringOpts = scoringOptionsFromProfile(profile, {
    biEncoder,
    reranker,
    biEncoderHash: biEncoderModelIdHash(corpus.biEncoderModelId, corpus.biEncoderRevision, 'dense'),
    retrievalKeyLayout: layout,
  });
  const thresholdPpm = Math.min(computeAcceptanceThresholdPpm(profile), 355);
  return { corpus, profile, scoringOpts, thresholdPpm, reranker: reranker as ValidatorScorerContext['reranker'] };
}

/**
 * RUNTIME-PIN ASSERTION: probe the scorer interpreter's --health fingerprint
 * and assert it reproduces the bundle's pinned reranker runtime (torch /
 * transformers versions, fp32 / tf32=false / cuda flags) PLUS the resolved
 * model id/revision + promptTemplateHash. A mismatch is a HARD ERROR before any
 * score replay: the 5-ppm replay tolerance absorbs CPU↔GPU fp32 drift, but a
 * wrong torch/transformers/model/prompt pin could exceed it and silently
 * corrupt a score replay. Never changes scores — it only refuses to score
 * against a runtime that cannot reproduce the pinned scorer.
 */
function assertScorerRuntimePin(bundle: CoreTexBundleManifest): void {
  const pins = scorerRuntimeBundlePinsFromManifest(bundle);
  const pythonBin = process.env['CORETEX_RERANKER_PYTHON'] ?? 'python3';
  const health = probeScorerHealth(realSyncSpawner, pythonBin, resolveRerankerScriptPath());
  const resolved = {
    modelId: process.env['CORETEX_RERANKER_MODEL_ID'] ?? pins.modelId,
    revision: process.env['CORETEX_RERANKER_REVISION'] ?? pins.revision,
    promptTemplateHash: qwenRerankerPromptTemplateHash(resolveQwenRerankerInstruction()),
  };
  const verdict = scorerRuntimeMatchesBundle(health, pins, resolved);
  if (!verdict.ok) {
    die(`scorer runtime-pin assertion FAILED before score replay: ${verdict.reason}. `
      + `The fail-closed validator scorer must reproduce the bundle reranker pins `
      + `(${pins.modelId}@${pins.revision}, torch ${pins.torchRange}, transformers ${pins.transformersRange}, fp32/tf32=false). `
      + 'Re-run coretex-validator-setup to rebuild the pinned scorer venv, or fix CORETEX_RERANKER_PYTHON.');
  }
}

function scorerForParent(ctx: ValidatorScorerContext, parentState: CortexState, epochId: number) {
  return async ({ normalizedPatchBytes, evalSeed }: { normalizedPatchBytes: Uint8Array; evalSeed: string }) => {
    const queryPack = deriveQueryPack(epochId, evalSeed, ctx.corpus, ctx.profile.hiddenPack);
    const scored = await evaluateRetrievalBenchmarkPatch(parentState, decodePatch(normalizedPatchBytes), ctx.corpus, queryPack, ctx.scoringOpts, {
      ...ctx.profile.patchAcceptanceFloors,
      acceptanceThresholdPpm: ctx.thresholdPpm,
    });
    return {
      scorePpm: scored.deltaPpm,
      accepted: scored.accepted,
      ...(scored.reason ? { rejectionReason: scored.reason } : {}),
    };
  };
}

async function closeReranker(reranker: { close?: () => Promise<void> } | undefined): Promise<void> {
  if (reranker && typeof reranker.close === 'function') await reranker.close();
}

async function syncMain() {
  const noProgressFlag = has('no-progress');
  // ── validator state dir / state file FIRST: setup-written defaults feed everything below ──
  const stateDir = opt('state-dir', process.env['CORETEX_VALIDATOR_STATE_DIR'] ?? '.coretex-validator')!;
  const statePath = opt('state', join(stateDir, 'validator-sync-state.json'))!;
  const pinPath = opt('key-pin-file', process.env['CORETEX_KEY_PIN_PATH'] ?? join(stateDir, 'epoch-signing-key.pin.json'))!;
  const savedState = readValidatorStateFile(statePath);
  const setup = savedState?.setup;

  // Finding 7: every trusted-state mutation (TOFU pin, substrate snapshot, state
  // file) is STAGED to a temp file and committed atomically only after all
  // mandatory checks pass. If any mandatory check throws, the finally disposes
  // the uncommitted temp files and the prior trusted state is byte-unchanged.
  const staging = new TrustedStateStaging();
  try {
    return await runSync({ stateDir, statePath, pinPath, savedState, setup, staging });
  } finally {
    staging.dispose();
  }
}

interface RunSyncCtx {
  readonly stateDir: string;
  readonly statePath: string;
  readonly pinPath: string;
  readonly savedState: ValidatorSyncStateFile | null;
  readonly setup: ValidatorSyncStateFile['setup'] | undefined;
  readonly staging: TrustedStateStaging;
}

async function runSync({ stateDir, statePath, pinPath, savedState, setup, staging }: RunSyncCtx) {
  const noProgressFlag = has('no-progress');

  const coordinatorStatusUri = opt('from-coordinator', process.env['CORETEX_COORDINATOR_STATUS_URL']);
  const status = coordinatorStatusUri ? await readJsonUri(coordinatorStatusUri) as Record<string, unknown> : null;

  const rpcUrl = opt('rpc-url', process.env['BASE_RPC_URL']);
  const registry = opt('registry', process.env['CORETEX_REGISTRY_ADDRESS']);
  const mining = opt('mining-contract', process.env['BOTCOIN_MINING_CONTRACT_ADDRESS'] ?? process.env['BOTCOIN_MINING_V4']);
  if (!rpcUrl) die('--rpc-url or BASE_RPC_URL is required');
  if (!isAddress(registry)) die('--registry or CORETEX_REGISTRY_ADDRESS is required');
  if (!isAddress(mining)) die('--mining-contract or BOTCOIN_MINING_CONTRACT_ADDRESS is required');

  // ── epoch: flag → coordinator status → EPOCH_ID → chain V4.currentEpoch() ──
  const epochRaw = opt('epoch', String(status?.epoch ?? status?.currentEpoch ?? process.env['EPOCH_ID'] ?? ''));
  let epoch: number;
  let epochSource: string;
  if (epochRaw) {
    epoch = Number(epochRaw);
    epochSource = 'flag/status/env';
  } else {
    epoch = decodeUint(await ethCall(rpcUrl, mining, 'currentEpoch()'), 'mining.currentEpoch');
    epochSource = 'chain:V4.currentEpoch()';
  }
  if (!Number.isSafeInteger(epoch) || epoch < 0) die('epoch must be a non-negative safe integer');

  // ── local preconditions BEFORE heavy RPC: bundle manifest, artifact URIs, signing key ──
  const bundleManifestPath = opt('bundle-manifest', process.env['CORETEX_BUNDLE_MANIFEST'] ?? setup?.bundleManifestPath);
  if (!bundleManifestPath) {
    die('--bundle-manifest or CORETEX_BUNDLE_MANIFEST is required (or run coretex-validator-setup — its state file records the path): the validator client version-checks its local bundle against the on-chain coreVersionHash and derives replay mode flags from it (no silent defaults)');
  }
  const bundleManifest = JSON.parse(readFileSync(bundleManifestPath, 'utf8')) as CoreTexBundleManifest;
  if (!isBytes32(bundleManifest.bundleHash)) die(`bundle manifest ${bundleManifestPath} has no bundleHash`);
  const policyAtomsMode = policyAtomsModeFromManifest(bundleManifest);

  // ── FAIL-CLOSED scorer env gate — BEFORE any expensive work. The deterministic
  //    stub must be unreachable from the rescore path; a misconfigured env is a
  //    hard error naming the required vars. --skip-score-replay is the ONLY skip.
  const skipScoreReplay = has('skip-score-replay');
  if (!skipScoreReplay) {
    try {
      assertValidatorRerankerEnv(validatorRerankerPinsFromManifest(bundleManifest));
    } catch (err) {
      die(err instanceof Error ? err.message : String(err));
    }
  }

  const artifactBase = opt('artifact-base-url', process.env['CORETEX_ARTIFACT_BASE_URL'] ?? setup?.artifactBaseUrl);
  const rotationUri = opt(
    'rotation-manifest',
    stringField(status, 'rotationManifestUrl') ?? joinUrl(artifactBase, `epoch-rotations/epoch-rotation-${epoch}.json`),
  );
  const deltaUri = opt(
    'corpus-delta',
    stringField(status, 'corpusDeltaUrl') ?? joinUrl(artifactBase, `epoch-rotations/corpus-delta-epoch-${epoch}.json`),
  );
  const baselineUri = opt(
    'baseline-manifest',
    stringField(status, 'baselineManifestUrl'),
  );
  if (!rotationUri || !deltaUri) {
    die('rotation manifest and corpus delta are required (corpus-delta continuity is part of validator sync); pass --from-coordinator, --artifact-base-url, or --rotation-manifest/--corpus-delta');
  }

  // ── MANDATORY signature verification under the TOFU-pinned key ──
  const publicKeyUri = opt('public-key', stringField(status, 'epochSigningPublicKeyUrl'));
  if (!publicKeyUri) {
    die('epoch signing public key is required (signature verification is mandatory): pass --public-key or provide coordinator status epochSigningPublicKeyUrl');
  }

  // ── confirmed-tag consistency (Finding 6): compute the confirmed head ONCE,
  //    then read EVERY on-chain value (pins + liveStateRoot + transitionCount +
  //    secret reveal) AND replay logs AND compare the reproduced root at THAT
  //    SAME confirmed block tag. Reading liveStateRoot at 'latest' while the
  //    logs only reach confirmedHead races a fast chain into a false drift. ──
  const latest = await latestBlock(rpcUrl);
  const logOpts = rangeLogOptions();
  const confirmationDepth = BigInt(logOpts.confirmationDepth ?? CORETEX_DEFAULT_CONFIRMATION_DEPTH);
  const confirmedHead = latest - confirmationDepth;
  if (confirmedHead < 0n) die(`chain head ${latest} is below the confirmation depth ${confirmationDepth} — no confirmed block to sync against yet`);
  const confirmedTag = blockHex(confirmedHead);

  const chain = await readChainContext(rpcChainCaller(rpcUrl), registry, mining, epoch, confirmedTag);
  // ── self version-check against the on-chain coreVersionHash ──
  const version = checkValidatorBundleVersion(bundleManifest.bundleHash, chain.coreVersionHash, has('allow-version-mismatch'));

  const publicKey = await readTextUri(publicKeyUri);
  const tofu = checkTofuKeyPin(pinPath, publicKey);

  const rotation = await readJsonUri(rotationUri) as Record<string, unknown>;
  const delta = parseCorpusDelta(await readJsonUri(deltaUri) as never);
  if (!verifyEpochRotationManifestSignature(rotation as never, publicKey)) throw new Error('rotation manifest signature invalid');
  if (!verifyCorpusDeltaSignature(delta, publicKey)) throw new Error('corpus delta signature invalid');
  // Finding 7: stage the first-use TOFU pin instead of writing it eagerly — it
  // is committed atomically at the END, only after every mandatory check passes.
  if (!tofu.pinned) staging.stage(pinPath, serializeTofuKeyPin(publicKey).body);

  const deltaHash = hashCorpusDelta(delta);
  const rotationHash = hashJson(rotation);
  if (String(rotation.corpusDeltaHash).toLowerCase() !== deltaHash.toLowerCase()) {
    throw new Error(`rotation corpusDeltaHash ${rotation.corpusDeltaHash} != computed ${deltaHash}`);
  }
  if (String(rotation.nextCorpusRoot).toLowerCase() !== chain.corpusRoot.toLowerCase()) {
    throw new Error(`rotation nextCorpusRoot ${rotation.nextCorpusRoot} != chain corpusRoot ${chain.corpusRoot}`);
  }
  if (String(rotation.bundleHash).toLowerCase() !== chain.coreVersionHash.toLowerCase()) {
    throw new Error(`rotation bundleHash ${rotation.bundleHash} != chain coreVersionHash ${chain.coreVersionHash}`);
  }
  if (rotation.activeFrontierRoot && String(rotation.activeFrontierRoot).toLowerCase() !== chain.activeFrontierRoot.toLowerCase()) {
    throw new Error(`rotation activeFrontierRoot ${rotation.activeFrontierRoot} != chain activeFrontierRoot ${chain.activeFrontierRoot}`);
  }
  if (rotation.hiddenSeedCommit && String(rotation.hiddenSeedCommit).toLowerCase() !== chain.hiddenSeedCommit.toLowerCase()) {
    throw new Error(`rotation hiddenSeedCommit ${rotation.hiddenSeedCommit} != chain hiddenSeedCommit ${chain.hiddenSeedCommit}`);
  }
  if (rotation.previousCorpusRoot && delta.previousRoot.toLowerCase() !== String(rotation.previousCorpusRoot).toLowerCase()) {
    throw new Error(`delta.previousRoot ${delta.previousRoot} != rotation.previousCorpusRoot ${rotation.previousCorpusRoot}`);
  }
  if (delta.nextRoot.toLowerCase() !== String(rotation.nextCorpusRoot).toLowerCase()) {
    throw new Error(`delta.nextRoot ${delta.nextRoot} != rotation.nextCorpusRoot ${rotation.nextCorpusRoot}`);
  }
  let baselineManifestHash: string | undefined;
  if (baselineUri) {
    baselineManifestHash = hashJson(await readJsonUri(baselineUri));
    if (baselineManifestHash.toLowerCase() !== chain.baselineManifestHash.toLowerCase()) {
      throw new Error(`baseline manifest hash ${baselineManifestHash} != chain baselineManifestHash ${chain.baselineManifestHash}`);
    }
  } else if (isBytes32(rotation.baselineManifestHash)) {
    baselineManifestHash = String(rotation.baselineManifestHash).toLowerCase();
    if (baselineManifestHash !== chain.baselineManifestHash.toLowerCase()) {
      throw new Error(`rotation baselineManifestHash ${rotation.baselineManifestHash} != chain baselineManifestHash ${chain.baselineManifestHash}`);
    }
  } else if (rotationHash.toLowerCase() === chain.baselineManifestHash.toLowerCase()) {
    baselineManifestHash = rotationHash.toLowerCase();
  }

  // ── corpus-delta continuity against the LOCAL previous corpus root ──
  const previous = resolvePreviousCorpusRoot(statePath, bundleManifest);
  checkCorpusDeltaContinuity(delta.previousRoot, previous.root);

  const artifacts = {
    rotationManifestUrl: rotationUri,
    corpusDeltaUrl: deltaUri,
    ...(baselineUri ? { baselineManifestUrl: baselineUri } : {}),
    rotationManifestHash: rotationHash,
    corpusDeltaHash: deltaHash,
    baselineManifestHash: baselineManifestHash ?? 'not configured',
    epochSigningKeyFingerprint: tofu.fingerprint,
    epochSigningKeyPin: tofu.pinned ? 'matched' : 'pinned (first use)',
    deltaContinuity: { previousRoot: delta.previousRoot, localPreviousRootSource: previous.source },
  };

  // ── registry log replay (DEFAULT — no longer gated on --parent-state/--from-block) ──
  const snapshotBinPath = join(stateDir, 'substrate-state.bin');
  const snapshotAvailable = existsSync(snapshotBinPath)
    && isBytes32(savedState?.replay?.stateRoot)
    && Number.isSafeInteger(savedState?.replay?.cursorBlock);
  const fromBlockResolved = resolveReplayFromBlock({
    flag: opt('from-block'),
    envReplayFromBlock: process.env['CORETEX_REPLAY_FROM_BLOCK'],
    envRegistryDeployBlock: process.env['CORETEX_REGISTRY_DEPLOY_BLOCK'],
    snapshotCursorBlock: snapshotAvailable ? savedState!.replay!.cursorBlock : undefined,
    stateRegistryDeployBlock: savedState?.registryDeployBlock,
  });
  const blankRoot = blankSubstrateStateRoot();
  const explicitParentPath = opt('parent-state', process.env['CORETEX_PARENT_STATE_PATH']);
  const bootstrap = resolveReplayParentBootstrap({
    explicitParentStatePath: explicitParentPath,
    snapshotAvailable,
    chainParentStateRoot: chain.parentStateRoot,
    blankRoot,
    fromBlockSource: fromBlockResolved.source,
  });
  let parent: CortexState;
  if (bootstrap.source === 'explicit-file') {
    parent = loadPackedState(explicitParentPath!);
  } else if (bootstrap.source === 'snapshot') {
    parent = loadPackedState(snapshotBinPath);
    const snapshotRoot = bytesToHex(merkleizeState(parent));
    if (snapshotRoot.toLowerCase() !== savedState!.replay!.stateRoot!.toLowerCase()) {
      die(`replay snapshot ${snapshotBinPath} merkles to ${snapshotRoot} != recorded ${savedState!.replay!.stateRoot} — the state dir is corrupt; delete it and re-sync from the deploy block`);
    }
  } else {
    parent = blankSubstrateState();
  }

  const fromBlock = fromBlockResolved.fromBlock;
  // Registry log replay: surface the confirmed block window being paginated so
  // a validator sees the replay is moving (stderr only — stdout JSON unaffected).
  const replayProgress = makeProgress({
    label: 'registry log replay',
    unit: 'blocks',
    ...(confirmedHead >= fromBlock ? { total: Number(confirmedHead - fromBlock + 1n) } : {}),
    noProgressFlag,
  });
  const logs = confirmedHead >= fromBlock
    ? await coretexRangeLogs(rpcUrl, registry, blockHex(fromBlock), blockHex(confirmedHead), { latestBlock: latest, ...logOpts })
    : [];
  if (confirmedHead >= fromBlock) replayProgress.update(Number(confirmedHead - fromBlock + 1n));
  replayProgress.done();
  const advances = logs
    .map(decodeCoreTexStateAdvanced)
    .filter((v): v is CoreTexStateAdvancedEvent => v !== null)
    .sort((a, b) => cmpBig(a.epoch, b.epoch) || cmpBig(a.transitionIndex, b.transitionIndex));
  const crossEpochWindow = advances.some((a) => a.epoch !== BigInt(epoch));

  const replayResult = replayCoreTexFromLogs(parent, logs, {
    // A bootstrap window replaying multiple epochs cannot pin every advance to
    // the CURRENT epoch's context (older epochs legitimately carried older
    // pins) — root continuity + the final liveStateRoot check still hold.
    ...(crossEpochWindow ? {} : {
      expectedBundleHash: chain.coreVersionHash,
      expectedCorpusRoot: chain.corpusRoot,
      expectedActiveFrontierRoot: chain.activeFrontierRoot,
      expectedBaselineManifestHash: chain.baselineManifestHash,
      expectedHiddenSeedCommit: chain.hiddenSeedCommit,
    }),
    policyAtomsMode,
    acknowledgedRevertedEpochs: all('acknowledge-reverted-epoch').map((v) => Number(v)),
  });
  if (!replayResult.ok) throw new Error(`registry replay failed: ${replayResult.code} ${replayResult.message ?? ''}`);
  const reproducedFinalRoot = replayResult.reproducedFinalRoot;
  if (!reproducedFinalRoot || reproducedFinalRoot.toLowerCase() !== chain.liveStateRoot.toLowerCase()) {
    throw new Error(`registry replay root ${reproducedFinalRoot} != chain liveStateRoot ${chain.liveStateRoot}`);
  }

  // Per-epoch transition accounting: cumulative across incremental syncs for
  // managed bootstraps; window-total for explicit --parent-state overrides
  // (the operator asserts the parent is the epoch parent in that case).
  const epochTransitions: Record<string, number> = { ...(savedState?.replay?.epochTransitions ?? {}) };
  if (bootstrap.source !== 'snapshot') for (const k of Object.keys(epochTransitions)) delete epochTransitions[k];
  for (const adv of advances) {
    const k = adv.epoch.toString();
    epochTransitions[k] = (epochTransitions[k] ?? 0) + 1;
  }
  if (bootstrap.source === 'explicit-file') {
    if (replayResult.transitions !== chain.transitionCount) {
      throw new Error(`registry replay transitions ${replayResult.transitions} != chain transitionCount ${chain.transitionCount}`);
    }
  } else {
    const cumulative = epochTransitions[String(epoch)] ?? 0;
    if (cumulative !== chain.transitionCount) {
      throw new Error(`registry replay cumulative transitions for epoch ${epoch}: local ${cumulative} != chain transitionCount ${chain.transitionCount}`);
    }
  }

  // ── state walk: recover the per-advance parent substrate (needed for
  //    post-reveal rescoring) and the final state for the snapshot. ──
  let walkState = parent;
  const advanceRecords: { adv: CoreTexStateAdvancedEvent; parentState: CortexState; parentRoot: string }[] = [];
  for (const adv of advances) {
    const parentRoot = bytesToHex(merkleizeState(walkState));
    const applied = applyPatch(walkState, decodePatch(adv.compactPatchBytes), policyAtomsMode);
    if (!applied.ok) throw new Error(`internal: state walk applyPatch ${applied.code} diverged from canonical replay at epoch ${adv.epoch} transition ${adv.transitionIndex}`);
    advanceRecords.push({ adv, parentState: walkState, parentRoot });
    walkState = applied.state;
  }
  const finalRoot = bytesToHex(merkleizeState(walkState));
  if (finalRoot.toLowerCase() !== reproducedFinalRoot.toLowerCase()) {
    throw new Error(`internal: state walk root ${finalRoot} != canonical replay root ${reproducedFinalRoot}`);
  }
  const newCursorBlock = Number(confirmedHead >= fromBlock ? confirmedHead : fromBlock - 1n);
  mkdirSync(stateDir, { recursive: true });
  // Finding 7: stage the substrate snapshot — committed atomically with the
  // state file + TOFU pin only after all mandatory checks pass.
  staging.stage(snapshotBinPath, pack(walkState));

  const replay = {
    ...replayResult,
    parentBootstrap: bootstrap.source,
    fromBlock: fromBlock.toString(),
    fromBlockSource: fromBlockResolved.source,
    cursorBlock: newCursorBlock,
    windowAdvances: advances.length,
    ...(crossEpochWindow ? { pinScope: 'cross-epoch window — per-advance context pins omitted (root continuity + final liveStateRoot still verified)' } : {}),
    snapshotPath: snapshotBinPath,
  };

  // ── post-reveal eval artifact verification (AUTOMATIC, fail-closed scorer) ──
  type EvalVerification = {
    artifactHash: string; artifactUrl: string; epoch: string; transitionIndex: string;
    miner: string; outcome?: string; gateDeltaPpm?: number; confirmDeltaPpm?: number;
  };
  const evalReplay: {
    status: string;
    verified: EvalVerification[];
    pending: { artifactHash: string; epoch: string; reason: string }[];
    skipped: boolean;
  } = { status: chain.evalReplayStatus, verified: [], pending: [], skipped: false };
  let runtime: ReturnType<typeof applyScorerRuntimeDefaults> | undefined;

  // Finding 5: the eval-verification backlog is loaded from the state file and
  // re-drained every sync. It tracks EVERY accepted advance not yet score-
  // verified independently of the root-continuity cursor, so a restart between
  // reveal and the next sync can never permanently skip a required score replay.
  let evalBacklog = upsertEvalBacklog(savedState?.evalBacklog, advanceRecords.map(
    (rec) => evalBacklogEntryFromAdvance(rec.adv, newCursorBlock, 'awaiting_epoch_secret_reveal'),
  ));
  // Re-attemptable parent states for THIS pass: the current walk's per-advance
  // parents, keyed by the advance's parentStateRoot. A backlog entry can be
  // score-replayed only when its parent state is reconstructable here.
  const parentByRoot = new Map<string, { adv: CoreTexStateAdvancedEvent; parentState: CortexState; parentRoot: string }>();
  for (const rec of advanceRecords) parentByRoot.set(rec.parentRoot.toLowerCase(), rec);

  // Per-epoch secret resolver (Finding 6: confirmed tag; verifies the commit).
  const epochSecretCache = new Map<string, string | null>();
  const epochSecretFor = async (e: number): Promise<string | null> => {
    const key = String(e);
    if (epochSecretCache.has(key)) return epochSecretCache.get(key)!;
    const secret = decodeBytes32(await ethCall(rpcUrl, mining!, 'epochSecret(uint64)', [e], confirmedTag), 'mining.epochSecret');
    let value: string | null = null;
    if (secret.toLowerCase() !== ZERO32) {
      const commit = decodeBytes32(await ethCall(rpcUrl, registry!, 'epochHiddenSeedCommit(uint64)', [e], confirmedTag), 'registry.epochHiddenSeedCommit');
      const recomputed = bytesToHex(keccak256(hexToBytes(secret))).toLowerCase();
      if (recomputed !== commit.toLowerCase()) throw new Error(`epoch ${e} epochSecret commit ${recomputed} != registry hiddenSeedCommit ${commit}`);
      value = secret;
    }
    epochSecretCache.set(key, value);
    return value;
  };

  if (skipScoreReplay) {
    evalReplay.skipped = true;
    warn('WARNING: --skip-score-replay passed — post-reveal eval artifacts were NOT verified and scores were NOT re-scored. '
      + `This run does NOT attest score honesty (exit code ${SKIP_SCORE_REPLAY_EXIT_CODE}).`);
  } else if (evalBacklog.length > 0) {
    // Reveal pre-scan (cheap RPC reads, no scorer): does any backlog entry have
    // a revealed secret AND a reconstructable parent state in THIS pass? Only
    // then do we pay for the (expensive) scorer context + runtime-pin probe.
    let anyDrainable = false;
    for (const entry of evalBacklog) {
      if ((await epochSecretFor(entry.epochId)) && parentByRoot.has(entry.parentStateRoot.toLowerCase())) {
        anyDrainable = true;
        break;
      }
    }
    if (!anyDrainable) {
      // Nothing to score yet — record every entry as still-pending and keep the
      // whole backlog (never dropped). No scorer is constructed.
      for (const entry of evalBacklog) {
        const revealed = (await epochSecretFor(entry.epochId)) !== null;
        evalReplay.pending.push({
          artifactHash: entry.artifactHash.toLowerCase(),
          epoch: String(entry.epochId),
          reason: revealed ? 'awaiting_parent_state_replay' : 'awaiting_epoch_secret_reveal',
        });
      }
    } else {
    if (!artifactBase) {
      die('post-reveal eval verification requires the artifact base URL: set CORETEX_ARTIFACT_BASE_URL, pass --artifact-base-url, or run coretex-validator-setup');
    }
    const corpusPath = opt('corpus', process.env['CORETEX_CORPUS_PATH'] ?? setup?.corpusPath);
    if (!corpusPath) {
      die('post-reveal eval verification requires the materialized corpus: run coretex-validator-setup or pass --corpus/CORETEX_CORPUS_PATH');
    }
    // RUNTIME hygiene before the scorer spawns: setup-recorded venv interpreter
    // + sane thread default (operator env always wins; scores unaffected).
    runtime = applyScorerRuntimeDefaults(setup);
    // RUNTIME-PIN ASSERTION: hard-fail BEFORE any score replay if the scorer
    // runtime fingerprint does not reproduce the bundle reranker pins.
    assertScorerRuntimePin(bundleManifest);
    const ctx = await buildValidatorScorerContext(bundleManifest, corpusPath);
    const loadedPins: LoadedScorerContextPins = { corpusRoot: ctx.corpus.corpusRoot, coreVersionHash: chain.coreVersionHash };
    const rpcClient = createBaseRpcClient(rpcUrl);
    // Per-advance score-replay progress + ETA (stderr only; stdout JSON clean).
    const scoreProgress = makeProgress({ label: 'post-reveal score replay', unit: 'advances', total: evalBacklog.length, noProgressFlag });
    let scoredAdvances = 0;
    try {
      // Snapshot the backlog to iterate; entries removed only on a PASSING replay.
      for (const entry of [...evalBacklog]) {
        const artifactHash = entry.artifactHash.toLowerCase();
        const secret = await epochSecretFor(entry.epochId);
        if (!secret) {
          // Still pre-reveal — keep it in the backlog (NOT dropped) and report it.
          evalReplay.pending.push({ artifactHash, epoch: String(entry.epochId), reason: 'awaiting_epoch_secret_reveal' });
          scoreProgress.update(++scoredAdvances);
          continue;
        }
        // Finding 8: a rescore must only happen with the corpus/bundle matching
        // the advance's on-chain pins. Mismatch → leave pending (never bogus).
        const ctxSel = selectScorerContextForAdvance(entry, loadedPins);
        if (ctxSel.action === 'pending') {
          evalBacklog = upsertEvalBacklog(evalBacklog, [{ ...entry, reason: 'epoch-context-unavailable' }]);
          evalReplay.pending.push({ artifactHash, epoch: String(entry.epochId), reason: `epoch-context-unavailable: ${ctxSel.detail}` });
          warn(`[eval-backlog] epoch ${entry.epochId} ${artifactHash}: ${ctxSel.detail}`);
          scoreProgress.update(++scoredAdvances);
          continue;
        }
        // The per-advance parent state must be reconstructable in THIS pass.
        const rec = parentByRoot.get(entry.parentStateRoot.toLowerCase());
        if (!rec) {
          evalReplay.pending.push({ artifactHash, epoch: String(entry.epochId), reason: 'awaiting_parent_state_replay' });
          warn(`[eval-backlog] epoch ${entry.epochId} ${artifactHash}: parent state ${entry.parentStateRoot} not in this replay window — re-sync covering its advance to drain (kept pending, never dropped)`);
          scoreProgress.update(++scoredAdvances);
          continue;
        }
        const artifactUrl = evalReportArtifactUrl(artifactBase, artifactHash);
        const artifact = await readJsonUri(artifactUrl) as CoreTexPostRevealEvalReportArtifact;
        if (String(artifact.artifactHash).toLowerCase() !== artifactHash) {
          throw new Error(`eval artifact ${artifactUrl} carries artifactHash ${artifact.artifactHash} != on-chain evalReportHash ${artifactHash}`);
        }
        // Finding 4: bind the artifact to the EXACT decoded advance BEFORE scoring
        // — root replay and score replay then provably concern the same patch.
        assertArtifactBoundToAdvance(artifact, rec.adv);
        if (ctx.corpus.corpusRoot.toLowerCase() !== artifact.context.corpusRoot.toLowerCase()) {
          throw new Error(`eval artifact ${artifactHash} context.corpusRoot ${artifact.context.corpusRoot} != local materialized corpus root ${ctx.corpus.corpusRoot} — re-run coretex-validator-setup for this epoch's corpus`);
        }
        const result = await verifyPostRevealEvalReportArtifact(artifact, {
          rpcClient,
          epochSecret: secret,
          scorer: scorerForParent(ctx, rec.parentState, artifact.epochId),
        });
        if (!result.ok) {
          throw new Error(`post-reveal eval verification FAILED for ${artifactUrl}: ${result.code} ${result.detail}`);
        }
        // PASS — and only now is the entry removed from the backlog.
        evalBacklog = removeFromEvalBacklog(evalBacklog, entry);
        evalReplay.verified.push({
          artifactHash,
          artifactUrl,
          epoch: String(entry.epochId),
          transitionIndex: rec.adv.transitionIndex.toString(),
          miner: rec.adv.miner,
          outcome: artifact.outcome,
          gateDeltaPpm: result.gateDeltaPpm,
          confirmDeltaPpm: result.confirmDeltaPpm,
        });
        scoreProgress.update(++scoredAdvances);
      }
    } finally {
      scoreProgress.done();
      await closeReranker(ctx.reranker);
    }
    }
  }

  // evalVerifiedThroughBlock advances only when the backlog is fully drained
  // (every accepted advance through the confirmed head is score-verified).
  const priorVerifiedThrough = savedState?.evalVerifiedThroughBlock ?? -1;
  const evalVerifiedThroughBlock = evalBacklog.length === 0 && !skipScoreReplay
    ? Math.max(priorVerifiedThrough, newCursorBlock)
    : priorVerifiedThrough;

  // ── manually supplied eval artifacts (hash + optional secret-commit audit) ──
  const epochSecret = opt('epoch-secret', process.env['CORETEX_EPOCH_SECRET']);
  const evalArtifacts = [];
  for (const uri of all('eval-artifact')) {
    const artifact = await readJsonUri(uri) as Record<string, unknown>;
    const hash = hashPostRevealEvalReportArtifact(artifact as never);
    if (hash !== String(artifact.artifactHash).toLowerCase()) throw new Error(`eval artifact hash mismatch for ${uri}`);
    if (epochSecret) {
      const commit = bytesToHex(keccak256(hexToBytes(epochSecret))).toLowerCase();
      const hidden = (artifact.context as { hiddenSeedCommit?: string } | undefined)?.hiddenSeedCommit;
      if (!hidden || commit !== hidden.toLowerCase()) throw new Error(`eval artifact epochSecret commit mismatch for ${uri}`);
    }
    evalArtifacts.push({ uri, artifactHash: hash, postRevealSecretChecked: Boolean(epochSecret) });
  }

  if (chain.evalReplayStatus === 'awaiting_epoch_secret_reveal') {
    warn('status: awaiting_epoch_secret_reveal — mining epochSecret is zero/unrevealed; post-reveal eval replay must wait');
  }

  // Finding 7: stage the state-file mutation. The TOFU pin + snapshot were also
  // staged; nothing is committed until ALL mandatory checks above have passed.
  staging.stage(statePath, serializeMergedValidatorState(statePath, {
    epoch,
    bundleHash: bundleManifest.bundleHash,
    corpusRoot: delta.nextRoot,
    rotationManifestHash: rotationHash,
    corpusDeltaHash: deltaHash,
    evalReplayStatus: chain.evalReplayStatus,
    epochSigningKeyFingerprint: tofu.fingerprint,
    replay: {
      stateRoot: finalRoot,
      cursorBlock: newCursorBlock,
      statePath: snapshotBinPath,
      epochTransitions,
    },
    evalBacklog,
    evalVerifiedThroughBlock,
  }));

  // ── ATOMIC COMMIT (Finding 7): every mandatory check for this sync pass has
  //    passed — commit the staged TOFU pin + snapshot + state file together. A
  //    throw anywhere above leaves the prior trusted state byte-unchanged. The
  //    post-reveal backlog is best-effort (it may remain pending without failing
  //    the sync) but is persisted atomically here too. ──
  staging.commit();

  process.stdout.write(JSON.stringify({
    ok: true,
    command: 'coretex-validator-sync',
    epoch,
    epochSource,
    registry,
    miningContract: mining,
    bundleVersion: { localBundleHash: bundleManifest.bundleHash, chainCoreVersionHash: chain.coreVersionHash, match: version.match, policyAtomsMode },
    evalReplayStatus: chain.evalReplayStatus,
    chain,
    artifacts,
    replay,
    evalReplay,
    evalArtifacts,
    statePath,
  }, null, 2) + '\n');

  // Final PASS/FAIL summary block — stderr only, after the machine-readable
  // JSON on stdout. A --skip-score-replay run is a non-attesting PASS-with-caveat.
  renderSummaryBlock('coretex-validator-sync', true, [
    `epoch ${epoch} (${epochSource}); bundle ${version.match ? 'matches' : 'MISMATCH (read-only)'} on-chain coreVersionHash`,
    `registry replay: ${advances.length} advance(s), final root == chain liveStateRoot`,
    evalReplay.skipped
      ? `score replay: SKIPPED (--skip-score-replay) — NOT a score attestation (exit ${SKIP_SCORE_REPLAY_EXIT_CODE})`
      : `score replay: ${evalReplay.verified.length} verified, ${evalReplay.pending.length} pending (status ${chain.evalReplayStatus})`,
    ...(runtime ? [`scorer python: ${runtime.scorerPython ?? 'python3'} (${runtime.scorerPythonSource}); RERANKER_NUM_THREADS=${runtime.thread.threads} (${runtime.thread.source})`] : []),
    `state file: ${statePath}`,
  ]);

  if (skipScoreReplay) process.exit(SKIP_SCORE_REPLAY_EXIT_CODE);
}

// ── verify-patch subcommand ───────────────────────────────────────────────────

async function verifyPatchMain() {
  const hash = opt('hash');
  if (!isBytes32(hash)) die('verify-patch requires --hash 0x<bytes32 artifactHash>');
  const stateDir = opt('state-dir', process.env['CORETEX_VALIDATOR_STATE_DIR'] ?? '.coretex-validator')!;
  const statePath = opt('state', join(stateDir, 'validator-sync-state.json'))!;
  const setup = readValidatorStateFile(statePath)?.setup;
  const artifactBase = opt('artifact-base-url', process.env['CORETEX_ARTIFACT_BASE_URL'] ?? setup?.artifactBaseUrl);
  const artifactUri = opt('artifact-url', joinUrl(artifactBase, `eval-reports/${hash.toLowerCase()}.json`));
  if (!artifactUri) die('verify-patch requires CORETEX_ARTIFACT_BASE_URL / --artifact-base-url (or an explicit --artifact-url)');
  const artifact = await readJsonUri(artifactUri) as CoreTexPostRevealEvalReportArtifact;
  if (String(artifact.artifactHash).toLowerCase() !== hash.toLowerCase()) {
    die(`fetched artifact hash ${artifact.artifactHash} != requested ${hash}`);
  }

  const bundleManifestPath = opt('bundle-manifest', process.env['CORETEX_BUNDLE_MANIFEST'] ?? setup?.bundleManifestPath);
  if (!bundleManifestPath) die('--bundle-manifest, CORETEX_BUNDLE_MANIFEST, or a coretex-validator-setup state file is required');
  const bundle = JSON.parse(readFileSync(bundleManifestPath, 'utf8')) as CoreTexBundleManifest;
  if (!isBytes32(bundle.bundleHash)) die(`bundle manifest ${bundleManifestPath} has no bundleHash`);
  checkValidatorBundleVersion(bundle.bundleHash, artifact.context.coreVersionHash, has('allow-version-mismatch'));

  // ── FAIL-CLOSED scorer gate (same gate as sync): the deterministic stub is
  //    unreachable; --skip-score-replay is the ONLY skip and cannot attest.
  if (has('skip-score-replay')) {
    const recomputed = hashPostRevealEvalReportArtifact(artifact);
    const hashBound = recomputed === hash.toLowerCase()
      && String(artifact.evalReportHash).toLowerCase() === hash.toLowerCase();
    if (!hashBound) die(`artifact hash binding failed: recomputed ${recomputed}, evalReportHash ${artifact.evalReportHash}, requested ${hash}`);
    warn('WARNING: --skip-score-replay passed — verify-patch checked ONLY the artifact hash binding. '
      + `Scores were NOT re-scored; this run does NOT attest score honesty (exit code ${SKIP_SCORE_REPLAY_EXIT_CODE}).`);
    process.stdout.write(JSON.stringify({
      command: 'coretex-validator-sync verify-patch',
      artifactUrl: artifactUri,
      artifactHash: hash.toLowerCase(),
      epochId: artifact.epochId,
      minerAddress: artifact.minerAddress,
      outcome: artifact.outcome,
      scoreReplay: 'SKIPPED (--skip-score-replay): artifact hash binding only — NOT a score attestation',
    }, null, 2) + '\n');
    process.exit(SKIP_SCORE_REPLAY_EXIT_CODE);
  }
  try {
    assertValidatorRerankerEnv(validatorRerankerPinsFromManifest(bundle));
  } catch (err) {
    die(err instanceof Error ? err.message : String(err));
  }

  const rpcUrl = opt('rpc-url', process.env['BASE_RPC_URL']);
  if (!rpcUrl) die('--rpc-url or BASE_RPC_URL is required (blockhash binding replay)');
  const epochSecret = opt('epoch-secret', process.env['CORETEX_EPOCH_SECRET']);
  if (!isBytes32(epochSecret)) die('--epoch-secret or CORETEX_EPOCH_SECRET (revealed bytes32) is required for post-reveal verification');
  const corpusPath = opt('corpus', process.env['CORETEX_CORPUS_PATH'] ?? setup?.corpusPath);
  if (!corpusPath) die('--corpus, CORETEX_CORPUS_PATH, or a coretex-validator-setup state file is required (materialized epoch corpus)');
  const parentStatePath = opt('parent-state', process.env['CORETEX_PARENT_STATE_PATH']);
  if (!parentStatePath) die('--parent-state or CORETEX_PARENT_STATE_PATH is required');

  const parent = loadPackedState(parentStatePath);
  const parentRoot = bytesToHex(merkleizeState(parent));
  if (parentRoot.toLowerCase() !== artifact.context.parentStateRoot.toLowerCase()) {
    die(`local parent state root ${parentRoot} != artifact context parentStateRoot ${artifact.context.parentStateRoot}`);
  }

  // RUNTIME hygiene before the scorer spawns (same as sync): setup-recorded
  // venv interpreter + sane thread default. Operator env wins; scores unaffected.
  applyScorerRuntimeDefaults(setup);
  // RUNTIME-PIN ASSERTION (same gate as sync): hard-fail before any score replay
  // if the scorer runtime fingerprint does not reproduce the bundle reranker pins.
  assertScorerRuntimePin(bundle);
  const ctx = await buildValidatorScorerContext(bundle, corpusPath);
  if (ctx.corpus.corpusRoot.toLowerCase() !== artifact.context.corpusRoot.toLowerCase()) {
    await closeReranker(ctx.reranker);
    die(`local corpus root ${ctx.corpus.corpusRoot} != artifact context corpusRoot ${artifact.context.corpusRoot}`);
  }

  try {
    const result = await verifyPostRevealEvalReportArtifact(artifact, {
      rpcClient: createBaseRpcClient(rpcUrl),
      epochSecret,
      scorer: scorerForParent(ctx, parent, artifact.epochId),
    });
    process.stdout.write(JSON.stringify({
      command: 'coretex-validator-sync verify-patch',
      artifactUrl: artifactUri,
      artifactHash: hash.toLowerCase(),
      epochId: artifact.epochId,
      minerAddress: artifact.minerAddress,
      outcome: artifact.outcome,
      ...result,
    }, null, 2) + '\n');
    if (!result.ok) process.exit(1);
  } finally {
    await closeReranker(ctx.reranker);
  }
}

async function main() {
  if (has('help') || args[0] === '-h' || args[0] === 'help') {
    process.stdout.write(USAGE + '\n');
    return;
  }
  if (args[0] === 'verify-patch') return verifyPatchMain();
  return syncMain();
}

const invokedAsScript = (() => {
  if (!process.argv[1]) return false;
  try {
    return pathToFileURL(realpathSync(process.argv[1])).href === import.meta.url;
  } catch {
    return false;
  }
})();

if (invokedAsScript) {
  main().catch((err) => die(err instanceof Error ? err.stack ?? err.message : String(err)));
}
