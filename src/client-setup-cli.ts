#!/usr/bin/env node
/**
 * coretex-client-setup — one-command validator artifact hydration.
 *
 * Standalone (installed-package) mode, the default:
 *   1. Fetches the launch artifact manifest from
 *      `<CORETEX_ARTIFACT_BASE_URL>/coretex-launch-v16-artifacts.json`
 *      (override: --manifest <path-or-url>).
 *   2. Downloads the corpus + embeddings + bundle manifest + evaluator profile
 *      into the validator state dir (default `.coretex-client`, env
 *      CORETEX_VALIDATOR_STATE_DIR) with SHA-256 + byte-size verification.
 *   3. Materializes the production corpus via the in-package canonical
 *      materializer (scripts/materialize-production-corpus.mjs)
 *      and cross-checks the materialized corpusRoot against the manifest.
 *   4. Writes the bundle manifest path, materialized corpus path, previous
 *      corpus root, and registry deploy block into the validator state file so
 *      `coretex-client-sync` needs no manual flags.
 *
 * Repo-hydration mode (--repo-root <dir>, used by the
 * scripts/setup-validator-artifacts.mjs shim): payloads land at their
 * committed repo-relative paths, bundle/profile are verified in place,
 * verifyBundleManifest() additionally checks the pinned source tree, and the
 * materialized root comes from the manifest. `--verify-only` / `--no-download`
 * behave exactly as the historical scripts/setup-validator-artifacts.mjs.
 */
import { createHash } from 'node:crypto';
import {
  copyFileSync,
  createReadStream,
  createWriteStream,
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import http from 'node:http';
import https from 'node:https';

import { verifyBundleManifest, type CoreTexBundleManifest } from './bundle/index.js';
import { rpcCall } from './replay/v4.js';
import { bytesToHex } from './state/merkle.js';
import { keccak256 } from './state/keccak256.js';
import { resolveCortexPackageRoot, resolveRerankerScriptPath } from './eval/reranker.js';
import {
  bootstrapScorerVenv,
  VenvBootstrapError,
  makeProgress,
  renderSummaryBlock,
  realSyncSpawner,
  type VenvBootstrapResult,
} from './client-runtime.js';

export const LAUNCH_ARTIFACT_MANIFEST_FILENAME = 'coretex-launch-v16-artifacts.json';
export const LAUNCH_ARTIFACT_MANIFEST_SCHEMA = 'coretex.launch-artifacts.v1';
export const VALIDATOR_STATE_FILENAME = 'client-sync-state.json';
const REPO_DEFAULT_MANIFEST = 'release/calibration/2026-06-04-memory-atom-v16/coretex-launch-v16-artifacts.json';

const USAGE = `coretex-client-setup — hydrate + verify CoreTex client artifacts

Usage:
  coretex-client-setup [--artifact-base-url <url>] [--manifest <path-or-url>]
                          [--state-dir <dir>] [--registry-deploy-block <n>]
                          [--verify-only] [--no-download] [--repo-root <dir>]
                          [--no-venv-bootstrap] [--no-progress]
                          [--verify-chain-config]

Env:
  CORETEX_ARTIFACT_BASE_URL      artifact base URL (manifest + payloads)
  CORETEX_VALIDATOR_STATE_DIR    state dir (default .coretex-client)
  CORETEX_REGISTRY_DEPLOY_BLOCK  registry deploy block recorded for sync replay
  CORETEX_RERANKER_PYTHON        operator scorer interpreter (skips venv bootstrap when valid)
  CORETEX_VALIDATOR_SKIP_VENV=1  skip the Python venv bootstrap (same as --no-venv-bootstrap)

Setup is artifact hydration and works fully offline — it never requires an RPC.
Chain-config env vars (BASE_RPC_URL, CORETEX_REGISTRY_ADDRESS,
BOTCOIN_MINING_CONTRACT_ADDRESS) are OPTIONAL here, but when present they are
syntax-checked up front (before any expensive download/materialization) and
cross-checked against the manifest's published chain config. Pass
--verify-chain-config to additionally probe the RPC (chainId, deployed code at
both addresses, registry→V4 pin) — requires BASE_RPC_URL + both addresses
(env or manifest).

By default setup also bootstraps a self-contained CPU scorer venv under
<state-dir>/scorer-venv (idempotent; skipped when CORETEX_RERANKER_PYTHON
already imports the pinned torch+transformers) and records its interpreter so
sync's score replay runs without manual Python setup. Progress + ETA print to
stderr (TTY-aware; suppress with --no-progress or CI=1) — stdout stays clean.

After setup completes, \`coretex-client-sync\` needs only BASE_RPC_URL,
CORETEX_REGISTRY_ADDRESS, BOTCOIN_MINING_CONTRACT_ADDRESS, and
CORETEX_ARTIFACT_BASE_URL.`;

const args = process.argv.slice(2);
function opt(name: string, fallback?: string): string | undefined {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : fallback;
}
function has(name: string): boolean {
  return args.includes(`--${name}`);
}
function die(message: string): never {
  process.stderr.write(`HARD FAIL: ${message}\n`);
  process.exit(1);
}
function log(message: string): void {
  process.stdout.write(`[setup] ${message}\n`);
}

// ── exported manifest/state primitives (unit-tested directly) ────────────────

export interface LaunchArtifactPayload {
  readonly role: string;
  readonly path: string;
  readonly fileName?: string;
  readonly sha256: string;
  readonly bytes?: number;
}

/** Final chain config published with the launch artifacts so operators never
 *  hand-copy addresses: setup records it into the validator state file and
 *  cross-checks any operator-provided env against it. Optional — absent until
 *  the final deployment is cut. */
export interface LaunchManifestChainConfig {
  readonly chainId: number;
  readonly registryAddress: string;
  readonly miningContractAddress: string;
  readonly registryDeployBlock?: number;
  readonly confirmationDepth?: number;
}

export interface LaunchArtifactManifest {
  readonly schema: string;
  readonly name: string;
  readonly artifactBaseUrlEnv?: string;
  readonly defaultBaseUrl?: string;
  readonly corpusRoot: string;
  readonly payloads: readonly LaunchArtifactPayload[];
  readonly materializedRoot: string;
  readonly bundlePath: string;
  readonly bundleHash: string;
  readonly bundleSha256: string;
  readonly profilePath: string;
  readonly profileSha256: string;
  readonly chain?: LaunchManifestChainConfig;
}

export function isEvmAddress(value: unknown): value is string {
  return typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/.test(value);
}

/** Chain-config addresses must be syntactically valid AND non-zero: the zero
 *  address is never a deployed contract, so a zeroed-but-well-formed value is
 *  exactly the placeholder mistake this validation exists to catch. */
export function isUsableContractAddress(value: unknown): value is string {
  return isEvmAddress(value) && !/^0x0{40}$/.test(value);
}

export function parseLaunchArtifactManifest(raw: unknown): LaunchArtifactManifest {
  const m = raw as LaunchArtifactManifest;
  if (!m || typeof m !== 'object') throw new Error('launch artifact manifest is not an object');
  if (m.schema !== LAUNCH_ARTIFACT_MANIFEST_SCHEMA) {
    throw new Error(`unsupported artifact manifest schema ${String(m.schema)} (expected ${LAUNCH_ARTIFACT_MANIFEST_SCHEMA})`);
  }
  if (!Array.isArray(m.payloads) || m.payloads.length === 0) throw new Error('launch artifact manifest has no payloads');
  for (const required of ['corpusRoot', 'bundlePath', 'bundleHash', 'bundleSha256', 'profilePath', 'profileSha256'] as const) {
    if (typeof m[required] !== 'string' || m[required].length === 0) {
      throw new Error(`launch artifact manifest missing ${required}`);
    }
  }
  for (const payload of m.payloads) {
    if (typeof payload.path !== 'string' || typeof payload.sha256 !== 'string') {
      throw new Error(`launch artifact payload malformed (role=${String(payload.role)})`);
    }
  }
  if (m.chain !== undefined) {
    const c = m.chain;
    if (!c || typeof c !== 'object') throw new Error('launch artifact manifest chain config is not an object');
    if (!Number.isSafeInteger(c.chainId) || c.chainId <= 0) throw new Error('manifest chain.chainId must be a positive integer');
    if (!isUsableContractAddress(c.registryAddress)) throw new Error('manifest chain.registryAddress must be a non-zero 0x-prefixed 20-byte address');
    if (!isUsableContractAddress(c.miningContractAddress)) throw new Error('manifest chain.miningContractAddress must be a non-zero 0x-prefixed 20-byte address');
    if (c.registryDeployBlock !== undefined && (!Number.isSafeInteger(c.registryDeployBlock) || c.registryDeployBlock < 0)) {
      throw new Error('manifest chain.registryDeployBlock must be a non-negative integer');
    }
    if (c.confirmationDepth !== undefined && (!Number.isSafeInteger(c.confirmationDepth) || c.confirmationDepth < 0)) {
      throw new Error('manifest chain.confirmationDepth must be a non-negative integer');
    }
  }
  return m;
}

/**
 * Optional RPC probe behind --verify-chain-config: setup itself stays
 * offline-capable artifact hydration; this is an explicit opt-in that catches
 * bad chain config BEFORE the first sync. Checks: RPC reachable, chainId
 * matches (when expected is known), deployed code at both addresses, and the
 * registry's botcoinMiningV4 pin equals the V4 address.
 */
export async function verifyChainConfig(inputs: {
  readonly rpcUrl: string;
  readonly registryAddress: string;
  readonly miningContractAddress: string;
  readonly expectedChainId?: number;
}): Promise<{ chainId: number }> {
  const { rpcUrl, registryAddress, miningContractAddress, expectedChainId } = inputs;
  const chainIdHex = await rpcCall<string>(rpcUrl, 'eth_chainId', []);
  const chainId = Number(BigInt(chainIdHex));
  if (expectedChainId !== undefined && chainId !== expectedChainId) {
    throw new Error(`chain config: RPC chainId ${chainId} != expected ${expectedChainId}`);
  }
  for (const [label, address] of [['registry', registryAddress], ['mining contract', miningContractAddress]] as const) {
    const code = await rpcCall<string>(rpcUrl, 'eth_getCode', [address, 'latest']);
    if (!code || code === '0x') throw new Error(`chain config: no deployed code at ${label} address ${address}`);
  }
  const selector = bytesToHex(keccak256(new TextEncoder().encode('botcoinMiningV4()'))).slice(0, 10);
  const pinned = await rpcCall<string>(rpcUrl, 'eth_call', [{ to: registryAddress, data: selector }, 'latest']);
  const pinnedAddress = `0x${(pinned ?? '').slice(-40)}`.toLowerCase();
  if (pinnedAddress !== miningContractAddress.toLowerCase()) {
    throw new Error(`chain config: registry.botcoinMiningV4() = ${pinnedAddress} != configured mining contract ${miningContractAddress}`);
  }
  return { chainId };
}

/** `<base>/coretex-launch-v16-artifacts.json` */
export function launchManifestUrl(artifactBaseUrl: string): string {
  return `${artifactBaseUrl.replace(/\/+$/, '')}/${LAUNCH_ARTIFACT_MANIFEST_FILENAME}`;
}

/** Payload download URL: `<base>/<fileName ?? basename(path)>`. */
export function payloadDownloadUrl(artifactBaseUrl: string, payload: { path: string; fileName?: string }): string {
  const suffix = payload.fileName ?? payload.path.split('/').pop()!;
  return `${artifactBaseUrl.replace(/\/+$/, '')}/${suffix}`;
}

/** Merge-write the validator state file: setup NEVER clobbers sync-owned
 *  fields (replay snapshot/cursor) and sync preserves setup-owned fields. */
export function mergeValidatorStateFile(
  statePath: string,
  patch: Record<string, unknown>,
): Record<string, unknown> {
  let previous: Record<string, unknown> = {};
  if (existsSync(statePath)) {
    try {
      previous = JSON.parse(readFileSync(statePath, 'utf8')) as Record<string, unknown>;
    } catch (err) {
      // Trusted state (carries the gap-3c base-corpus anchor and, after syncs,
      // the eval backlog/cursor): merging over a corrupt file would silently
      // discard it. Hard-fail; recovery is an explicit operator action.
      throw new Error(
        `corrupt validator state file at ${statePath}: ${err instanceof Error ? err.message : String(err)}. ` +
        'Restore it from backup, or delete it explicitly to re-run setup fresh.',
      );
    }
  }
  const merged = {
    schema: 'coretex.client-sync-state.v1',
    ...previous,
    ...patch,
    updatedAt: new Date().toISOString(),
  };
  mkdirSync(dirname(resolve(statePath)), { recursive: true });
  // Atomic tmp+rename: a crash mid-write must never corrupt the trusted state.
  const tmpPath = `${statePath}.tmp-${process.pid}`;
  writeFileSync(tmpPath, JSON.stringify(merged, null, 2) + '\n');
  renameSync(tmpPath, statePath);
  return merged;
}

// ── download / verify helpers ─────────────────────────────────────────────────

export function sha256File(path: string): Promise<string> {
  return new Promise((resolveHash, reject) => {
    const h = createHash('sha256');
    const stream = createReadStream(path);
    stream.on('data', (chunk) => h.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolveHash(h.digest('hex')));
  });
}

export async function verifyPayloadFile(
  path: string,
  expected: { sha256: string; bytes?: number | undefined },
): Promise<{ ok: boolean; reason?: string }> {
  if (!existsSync(path)) return { ok: false, reason: 'missing' };
  const st = statSync(path);
  if (expected.bytes != null && st.size !== expected.bytes) {
    return { ok: false, reason: `size ${st.size} != ${expected.bytes}` };
  }
  const actual = await sha256File(path);
  if (actual.toLowerCase() !== expected.sha256.toLowerCase()) {
    return { ok: false, reason: `sha256 ${actual} != ${expected.sha256}` };
  }
  return { ok: true };
}

/** Optional byte-progress callback: (downloadedBytes, totalBytesOrUndefined). */
export type DownloadProgress = (downloaded: number, total: number | undefined) => void;

function downloadHttp(url: string, outPath: string, onProgress?: DownloadProgress, redirects = 0): Promise<void> {
  return new Promise((resolveDone, reject) => {
    const client = url.startsWith('https:') ? https : http;
    const req = client.get(url, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode ?? 0)) {
        res.resume();
        if (!res.headers.location || redirects >= 5) return reject(new Error(`redirect failed for ${url}`));
        return resolveDone(downloadHttp(new URL(res.headers.location, url).toString(), outPath, onProgress, redirects + 1));
      }
      if ((res.statusCode ?? 0) < 200 || (res.statusCode ?? 0) >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      const totalHeader = Number(res.headers['content-length']);
      const total = Number.isFinite(totalHeader) && totalHeader > 0 ? totalHeader : undefined;
      let downloaded = 0;
      if (onProgress) res.on('data', (chunk: Buffer) => { downloaded += chunk.length; onProgress(downloaded, total); });
      const file = createWriteStream(outPath);
      res.pipe(file);
      file.on('finish', () => file.close(() => resolveDone()));
      file.on('error', reject);
    });
    req.on('error', reject);
  });
}

export async function downloadArtifact(url: string, outPath: string, baseDir: string, onProgress?: DownloadProgress): Promise<void> {
  mkdirSync(dirname(outPath), { recursive: true });
  const tmp = `${outPath}.tmp-${process.pid}`;
  try { if (existsSync(tmp)) unlinkSync(tmp); } catch { /* stale tmp */ }
  if (url.startsWith('file://')) {
    copyFileSync(fileURLToPath(url), tmp);
  } else if (url.startsWith('http://') || url.startsWith('https://')) {
    await downloadHttp(url, tmp, onProgress);
  } else {
    copyFileSync(resolve(baseDir, url), tmp);
  }
  renameSync(tmp, outPath);
}

async function readJsonUri(uri: string, baseDir: string): Promise<unknown> {
  if (uri.startsWith('http://') || uri.startsWith('https://')) {
    const res = await fetch(uri);
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${uri}`);
    return res.json();
  }
  if (uri.startsWith('file://')) return JSON.parse(readFileSync(new URL(uri), 'utf8'));
  return JSON.parse(readFileSync(resolve(baseDir, uri), 'utf8'));
}

// ── materialize via the in-package canonical script ──────────────────────────

function materializeCorpus(opts: {
  profilePath: string;
  bundlePath: string;
  corpusPath: string;
  embPath: string;
  materializedRoot: string;
  baseDir: string;
}): void {
  const materializer = join(resolveCortexPackageRoot(), 'scripts', 'materialize-production-corpus.mjs');
  if (!existsSync(materializer)) die(`in-package materializer missing: ${materializer}`);
  const cmd = [
    materializer,
    '--profile', opts.profilePath,
    '--bundle', opts.bundlePath,
    '--corpus', opts.corpusPath,
    '--emb', opts.embPath,
    '--materialized-root', opts.materializedRoot,
  ];
  log(`MATERIALIZE: node ${cmd.join(' ')}`);
  const res = spawnSync(process.execPath, cmd, {
    cwd: opts.baseDir,
    stdio: 'inherit',
    env: { ...process.env, CORETEX_REPO_ROOT: opts.baseDir },
  });
  if (res.status !== 0) die(`materialize exited ${res.status}`);
}

function materializedPaths(materializedRoot: string, bundleHash: string): {
  dir: string; manifest: string; corpusJson: string; ndjson: string;
} {
  const tag = bundleHash.slice(2, 10);
  const dir = join(materializedRoot, tag);
  const corpusJson = join(dir, 'corpus.json');
  return { dir, manifest: join(dir, 'manifest.json'), corpusJson, ndjson: `${corpusJson}.events.ndjson` };
}

function verifyMaterialized(materializedRoot: string, manifest: LaunchArtifactManifest, corpusSha: string, embSha: string): string {
  const paths = materializedPaths(materializedRoot, manifest.bundleHash);
  if (!existsSync(paths.manifest)) {
    die(`materialized cache missing: ${paths.manifest}. Run coretex-client-setup without --verify-only.`);
  }
  if (!existsSync(paths.corpusJson) || !existsSync(paths.ndjson)) {
    die(`materialized corpus files missing under ${paths.dir}`);
  }
  const mat = JSON.parse(readFileSync(paths.manifest, 'utf8')) as Record<string, unknown>;
  const checks: ReadonlyArray<[string, unknown, string]> = [
    ['bundleHash', mat.bundleHash, manifest.bundleHash],
    ['corpusRoot', mat.corpusRoot, manifest.corpusRoot],
    ['sourceCorpusSha256', mat.sourceCorpusSha256, `0x${corpusSha}`],
    ['sourceEmbSha256', mat.sourceEmbSha256, `0x${embSha}`],
    ['sourceProfileSha256', mat.sourceProfileSha256, `0x${manifest.profileSha256}`],
    ['sourceBundleSha256', mat.sourceBundleSha256, `0x${manifest.bundleSha256}`],
  ];
  for (const [label, actual, expected] of checks) {
    if (String(actual ?? '').toLowerCase() !== expected.toLowerCase()) {
      die(`materialized ${label} drift ${String(actual)} != ${expected}`);
    }
  }
  if (typeof mat.eventCount !== 'number' || mat.eventCount <= 0) {
    die(`materialized eventCount invalid: ${String(mat.eventCount)}`);
  }
  log(`OK materialized: ${paths.manifest}`);
  return paths.corpusJson;
}

// ── main ──────────────────────────────────────────────────────────────────────

async function ensurePayload(opts: {
  dest: string;
  expected: { sha256: string; bytes?: number | undefined };
  role: string;
  url: string | null;
  verifyOnly: boolean;
  noDownload: boolean;
  baseDir: string;
  noProgress?: boolean;
}): Promise<void> {
  const existing = await verifyPayloadFile(opts.dest, opts.expected);
  if (existing.ok) {
    log(`OK ${opts.role}: ${opts.dest}`);
    return;
  }
  if (opts.verifyOnly || opts.noDownload) {
    die(`${opts.dest} ${existing.reason}; download disabled`);
  }
  if (!opts.url) {
    die(`${opts.dest} ${existing.reason}; set CORETEX_ARTIFACT_BASE_URL or pass --artifact-base-url`);
  }
  log(`FETCH ${opts.role}: ${opts.url}`);
  // Byte/total + ETA progress on the (potentially large) artifact download —
  // stderr only, so stdout stays clean. content-length supplies the total.
  const progress = makeProgress({
    label: `download ${opts.role}`,
    unit: 'bytes',
    ...(opts.expected.bytes !== undefined ? { total: opts.expected.bytes } : {}),
    noProgressFlag: opts.noProgress ?? false,
  });
  await downloadArtifact(opts.url, opts.dest, opts.baseDir, (downloaded, total) => {
    progress.update(total !== undefined ? Math.min(downloaded, total) : downloaded);
  });
  progress.done();
  const after = await verifyPayloadFile(opts.dest, opts.expected);
  if (!after.ok) die(`downloaded ${opts.dest} failed verification: ${after.reason}`);
  log(`OK ${opts.role}: ${opts.dest}`);
}

async function main(): Promise<void> {
  if (has('help') || args.includes('-h')) {
    process.stdout.write(USAGE + '\n');
    return;
  }
  const verifyOnly = has('verify-only');
  const noDownload = has('no-download');
  const noProgress = has('no-progress');
  const skipVenv = has('no-venv-bootstrap') || process.env['CORETEX_VALIDATOR_SKIP_VENV'] === '1';
  const repoRoot = opt('repo-root');
  const artifactBase = opt('artifact-base-url', process.env['CORETEX_ARTIFACT_BASE_URL']);
  const stateDir = resolve(opt('state-dir', process.env['CORETEX_VALIDATOR_STATE_DIR'] ?? (repoRoot ? join(repoRoot, '.coretex-client') : '.coretex-client'))!);
  const statePath = join(stateDir, VALIDATOR_STATE_FILENAME);
  const deployBlockRaw = opt('registry-deploy-block', process.env['CORETEX_REGISTRY_DEPLOY_BLOCK']);
  if (deployBlockRaw !== undefined && (!Number.isSafeInteger(Number(deployBlockRaw)) || Number(deployBlockRaw) < 0)) {
    die('--registry-deploy-block must be a non-negative integer');
  }

  // ── early chain-config syntax checks (BEFORE any expensive work) ──
  // Setup never requires these envs (it is offline artifact hydration), but a
  // malformed value provided now would only surface on the first sync — after
  // downloads + materialization. Fail fast instead.
  const envRegistry = process.env['CORETEX_REGISTRY_ADDRESS'];
  const envMining = process.env['BOTCOIN_MINING_CONTRACT_ADDRESS'];
  const envRpcUrl = process.env['BASE_RPC_URL'];
  if (envRegistry !== undefined && !isUsableContractAddress(envRegistry)) {
    die(`CORETEX_REGISTRY_ADDRESS is set but malformed or zero (${envRegistry}): expected a non-zero 0x-prefixed 20-byte address`);
  }
  if (envMining !== undefined && !isUsableContractAddress(envMining)) {
    die(`BOTCOIN_MINING_CONTRACT_ADDRESS is set but malformed or zero (${envMining}): expected a non-zero 0x-prefixed 20-byte address`);
  }
  if (envRpcUrl !== undefined && !/^(https?|wss?):\/\/\S+$/.test(envRpcUrl)) {
    die(`BASE_RPC_URL is set but malformed (${envRpcUrl}): expected an http(s)/ws(s) URL`);
  }
  const verifyChain = has('verify-chain-config');

  // Base dir for resolving relative paths: repo root in repo mode, cwd otherwise.
  const baseDir = repoRoot ? resolve(repoRoot) : process.cwd();

  // ── launch artifact manifest ──
  let manifestSource = opt('manifest');
  if (!manifestSource) {
    if (repoRoot) manifestSource = REPO_DEFAULT_MANIFEST;
    else if (artifactBase) manifestSource = launchManifestUrl(artifactBase);
    else die('--manifest or --artifact-base-url (CORETEX_ARTIFACT_BASE_URL) is required to locate the launch artifact manifest');
  }
  const manifest = parseLaunchArtifactManifest(await readJsonUri(manifestSource, baseDir));
  const base = artifactBase
    ?? (manifest.artifactBaseUrlEnv ? process.env[manifest.artifactBaseUrlEnv] : undefined)
    ?? manifest.defaultBaseUrl
    ?? null;
  log(`manifest: ${manifestSource}`);
  log(`launch artifact: ${manifest.name}`);

  // ── chain config: manifest-vs-env cross-check + optional RPC probe ──
  // Both run BEFORE payload hydration so bad chain config never costs a full
  // download/materialization pass.
  if (manifest.chain) {
    if (envRegistry && envRegistry.toLowerCase() !== manifest.chain.registryAddress.toLowerCase()) {
      die(`CORETEX_REGISTRY_ADDRESS (${envRegistry}) != manifest chain.registryAddress (${manifest.chain.registryAddress})`);
    }
    if (envMining && envMining.toLowerCase() !== manifest.chain.miningContractAddress.toLowerCase()) {
      die(`BOTCOIN_MINING_CONTRACT_ADDRESS (${envMining}) != manifest chain.miningContractAddress (${manifest.chain.miningContractAddress})`);
    }
    log(`chain config (manifest): chainId=${manifest.chain.chainId} registry=${manifest.chain.registryAddress} v4=${manifest.chain.miningContractAddress}`
      + (manifest.chain.registryDeployBlock !== undefined ? ` deployBlock=${manifest.chain.registryDeployBlock}` : '')
      + (manifest.chain.confirmationDepth !== undefined ? ` confirmationDepth=${manifest.chain.confirmationDepth}` : ''));
  }
  if (verifyChain) {
    const registryAddress = envRegistry ?? manifest.chain?.registryAddress;
    const miningContractAddress = envMining ?? manifest.chain?.miningContractAddress;
    if (!envRpcUrl) die('--verify-chain-config requires BASE_RPC_URL');
    if (!registryAddress || !miningContractAddress) {
      die('--verify-chain-config requires CORETEX_REGISTRY_ADDRESS + BOTCOIN_MINING_CONTRACT_ADDRESS (env) or a manifest chain config');
    }
    try {
      const probe = await verifyChainConfig({
        rpcUrl: envRpcUrl,
        registryAddress,
        miningContractAddress,
        ...(manifest.chain ? { expectedChainId: manifest.chain.chainId } : {}),
      });
      log(`chain config VERIFIED on-chain: chainId=${probe.chainId} registry=${registryAddress} v4=${miningContractAddress} (code present, registry→V4 pin matches)`);
    } catch (err) {
      die(err instanceof Error ? err.message : String(err));
    }
  }

  // ── payload destinations ──
  const artifactsDir = repoRoot ? baseDir : join(stateDir, 'artifacts');
  const destFor = (payload: { path: string; fileName?: string }): string =>
    repoRoot ? resolve(baseDir, payload.path) : join(artifactsDir, payload.fileName ?? basename(payload.path));

  const corpusPayload = manifest.payloads.find((p) => p.role === 'corpus');
  const embPayload = manifest.payloads.find((p) => p.role === 'embeddings');
  if (!corpusPayload || !embPayload) die('launch artifact manifest must carry corpus + embeddings payloads');

  for (const payload of manifest.payloads) {
    await ensurePayload({
      dest: destFor(payload),
      expected: { sha256: payload.sha256, bytes: payload.bytes },
      role: payload.role,
      url: base ? payloadDownloadUrl(base, payload) : null,
      verifyOnly,
      noDownload,
      baseDir,
      noProgress,
    });
  }

  // ── bundle manifest + evaluator profile ──
  const bundleDest = repoRoot ? resolve(baseDir, manifest.bundlePath) : join(artifactsDir, basename(manifest.bundlePath));
  const profileDest = repoRoot ? resolve(baseDir, manifest.profilePath) : join(artifactsDir, basename(manifest.profilePath));
  if (repoRoot) {
    // Repo mode: bundle/profile are committed files — verify in place, never download.
    for (const [label, path, sha] of [
      ['bundle', bundleDest, manifest.bundleSha256],
      ['profile', profileDest, manifest.profileSha256],
    ] as const) {
      const check = await verifyPayloadFile(path, { sha256: sha });
      if (!check.ok) die(`${label} ${path}: ${check.reason}`);
      log(`OK ${label}: ${path}`);
    }
  } else {
    await ensurePayload({
      dest: bundleDest,
      expected: { sha256: manifest.bundleSha256 },
      role: 'bundle-manifest',
      url: base ? payloadDownloadUrl(base, { path: manifest.bundlePath }) : null,
      verifyOnly, noDownload, baseDir, noProgress,
    });
    await ensurePayload({
      dest: profileDest,
      expected: { sha256: manifest.profileSha256 },
      role: 'evaluator-profile',
      url: base ? payloadDownloadUrl(base, { path: manifest.profilePath }) : null,
      verifyOnly, noDownload, baseDir, noProgress,
    });
  }

  const bundle = JSON.parse(readFileSync(bundleDest, 'utf8')) as CoreTexBundleManifest;
  if (bundle.bundleHash !== manifest.bundleHash) {
    die(`bundleHash drift ${bundle.bundleHash} != ${manifest.bundleHash}`);
  }
  if ((bundle.corpus?.root ?? '').toLowerCase() !== manifest.corpusRoot.toLowerCase()) {
    die(`corpusRoot drift ${bundle.corpus?.root} != ${manifest.corpusRoot}`);
  }
  if (repoRoot) {
    // Source-tree pin verification only makes sense against a repo checkout.
    const errors = verifyBundleManifest(bundle, baseDir);
    if (errors.length) die(`bundle manifest invalid:\n  - ${errors.join('\n  - ')}`);
  }
  log(`OK bundleHash: ${bundle.bundleHash}`);

  // ── materialize (or verify the existing materialization) ──
  const materializedRoot = repoRoot
    ? resolve(baseDir, manifest.materializedRoot)
    : join(stateDir, 'materialized');
  if (verifyOnly) {
    verifyMaterialized(materializedRoot, manifest, corpusPayload.sha256, embPayload.sha256);
  } else {
    materializeCorpus({
      profilePath: profileDest,
      bundlePath: bundleDest,
      corpusPath: destFor(corpusPayload),
      embPath: destFor(embPayload),
      materializedRoot,
      baseDir,
    });
    verifyMaterialized(materializedRoot, manifest, corpusPayload.sha256, embPayload.sha256);
  }
  const corpusJsonPath = materializedPaths(materializedRoot, manifest.bundleHash).corpusJson;

  // ── Python scorer venv bootstrap (RUNTIME hygiene; never touches scoring) ──
  //   Makes sync's CPU score replay self-contained given only python3. Skipped
  //   in --verify-only (a verify-only run never builds anything) and when opted
  //   out. The resolved interpreter is recorded so sync exports it as
  //   CORETEX_RERANKER_PYTHON for the scorer spawn.
  let venv: VenvBootstrapResult | undefined;
  if (!verifyOnly) {
    try {
      venv = bootstrapScorerVenv({
        stateDir,
        rerankerScriptPath: resolveRerankerScriptPath(),
        envScorerPython: process.env['CORETEX_RERANKER_PYTHON'],
        optOut: skipVenv,
      }, realSyncSpawner);
      log(`scorer python: ${venv.status} — ${venv.detail}`);
    } catch (err) {
      if (err instanceof VenvBootstrapError) {
        // A failed bootstrap is a hard, actionable failure — never leave a
        // half-built venv claimed as ready.
        renderSummaryBlock('coretex-client-setup', false, [
          'Python scorer venv bootstrap FAILED — score replay is not yet self-contained.',
          ...err.message.split('\n'),
        ]);
        die(err.message);
      }
      throw err;
    }
  }

  // ── validator state file: sync needs no manual flags after this ──
  const recordScorerPython = venv && venv.status !== 'skipped-opt-out';
  // Explicit operator deploy block wins; otherwise fall back to the manifest's
  // published chain config so sync replay needs no hand-copied value.
  const registryDeployBlock = deployBlockRaw !== undefined
    ? Number(deployBlockRaw)
    : manifest.chain?.registryDeployBlock;
  const state = mergeValidatorStateFile(statePath, {
    bundleHash: manifest.bundleHash,
    corpusRoot: manifest.corpusRoot,
    ...(registryDeployBlock !== undefined ? { registryDeployBlock } : {}),
    ...(manifest.chain ? { chain: manifest.chain } : {}),
    setup: {
      completedAt: new Date().toISOString(),
      launchName: manifest.name,
      manifestSource: isAbsolute(manifestSource) || /^(https?|file):/.test(manifestSource) ? manifestSource : resolve(baseDir, manifestSource),
      bundleManifestPath: bundleDest,
      profilePath: profileDest,
      corpusPath: corpusJsonPath,
      // The launch/genesis materialized corpus is the universal earliest ANCESTOR
      // of every epoch corpusRoot on the published delta chain. Record it under a
      // STABLE, distinct field (root + path) so historical corpus auto-resolution
      // can always walk FORWARD from this guaranteed ancestor — even when sync's
      // loaded corpus is overridden (--corpus/CORETEX_CORPUS_PATH) to a current,
      // post-rotation corpus that is AHEAD of (not an ancestor of) the target root.
      baseCorpusPath: corpusJsonPath,
      baseCorpusRoot: manifest.corpusRoot,
      materializedRoot,
      ...(base ? { artifactBaseUrl: base } : {}),
      ...(recordScorerPython ? { scorerPython: venv!.scorerPython, scorerVenvStatus: venv!.status } : {}),
    },
  });
  log(`state: ${statePath}`);
  log(`READY corpusRoot=${manifest.corpusRoot} bundleHash=${manifest.bundleHash}`);
  void state;

  renderSummaryBlock('coretex-client-setup', true, [
    `launch artifact: ${manifest.name}`,
    `corpusRoot=${manifest.corpusRoot}`,
    `bundleHash=${manifest.bundleHash}`,
    `materialized corpus: ${corpusJsonPath}`,
    venv
      ? `scorer python: ${recordScorerPython ? venv.scorerPython : '(operator-managed)'} [${venv.status}]`
      : 'scorer python: (verify-only — venv bootstrap skipped)',
    `state file: ${statePath}`,
    'Next: coretex-client-sync (needs only BASE_RPC_URL, CORETEX_REGISTRY_ADDRESS, BOTCOIN_MINING_CONTRACT_ADDRESS, CORETEX_ARTIFACT_BASE_URL)',
  ]);
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
