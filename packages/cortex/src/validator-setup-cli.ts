#!/usr/bin/env node
/**
 * coretex-validator-setup — one-command validator artifact hydration.
 *
 * Standalone (installed-package) mode, the default:
 *   1. Fetches the launch artifact manifest from
 *      `<CORETEX_ARTIFACT_BASE_URL>/coretex-launch-v16-artifacts.json`
 *      (override: --manifest <path-or-url>).
 *   2. Downloads the corpus + embeddings + bundle manifest + evaluator profile
 *      into the validator state dir (default `.coretex-validator`, env
 *      CORETEX_VALIDATOR_STATE_DIR) with SHA-256 + byte-size verification.
 *   3. Materializes the production corpus via the in-package canonical
 *      materializer (packages/cortex/scripts/materialize-production-corpus.mjs)
 *      and cross-checks the materialized corpusRoot against the manifest.
 *   4. Writes the bundle manifest path, materialized corpus path, previous
 *      corpus root, and registry deploy block into the validator state file so
 *      `coretex-validator-sync` needs no manual flags.
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
import { resolveCortexPackageRoot } from './eval/reranker.js';

export const LAUNCH_ARTIFACT_MANIFEST_FILENAME = 'coretex-launch-v16-artifacts.json';
export const LAUNCH_ARTIFACT_MANIFEST_SCHEMA = 'coretex.launch-artifacts.v1';
export const VALIDATOR_STATE_FILENAME = 'validator-sync-state.json';
const REPO_DEFAULT_MANIFEST = 'release/calibration/2026-06-04-memory-atom-v16/coretex-launch-v16-artifacts.json';

const USAGE = `coretex-validator-setup — hydrate + verify CoreTex validator artifacts

Usage:
  coretex-validator-setup [--artifact-base-url <url>] [--manifest <path-or-url>]
                          [--state-dir <dir>] [--registry-deploy-block <n>]
                          [--verify-only] [--no-download] [--repo-root <dir>]

Env:
  CORETEX_ARTIFACT_BASE_URL     artifact base URL (manifest + payloads)
  CORETEX_VALIDATOR_STATE_DIR   state dir (default .coretex-validator)
  CORETEX_REGISTRY_DEPLOY_BLOCK registry deploy block recorded for sync replay

After setup completes, \`coretex-validator-sync\` needs only BASE_RPC_URL,
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
  return m;
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
    } catch {
      previous = {};
    }
  }
  const merged = {
    schema: 'coretex.validator-sync-state.v1',
    ...previous,
    ...patch,
    updatedAt: new Date().toISOString(),
  };
  mkdirSync(dirname(resolve(statePath)), { recursive: true });
  writeFileSync(statePath, JSON.stringify(merged, null, 2) + '\n');
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

function downloadHttp(url: string, outPath: string, redirects = 0): Promise<void> {
  return new Promise((resolveDone, reject) => {
    const client = url.startsWith('https:') ? https : http;
    const req = client.get(url, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode ?? 0)) {
        res.resume();
        if (!res.headers.location || redirects >= 5) return reject(new Error(`redirect failed for ${url}`));
        return resolveDone(downloadHttp(new URL(res.headers.location, url).toString(), outPath, redirects + 1));
      }
      if ((res.statusCode ?? 0) < 200 || (res.statusCode ?? 0) >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      const file = createWriteStream(outPath);
      res.pipe(file);
      file.on('finish', () => file.close(() => resolveDone()));
      file.on('error', reject);
    });
    req.on('error', reject);
  });
}

export async function downloadArtifact(url: string, outPath: string, baseDir: string): Promise<void> {
  mkdirSync(dirname(outPath), { recursive: true });
  const tmp = `${outPath}.tmp-${process.pid}`;
  try { if (existsSync(tmp)) unlinkSync(tmp); } catch { /* stale tmp */ }
  if (url.startsWith('file://')) {
    copyFileSync(fileURLToPath(url), tmp);
  } else if (url.startsWith('http://') || url.startsWith('https://')) {
    await downloadHttp(url, tmp);
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
    die(`materialized cache missing: ${paths.manifest}. Run coretex-validator-setup without --verify-only.`);
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
  await downloadArtifact(opts.url, opts.dest, opts.baseDir);
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
  const repoRoot = opt('repo-root');
  const artifactBase = opt('artifact-base-url', process.env['CORETEX_ARTIFACT_BASE_URL']);
  const stateDir = resolve(opt('state-dir', process.env['CORETEX_VALIDATOR_STATE_DIR'] ?? (repoRoot ? join(repoRoot, '.coretex-validator') : '.coretex-validator'))!);
  const statePath = join(stateDir, VALIDATOR_STATE_FILENAME);
  const deployBlockRaw = opt('registry-deploy-block', process.env['CORETEX_REGISTRY_DEPLOY_BLOCK']);
  if (deployBlockRaw !== undefined && (!Number.isSafeInteger(Number(deployBlockRaw)) || Number(deployBlockRaw) < 0)) {
    die('--registry-deploy-block must be a non-negative integer');
  }

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
      verifyOnly, noDownload, baseDir,
    });
    await ensurePayload({
      dest: profileDest,
      expected: { sha256: manifest.profileSha256 },
      role: 'evaluator-profile',
      url: base ? payloadDownloadUrl(base, { path: manifest.profilePath }) : null,
      verifyOnly, noDownload, baseDir,
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

  // ── validator state file: sync needs no manual flags after this ──
  const state = mergeValidatorStateFile(statePath, {
    bundleHash: manifest.bundleHash,
    corpusRoot: manifest.corpusRoot,
    ...(deployBlockRaw !== undefined ? { registryDeployBlock: Number(deployBlockRaw) } : {}),
    setup: {
      completedAt: new Date().toISOString(),
      launchName: manifest.name,
      manifestSource: isAbsolute(manifestSource) || /^(https?|file):/.test(manifestSource) ? manifestSource : resolve(baseDir, manifestSource),
      bundleManifestPath: bundleDest,
      profilePath: profileDest,
      corpusPath: corpusJsonPath,
      materializedRoot,
      ...(base ? { artifactBaseUrl: base } : {}),
    },
  });
  log(`state: ${statePath}`);
  log(`READY corpusRoot=${manifest.corpusRoot} bundleHash=${manifest.bundleHash}`);
  void state;
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
