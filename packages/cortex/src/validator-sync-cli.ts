#!/usr/bin/env node
/**
 * coretex-validator-sync — one-command validator sync + audit CLI.
 *
 * sync (default):
 *   1. Reads the on-chain epoch pins (registry + V4 mining context) including the
 *      epoch-secret reveal status (`awaiting_epoch_secret_reveal` before reveal).
 *   2. Self version-check: the local bundle manifest's bundleHash MUST equal the
 *      on-chain coreVersionHash (escape: --allow-version-mismatch, read-only).
 *   3. Fetches the signed EpochRotationManifest + signed CorpusDelta and verifies
 *      signatures (MANDATORY — a missing public key is a hard error) under a
 *      TOFU-pinned epoch signing key.
 *   4. Corpus-delta continuity: delta.previousRoot must equal the LOCAL previous
 *      corpus root (validator state file / --previous-corpus-root / bundle corpus.root).
 *   5. Optionally replays the registry logs (paginated + confirmation-depth capped)
 *      against the on-chain liveStateRoot with mode flags derived from the bundle.
 *
 * verify-patch --hash 0x…:
 *   Fetches a post-reveal eval artifact by hash from CORETEX_ARTIFACT_BASE_URL and
 *   replays it through verifyPostRevealEvalReportArtifact (the single entrypoint).
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync, realpathSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import http from 'node:http';
import https from 'node:https';

import { coretexRangeLogs, replayCoreTexFromLogs, type CoreTexRangeLogOptions } from './replay/coretex-registry.js';
import { loadPackedState, rpcCall } from './replay/v4.js';
import { bytesToHex, hexToBytes, merkleizeState } from './state/merkle.js';
import { decodePatch } from './state/patch.js';
import { keccak256 } from './state/keccak256.js';
import { hashCorpusDelta, hashJson, verifyEpochRotationManifestSignature } from './corpus/epoch-rotation.js';
import { parseCorpusDelta, verifyCorpusDeltaSignature } from './corpus/delta.js';
import {
  hashPostRevealEvalReportArtifact,
  verifyPostRevealEvalReportArtifact,
  type CoreTexPostRevealEvalReportArtifact,
} from './replay/eval-report-artifact.js';
import { DEFAULT_PROFILE, scoringOptionsFromProfile, type CoreTexBundleManifest } from './bundle/index.js';
import { loadProductionCorpus } from './eval/retrieval-corpus.js';
import { deriveQueryPack } from './eval/hidden-query-pack.js';
import { computeAcceptanceThresholdPpm, evaluateRetrievalBenchmarkPatch } from './eval/retrieval-benchmark.js';
import { biEncoderFromEnv } from './eval/bi-encoder.js';
import { rerankerFromEnv } from './eval/reranker.js';
import { biEncoderModelIdHash } from './substrate/retrieval-decoder.js';
import { createBaseRpcClient } from './coordinator/base-blockhash.js';

const ZERO32 = `0x${'00'.repeat(32)}`;
const args = process.argv.slice(2);

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
async function ethCall(rpcUrl: string, to: string, signature: string, callArgs: readonly (string | number | bigint)[] = []): Promise<string> {
  return rpcCall<string>(rpcUrl, 'eth_call', [{ to, data: calldata(signature, callArgs) }, 'latest']);
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
function stringField(obj: Record<string, unknown> | null, key: string): string | undefined {
  const value = obj?.[key];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}
function blockHex(block: bigint): string {
  return `0x${block.toString(16)}`;
}
async function latestBlock(rpcUrl: string): Promise<bigint> {
  return BigInt(await rpcCall<string>(rpcUrl, 'eth_blockNumber', []));
}

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

/** Write the TOFU pin after the FIRST fully verified sync. */
export function writeTofuKeyPin(pinPath: string, publicKeyPem: string): { fingerprint: string } {
  const fingerprint = sha256Fingerprint(publicKeyPem);
  mkdirSync(dirname(resolve(pinPath)), { recursive: true });
  writeFileSync(pinPath, JSON.stringify({
    schema: 'coretex.epoch-signing-key-pin.v1',
    pinnedAt: new Date().toISOString(),
    fingerprint,
    publicKeyPem,
  }, null, 2) + '\n');
  return { fingerprint };
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
  warn: (message: string) => void = (m) => process.stderr.write(`${m}\n`),
): { match: boolean } {
  if (localBundleHash.toLowerCase() === chainCoreVersionHash.toLowerCase()) return { match: true };
  const message = `validator client outdated: local bundle ${localBundleHash} != on-chain coreVersionHash ${chainCoreVersionHash}. Required bundle hash: ${chainCoreVersionHash}`;
  if (!allowMismatch) throw new Error(message);
  warn(`WARNING: ${message} — continuing READ-ONLY because --allow-version-mismatch was passed; do NOT attest from this run`);
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

// ── chain context ─────────────────────────────────────────────────────────────

async function readChainContext(rpcUrl: string, registry: string, mining: string, epoch: number) {
  const chainRegistry = decodeAddress(await ethCall(rpcUrl, mining, 'coreTexRegistry()'), 'mining.coreTexRegistry');
  if (chainRegistry.toLowerCase() !== registry.toLowerCase()) throw new Error(`V4 coreTexRegistry ${chainRegistry} != ${registry}`);
  const contextSet = decodeUint(await ethCall(rpcUrl, mining, 'coreTexEpochContextSet(uint64)', [epoch]), 'mining.coreTexEpochContextSet');
  if (contextSet !== 1) throw new Error(`V4 CoreTex epoch context not set for epoch ${epoch}`);
  const pins = {
    parentStateRoot: decodeBytes32(await ethCall(rpcUrl, registry, 'epochParentStateRoot(uint64)', [epoch]), 'registry.epochParentStateRoot'),
    liveStateRoot: decodeBytes32(await ethCall(rpcUrl, registry, 'liveStateRoot(uint64)', [epoch]), 'registry.liveStateRoot'),
    transitionCount: decodeUint(await ethCall(rpcUrl, registry, 'transitionCount(uint64)', [epoch]), 'registry.transitionCount'),
    coreVersionHash: decodeBytes32(await ethCall(rpcUrl, registry, 'epochCoreVersionHash(uint64)', [epoch]), 'registry.epochCoreVersionHash'),
    corpusRoot: decodeBytes32(await ethCall(rpcUrl, registry, 'epochCorpusRoot(uint64)', [epoch]), 'registry.epochCorpusRoot'),
    activeFrontierRoot: decodeBytes32(await ethCall(rpcUrl, registry, 'epochActiveFrontierRoot(uint64)', [epoch]), 'registry.epochActiveFrontierRoot'),
    baselineManifestHash: decodeBytes32(await ethCall(rpcUrl, registry, 'epochBaselineManifestHash(uint64)', [epoch]), 'registry.epochBaselineManifestHash'),
    hiddenSeedCommit: decodeBytes32(await ethCall(rpcUrl, registry, 'epochHiddenSeedCommit(uint64)', [epoch]), 'registry.epochHiddenSeedCommit'),
  };
  const epochCommit = decodeBytes32(await ethCall(rpcUrl, mining, 'epochCommit(uint64)', [epoch]), 'mining.epochCommit');
  if (epochCommit.toLowerCase() !== pins.hiddenSeedCommit.toLowerCase()) {
    throw new Error(`V4 epochCommit ${epochCommit} != registry hiddenSeedCommit ${pins.hiddenSeedCommit}`);
  }
  if (epochCommit.toLowerCase() === ZERO32) throw new Error(`V4 epochCommit(${epoch}) is zero`);
  const epochSecret = decodeBytes32(await ethCall(rpcUrl, mining, 'epochSecret(uint64)', [epoch]), 'mining.epochSecret');
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

async function syncMain() {
  const coordinatorStatusUri = opt('from-coordinator', process.env['CORETEX_COORDINATOR_STATUS_URL']);
  const status = coordinatorStatusUri ? await readJsonUri(coordinatorStatusUri) as Record<string, unknown> : null;
  const epochRaw = opt('epoch', String(status?.epoch ?? status?.currentEpoch ?? process.env['EPOCH_ID'] ?? ''));
  if (!epochRaw) die('--epoch, EPOCH_ID, or coordinator status epoch is required');
  const epoch = Number(epochRaw);
  if (!Number.isSafeInteger(epoch) || epoch < 0) die('epoch must be a non-negative safe integer');

  const rpcUrl = opt('rpc-url', process.env['BASE_RPC_URL']);
  const registry = opt('registry', process.env['CORETEX_REGISTRY_ADDRESS']);
  const mining = opt('mining-contract', process.env['BOTCOIN_MINING_CONTRACT_ADDRESS'] ?? process.env['BOTCOIN_MINING_V4']);
  if (!rpcUrl) die('--rpc-url or BASE_RPC_URL is required');
  if (!isAddress(registry)) die('--registry or CORETEX_REGISTRY_ADDRESS is required');
  if (!isAddress(mining)) die('--mining-contract or BOTCOIN_MINING_CONTRACT_ADDRESS is required');

  // ── local preconditions BEFORE any RPC: bundle manifest, artifact URIs, signing key ──
  const bundleManifestPath = opt('bundle-manifest', process.env['CORETEX_BUNDLE_MANIFEST']);
  if (!bundleManifestPath) {
    die('--bundle-manifest or CORETEX_BUNDLE_MANIFEST is required: the validator client version-checks its local bundle against the on-chain coreVersionHash and derives replay mode flags from it (no silent defaults)');
  }
  const bundleManifest = JSON.parse(readFileSync(bundleManifestPath, 'utf8')) as CoreTexBundleManifest;
  if (!isBytes32(bundleManifest.bundleHash)) die(`bundle manifest ${bundleManifestPath} has no bundleHash`);
  const policyAtomsMode = policyAtomsModeFromManifest(bundleManifest);

  // ── validator state dir / TOFU pin file ──
  const stateDir = opt('state-dir', process.env['CORETEX_VALIDATOR_STATE_DIR'] ?? '.coretex-validator')!;
  const statePath = opt('state', join(stateDir, 'validator-sync-state.json'))!;
  const pinPath = opt('key-pin-file', process.env['CORETEX_KEY_PIN_PATH'] ?? join(stateDir, 'epoch-signing-key.pin.json'))!;

  const artifactBase = opt('artifact-base-url', process.env['CORETEX_ARTIFACT_BASE_URL']);
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

  const chain = await readChainContext(rpcUrl, registry, mining, epoch);
  // ── self version-check against the on-chain coreVersionHash ──
  const version = checkValidatorBundleVersion(bundleManifest.bundleHash, chain.coreVersionHash, has('allow-version-mismatch'));

  const publicKey = await readTextUri(publicKeyUri);
  const tofu = checkTofuKeyPin(pinPath, publicKey);

  const rotation = await readJsonUri(rotationUri) as Record<string, unknown>;
  const delta = parseCorpusDelta(await readJsonUri(deltaUri) as never);
  if (!verifyEpochRotationManifestSignature(rotation as never, publicKey)) throw new Error('rotation manifest signature invalid');
  if (!verifyCorpusDeltaSignature(delta, publicKey)) throw new Error('corpus delta signature invalid');
  if (!tofu.pinned) writeTofuKeyPin(pinPath, publicKey);

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

  let replay: unknown = null;
  const parentStatePath = opt('parent-state', process.env['CORETEX_PARENT_STATE_PATH']);
  const fromBlockRaw = opt('from-block', process.env['CORETEX_REPLAY_FROM_BLOCK'] ?? process.env['CORETEX_REGISTRY_DEPLOY_BLOCK']);
  if (parentStatePath && fromBlockRaw) {
    const parent = loadPackedState(parentStatePath);
    const latest = await latestBlock(rpcUrl);
    const logs = await coretexRangeLogs(rpcUrl, registry, blockHex(BigInt(fromBlockRaw)), blockHex(latest), {
      latestBlock: latest,
      ...rangeLogOptions(),
    });
    const result = replayCoreTexFromLogs(parent, logs, {
      expectedBundleHash: chain.coreVersionHash,
      expectedCorpusRoot: chain.corpusRoot,
      expectedActiveFrontierRoot: chain.activeFrontierRoot,
      expectedBaselineManifestHash: chain.baselineManifestHash,
      expectedHiddenSeedCommit: chain.hiddenSeedCommit,
      policyAtomsMode,
      acknowledgedRevertedEpochs: all('acknowledge-reverted-epoch').map((v) => Number(v)),
    });
    if (!result.ok) throw new Error(`registry replay failed: ${result.code} ${result.message ?? ''}`);
    if (result.reproducedFinalRoot?.toLowerCase() !== chain.liveStateRoot.toLowerCase()) {
      throw new Error(`registry replay root ${result.reproducedFinalRoot} != chain liveStateRoot ${chain.liveStateRoot}`);
    }
    if (result.transitions !== chain.transitionCount) {
      throw new Error(`registry replay transitions ${result.transitions} != chain transitionCount ${chain.transitionCount}`);
    }
    replay = result;
  }

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
    process.stderr.write('status: awaiting_epoch_secret_reveal — mining epochSecret is zero/unrevealed; post-reveal eval replay must wait\n');
  }

  mkdirSync(dirname(resolve(statePath)), { recursive: true });
  writeFileSync(statePath, JSON.stringify({
    schema: 'coretex.validator-sync-state.v1',
    updatedAt: new Date().toISOString(),
    epoch,
    bundleHash: bundleManifest.bundleHash,
    corpusRoot: delta.nextRoot,
    rotationManifestHash: rotationHash,
    corpusDeltaHash: deltaHash,
    evalReplayStatus: chain.evalReplayStatus,
    epochSigningKeyFingerprint: tofu.fingerprint,
  }, null, 2) + '\n');

  process.stdout.write(JSON.stringify({
    ok: true,
    command: 'coretex-validator-sync',
    epoch,
    registry,
    miningContract: mining,
    bundleVersion: { localBundleHash: bundleManifest.bundleHash, chainCoreVersionHash: chain.coreVersionHash, match: version.match, policyAtomsMode },
    evalReplayStatus: chain.evalReplayStatus,
    chain,
    artifacts,
    ...(replay ? { replay } : { replay: 'skipped: pass --parent-state and --from-block to replay registry logs' }),
    evalArtifacts,
    statePath,
  }, null, 2) + '\n');
}

// ── verify-patch subcommand ───────────────────────────────────────────────────

async function verifyPatchMain() {
  const hash = opt('hash');
  if (!isBytes32(hash)) die('verify-patch requires --hash 0x<bytes32 artifactHash>');
  const artifactBase = opt('artifact-base-url', process.env['CORETEX_ARTIFACT_BASE_URL']);
  const artifactUri = opt('artifact-url', joinUrl(artifactBase, `eval-reports/${hash.toLowerCase()}.json`));
  if (!artifactUri) die('verify-patch requires CORETEX_ARTIFACT_BASE_URL / --artifact-base-url (or an explicit --artifact-url)');
  const artifact = await readJsonUri(artifactUri) as CoreTexPostRevealEvalReportArtifact;
  if (String(artifact.artifactHash).toLowerCase() !== hash.toLowerCase()) {
    die(`fetched artifact hash ${artifact.artifactHash} != requested ${hash}`);
  }

  const rpcUrl = opt('rpc-url', process.env['BASE_RPC_URL']);
  if (!rpcUrl) die('--rpc-url or BASE_RPC_URL is required (blockhash binding replay)');
  const epochSecret = opt('epoch-secret', process.env['CORETEX_EPOCH_SECRET']);
  if (!isBytes32(epochSecret)) die('--epoch-secret or CORETEX_EPOCH_SECRET (revealed bytes32) is required for post-reveal verification');
  const bundleManifestPath = opt('bundle-manifest', process.env['CORETEX_BUNDLE_MANIFEST']);
  if (!bundleManifestPath) die('--bundle-manifest or CORETEX_BUNDLE_MANIFEST is required');
  const corpusPath = opt('corpus', process.env['CORETEX_CORPUS_PATH']);
  if (!corpusPath) die('--corpus or CORETEX_CORPUS_PATH is required (materialized epoch corpus)');
  const parentStatePath = opt('parent-state', process.env['CORETEX_PARENT_STATE_PATH']);
  if (!parentStatePath) die('--parent-state or CORETEX_PARENT_STATE_PATH is required');

  const bundle = JSON.parse(readFileSync(bundleManifestPath, 'utf8')) as CoreTexBundleManifest;
  if (!isBytes32(bundle.bundleHash)) die(`bundle manifest ${bundleManifestPath} has no bundleHash`);
  checkValidatorBundleVersion(bundle.bundleHash, artifact.context.coreVersionHash, has('allow-version-mismatch'));
  const profile = bundle.evaluator?.profile ?? DEFAULT_PROFILE;

  const corpus = loadProductionCorpus(corpusPath, { verifyCorpusRoot: true, verifySplits: true });
  if (corpus.corpusRoot.toLowerCase() !== artifact.context.corpusRoot.toLowerCase()) {
    die(`local corpus root ${corpus.corpusRoot} != artifact context corpusRoot ${artifact.context.corpusRoot}`);
  }
  const parent = loadPackedState(parentStatePath);
  const parentRoot = bytesToHex(merkleizeState(parent));
  if (parentRoot.toLowerCase() !== artifact.context.parentStateRoot.toLowerCase()) {
    die(`local parent state root ${parentRoot} != artifact context parentStateRoot ${artifact.context.parentStateRoot}`);
  }

  const layout = corpus.biEncoderRetrievalKeyLayout;
  const biEncoder = biEncoderFromEnv(layout, { modelId: corpus.biEncoderModelId, revision: corpus.biEncoderRevision });
  const reranker = await rerankerFromEnv();
  const scoringOpts = scoringOptionsFromProfile(profile, {
    biEncoder,
    reranker,
    biEncoderHash: biEncoderModelIdHash(corpus.biEncoderModelId, corpus.biEncoderRevision, 'dense'),
    retrievalKeyLayout: layout,
  });
  const thresholdPpm = Math.min(computeAcceptanceThresholdPpm(profile), 355);

  try {
    const result = await verifyPostRevealEvalReportArtifact(artifact, {
      rpcClient: createBaseRpcClient(rpcUrl),
      epochSecret,
      scorer: async ({ normalizedPatchBytes, evalSeed }) => {
        const pack = deriveQueryPack(artifact.epochId, evalSeed, corpus, profile.hiddenPack);
        const scored = await evaluateRetrievalBenchmarkPatch(parent, decodePatch(normalizedPatchBytes), corpus, pack, scoringOpts, {
          ...profile.patchAcceptanceFloors,
          acceptanceThresholdPpm: thresholdPpm,
        });
        return {
          scorePpm: scored.deltaPpm,
          accepted: scored.accepted,
          ...(scored.reason ? { rejectionReason: scored.reason } : {}),
        };
      },
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
    const closable = reranker as { close?: () => Promise<void> };
    if (typeof closable.close === 'function') await closable.close();
  }
}

async function main() {
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
