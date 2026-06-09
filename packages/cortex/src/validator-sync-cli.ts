#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';

import { coretexRangeLogs, replayCoreTexFromLogs } from './replay/coretex-registry.js';
import { loadPackedState, rpcCall } from './replay/v4.js';
import { bytesToHex, hexToBytes } from './state/merkle.js';
import { keccak256 } from './state/keccak256.js';
import { hashCorpusDelta, hashJson, verifyEpochRotationManifestSignature } from './corpus/epoch-rotation.js';
import { parseCorpusDelta, verifyCorpusDeltaSignature } from './corpus/delta.js';
import { hashPostRevealEvalReportArtifact } from './replay/eval-report-artifact.js';

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
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https:') ? https : http;
    const req = client.get(url, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode ?? 0)) {
        res.resume();
        if (!res.headers.location || redirects >= 5) return reject(new Error(`redirect failed for ${url}`));
        return resolve(download(new URL(res.headers.location, url).toString(), redirects + 1));
      }
      if ((res.statusCode ?? 0) < 200 || (res.statusCode ?? 0) >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      let out = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { out += d; });
      res.on('end', () => resolve(out));
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
  return pins;
}

async function main() {
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
  const chain = await readChainContext(rpcUrl, registry, mining, epoch);

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
  const publicKeyUri = opt('public-key', stringField(status, 'epochSigningPublicKeyUrl') ?? '');

  let artifacts: unknown = 'skipped: pass --from-coordinator or --artifact-base-url to fetch public artifacts';
  if (rotationUri || deltaUri || baselineUri) {
    if (!rotationUri || !deltaUri) die('rotation/corpus delta URLs are required together; pass --from-coordinator or --artifact-base-url');
    const rotation = await readJsonUri(rotationUri) as Record<string, unknown>;
    const delta = parseCorpusDelta(await readJsonUri(deltaUri) as never);
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

    if (publicKeyUri) {
      const publicKey = await readTextUri(publicKeyUri);
      if (!verifyEpochRotationManifestSignature(rotation as never, publicKey)) throw new Error('rotation manifest signature invalid');
      if (!verifyCorpusDeltaSignature(delta, publicKey)) throw new Error('corpus delta signature invalid');
    }
    artifacts = {
      rotationManifestUrl: rotationUri,
      corpusDeltaUrl: deltaUri,
      ...(baselineUri ? { baselineManifestUrl: baselineUri } : {}),
      rotationManifestHash: rotationHash,
      corpusDeltaHash: deltaHash,
      baselineManifestHash: baselineManifestHash ?? 'not configured',
    };
  }

  let replay: unknown = null;
  const parentStatePath = opt('parent-state', process.env['CORETEX_PARENT_STATE_PATH']);
  const fromBlockRaw = opt('from-block', process.env['CORETEX_REPLAY_FROM_BLOCK'] ?? process.env['CORETEX_REGISTRY_DEPLOY_BLOCK']);
  if (parentStatePath && fromBlockRaw) {
    const parent = loadPackedState(parentStatePath);
    const latest = await latestBlock(rpcUrl);
    const logs = await coretexRangeLogs(rpcUrl, registry, blockHex(BigInt(fromBlockRaw)), blockHex(latest));
    const result = replayCoreTexFromLogs(parent, logs, {
      expectedBundleHash: chain.coreVersionHash,
      expectedCorpusRoot: chain.corpusRoot,
      expectedActiveFrontierRoot: chain.activeFrontierRoot,
      expectedBaselineManifestHash: chain.baselineManifestHash,
      expectedHiddenSeedCommit: chain.hiddenSeedCommit,
      policyAtomsMode: true,
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

  process.stdout.write(JSON.stringify({
    ok: true,
    command: 'coretex-validator-sync',
    epoch,
    registry,
    miningContract: mining,
    chain,
    artifacts,
    ...(replay ? { replay } : { replay: 'skipped: pass --parent-state and --from-block to replay registry logs' }),
    evalArtifacts,
  }, null, 2) + '\n');
}

main().catch((err) => die(err instanceof Error ? err.stack ?? err.message : String(err)));
