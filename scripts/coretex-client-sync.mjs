#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

import { bytesToHex, keccak256 } from '../dist/index.js';
export * from '../dist/client-sync-cli.js';

export const ZERO_BYTES32 = '0x' + '00'.repeat(32);

function isBytes32Hex(value) {
  return typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value);
}

function isAddressHex(value) {
  return typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/.test(value);
}

function normalizeBytes32(value, label) {
  if (!isBytes32Hex(value)) throw new Error(`${label} must be bytes32 hex`);
  return value.toLowerCase();
}

function normalizeAddress(value, label) {
  if (!isAddressHex(value)) throw new Error(`${label} must be address hex`);
  return value.toLowerCase();
}

function hexToBytes(hex) {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function epochSecretCommit(epochSecret) {
  return bytesToHex(keccak256(hexToBytes(normalizeBytes32(epochSecret, 'epochSecret')))).toLowerCase();
}

function selector(signature) {
  return bytesToHex(keccak256(new TextEncoder().encode(signature))).slice(0, 10).toLowerCase();
}

function encodeUint64Arg(value) {
  const n = BigInt(value);
  if (n < 0n || n > 0xffffffffffffffffn) throw new Error(`uint64 argument out of range: ${value}`);
  return n.toString(16).padStart(64, '0');
}

function callData(signature, args = []) {
  return `${selector(signature)}${args.map(encodeUint64Arg).join('')}`;
}

function decodeBytes32(result, label) {
  if (typeof result !== 'string' || !/^0x[0-9a-fA-F]{64,}$/.test(result)) {
    throw new Error(`${label} eth_call returned malformed bytes32`);
  }
  return `0x${result.slice(2, 66).toLowerCase()}`;
}

function decodeAddress(result, label) {
  const word = decodeBytes32(result, label);
  return `0x${word.slice(-40)}`;
}

export async function rpcEthCall({ rpcUrl, to, data }) {
  const payload = { jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to, data }, 'latest'] };
  const res = await fetch(rpcUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
  if (!res.ok) throw new Error(`RPC eth_call HTTP ${res.status}`);
  const j = await res.json();
  if (j.error) throw new Error(`RPC error: ${j.error.message ?? JSON.stringify(j.error)}`);
  if (typeof j.result !== 'string') throw new Error('RPC eth_call missing result');
  return j.result;
}

async function callView({ rpcUrl, to, signature, args: callArgs = [], ethCall }) {
  return ethCall({ rpcUrl, to, signature, args: callArgs, data: callData(signature, callArgs) });
}

export function verifyEpochSecretRevealBinding({
  hiddenSeedCommit,
  miningEpochCommit,
  epochSecret,
  requireReveal = false,
}) {
  const hidden = normalizeBytes32(hiddenSeedCommit, 'registry hiddenSeedCommit');
  const commit = normalizeBytes32(miningEpochCommit, 'mining epochCommit');
  const secret = normalizeBytes32(epochSecret, 'mining epochSecret');
  if (commit !== hidden) {
    throw new Error(`mining epochCommit ${commit} != registry hiddenSeedCommit ${hidden}`);
  }
  if (secret === ZERO_BYTES32) {
    if (requireReveal) throw new Error('awaiting_epoch_secret_reveal: mining epochSecret is zero/unrevealed');
    return { evalReplayStatus: 'awaiting_epoch_secret_reveal', epochSecretRevealed: false };
  }
  const recomputed = epochSecretCommit(secret);
  if (recomputed !== hidden) {
    throw new Error(`mining epochSecret commit ${recomputed} != registry hiddenSeedCommit ${hidden}`);
  }
  return { evalReplayStatus: 'epoch_secret_revealed', epochSecretRevealed: true };
}

export async function readOnChainEpochPins({
  rpcUrl,
  registry,
  miningContract,
  epoch,
  requireReveal = false,
  ethCall = rpcEthCall,
}) {
  const registryAddress = normalizeAddress(registry, 'registry');
  const miningAddress = normalizeAddress(miningContract, 'miningContract');
  const epochNumber = Number(epoch);
  if (!Number.isSafeInteger(epochNumber) || epochNumber < 0) throw new Error('epoch must be a non-negative safe integer');
  const call = (to, signature, callArgs = []) => callView({ rpcUrl, to, signature, args: callArgs, ethCall });
  const chainRegistry = decodeAddress(await call(miningAddress, 'coreTexRegistry()'), 'mining.coreTexRegistry');
  if (chainRegistry !== registryAddress) {
    throw new Error(`mining coreTexRegistry ${chainRegistry} != configured registry ${registryAddress}`);
  }
  const pins = {
    parentStateRoot: decodeBytes32(await call(registryAddress, 'epochParentStateRoot(uint64)', [epochNumber]), 'registry.epochParentStateRoot'),
    liveStateRoot: decodeBytes32(await call(registryAddress, 'liveStateRoot(uint64)', [epochNumber]), 'registry.liveStateRoot'),
    coreVersionHash: decodeBytes32(await call(registryAddress, 'epochCoreVersionHash(uint64)', [epochNumber]), 'registry.epochCoreVersionHash'),
    corpusRoot: decodeBytes32(await call(registryAddress, 'epochCorpusRoot(uint64)', [epochNumber]), 'registry.epochCorpusRoot'),
    activeFrontierRoot: decodeBytes32(await call(registryAddress, 'epochActiveFrontierRoot(uint64)', [epochNumber]), 'registry.epochActiveFrontierRoot'),
    baselineManifestHash: decodeBytes32(await call(registryAddress, 'epochBaselineManifestHash(uint64)', [epochNumber]), 'registry.epochBaselineManifestHash'),
    hiddenSeedCommit: decodeBytes32(await call(registryAddress, 'epochHiddenSeedCommit(uint64)', [epochNumber]), 'registry.epochHiddenSeedCommit'),
  };
  const transitionCount = Number(BigInt(await call(registryAddress, 'transitionCount(uint64)', [epochNumber])));
  const miningEpochCommit = decodeBytes32(await call(miningAddress, 'epochCommit(uint64)', [epochNumber]), 'mining.epochCommit');
  const epochSecret = decodeBytes32(await call(miningAddress, 'epochSecret(uint64)', [epochNumber]), 'mining.epochSecret');
  const reveal = verifyEpochSecretRevealBinding({
    hiddenSeedCommit: pins.hiddenSeedCommit,
    miningEpochCommit,
    epochSecret,
    requireReveal,
  });
  return {
    ...pins,
    miningEpochCommit,
    transitionCount,
    registryAddress,
    miningContractAddress: miningAddress,
    evalReplayStatus: reveal.evalReplayStatus,
    epochSecretRevealed: reveal.epochSecretRevealed,
  };
}

export function mergeChainPins(offlinePins = {}, chainPins = {}) {
  const out = { ...offlinePins };
  for (const key of ['parentStateRoot', 'liveStateRoot', 'coreVersionHash', 'corpusRoot', 'activeFrontierRoot', 'baselineManifestHash', 'hiddenSeedCommit']) {
    if (!chainPins[key]) continue;
    if (out[key] && String(out[key]).toLowerCase() !== String(chainPins[key]).toLowerCase()) {
      throw new Error(`registry pin mismatch ${key}: offline=${out[key]} chain=${chainPins[key]}`);
    }
    out[key] = chainPins[key];
  }
  return out;
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
  const proc = spawnSync(process.execPath, [new URL('../dist/client-sync-cli.js', import.meta.url), ...process.argv.slice(2)], {
    stdio: 'inherit',
  });
  process.exit(proc.status ?? 1);
}
